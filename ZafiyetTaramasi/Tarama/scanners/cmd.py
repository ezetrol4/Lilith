"""
OWASP Top 10:2025 — A05 Injection
OS Command Injection Scanner

Tespit yöntemleri:
  1. Çıktı bazlı — komut çıktısı yanıtta görünüyor mu?
  2. Hata bazlı  — shell hata mesajları yanıtta var mı?
  3. Kör zaman   — sleep/ping ile gecikme ölçümü (P0-6: varsayılan olarak KAPALI)

P0-6 kanıt kuralları:
  - CONFIRMED yalnızca YAPILANDIRILMIŞ komut çıktısı (birden çok passwd satırı, tam `id`
    çıktısı, win.ini bölüm çifti) baseline'da yokken belirir VE tekrarda yeniden görülürse.
  - Genel işaretler (`/bin/`, `daemon:`, çıplak `uid=`, tek win.ini bölümü), yansıyan girdi,
    genel uygulama hataları ve HTTP durum farkları yürütme KANITLAMAZ → en fazla MANUAL_REVIEW.
  - Yanıt varlığı `is None` ile test edilir (§67); 4xx/5xx baseline geçerli bir baseline'dır.
  - WAF / challenge / rate-limit yanıtı kanıt değildir ve TÜM sonraki CMD yoklamalarını durdurur.
"""
import html
import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote, quote_plus

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from . import owasp as owasp_2025
from .credential_guard import credential_form_reason, not_assessed_finding
from ..services.evidence_redaction import redact_sensitive_text
from ..services.safe_http import SafeSession, safe_session


_OWASP_INJECTION = owasp_2025.A05_INJECTION
_CWE_CMDI = "CWE-78"


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Çıktı bazlı payload'lar: (payload, çıktı ailesi) — payload'lar değişmedi (P0-6)
# ---------------------------------------------------------------------------
_PASSWD, _ID, _WININI = "passwd", "id", "win.ini"

_OUTPUT_PAYLOADS: list[tuple[str, str]] = [
    # Unix — /etc/passwd içeriği
    ("; cat /etc/passwd",           _PASSWD),
    ("|cat /etc/passwd",            _PASSWD),
    ("&& cat /etc/passwd",          _PASSWD),
    ("`cat /etc/passwd`",           _PASSWD),
    ("$(cat /etc/passwd)",          _PASSWD),
    # Unix — id çıktısı
    ("; id",                        _ID),
    ("|id",                         _ID),
    ("$(id)",                       _ID),
    # Windows — win.ini içeriği
    ("; type C:\\Windows\\win.ini", _WININI),
    ("| type C:\\Windows\\win.ini", _WININI),
    ("& type C:\\Windows\\win.ini", _WININI),
]

# Yapılandırılmış (güçlü) çıktı kanıtı
_PASSWD_LINE_RE = re.compile(
    r"^[a-z_][a-z0-9_.-]*:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*$", re.IGNORECASE | re.MULTILINE)
_PASSWD_ROOT_RE = re.compile(r"^root:[^:\n]*:0:0:[^:\n]*:[^:\n]*:[^:\n]*$", re.MULTILINE)
_ID_OUTPUT_RE = re.compile(r"\buid=\d+\([\w.$-]+\)\s+gid=\d+\([\w.$-]+\)")
_WININI_FONTS_RE = re.compile(r"\[fonts\]", re.IGNORECASE)
_WININI_EXT_RE = re.compile(r"\[extensions\]", re.IGNORECASE)

# Zayıf (genel) işaretler — tek başına yürütme kanıtı DEĞİL
_WEAK_MARKERS = {
    _PASSWD: ("root:x:0:0", "daemon:", "/bin/"),
    _ID: ("uid=", "gid=", "groups="),
    _WININI: ("[fonts]", "[extensions]", "[mci"),
}

# ---------------------------------------------------------------------------
# Hata bazlı kalıplar
# ---------------------------------------------------------------------------
# Yapılandırılmış shell hatası → POTENTIAL (komut yorumlama belirtisi, yürütme kanıtı değil)
_SHELL_ERROR_RE = re.compile(
    r"(?<![\w/.-])(?:/(?:usr/)?bin/)?(?:ba|da|z|k)?sh: (?:line )?\d+: "        # sh: 1: …  /  bash: line 1: …
    r"|(?<![\w/.-])/(?:usr/)?bin/(?:ba|da|z|k)?sh: "                           # /bin/sh: …
    r"|(?<![\w/.-])(?:ba|da|z|k)?sh: [^\n<:]{1,80}: (?:command )?not found"    # sh: foo: not found
    r"|syntax error near unexpected token"
    r"|is not recognized as an internal or external command",
    re.IGNORECASE,
)
# Genel uygulama/işletim sistemi hata metni → yalnızca MANUAL_REVIEW
_GENERIC_ERROR_RE = re.compile(
    r"command not found|no such file or directory|permission denied|"
    r"(?:the system )?cannot find the path specified|\bcmd\.exe\b|\bposix_spawn\b|"
    r"(?<![\w/.-])(?:ba|da|z|k)?sh: ",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Engelleme (WAF / challenge / rate limit) — kanıt değildir, yoklamalar DURUR
# ---------------------------------------------------------------------------
_BLOCK_STATUSES = frozenset({403, 406, 419, 429})
_WAF_TEXT_RE = re.compile(
    r"attention required|access denied|request (?:was )?blocked|you have been blocked|"
    r"web application firewall|verify you are (?:a )?human|captcha|mod_security|"
    r"too many requests|rate.?limit|challenge-platform|cf-chl",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Zaman bazlı payload'lar: (payload, beklenen_gecikme_sn, etiket) — varsayılan KAPALI
# ---------------------------------------------------------------------------
_TIME_PAYLOADS: list[tuple[str, float, str]] = [
    ("; sleep 4",                   4.0, "Unix sleep"),
    ("| sleep 4",                   4.0, "Unix pipe sleep"),
    ("&& sleep 4",                  4.0, "Unix AND sleep"),
    ("`sleep 4`",                   4.0, "Unix backtick sleep"),
    ("$(sleep 4)",                  4.0, "Unix subshell sleep"),
    ("; ping -c 4 127.0.0.1",      4.0, "Unix ping"),
    ("& timeout /t 4 /nobreak >nul", 4.0, "Windows timeout"),
    ("& ping -n 4 127.0.0.1",      4.0, "Windows ping"),
]

_TIME_MULTIPLIER = 0.75

_SKIP_TYPES = frozenset({"submit", "button", "image", "reset", "file", "checkbox", "radio"})
_CSRF_NAMES = frozenset({"csrf", "csrftoken", "_token", "authenticity_token",
                          "__requestverificationtoken"})
_BASELINE_VALUE = "lilith_baseline"
# Komut çıktısı sıklıkla <pre>, <br> vb. içinde döner: etiketler satır sonuna çevrilir (yalnızca eşleştirme için)
_TAG_RE = re.compile(r"<[^>]+>")


def _is_csrf(name: str) -> bool:
    return any(c in name.lower() for c in _CSRF_NAMES)


def _extract_snippet(body: str, marker: str, width: int = 120) -> str:
    """marker etrafında width karakter döner."""
    # Kanıt penceresi kesilmeden ÖNCE tüm gövde redakte edilir (yalnızca kanıt metni;
    # tespit ham gövde üzerinde yapılır)
    body = redact_sensitive_text(body)
    idx = body.lower().find(marker.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 20)
    end   = min(len(body), idx + width)
    raw   = body[start:end].strip()
    return re.sub(r"\s+", " ", raw) + ("…" if end < len(body) else "")


def _body(response) -> str:
    """Yanıt gövdesi (durum kodundan bağımsız). Yanıt yoksa çağıran None ile ayrı ele alır."""
    return response.content.decode(errors="replace")


def _without_reflection(body: str, payload: str) -> str:
    """Yansıtılan payload'ı (ham, HTML kaçışlı, URL kodlu) gövdeden çıkarır: yansıma ≠ yürütme."""
    for variant in {payload, html.escape(payload, quote=True), html.escape(payload, quote=False),
                    quote(payload, safe=""), quote_plus(payload)}:
        if variant:
            body = body.replace(variant, " ")
    return _TAG_RE.sub("\n", body)


def _structured_output(family: str, text: str) -> str | None:
    """Yapılandırılmış komut çıktısı bulunursa kanıt işaretini döner."""
    if family == _PASSWD:
        root = _PASSWD_ROOT_RE.search(text)
        if root and len(_PASSWD_LINE_RE.findall(text)) >= 2:
            return root.group(0)
        return None
    if family == _ID:
        match = _ID_OUTPUT_RE.search(text)
        return match.group(0) if match else None
    if family == _WININI:
        if _WININI_FONTS_RE.search(text) and _WININI_EXT_RE.search(text):
            return "[fonts]"
    return None


def _new_structured_output(family: str, baseline_text: str, text: str) -> str | None:
    marker = _structured_output(family, text)
    if marker is None or _structured_output(family, baseline_text) is not None:
        return None
    return marker


def _new_weak_marker(family: str, baseline_text: str, text: str) -> str | None:
    lowered, base = text.lower(), baseline_text.lower()
    for marker in _WEAK_MARKERS[family]:
        if marker.lower() in lowered and marker.lower() not in base:
            return marker
    return None


def _new_match(pattern: re.Pattern, baseline_text: str, text: str) -> str | None:
    match = pattern.search(text)
    if match and not pattern.search(baseline_text):
        return match.group(0)
    return None


class _ProbeBlocked(Exception):
    """WAF / challenge / rate-limit yanıtı — sonraki tüm CMD yoklamaları durdurulur."""


# ===========================================================================


class CmdInjectionScanner(Scanner):
    def __init__(self, session: requests.Session | None = None, timeout: float = 12.0,
                 max_forms: int = 3, max_fields_per_form: int = 3, *, time_based_probes: bool = False):
        # Zaman bazlı kör yoklamalar sunucuda bilinçli olarak komut (sleep/ping) çalıştırmaya
        # ve iş parçacığı tutmaya çalışır; alan başına 16 isteğe kadar çıkar. Varsayılan KAPALI;
        # yalnızca kodla (kontrollü lab / test) açılır — istek/ayar/ortam değişkeni açamaz.
        if not isinstance(time_based_probes, bool):
            raise TypeError("time_based_probes bool olmalıdır")
        self._external_session   = session
        self.timeout             = timeout
        self.max_forms           = max_forms
        self.max_fields_per_form = max_fields_per_form
        self.time_based_probes   = time_based_probes

    def _make_session(self) -> SafeSession:
        if self._external_session:
            return safe_session(self._external_session)
        s = safe_session()
        s.headers["User-Agent"] = _USER_AGENT
        return s

    # -----------------------------------------------------------------------
    # Form yardımcıları (SQL scanner ile aynı desen)
    # -----------------------------------------------------------------------

    def _form_details(self, form) -> dict:
        inputs = [
            {"type": t.get("type", "text"), "name": t.get("name"), "value": t.get("value", "")}
            for t in form.find_all("input")
        ]
        return {
            "action": form.get("action"),
            "method": form.get("method", "get").lower(),
            "inputs": inputs,
        }

    def _injectable_fields(self, details: dict) -> list[str]:
        fields = []
        for inp in details["inputs"]:
            t    = inp.get("type", "text").lower()
            name = inp.get("name") or ""
            if t in _SKIP_TYPES or not name or _is_csrf(name):
                continue
            fields.append(name)
        return fields

    def _build_data(self, details: dict, target_field: str, payload: str) -> dict:
        data = {}
        for inp in details["inputs"]:
            name = inp.get("name")
            if not name:
                continue
            data[name] = payload if name == target_field else (inp.get("value") or "test")
        return data

    def _submit(self, url: str, method: str, data: dict,
                session: requests.Session, timeout: float | None = None) -> requests.Response | None:
        t = timeout or self.timeout
        try:
            return session.post(url, data=data, timeout=t) if method == "post" \
                   else session.get(url, params=data, timeout=t)
        except requests.RequestException:
            return None

    @staticmethod
    def _check_blocked(response, baseline_text: str) -> None:
        """Engelleme yanıtı kanıt değildir; görülünce yoklamalar durur (atlatma denenmez)."""
        status = getattr(response, "status_code", None)
        if isinstance(status, int) and status in _BLOCK_STATUSES:
            raise _ProbeBlocked(f"HTTP {status}")
        if isinstance(status, int) and status == 503:
            retry_after = response.headers.get("Retry-After") if response.headers is not None else None
            if isinstance(retry_after, str) and retry_after:
                raise _ProbeBlocked("HTTP 503 | Retry-After")
        waf = _new_match(_WAF_TEXT_RE, baseline_text, _body(response))
        if waf:
            raise _ProbeBlocked(f"HTTP {status} | yanıtta: '{waf}'")

    def _form_baseline(self, url, method, details, field, session) -> str | None:
        """Baseline gövdesi; yanıt YOKSA None (alan test edilmez — 'yeni' kanıt kurulamaz).
        4xx/5xx baseline geçerlidir (Response truthiness kullanılmaz, §67)."""
        res = self._submit(url, method, self._build_data(details, field, _BASELINE_VALUE), session)
        return None if res is None else _body(res)

    # -----------------------------------------------------------------------
    # Tespit yöntemleri
    # -----------------------------------------------------------------------

    def _output_finding(self, *, url, field, payload, body, marker, structured, reproduced,
                        url_param=False) -> Finding:
        snippet = _extract_snippet(body, marker)
        location = f"Parametre: {field}" if url_param else f"Alan: {field}"
        suffix = " (URL Parameter)" if url_param else ""
        recommendation = ("Avoid passing user-controlled input to a system shell; use safe APIs "
                          "or strict allowlisting/argument-array execution instead.")
        if structured and reproduced:
            return Finding(
                severity=Severity.CRITICAL,
                title="OS Command Execution Confirmed",
                evidence=f"URL: {url} | {location} | Payload: {payload} | Yapılandırılmış çıktı (tekrarlandı): "
                         f"{snippet or marker}",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="Structured command output (not present in the baseline response and not a "
                            "reflection of the submitted input) appeared after the modified input was "
                            "submitted, and reproduced on a follow-up request.",
                affected_url=url, parameter=field, owasp=_OWASP_INJECTION, cwe=_CWE_CMDI,
                mitre="T1059 - Command and Scripting Interpreter", recommendation=recommendation,
            )
        if structured:
            return Finding(
                severity=Severity.CRITICAL,
                title="Potential OS Command Injection - Output Based" + suffix,
                evidence=f"URL: {url} | {location} | Payload: {payload} | Yapılandırılmış çıktı "
                         f"({'tekrar doğrulaması yok' if url_param else 'tekrarlanmadı'}): {snippet or marker}",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                description="Structured command output appeared only after the modified input was submitted "
                            "(absent from the baseline, not a reflection of the input), but it was not "
                            "reproduced, so this is not treated as confirmed execution.",
                affected_url=url, parameter=field, owasp=_OWASP_INJECTION, cwe=_CWE_CMDI,
                recommendation=recommendation,
            )
        return Finding(
            severity=Severity.CRITICAL,
            title="Potential OS Command Injection - Ambiguous Output Marker" + suffix,
            evidence=f"URL: {url} | {location} | Payload: {payload} | Genel işaret (yapılandırılmış çıktı "
                     f"değil): {snippet or marker}",
            confidence=Confidence.LOW,
            status=FindingStatus.MANUAL_REVIEW,
            description="A generic command-related string (for example '/bin/', 'daemon:' or a bare 'uid=') "
                        "appeared that was not in the baseline response. Such strings also occur in ordinary "
                        "page content and application errors, so this does not establish command execution. "
                        "Manual verification is required.",
            affected_url=url, parameter=field, owasp=_OWASP_INJECTION, cwe=_CWE_CMDI,
            recommendation=recommendation,
        )

    def _error_finding(self, *, url, field, payload, body, matched, strong, url_param=False) -> Finding:
        snippet = _extract_snippet(body, matched)
        location = f"Parametre: {field}" if url_param else f"Alan: {field}"
        suffix = " (URL Parameter)" if url_param else ""
        recommendation = ("Avoid passing user-controlled input to a system shell; use safe APIs "
                          "or strict allowlisting/argument-array execution instead.")
        if strong:
            return Finding(
                severity=Severity.HIGH,
                title="Potential OS Command Injection - Shell Error" + suffix,
                evidence=f"URL: {url} | {location} | Payload: {payload!r} | Hata: {snippet or matched}",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                description="A structured shell error appeared only after the modified input was submitted, "
                            "absent from the baseline response. A shell error indicates possible command "
                            "interpretation, but is weaker evidence than confirmed command output, so this "
                            "is not treated as confirmed execution.",
                affected_url=url, parameter=field, owasp=_OWASP_INJECTION, cwe=_CWE_CMDI,
                recommendation=recommendation,
            )
        return Finding(
            severity=Severity.HIGH,
            title="Potential OS Command Injection - Generic Error" + suffix,
            evidence=f"URL: {url} | {location} | Payload: {payload!r} | Genel hata metni: {snippet or matched}",
            confidence=Confidence.LOW,
            status=FindingStatus.MANUAL_REVIEW,
            description="A generic operating-system or application error message (for example 'No such file "
                        "or directory' or 'Permission denied') appeared that was not in the baseline response. "
                        "Ordinary application errors produce the same text, so this does not indicate command "
                        "interpretation on its own. Manual verification is required.",
            affected_url=url, parameter=field, owasp=_OWASP_INJECTION, cwe=_CWE_CMDI,
            recommendation=recommendation,
        )

    def _test_output_based(self, url: str, method: str, details: dict,
                           field: str, session: requests.Session, result: ScanResult) -> bool:
        baseline_body = self._form_baseline(url, method, details, field, session)
        if baseline_body is None:
            return False
        baseline_text = _TAG_RE.sub("\n", baseline_body)

        for payload, family in _OUTPUT_PAYLOADS:
            data = self._build_data(details, field, payload)
            res  = self._submit(url, method, data, session)
            if res is None:
                continue
            self._check_blocked(res, baseline_body)
            body = _body(res)
            text = _without_reflection(body, payload)

            marker = _new_structured_output(family, baseline_text, text)
            if marker is not None:
                # Tek bir yanıt yeterli değildir — sınırlı bir doğrulama tekrarı (CLAUDE.md §5)
                repeat_res = self._submit(url, method, data, session)
                reproduced = False
                if repeat_res is not None:
                    self._check_blocked(repeat_res, baseline_body)
                    reproduced = _new_structured_output(
                        family, baseline_text, _without_reflection(_body(repeat_res), payload)) is not None
                result.findings.append(self._output_finding(
                    url=url, field=field, payload=payload, body=body, marker=marker,
                    structured=True, reproduced=reproduced))
                return True

            weak = _new_weak_marker(family, baseline_text, text)
            if weak is not None:
                result.findings.append(self._output_finding(
                    url=url, field=field, payload=payload, body=body, marker=weak,
                    structured=False, reproduced=False))
                return True
        return False

    def _test_error_based(self, url: str, method: str, details: dict,
                          field: str, session: requests.Session, result: ScanResult) -> bool:
        baseline_body = self._form_baseline(url, method, details, field, session)
        if baseline_body is None:
            return False

        # Birkaç basit enjeksiyon karakteri dene
        for payload in (";", "|", "&", "`", "$(", "'|'"):
            data = self._build_data(details, field, payload)
            res  = self._submit(url, method, data, session)
            if res is None:
                continue
            self._check_blocked(res, baseline_body)
            body = _body(res)
            text = _without_reflection(body, payload)
            for pattern, strong in ((_SHELL_ERROR_RE, True), (_GENERIC_ERROR_RE, False)):
                matched = _new_match(pattern, baseline_body, text)
                if matched:
                    result.findings.append(self._error_finding(
                        url=url, field=field, payload=payload, body=body, matched=matched, strong=strong))
                    return True
        return False

    def _test_time_based(self, url: str, method: str, details: dict,
                         field: str, baseline: float,
                         session: requests.Session, result: ScanResult) -> bool:
        """Yalnızca time_based_probes=True iken çağrılır (kontrollü lab)."""
        for payload, sleep_sec, label in _TIME_PAYLOADS:
            data = self._build_data(details, field, payload)
            t0   = time.time()
            res  = self._submit(url, method, data, session, timeout=self.timeout)
            elapsed = time.time() - t0
            if res is None:
                continue   # zaman aşımı / bağlantı hatası gecikme kanıtı DEĞİLDİR
            self._check_blocked(res, "")
            if elapsed < baseline + sleep_sec * _TIME_MULTIPLIER:
                continue

            # Tek bir yavaş istek yeterli kanıt değildir — sınırlı bir doğrulama
            # tekrarı ile gecikmenin tekrarlanabilir olduğunu kontrol et (CLAUDE.md §5)
            t1 = time.time()
            repeat_res = self._submit(url, method, data, session, timeout=self.timeout)
            elapsed_repeat = time.time() - t1
            reproduced = (repeat_res is not None
                          and elapsed_repeat >= baseline + sleep_sec * _TIME_MULTIPLIER)

            result.findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"Potential Blind Command Injection ({label})",
                evidence=(
                    f"URL: {url} | Alan: {field} | "
                    f"Gecikme: {elapsed:.1f}s (tekrar: {elapsed_repeat:.1f}s) | Payload: {payload}"
                ),
                confidence=Confidence.HIGH if reproduced else Confidence.LOW,
                status=FindingStatus.CONFIRMED if reproduced else FindingStatus.MANUAL_REVIEW,
                description="A response delay matching the injected sleep duration was observed"
                            + (" and reproduced on a follow-up request." if reproduced else
                               ", but did not reproduce on a follow-up request — a single timing anomaly is "
                               "not reliable evidence of blind command injection on its own."),
                affected_url=url,
                parameter=field,
                owasp=_OWASP_INJECTION,
                cwe=_CWE_CMDI,
                mitre="T1059 - Command and Scripting Interpreter" if reproduced else None,
                recommendation="Avoid passing user-controlled input to a system shell; use safe APIs "
                               "or strict allowlisting/argument-array execution instead.",
            ))
            return True
        return False

    # -----------------------------------------------------------------------
    # URL parametresi testi
    # -----------------------------------------------------------------------

    def _get(self, session, url) -> requests.Response | None:
        try:
            return session.get(url, timeout=self.timeout)
        except requests.RequestException:
            return None

    def _test_url_params(self, url: str, baseline: float,
                         session: requests.Session, result: ScanResult) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        flat = {k: v[0] for k, v in params.items()}

        def build(param, value):
            injected = {k: (value if k == param else v) for k, v in flat.items()}
            return urlunparse(parsed._replace(query=urlencode(injected)))

        for param in flat:
            if _is_csrf(param):
                continue

            # Baseline: zararsız değerle referans yanıt. Yanıt yoksa 'yeni' kanıt kurulamaz → atla.
            baseline_res = self._get(session, build(param, _BASELINE_VALUE))
            if baseline_res is None:
                continue
            baseline_body = _body(baseline_res)
            baseline_text = _TAG_RE.sub("\n", baseline_body)

            # 1. Çıktı bazlı (URL yolunda tekrar doğrulaması yok → en fazla POTENTIAL; P1-5)
            found = False
            for payload, family in _OUTPUT_PAYLOADS:
                test_url = build(param, payload)
                res = self._get(session, test_url)
                if res is None:
                    continue
                self._check_blocked(res, baseline_body)
                body = _body(res)
                text = _without_reflection(body, payload)
                marker = _new_structured_output(family, baseline_text, text)
                structured = marker is not None
                if not structured:
                    marker = _new_weak_marker(family, baseline_text, text)
                if marker is not None:
                    result.findings.append(self._output_finding(
                        url=test_url, field=param, payload=payload, body=body, marker=marker,
                        structured=structured, reproduced=False, url_param=True))
                    found = True
                    break
            if found:
                continue

            # 2. Hata bazlı
            for payload in (";", "|", "&", "`"):
                test_url = build(param, payload)
                res = self._get(session, test_url)
                if res is None:
                    continue
                self._check_blocked(res, baseline_body)
                body = _body(res)
                text = _without_reflection(body, payload)
                for pattern, strong in ((_SHELL_ERROR_RE, True), (_GENERIC_ERROR_RE, False)):
                    matched = _new_match(pattern, baseline_body, text)
                    if matched:
                        result.findings.append(self._error_finding(
                            url=test_url, field=param, payload=payload, body=body, matched=matched,
                            strong=strong, url_param=True))
                        found = True
                        break
                if found:
                    break

    # -----------------------------------------------------------------------
    # Ana tarama
    # -----------------------------------------------------------------------

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="cmd", target=target)
        session = self._make_session()

        try:
            t0       = time.time()
            response = session.get(target, timeout=self.timeout)
            baseline = time.time() - t0
        except requests.RequestException as e:
            result.error = str(e)
            return result

        forms = BeautifulSoup(response.content, "html.parser").find_all("form")
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="forms_detected",
            evidence=str(len(forms)),
        ))

        time_skipped = 0
        try:
            # URL parametrelerini test et
            self._test_url_params(target, baseline, session, result)

            # Form alanlarını test et
            for form in forms[:self.max_forms]:
                details    = self._form_details(form)
                action_url = urljoin(target, details["action"] or target)
                method     = details["method"]

                # Kimlik bilgisi işleyen formlara payload gönderilmez (P0-4.1) — değerlendirilmedi
                reason = credential_form_reason(form, action_url)
                if reason:
                    result.findings.append(not_assessed_finding(action_url, reason))
                    continue

                for field in self._injectable_fields(details)[:self.max_fields_per_form]:
                    # 1. Çıktı bazlı (en güvenilir)
                    if self._test_output_based(action_url, method, details, field, session, result):
                        continue

                    # 2. Hata bazlı
                    if self._test_error_based(action_url, method, details, field, session, result):
                        continue

                    # 3. Zaman bazlı (son çare, yavaş) — varsayılan KAPALI
                    if self.time_based_probes:
                        self._test_time_based(action_url, method, details, field, baseline, session, result)
                    else:
                        time_skipped += 1
        except _ProbeBlocked as blocked:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Komut enjeksiyonu testi durduruldu: engelleme yanıtı",
                evidence=f"Sonuç: BLOCKED — {blocked} | sonraki komut enjeksiyonu yoklamaları durduruldu",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description="A WAF, challenge or rate-limit response was received. It is not evidence of "
                            "command injection, and all further command-injection probes were stopped "
                            "(no retries or evasion). The remaining surface was not assessed — this is not "
                            "a SECURE result.",
                affected_url=target,
            ))
            return result

        if time_skipped:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Kör (zaman bazlı) komut enjeksiyonu testi yürütülmedi",
                evidence=f"Sonuç: NOT_EXECUTED — zaman bazlı yoklamalar varsayılan olarak kapalı | "
                         f"Atlanan alan: {time_skipped}",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description="Time-based blind probes deliberately make the server execute delaying commands "
                            "and hold workers, so they are disabled in default scans. Blind command injection "
                            "was not assessed for the listed fields — this is not a SECURE result.",
                affected_url=target,
            ))
        return result
