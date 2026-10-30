"""
OWASP Top 10:2025 — A05 Injection
OS Command Injection Scanner

Tespit yöntemleri:
  1. Çıktı bazlı — komut çıktısı (root:x:0:0, uid=, [fonts]) yanıtta görünüyor mu?
  2. Hata bazlı  — shell hata mesajları yanıtta var mı?
  3. Kör zaman   — sleep/ping ile gecikme ölçümü
"""
import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from ..services.evidence_redaction import redact_sensitive_text
from ..services.safe_http import SafeSession, safe_session


_OWASP_INJECTION = "A03:2021 - Injection"
_CWE_CMDI = "CWE-78"


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Çıktı bazlı payload'lar: (payload, [beklenen_kalıplar])
# ---------------------------------------------------------------------------
_OUTPUT_PAYLOADS: list[tuple[str, list[str]]] = [
    # Unix — /etc/passwd içeriği
    ("; cat /etc/passwd",           ["root:x:0:0", "daemon:", "/bin/"]),
    ("|cat /etc/passwd",            ["root:x:0:0", "daemon:", "/bin/"]),
    ("&& cat /etc/passwd",          ["root:x:0:0", "daemon:", "/bin/"]),
    ("`cat /etc/passwd`",           ["root:x:0:0", "daemon:", "/bin/"]),
    ("$(cat /etc/passwd)",          ["root:x:0:0", "daemon:", "/bin/"]),
    # Unix — whoami / id çıktısı
    ("; id",                        ["uid=", "gid=", "groups="]),
    ("|id",                         ["uid=", "gid=", "groups="]),
    ("$(id)",                       ["uid=", "gid=", "groups="]),
    # Windows — win.ini içeriği
    ("; type C:\\Windows\\win.ini", ["[fonts]", "[extensions]", "[mci"]),
    ("| type C:\\Windows\\win.ini", ["[fonts]", "[extensions]", "[mci"]),
    ("& type C:\\Windows\\win.ini", ["[fonts]", "[extensions]", "[mci"]),
]

# ---------------------------------------------------------------------------
# Hata bazlı kalıplar — shell yanıtları (küçük harf karşılaştırması)
# ---------------------------------------------------------------------------
_ERROR_PATTERNS = frozenset({
    "sh: ",
    "/bin/sh:",
    "/bin/bash:",
    "command not found",
    "is not recognized as an internal or external command",
    "syntax error near unexpected token",
    "cannot find the path specified",
    "the system cannot find the path",
    "no such file or directory",
    "permission denied",
    "bash: ",
    "cmd.exe",
    "posix_spawn",
})

# ---------------------------------------------------------------------------
# Zaman bazlı payload'lar: (payload, beklenen_gecikme_sn, etiket)
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


# ===========================================================================


class CmdInjectionScanner(Scanner):
    def __init__(self, session: requests.Session | None = None, timeout: float = 12.0,
                 max_forms: int = 3, max_fields_per_form: int = 3):
        self._external_session   = session
        self.timeout             = timeout
        self.max_forms           = max_forms
        self.max_fields_per_form = max_fields_per_form

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

    # -----------------------------------------------------------------------
    # Tespit yöntemleri
    # -----------------------------------------------------------------------

    def _has_shell_error(self, body: str) -> str | None:
        """Shell hata kalıbını döner, yoksa None."""
        b = body.lower()
        for pattern in _ERROR_PATTERNS:
            if pattern in b:
                return pattern
        return None

    def _new_marker(self, baseline_body: str, test_body: str, marker: str) -> bool:
        """Marker'ın baseline'da zaten var olup olmadığını kontrol eder — yalnızca
        YENİ ortaya çıkan kanıt sayılır (CLAUDE.md 4.1)."""
        if marker.lower() not in test_body.lower():
            return False
        return marker.lower() not in baseline_body.lower()

    def _test_output_based(self, url: str, method: str, details: dict,
                           field: str, session: requests.Session, result: ScanResult) -> bool:
        baseline_res = self._submit(url, method, self._build_data(details, field, "lilith_baseline"), session)
        baseline_body = baseline_res.content.decode(errors="replace") if baseline_res else ""

        for payload, markers in _OUTPUT_PAYLOADS:
            data = self._build_data(details, field, payload)
            res  = self._submit(url, method, data, session)
            if not res:
                continue
            body = res.content.decode(errors="replace")
            for marker in markers:
                if not self._new_marker(baseline_body, body, marker):
                    continue

                # Tek bir yanıt yeterli değildir — sınırlı bir doğrulama tekrarı yap (CLAUDE.md 4.1)
                repeat_res = self._submit(url, method, data, session)
                repeat_body = repeat_res.content.decode(errors="replace") if repeat_res else ""
                reproduced = marker.lower() in repeat_body.lower()

                snippet = _extract_snippet(body, marker)
                result.findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="OS Command Execution Confirmed" if reproduced else "Potential OS Command Injection - Output Based",
                    evidence=(
                        f"URL: {url} | Alan: {field} | Payload: {payload} | "
                        f"Kanıt: {snippet or marker}"
                    ),
                    confidence=Confidence.HIGH if reproduced else Confidence.MEDIUM,
                    status=FindingStatus.CONFIRMED if reproduced else FindingStatus.POTENTIAL,
                    description="A distinctive command-execution marker appeared only after the modified "
                                "input was submitted, absent from the baseline response for the same field"
                                + (", and reproduced on a follow-up request." if reproduced else "."),
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

    def _test_error_based(self, url: str, method: str, details: dict,
                          field: str, session: requests.Session, result: ScanResult) -> bool:
        baseline_res = self._submit(url, method, self._build_data(details, field, "lilith_baseline"), session)
        baseline_body = baseline_res.content.decode(errors="replace") if baseline_res else ""

        # Birkaç basit enjeksiyon karakteri dene
        for payload in (";", "|", "&", "`", "$(", "'|'"):
            data = self._build_data(details, field, payload)
            res  = self._submit(url, method, data, session)
            if not res:
                continue
            body = res.content.decode(errors="replace")
            matched = self._has_shell_error(body)
            if matched and matched not in baseline_body.lower():
                snippet = _extract_snippet(body, matched)
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Potential OS Command Injection - Shell Error",
                    evidence=(
                        f"URL: {url} | Alan: {field} | Payload: {payload!r} | "
                        f"Hata: {snippet or matched}"
                    ),
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    description="A shell-related error string appeared only after the modified input was "
                                "submitted, absent from the baseline response. A shell error indicates "
                                "possible command interpretation, but is weaker evidence than confirmed "
                                "command output, so this is not treated as confirmed execution.",
                    affected_url=url,
                    parameter=field,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_CMDI,
                    recommendation="Avoid passing user-controlled input to a system shell; use safe APIs "
                                   "or strict allowlisting/argument-array execution instead.",
                ))
                return True
        return False

    def _test_time_based(self, url: str, method: str, details: dict,
                         field: str, baseline: float,
                         session: requests.Session, result: ScanResult) -> bool:
        for payload, sleep_sec, label in _TIME_PAYLOADS:
            data = self._build_data(details, field, payload)
            t0   = time.time()
            self._submit(url, method, data, session, timeout=self.timeout)
            elapsed = time.time() - t0
            if elapsed < baseline + sleep_sec * _TIME_MULTIPLIER:
                continue

            # Tek bir yavaş istek yeterli kanıt değildir — sınırlı bir doğrulama
            # tekrarı ile gecikmenin tekrarlanabilir olduğunu kontrol et (CLAUDE.md 4.4)
            t1 = time.time()
            self._submit(url, method, data, session, timeout=self.timeout)
            elapsed_repeat = time.time() - t1
            reproduced = elapsed_repeat >= baseline + sleep_sec * _TIME_MULTIPLIER

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

    def _test_url_params(self, url: str, baseline: float,
                         session: requests.Session, result: ScanResult) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        flat = {k: v[0] for k, v in params.items()}

        for param in flat:
            if _is_csrf(param):
                continue

            # Baseline: zararsız değerle referans yanıt (CLAUDE.md 4.1/4.2)
            baseline_injected = {k: ("lilith_baseline" if k == param else v) for k, v in flat.items()}
            baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_injected)))
            try:
                baseline_body = session.get(baseline_url, timeout=self.timeout).content.decode(errors="replace")
            except requests.RequestException:
                baseline_body = ""

            # 1. Çıktı bazlı
            found = False
            for payload, markers in _OUTPUT_PAYLOADS:
                injected = {k: (payload if k == param else v) for k, v in flat.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(injected)))
                try:
                    res = session.get(test_url, timeout=self.timeout)
                    body = res.content.decode(errors="replace")
                    for marker in markers:
                        if self._new_marker(baseline_body, body, marker):
                            snippet = _extract_snippet(body, marker)
                            result.findings.append(Finding(
                                severity=Severity.CRITICAL,
                                title="Potential OS Command Injection - Output Based (URL Parameter)",
                                evidence=(
                                    f"URL: {test_url} | Parametre: {param} | "
                                    f"Payload: {payload} | Kanıt: {snippet or marker}"
                                ),
                                confidence=Confidence.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                description="A distinctive command-execution marker appeared only after this "
                                            "URL parameter's value was modified, absent from the baseline "
                                            "response.",
                                affected_url=test_url,
                                parameter=param,
                                owasp=_OWASP_INJECTION,
                                cwe=_CWE_CMDI,
                                recommendation="Avoid passing user-controlled input to a system shell; use "
                                               "safe APIs or strict allowlisting/argument-array execution "
                                               "instead.",
                            ))
                            found = True
                            break
                    if found:
                        break
                except requests.RequestException:
                    continue
            if found:
                continue

            # 2. Hata bazlı
            for payload in (";", "|", "&", "`"):
                injected = {k: (payload if k == param else v) for k, v in flat.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(injected)))
                try:
                    res  = session.get(test_url, timeout=self.timeout)
                    body = res.content.decode(errors="replace")
                    matched = self._has_shell_error(body)
                    if matched and matched not in baseline_body.lower():
                        snippet = _extract_snippet(body, matched)
                        result.findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Potential OS Command Injection - Shell Error (URL Parameter)",
                            evidence=(
                                f"URL: {test_url} | Parametre: {param} | "
                                f"Payload: {payload!r} | Hata: {snippet or matched}"
                            ),
                            confidence=Confidence.MEDIUM,
                            status=FindingStatus.POTENTIAL,
                            description="A shell-related error string appeared only after this URL "
                                        "parameter's value was modified, absent from the baseline response.",
                            affected_url=test_url,
                            parameter=param,
                            owasp=_OWASP_INJECTION,
                            cwe=_CWE_CMDI,
                            recommendation="Avoid passing user-controlled input to a system shell; use safe "
                                           "APIs or strict allowlisting/argument-array execution instead.",
                        ))
                        found = True
                        break
                except requests.RequestException:
                    continue

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

        # URL parametrelerini test et
        self._test_url_params(target, baseline, session, result)

        # Form alanlarını test et
        for form in forms[:self.max_forms]:
            details    = self._form_details(form)
            action_url = urljoin(target, details["action"] or target)
            method     = details["method"]

            for field in self._injectable_fields(details)[:self.max_fields_per_form]:
                # 1. Çıktı bazlı (en güvenilir)
                if self._test_output_based(action_url, method, details, field, session, result):
                    continue

                # 2. Hata bazlı
                if self._test_error_based(action_url, method, details, field, session, result):
                    continue

                # 3. Zaman bazlı (son çare, yavaş)
                self._test_time_based(action_url, method, details, field, baseline, session, result)

        return result
