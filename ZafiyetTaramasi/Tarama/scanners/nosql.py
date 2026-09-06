"""
OWASP Top 10:2025 — A05 Injection
NoSQL Injection Scanner

Hedef: MongoDB ve diğer belge tabanlı veritabanları kullanan uygulamalar.

Tespit yöntemleri:
  1. Hata bazlı    — MongoDB/BSON/Mongoose hata mesajları yanıtta görünüyor mu?
  2. Boolean bazlı — HTTP param pollution ($ne/$gt/$regex operatörü) yanıt farkı
  3. JSON gövde    — API endpoint'lerine operatör değerleri gönder, yanıt farkına bak
"""
import re
import secrets
import requests
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus


_OWASP_INJECTION = "A03:2021 - Injection"
_CWE_NOSQLI = "CWE-943"


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Hata kalıpları — MongoDB / BSON / ODM mesajları (küçük harf)
# ---------------------------------------------------------------------------
_ERROR_PATTERNS = frozenset({
    "mongoerror",
    "mongo::error",
    "mongodb::error",
    "bsonerror",
    "mongoclient",
    "$where took too long",
    "nedb:",
    "invalid operator",
    "unknown top level operator",
    "unknown operator",
    "the dollar ($) prefixed field",
    "key $",
    "e11000 duplicate key",
    "failed to parse",
    "bad projection specification",
    "cannot use $",
    "errmsg",
})

# ---------------------------------------------------------------------------
# HTTP parametre kirliliği — alan adına eklenen suffix + değer
# Format: (suffix, true_value, false_value)
#   true_value  → geniş eşleşme bekleniyor (daha fazla sonuç)
#   false_value → dar eşleşme bekleniyor   (daha az / sıfır sonuç)
# ---------------------------------------------------------------------------
_PARAM_BOOL_PAIRS = [
    ("[$ne]",    "nosqltest_xyz_never_matches", "nosqltest_xyz_never_matches2"),
    ("[$gt]",    "",                             "zzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
    ("[$regex]", ".*",                           "^$"),
    ("[$in][]",  "a",                            "nosqltest_xyz_never_matches"),
]

# ---------------------------------------------------------------------------
# JSON gövde operatörleri — API endpoint'leri için
# ---------------------------------------------------------------------------
_JSON_PATH_HINTS = frozenset({"/api/", "/graphql", "/v1/", "/v2/", "/rest/", "/gql", "/auth", "/login"})
_JSON_FIELDS     = ("username", "email", "password", "id", "query", "filter", "search", "name")

_JSON_OPERATORS = [
    {"$gt": ""},
    {"$ne": "nosqltest_xyz_never_matches"},
    {"$regex": ".*"},
    {"$exists": True},
]

_BOOL_DIFF_THRESHOLD = 0.85

_SKIP_TYPES = frozenset({"submit", "button", "image", "reset", "file", "checkbox", "radio"})
_CSRF_NAMES = frozenset({"csrf", "csrftoken", "_token", "authenticity_token",
                          "__requestverificationtoken"})


def _is_csrf(name: str) -> bool:
    return any(c in name.lower() for c in _CSRF_NAMES)


def _has_nosql_error(body: str) -> str | None:
    """İlk eşleşen hata kalıbını döner, yoksa None."""
    b = body.lower()
    for p in _ERROR_PATTERNS:
        if p in b:
            return p
    return None


def _extract_snippet(body: str, marker: str, width: int = 150) -> str:
    idx = body.lower().find(marker.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 20)
    end   = min(len(body), idx + width)
    raw   = body[start:end].strip()
    return re.sub(r"\s+", " ", raw) + ("…" if end < len(body) else "")


# ===========================================================================


class NoSqlInjectionScanner(Scanner):
    def __init__(self, session: requests.Session | None = None, timeout: float = 10.0,
                 max_forms: int = 3, max_fields_per_form: int = 3):
        self._external_session   = session
        self.timeout             = timeout
        self.max_forms           = max_forms
        self.max_fields_per_form = max_fields_per_form

    def _make_session(self) -> requests.Session:
        if self._external_session:
            return self._external_session
        s = requests.Session()
        s.headers["User-Agent"] = _USER_AGENT
        return s

    # -----------------------------------------------------------------------
    # Form yardımcıları
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

    def _build_data(self, details: dict, field_override: dict[str, str]) -> dict:
        """field_override: {alan_adı: değer} — geri kalanlar varsayılan."""
        data = {}
        for inp in details["inputs"]:
            name = inp.get("name")
            if not name:
                continue
            data[name] = field_override.get(name, inp.get("value") or "test")
        return data

    def _submit(self, url: str, method: str, data: dict,
                session: requests.Session) -> requests.Response | None:
        try:
            return session.post(url, data=data, timeout=self.timeout) if method == "post" \
                   else session.get(url, params=data, timeout=self.timeout)
        except requests.RequestException:
            return None

    # -----------------------------------------------------------------------
    # Tespit yöntemleri — Form
    # -----------------------------------------------------------------------

    def _test_error_based(self, url: str, method: str, details: dict,
                          field: str, session: requests.Session, result: ScanResult) -> bool:
        """$where ve geçersiz operatörler ile hata mesajı tetiklemeye çalış."""
        baseline_res = self._submit(url, method, self._build_data(details, {field: "lilith_baseline"}), session)
        baseline_body = baseline_res.content.decode(errors="replace") if baseline_res else ""

        error_payloads = [
            {"$where": "1==1"},
            {"$invalidop": "x"},
            {"$regex": "["},          # geçersiz regex → hata
        ]
        for op_val in error_payloads:
            # HTTP param pollution: field[$where]=1==1 gibi
            flat_key = next(iter(op_val))
            flat_val = str(next(iter(op_val.values())))
            poll_key = f"{field}[{flat_key}]"
            data = {}
            for inp in details["inputs"]:
                name = inp.get("name")
                if not name:
                    continue
                if name == field:
                    data[poll_key] = flat_val
                else:
                    data[name] = inp.get("value") or "test"

            res = self._submit(url, method, data, session)
            if not res:
                continue
            body = res.content.decode(errors="replace")
            matched = _has_nosql_error(body)
            if matched and matched not in baseline_body.lower():
                snippet = _extract_snippet(body, matched)
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Potential NoSQL Injection - Database Error Triggered",
                    evidence=(
                        f"URL: {url} | Alan: {field} | "
                        f"Operatör: {flat_key} | Hata: {snippet or matched}"
                    ),
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    description="A MongoDB/BSON-specific error appeared only after an operator-shaped value "
                                "was submitted for this field, and was absent from the baseline response. "
                                "Accepting operator syntax alone does not confirm query manipulation, so this "
                                "is reported as potential rather than confirmed.",
                    affected_url=url,
                    parameter=field,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_NOSQLI,
                    recommendation="Validate and sanitize input types server-side so operator-shaped values "
                                   "(e.g. dicts with $ keys) cannot reach the query layer unexpectedly.",
                ))
                return True
        return False

    def _test_boolean_based(self, url: str, method: str, details: dict,
                            field: str, session: requests.Session, result: ScanResult) -> bool:
        """
        HTTP parametre kirliliği:
          - Geniş eşleşme: field[$ne]=asla_olmayan_değer  → çok sonuç (geniş)
          - Dar eşleşme:   field[$regex]=^$               → sıfır sonuç
        Yanıt büyüklüğü veya içerik farkı → MEDIUM bulgu.
        """
        # Önce temiz baseline al
        baseline_data = self._build_data(details, {field: secrets.token_hex(8)})
        baseline_res  = self._submit(url, method, baseline_data, session)
        if not baseline_res:
            return False
        baseline_body = baseline_res.content.decode(errors="replace")

        for suffix, true_val, false_val in _PARAM_BOOL_PAIRS:
            true_data  = {}
            false_data = {}
            for inp in details["inputs"]:
                name = inp.get("name")
                if not name:
                    continue
                if name == field:
                    true_data[f"{field}{suffix}"]  = true_val
                    false_data[f"{field}{suffix}"]  = false_val
                else:
                    v = inp.get("value") or "test"
                    true_data[name]  = v
                    false_data[name] = v

            true_res  = self._submit(url, method, true_data,  session)
            false_res = self._submit(url, method, false_data, session)
            if not true_res or not false_res:
                continue

            true_body  = true_res.content.decode(errors="replace")
            false_body = false_res.content.decode(errors="replace")

            # Geniş (true) ile dar (false) yanıtlar arasındaki fark
            ratio_tf = SequenceMatcher(None, true_body, false_body).ratio()
            # Geniş (true) ile baseline arasındaki fark
            ratio_tb = SequenceMatcher(None, true_body, baseline_body).ratio()

            # True yanıtı baseline'dan farklı VE false yanıtından farklıysa olası injection
            if ratio_tf < _BOOL_DIFF_THRESHOLD and ratio_tb < _BOOL_DIFF_THRESHOLD:
                result.findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Potential NoSQL Injection - Query Behavior Difference",
                    evidence=(
                        f"URL: {url} | Alan: {field} | "
                        f"Operatör: {suffix} | "
                        f"True/False fark: %{(1 - ratio_tf) * 100:.0f} | "
                        f"True/Baseline fark: %{(1 - ratio_tb) * 100:.0f}"
                    ),
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    description="An operator-shaped value produced a response that differs both from the "
                                "restrictive counterpart and from a clean baseline, suggesting the operator "
                                "influenced query behavior rather than being merely accepted as input.",
                    affected_url=url,
                    parameter=field,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_NOSQLI,
                    recommendation="Validate and sanitize input types server-side so operator-shaped values "
                                   "(e.g. dicts with $ keys) cannot reach the query layer unexpectedly.",
                ))
                return True
        return False

    # -----------------------------------------------------------------------
    # JSON gövde enjeksiyonu — API endpoint'leri
    # -----------------------------------------------------------------------

    def _looks_like_nosql_endpoint(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(hint in path for hint in _JSON_PATH_HINTS)

    def _test_json_injection(self, url: str, session: requests.Session, result: ScanResult) -> None:
        """JSON gövdede operatör değerleri ile hata veya yanıt farkı tespiti."""
        if not self._looks_like_nosql_endpoint(url):
            return

        # Baseline: geçersiz rastgele değerler
        baseline_body_map = {f: secrets.token_hex(8) for f in _JSON_FIELDS}
        try:
            baseline_res  = session.post(url, json=baseline_body_map, timeout=self.timeout)
            baseline_body = baseline_res.content.decode(errors="replace")
        except requests.RequestException:
            return

        for op in _JSON_OPERATORS:
            injected = {f: op for f in _JSON_FIELDS}
            try:
                res  = session.post(url, json=injected, timeout=self.timeout)
                body = res.content.decode(errors="replace")
            except requests.RequestException:
                continue

            # Önce hata bazlı — yalnızca baseline'da olmayan YENİ hata sayılır
            matched = _has_nosql_error(body)
            if matched and matched not in baseline_body.lower():
                snippet = _extract_snippet(body, matched)
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Potential NoSQL Injection - Database Error Triggered (JSON)",
                    evidence=(
                        f"URL: {url} | Tip: JSON | "
                        f"Operatör: {next(iter(op))} | Hata: {snippet or matched}"
                    ),
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    description="A MongoDB/BSON-specific error appeared only after a JSON field was replaced "
                                "with an operator object, and was absent from the baseline (valid-value) "
                                "response — this is distinguished from a generic JSON parser rejection.",
                    affected_url=url,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_NOSQLI,
                    recommendation="Validate and sanitize input types server-side so operator-shaped values "
                                   "cannot reach the query layer unexpectedly.",
                ))
                return

            # Sonra boolean farkı
            ratio = SequenceMatcher(None, baseline_body, body).ratio()
            if ratio < _BOOL_DIFF_THRESHOLD:
                result.findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Potential NoSQL Injection - Query Behavior Difference (JSON)",
                    evidence=(
                        f"URL: {url} | Tip: JSON | "
                        f"Operatör: {next(iter(op))} | "
                        f"Yanıt farkı: %{(1 - ratio) * 100:.0f}"
                    ),
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    description="Replacing a JSON field with an operator object produced a response that "
                                "differs meaningfully from the baseline (valid-value) response.",
                    affected_url=url,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_NOSQLI,
                ))
                return

    # -----------------------------------------------------------------------
    # URL parametresi testi
    # -----------------------------------------------------------------------

    def _test_url_params(self, url: str, session: requests.Session, result: ScanResult) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        flat = {k: v[0] for k, v in params.items()}

        for param in flat:
            if _is_csrf(param):
                continue

            # Baseline
            try:
                baseline_res  = session.get(url, timeout=self.timeout)
                baseline_body = baseline_res.content.decode(errors="replace")
            except requests.RequestException:
                continue

            # Hata bazlı — geçersiz regex operatörü
            for error_op, error_val in [("$regex", "["), ("$where", "1==1")]:
                injected = dict(flat)
                del injected[param]
                injected[f"{param}[{error_op}]"] = error_val
                test_url = urlunparse(parsed._replace(query=urlencode(injected)))
                try:
                    res  = session.get(test_url, timeout=self.timeout)
                    body = res.content.decode(errors="replace")
                    matched = _has_nosql_error(body)
                    if matched and matched not in baseline_body.lower():
                        snippet = _extract_snippet(body, matched)
                        result.findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Potential NoSQL Injection - Database Error Triggered (URL Parameter)",
                            evidence=(
                                f"URL: {test_url} | Parametre: {param} | "
                                f"Operatör: {error_op} | Hata: {snippet or matched}"
                            ),
                            confidence=Confidence.MEDIUM,
                            status=FindingStatus.POTENTIAL,
                            description="A MongoDB/BSON-specific error appeared only after this URL "
                                        "parameter was replaced with an operator-shaped value, and was "
                                        "absent from the baseline response.",
                            affected_url=test_url,
                            parameter=param,
                            owasp=_OWASP_INJECTION,
                            cwe=_CWE_NOSQLI,
                        ))
                        return
                except requests.RequestException:
                    continue

            # Boolean bazlı — $ne geniş eşleşme
            for suffix, true_val, false_val in _PARAM_BOOL_PAIRS[:2]:
                def _make(v, _flat=flat, _p=param, _s=suffix, _parsed=parsed):
                    inj = {k: val for k, val in _flat.items() if k != _p}
                    inj[f"{_p}{_s}"] = v
                    return urlunparse(_parsed._replace(query=urlencode(inj)))
                try:
                    r_true  = session.get(_make(true_val),  timeout=self.timeout)
                    r_false = session.get(_make(false_val), timeout=self.timeout)
                    t_body  = r_true.content.decode(errors="replace")
                    f_body  = r_false.content.decode(errors="replace")
                    ratio_tf = SequenceMatcher(None, t_body, f_body).ratio()
                    ratio_tb = SequenceMatcher(None, t_body, baseline_body).ratio()
                    if ratio_tf < _BOOL_DIFF_THRESHOLD and ratio_tb < _BOOL_DIFF_THRESHOLD:
                        result.findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Potential NoSQL Injection - Query Behavior Difference (URL Parameter)",
                            evidence=(
                                f"Parametre: {param} | Operatör: {suffix} | "
                                f"True/False fark: %{(1 - ratio_tf) * 100:.0f}"
                            ),
                            confidence=Confidence.MEDIUM,
                            status=FindingStatus.POTENTIAL,
                            description="An operator-shaped URL parameter value produced a response that "
                                        "differs both from the restrictive counterpart and from baseline.",
                            affected_url=_make(true_val),
                            parameter=param,
                            owasp=_OWASP_INJECTION,
                            cwe=_CWE_NOSQLI,
                        ))
                        return
                except requests.RequestException:
                    continue

    # -----------------------------------------------------------------------
    # Ana tarama
    # -----------------------------------------------------------------------

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="nosql", target=target)
        session = self._make_session()

        try:
            response = session.get(target, timeout=self.timeout)
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
        self._test_url_params(target, session, result)

        # JSON endpoint testi (hedef URL kendisi)
        self._test_json_injection(target, session, result)

        # Form alanlarını test et
        for form in forms[:self.max_forms]:
            details    = self._form_details(form)
            action_url = urljoin(target, details["action"] or target)
            method     = details["method"]

            # Form action URL'si NoSQL endpoint mi?
            self._test_json_injection(action_url, session, result)

            for field in self._injectable_fields(details)[:self.max_fields_per_form]:
                # 1. Hata bazlı
                if self._test_error_based(action_url, method, details, field, session, result):
                    continue

                # 2. Boolean bazlı (HTTP parametre kirliliği)
                self._test_boolean_based(action_url, method, details, field, session, result)

        return result
