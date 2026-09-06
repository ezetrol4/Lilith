"""
OWASP Top 10 — A09: Security Logging and Monitoring Failures

Kontroller:
- Hata sayfalarında bilgi sızdırma (stack trace, internal path, framework versiyonu)
- Debug modu tespiti (Django, PHP, ASP.NET, Spring, Node)
- İzleme / debug endpoint'leri (Actuator, Profiler, Kibana, Swagger vb.)
- API dokümantasyonu açık mı (Swagger UI, OpenAPI)
"""
import re
import requests
from urllib.parse import urlparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_OWASP_MONITORING = "A09:2021 - Security Logging and Monitoring Failures"
_CWE_ERROR_DISCLOSURE = "CWE-209"  # Generation of Error Message Containing Sensitive Information
_CWE_ACTIVE_DEBUG_CODE = "CWE-489"  # Active Debug Code

# --- Hata sayfası kalıpları: (pattern, description, is_debug_mode) ---
# is_debug_mode=True → tam framework debug sayfası (kaynak/ayarlar görünür) → HIGH
# is_debug_mode=False → genel stack trace / iç yol sızıntısı → MEDIUM

_ERROR_PATTERNS: list[tuple[re.Pattern, str, bool]] = [
    # Django debug sayfası
    (re.compile(r"Django Version:|INSTALLED_APPS|TemplateSyntaxError", re.I),
     "Django debug modu aktif — kaynak kod ve ayarlar görünüyor", True),
    # PHP hataları
    (re.compile(r"(Fatal error|Parse error|Warning):.+in /.+\.php on line", re.I),
     "PHP hata mesajı — dosya yolu ve satır numarası görünüyor", False),
    # Python traceback
    (re.compile(r"Traceback \(most recent call last\)|File \".+\.py\", line", re.I),
     "Python traceback açıkta — iç dosya yolları görünüyor", False),
    # Java / Spring stack trace
    (re.compile(r"at (org\.springframework|java\.lang|com\.sun)\.", re.I),
     "Java stack trace — sınıf adları ve iç yapı görünüyor", False),
    # ASP.NET
    (re.compile(r"System\.(Web|Data|Net)\.|Microsoft\.(CSharp|VisualBasic)\.", re.I),
     "ASP.NET exception — framework iç yapısı görünüyor", False),
    # Ruby on Rails
    (re.compile(r"ActionController::RoutingError|app/controllers/.+\.rb:", re.I),
     "Rails exception — controller yolları görünüyor", False),
    # Node / Express
    (re.compile(r"Error\n\s+at .+\(node_modules/", re.I),
     "Node.js stack trace — node_modules yolları görünüyor", False),
    # Generic internal path
    (re.compile(r"(/var/www/|/home/\w+/|C:\\inetpub\\|C:\\xampp\\)", re.I),
     "Sunucu iç dosya yolu açıkta", False),
    # SQL hata mesajı (hata bazlı injection'la örtüşür ama burada de ayrıca kontrol edelim)
    (re.compile(r"(ORA-\d{5}|SQLSTATE\[|mysql_fetch_array|pg_query\(\))", re.I),
     "Veritabanı hata mesajı — DB tipi ve sorgu yapısı görünüyor", False),
]

# --- İzleme / debug endpoint'leri ---
# (path, label, severity, başarı_kontrol_kalıbı_ya_da_None)

_MONITORING_ENDPOINTS: list[tuple[str, str, Severity, str | None]] = [
    # Spring Boot Actuator
    ("/actuator",              "Spring Boot Actuator",                 Severity.HIGH,     "actuator"),
    ("/actuator/env",          "Actuator /env — tüm env değişkenleri", Severity.CRITICAL, "activeProfiles"),
    ("/actuator/health",       "Actuator /health",                     Severity.LOW,      "status"),
    ("/actuator/mappings",     "Actuator /mappings — URL haritası",    Severity.MEDIUM,   "dispatcherServlet"),
    ("/actuator/beans",        "Actuator /beans",                      Severity.MEDIUM,   "beans"),
    ("/actuator/metrics",      "Actuator /metrics",                    Severity.MEDIUM,   "names"),
    ("/actuator/loggers",      "Actuator /loggers",                    Severity.MEDIUM,   "loggers"),
    ("/actuator/httptrace",    "Actuator /httptrace — HTTP geçmişi",   Severity.HIGH,     "traces"),
    # Prometheus
    ("/metrics",               "Prometheus metrics",                   Severity.MEDIUM,   "# HELP"),
    # Django Debug Toolbar
    ("/__debug__/",            "Django Debug Toolbar",                 Severity.HIGH,     None),
    # Symfony Profiler
    ("/_profiler",             "Symfony Profiler",                     Severity.HIGH,     "sf-toolbar"),
    ("/_profiler/latest",      "Symfony Profiler (son istek)",         Severity.HIGH,     None),
    # Laravel
    ("/telescope",             "Laravel Telescope",                    Severity.HIGH,     "telescope"),
    ("/horizon",               "Laravel Horizon",                      Severity.HIGH,     "horizon"),
    # PHP Clockwork
    ("/clockwork",             "Clockwork PHP Profiler",               Severity.MEDIUM,   "clockwork"),
    # Apache
    ("/server-info",           "Apache server-info",                   Severity.MEDIUM,   "Apache"),
    # Elasticsearch / Kibana
    ("/_cat/indices",          "Elasticsearch indeksleri açık",        Severity.CRITICAL, "index"),
    ("/_cluster/health",       "Elasticsearch cluster bilgisi",        Severity.HIGH,     "cluster_name"),
    ("/kibana",                "Kibana paneli",                        Severity.HIGH,     None),
    # Grafana
    ("/grafana",               "Grafana izleme paneli",                Severity.MEDIUM,   None),
    # Jupyter
    ("/notebooks",             "Jupyter Notebook",                     Severity.HIGH,     "jupyter"),
    ("/tree",                  "Jupyter dosya ağacı",                  Severity.HIGH,     "jupyter"),
    # Redis Commander
    ("/redis-commander",       "Redis Commander",                      Severity.CRITICAL, None),
    # Adminer / PHPMyAdmin
    ("/adminer",               "Adminer DB arayüzü",                   Severity.CRITICAL, "adminer"),
    ("/phpmyadmin",            "phpMyAdmin",                           Severity.CRITICAL, "phpMyAdmin"),
    ("/pma",                   "phpMyAdmin (kısa yol)",                Severity.CRITICAL, None),
    # Health / Status (bilgi değeri düşük ama varlık tespiti önemli)
    ("/health",                "Health endpoint",                      Severity.LOW,      None),
    ("/api/health",            "API health endpoint",                  Severity.LOW,      None),
    ("/status",                "Status endpoint",                      Severity.LOW,      None),
    ("/debug",                 "Debug endpoint",                       Severity.HIGH,     None),
    # Swagger / OpenAPI
    ("/swagger-ui.html",       "Swagger UI",                           Severity.MEDIUM,   "swagger"),
    ("/swagger-ui/",           "Swagger UI",                           Severity.MEDIUM,   "swagger"),
    ("/swagger-ui/index.html", "Swagger UI",                           Severity.MEDIUM,   "swagger"),
    ("/api-docs",              "API dokümantasyonu",                   Severity.MEDIUM,   None),
    ("/api/swagger",           "Swagger API",                          Severity.MEDIUM,   "swagger"),
    ("/openapi.json",          "OpenAPI spec",                         Severity.MEDIUM,   "openapi"),
    ("/openapi.yaml",          "OpenAPI spec (YAML)",                  Severity.MEDIUM,   "openapi"),
    ("/v2/api-docs",           "Swagger v2 API docs",                  Severity.MEDIUM,   "swagger"),
    ("/v3/api-docs",           "OpenAPI v3 API docs",                  Severity.MEDIUM,   "openapi"),
]

# Health-benzeri uçlar — içerik kısa/zararsızsa INFO'ya indirilir
_HEALTHLIKE_PATHS = frozenset({"/health", "/api/health", "/status", "/actuator/health"})
_HEALTHLIKE_SUSPICIOUS_RE = re.compile(
    r"(traceback|stack ?trace|password|secret|env|version|config)", re.I,
)

# Swagger/OpenAPI uçları — varsayılan olarak bilgilendirici, içerikte gizli veri varsa yükseltilir
_SWAGGER_PATHS = frozenset({
    "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html", "/api-docs",
    "/api/swagger", "/openapi.json", "/openapi.yaml", "/v2/api-docs", "/v3/api-docs",
})
_SWAGGER_SENSITIVE_RE = re.compile(
    r"(\"?(password|secret|api[_-]?key|access[_-]?token|private[_-]?key)\"?\s*:)", re.I,
)

# Evidence içinde maskelenecek olası secret kalıpları
_SECRET_MASK_RE = re.compile(
    r'(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|authorization)'
    r'(["\']?\s*[:=]\s*)["\']?([^\s"\',;]+)',
)

# Hata tetiklemek için kullanılacak sahte yollar
_ERROR_TRIGGER_PATHS = [
    "/this-page-does-not-exist-xyz-12345",
    "/../../etc/passwd",
    "/?id='",
]


def _mask_secrets(text: str) -> str:
    return _SECRET_MASK_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[MASKED]", text)


class ErrorDisclosureScanner(Scanner):
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = _USER_AGENT
        return s

    def _get(self, session: requests.Session, url: str) -> requests.Response | None:
        try:
            return session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="error_disclosure", target=target)
        session = self._make_session()

        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base += f":{parsed.port}"

        self._check_error_pages(session, target, base, result)
        self._check_monitoring_endpoints(session, base, result)

        return result

    # --- Hata sayfası analizi ---

    def _check_error_pages(self, session: requests.Session,
                            target: str, base: str,
                            result: ScanResult) -> None:
        seen_patterns: set[str] = set()

        for path in _ERROR_TRIGGER_PATHS:
            url = base + path if path.startswith("/") else target + path
            res = self._get(session, url)
            if not res:
                continue

            body = res.text
            for pattern, description, is_debug_mode in _ERROR_PATTERNS:
                m = pattern.search(body)
                if m and description not in seen_patterns:
                    seen_patterns.add(description)
                    line = _mask_secrets(self._extract_line(body, m.start()))

                    if is_debug_mode:
                        result.findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Application Debug Mode Exposed",
                            evidence=f"{description} | Tetikleyen URL: {url} | Örnek: {line}",
                            confidence=Confidence.HIGH,
                            status=FindingStatus.CONFIRMED,
                            description="A framework debug page is reliably exposed, revealing source-level "
                                        "internals (settings, installed apps, template context) to visitors.",
                            affected_url=url,
                            owasp=_OWASP_MONITORING,
                            cwe=_CWE_ACTIVE_DEBUG_CODE,
                            recommendation="Disable debug mode in the production configuration.",
                        ))
                    else:
                        result.findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Application Stack Trace Disclosure",
                            evidence=f"{description} | Tetikleyen URL: {url} | Örnek: {line}",
                            confidence=Confidence.HIGH,
                            status=FindingStatus.CONFIRMED,
                            description="An error response exposes internal implementation details (stack "
                                        "trace, file path, or database error), which can help an attacker "
                                        "map the application's internals.",
                            affected_url=url,
                            owasp=_OWASP_MONITORING,
                            cwe=_CWE_ERROR_DISCLOSURE,
                            recommendation="Return generic error pages to clients and log full details "
                                           "server-side only.",
                        ))

        if not seen_patterns:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Hata sayfaları bilgi sızdırmıyor",
                evidence="Tetiklenen hatalarda stack trace veya iç yol bulunamadı",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.SECURE,
                description="Triggered error responses did not contain stack traces or internal path "
                            "disclosure for the patterns this scanner checks.",
                affected_url=target,
            ))

    def _extract_line(self, text: str, pos: int, max_len: int = 120) -> str:
        """Eşleşmenin bulunduğu satırı döner."""
        start = text.rfind("\n", 0, pos) + 1
        end   = text.find("\n", pos)
        if end == -1:
            end = len(text)
        line = text[start:end].strip()
        return line[:max_len] + ("…" if len(line) > max_len else "")

    # --- İzleme / debug endpoint'leri ---

    def _check_monitoring_endpoints(self, session: requests.Session,
                                     base: str, result: ScanResult) -> None:
        found_any = False

        for path, label, table_severity, keyword in _MONITORING_ENDPOINTS:
            res = self._get(session, base + path)
            if not res or res.status_code not in (200, 401, 403):
                continue

            # keyword varsa yanıt gövdesinde de kontrol et (false positive azalt)
            if keyword and res.status_code == 200:
                if keyword.lower() not in res.text.lower():
                    continue

            found_any = True
            status_note = {200: "erişilebilir", 401: "auth gerekiyor", 403: "yasaklı"}
            snippet = ""
            if res.status_code == 200 and res.text:
                snippet = " | İçerik: " + _mask_secrets(res.text[:150].replace("\n", " ").strip()) + "…"

            if res.status_code != 200:
                # Uç var ama erişim kontrolü çalışıyor — bu güvenli davranış, zayıflık değil
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"İzleme endpoint'i bulundu: {path}",
                    evidence=f"{label} — HTTP {res.status_code} ({status_note.get(res.status_code, '')})",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.INFORMATIONAL,
                    description="This endpoint's path exists but requires authentication or is forbidden, "
                                "which limits exposure — endpoint existence alone is not a vulnerability.",
                    affected_url=base + path,
                ))
                continue

            if path in _SWAGGER_PATHS:
                sensitive = _SWAGGER_SENSITIVE_RE.search(res.text)
                if sensitive:
                    result.findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"Sensitive Data Potentially Exposed in API Documentation: {path}",
                        evidence=f"{label} — HTTP 200{snippet}",
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        description="Public API documentation contains what appears to be a secret/token "
                                    "field name. Public API docs are not automatically insecure — this is "
                                    "flagged because a credential-like key was observed in the response.",
                        affected_url=base + path,
                        owasp=_OWASP_MONITORING,
                        cwe="CWE-200",
                        recommendation="Review the documentation source for embedded secrets/tokens and "
                                       "remove them; regenerate any credential that was exposed.",
                    ))
                else:
                    result.findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"Public API Documentation Detected: {path}",
                        evidence=f"{label} — HTTP 200{snippet}",
                        confidence=Confidence.HIGH,
                        status=FindingStatus.INFORMATIONAL,
                        description="Swagger/OpenAPI documentation being publicly reachable is not "
                                    "automatically a vulnerability.",
                        affected_url=base + path,
                    ))
                continue

            severity = table_severity
            if path in _HEALTHLIKE_PATHS and len(res.text) < 200 and not _HEALTHLIKE_SUSPICIOUS_RE.search(res.text):
                severity = Severity.INFO

            result.findings.append(Finding(
                severity=severity,
                title=f"İzleme endpoint'i bulundu: {path}",
                evidence=f"{label} — HTTP 200{snippet}",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL if severity == Severity.INFO else FindingStatus.CONFIRMED,
                description=None if severity == Severity.INFO else
                            "This monitoring/management endpoint is publicly reachable and its response "
                            "content indicates it exposes more than basic status information.",
                affected_url=base + path,
                owasp=None if severity == Severity.INFO else _OWASP_MONITORING,
                recommendation=None if severity == Severity.INFO else
                               f"Restrict {path} to internal networks or authenticated operators only.",
            ))

        if not found_any:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="İzleme endpoint'leri bulunamadı",
                evidence="Tarama kapsamındaki debug/monitoring yolları erişilebilir değil",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                affected_url=base,
            ))
