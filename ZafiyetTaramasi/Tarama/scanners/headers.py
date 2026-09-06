import re
import urllib.request
import urllib.error
from urllib.parse import urlparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus


_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_CWE_PROTECTION_FAILURE = "CWE-693"    # Protection Mechanism Failure
_CWE_CLICKJACKING = "CWE-1021"         # Improper Restriction of Rendered UI Layers or Frames
_CWE_INFO_EXPOSURE = "CWE-200"         # Exposure of Sensitive Information to an Unauthorized Actor

# header adı -> (eksikken severity, description, recommendation, cwe)
_MISSING_HEADER_INFO: dict[str, tuple[Severity, str, str, str | None]] = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "No Strict-Transport-Security header was returned even though the target is served over HTTPS, "
        "so browsers are not instructed to enforce HTTPS on future visits to this host.",
        "Return a Strict-Transport-Security header (e.g. max-age=31536000; includeSubDomains) once HTTPS "
        "is fully and correctly deployed across the site.",
        _CWE_PROTECTION_FAILURE,
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy header was returned, so the browser has no restriction on which "
        "script, style, or frame sources may execute on this page.",
        "Deploy a Content-Security-Policy that restricts script/style/frame sources to trusted origins.",
        _CWE_PROTECTION_FAILURE,
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "No X-Frame-Options header was returned, so the page may be embedded in a frame on another origin.",
        "Add X-Frame-Options: DENY or SAMEORIGIN, or rely on an equivalent CSP frame-ancestors directive.",
        _CWE_CLICKJACKING,
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "No X-Content-Type-Options header was returned, so browsers may MIME-sniff response bodies into "
        "an unintended content type.",
        "Add X-Content-Type-Options: nosniff.",
        _CWE_PROTECTION_FAILURE,
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "No Referrer-Policy header was returned, so the browser falls back to its default referrer "
        "behavior, which may leak full URLs to third-party destinations.",
        "Add a Referrer-Policy header (e.g. strict-origin-when-cross-origin).",
        None,
    ),
    "Permissions-Policy": (
        Severity.LOW,
        "No Permissions-Policy header was returned, so the browser applies its default access rules for "
        "sensitive features/APIs on this origin.",
        "Add a Permissions-Policy header restricting access to browser features (camera, microphone, "
        "geolocation, etc.) that the application does not need.",
        None,
    ),
    "X-XSS-Protection": (
        Severity.INFO,
        "X-XSS-Protection is deprecated and ignored by modern browsers, so its absence has no practical "
        "security effect.",
        "Rely on a strong Content-Security-Policy as the primary XSS defense instead of the deprecated "
        "X-XSS-Protection header.",
        None,
    ),
}

# Varlığı bilgi sızdırma anlamına gelen headerlar
_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


class HeaderScanner(Scanner):
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    # --- Ana tarama ---

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner="headers", target=target)
        is_https = urlparse(target).scheme == "https"
        try:
            response = urllib.request.urlopen(target, timeout=self.timeout)
            self._analyze(result, response.info(), target, is_https)
        except urllib.error.HTTPError as e:
            # 4xx/5xx yanıtlarında header'lar hâlâ okunabilir — analizi sürdür
            self._analyze(result, e.headers, target, is_https)
            result.findings.append(Finding(
                severity=Severity.LOW,
                title=f"Sunucu HTTP {e.code} döndürdü",
                evidence=str(e.reason),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description="The server responded with a non-2xx HTTP status; header analysis still "
                            "proceeded against this response.",
                affected_url=target,
            ))
        except urllib.error.URLError as e:
            result.error = f"Bağlantı hatası: {e.reason}"
        except Exception as e:
            result.error = str(e)

        return result

    def _analyze(self, result: ScanResult, headers, target: str, is_https: bool) -> None:
        csp_value = headers.get("Content-Security-Policy", "")
        frame_ancestors_covers_clickjacking = "frame-ancestors" in csp_value.lower()

        for name, (missing_severity, description, recommendation, cwe) in _MISSING_HEADER_INFO.items():
            value = headers.get(name, "")
            if value:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=name,
                    evidence=value,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.SECURE,
                    affected_url=target,
                ))
                result.findings.extend(self._check_value(name, value, target))
                continue

            if name == "Strict-Transport-Security" and not is_https:
                # HSTS, HTTPS kullanılmayan hedefte anlamsızdır — eksiklik olarak raporlama
                continue
            if name == "X-Frame-Options" and frame_ancestors_covers_clickjacking:
                # CSP frame-ancestors zaten clickjacking korumasını sağlıyor — duplicate finding üretme
                continue

            result.findings.append(Finding(
                severity=missing_severity,
                title=f"{name} eksik",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description=description,
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                cwe=cwe,
                recommendation=recommendation,
            ))

        for name in _LEAK_HEADERS:
            value = headers.get(name, "")
            if value:
                result.findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"{name} bilgi sızdırıyor",
                    evidence=value,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description=f"The {name} header discloses server/framework version information that "
                                "can help an attacker fingerprint the technology stack.",
                    affected_url=target,
                    owasp=_OWASP_MISCONFIG,
                    cwe=_CWE_INFO_EXPOSURE,
                    recommendation=f"Suppress or generalize the {name} header at the web server/proxy level.",
                ))

    # --- Değer kalitesi kontrolleri ---

    def _check_value(self, name: str, value: str, target: str) -> list[Finding]:
        dispatch = {
            "Strict-Transport-Security": self._check_hsts,
            "Content-Security-Policy":   self._check_csp,
            "X-XSS-Protection":          self._check_xss_protection,
            "X-Content-Type-Options":    self._check_xcto,
        }
        fn = dispatch.get(name)
        return fn(value, target) if fn else []

    def _check_hsts(self, value: str, target: str) -> list[Finding]:
        findings = []
        match = re.search(r'max-age=(\d+)', value, re.I)
        if match:
            max_age = int(match.group(1))
            if max_age < 31536000:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="HSTS max-age yetersiz",
                    evidence=f"max-age={max_age} (önerilen: en az 31536000 / 1 yıl)",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="The HSTS max-age is shorter than one year, so browsers stop enforcing "
                                "HTTPS for this host sooner than recommended.",
                    affected_url=target,
                    owasp=_OWASP_MISCONFIG,
                    cwe=_CWE_PROTECTION_FAILURE,
                    recommendation="Increase Strict-Transport-Security max-age to at least 31536000 (1 year).",
                ))
        else:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="HSTS max-age direktifi bulunamadı",
                evidence=value,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The Strict-Transport-Security header is present but has no max-age directive, "
                            "so browsers cannot determine how long to enforce HTTPS.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                cwe=_CWE_PROTECTION_FAILURE,
                recommendation="Add a max-age directive of at least 31536000 seconds to the "
                               "Strict-Transport-Security header.",
            ))
        if "includesubdomains" not in value.lower():
            findings.append(Finding(
                severity=Severity.LOW,
                title="HSTS includeSubDomains eksik",
                evidence=value,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.CONFIRMED,
                description="The Strict-Transport-Security header does not include includeSubDomains, so "
                            "subdomains are not covered by HSTS enforcement.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                recommendation="Add includeSubDomains to the Strict-Transport-Security header if all "
                               "subdomains are served over HTTPS.",
            ))
        return findings

    def _check_csp(self, value: str, target: str) -> list[Finding]:
        findings = []
        if "'unsafe-inline'" in value:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="CSP 'unsafe-inline' içeriyor",
                evidence="XSS koruması zayıflıyor — inline script çalıştırmaya izin veriliyor",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The Content-Security-Policy permits 'unsafe-inline', which significantly "
                            "weakens CSP's ability to mitigate cross-site scripting.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                cwe=_CWE_PROTECTION_FAILURE,
                recommendation="Prefer CSP nonces or hashes and remove 'unsafe-inline' where practical.",
            ))
        if "'unsafe-eval'" in value:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="CSP 'unsafe-eval' içeriyor",
                evidence="eval() çağrılarına izin veriliyor — kod enjeksiyon riski",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The Content-Security-Policy permits 'unsafe-eval', allowing string-to-code "
                            "execution APIs such as eval().",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                cwe=_CWE_PROTECTION_FAILURE,
                recommendation="Remove 'unsafe-eval' and refactor code that relies on eval()/similar APIs.",
            ))
        if "default-src" not in value and "script-src" not in value:
            findings.append(Finding(
                severity=Severity.LOW,
                title="CSP default-src / script-src direktifi eksik",
                evidence=value[:120],
                confidence=Confidence.MEDIUM,
                status=FindingStatus.CONFIRMED,
                description="The Content-Security-Policy does not define default-src or script-src, so "
                            "script execution is not meaningfully restricted.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                recommendation="Add an explicit script-src (or default-src) directive listing trusted "
                               "script origins.",
            ))
        return findings

    def _check_xss_protection(self, value: str, target: str) -> list[Finding]:
        if value.strip() == "0":
            return [Finding(
                severity=Severity.INFO,
                title="X-XSS-Protection açıkça devre dışı bırakılmış",
                evidence="Değer '0' — tarayıcı XSS filtresi kapalı",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description="X-XSS-Protection is deprecated and ignored by modern browsers, so this "
                            "setting has no practical effect either way.",
                affected_url=target,
                recommendation="Rely on a strong Content-Security-Policy as the primary XSS defense "
                               "instead of the deprecated X-XSS-Protection header.",
            )]
        return []

    def _check_xcto(self, value: str, target: str) -> list[Finding]:
        if value.lower().strip() != "nosniff":
            return [Finding(
                severity=Severity.LOW,
                title="X-Content-Type-Options 'nosniff' değil",
                evidence=f"Gerçek değer: '{value}'",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="X-Content-Type-Options is present but not set to 'nosniff', so MIME-sniffing "
                            "protection is not fully applied.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                cwe=_CWE_PROTECTION_FAILURE,
                recommendation="Set X-Content-Type-Options to 'nosniff'.",
            )]
        return []
