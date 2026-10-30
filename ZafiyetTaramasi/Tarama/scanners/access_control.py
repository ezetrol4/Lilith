"""
OWASP Top 10 — A01: Broken Access Control

Kontroller:
- CORS misconfiguration (wildcard, credentials ile wildcard, arbitrary origin reflection)
- HTTP tehlikeli metodlar (TRACE, PUT, DELETE)
- Dizin listeleme açığı
- Cookie güvenlik bayrakları (HttpOnly, Secure, SameSite)
"""
import re
import requests
from urllib.parse import urlparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from ..services.safe_http import SafeSession, safe_session


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_OWASP_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_CWE_DIR_LISTING = "CWE-548"      # Exposure of Information Through Directory Listing
_CWE_HTTPONLY = "CWE-1004"        # Sensitive Cookie Without 'HttpOnly' Flag
_CWE_SECURE_FLAG = "CWE-614"      # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

_DIR_LISTING_PATTERNS = (
    "Index of /",
    "Directory listing for",
    "Parent Directory",
    "[To Parent Directory]",
)

_DANGEROUS_METHODS = frozenset({"PUT", "DELETE", "TRACE", "CONNECT"})

# CORS reflection probu için kullanılan, RFC 2606 uyarınca test amaçlı ayrılmış (.invalid) sahte origin
_CORS_PROBE_ORIGIN = "https://lilith-cors-probe.invalid"

# Oturum/kimlik doğrulama ile ilişkili olması muhtemel cookie adı kalıpları
_SESSION_COOKIE_RE = re.compile(
    r"(sess|auth|token|jwt|login|remember|csrf|jsessionid|phpsessid|"
    r"connect\.sid|\.aspxauth|identity)",
    re.I,
)

# Dizin listeleme + backup riski olan yollar
_PROBE_PATHS = [
    "/backup/", "/old/", "/test/", "/dev/",
    "/staging/", "/temp/", "/logs/", "/upload/", "/uploads/",
]


def _cookie_risk_profile(name: str) -> tuple[Severity, Confidence]:
    """Cookie adına göre olası hassasiyeti tahmin eder — her cookie'yi aynı önemde saymaz."""
    if _SESSION_COOKIE_RE.search(name):
        return Severity.MEDIUM, Confidence.MEDIUM
    return Severity.LOW, Confidence.LOW


class AccessControlScanner(Scanner):
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _make_session(self) -> SafeSession:
        s = safe_session()
        s.headers["User-Agent"] = _USER_AGENT
        return s

    def _get(self, session: requests.Session, url: str,
             **kwargs) -> requests.Response | None:
        try:
            return session.get(url, timeout=self.timeout,
                               allow_redirects=True, **kwargs)
        except requests.RequestException:
            return None

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="Access Control", target=target)
        session = self._make_session()

        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base += f":{parsed.port}"
        is_https = parsed.scheme == "https"

        res = self._get(session, target)
        if res:
            self._check_cors(res, target, result)
            self._check_dir_listing(res, target, result)
            self._check_cookies(res, target, is_https, result)

        self._check_cors_reflection(session, target, result)
        self._check_http_methods(session, target, result)
        self._check_probe_paths(session, base, result)

        return result

    # --- CORS ---

    def _check_cors(self, res: requests.Response, target: str, result: ScanResult) -> None:
        origin = res.headers.get("Access-Control-Allow-Origin", "")
        credentials = res.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if not origin:
            return

        if origin == "*" and credentials:
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="CORS: Wildcard + credentials=true (spesifikasyona aykırı kombinasyon)",
                evidence="Access-Control-Allow-Origin: * ile Access-Control-Allow-Credentials: true birlikte gönderiliyor",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="Modern browsers reject this exact combination client-side (a wildcard origin "
                            "cannot be paired with credentialed access per the Fetch spec), so it is not "
                            "directly exploitable via a standard browser fetch/XHR. It still signals careless "
                            "CORS configuration and may be usable by non-browser HTTP clients that do not "
                            "enforce CORS.",
                affected_url=target,
                owasp=_OWASP_ACCESS_CONTROL,
                recommendation="Do not combine a wildcard origin with Access-Control-Allow-Credentials: true; "
                               "use an explicit allowlist of trusted origins instead.",
            ))
        elif origin == "*":
            result.findings.append(Finding(
                severity=Severity.LOW,
                title="CORS: Tüm kaynaklara izin verilmiş (wildcard)",
                evidence="Access-Control-Allow-Origin: *",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="A wildcard CORS origin allows any website to read this response cross-origin. "
                            "This is often an intentional choice for public/static APIs without credentialed "
                            "access, so it is not automatically high risk — confirm it matches the endpoint's "
                            "intended audience.",
                affected_url=target,
                owasp=_OWASP_ACCESS_CONTROL,
                recommendation="Confirm this endpoint is meant to be publicly readable by any origin; use an "
                               "explicit allowlist otherwise.",
            ))
        else:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="CORS politikası",
                evidence=f"Access-Control-Allow-Origin: {origin}",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=target,
            ))

    def _check_cors_reflection(self, session: requests.Session, target: str, result: ScanResult) -> None:
        """Sunucunun keyfi bir Origin değerini doğrudan yansıtıp yansıtmadığını test eder."""
        res = self._get(session, target, headers={"Origin": _CORS_PROBE_ORIGIN})
        if not res:
            return

        reflected = res.headers.get("Access-Control-Allow-Origin", "")
        if reflected != _CORS_PROBE_ORIGIN:
            return  # Yansıma gözlemlenmedi

        credentials = res.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if credentials:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Potentially Insecure CORS Origin Reflection",
                evidence=f"Origin: {_CORS_PROBE_ORIGIN} gönderildi — sunucu aynı değeri "
                         "Access-Control-Allow-Origin olarak yansıttı ve Allow-Credentials: true döndürdü",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The server reflected an arbitrary, attacker-controlled Origin value back in "
                            "Access-Control-Allow-Origin while also allowing credentials, letting any origin "
                            "make authenticated cross-origin requests and read the response.",
                affected_url=target,
                owasp=_OWASP_ACCESS_CONTROL,
                recommendation="Use an explicit allowlist of trusted origins and avoid reflecting arbitrary "
                               "Origin values, especially while Access-Control-Allow-Credentials is enabled.",
            ))
        else:
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Potentially Insecure CORS Origin Reflection",
                evidence=f"Origin: {_CORS_PROBE_ORIGIN} gönderildi — sunucu aynı değeri "
                         "Access-Control-Allow-Origin olarak yansıttı (credentials olmadan)",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                description="The server reflects arbitrary Origin values back in Access-Control-Allow-Origin "
                            "instead of using an allowlist. No credentialed access was observed, which limits "
                            "impact, but this behavior is functionally equivalent to a wildcard for "
                            "unauthenticated data.",
                affected_url=target,
                owasp=_OWASP_ACCESS_CONTROL,
                recommendation="Use an explicit allowlist of trusted origins instead of reflecting the "
                               "request's Origin header.",
            ))

    # --- Dizin listeleme ---

    def _check_dir_listing(self, res: requests.Response,
                            url: str, result: ScanResult) -> None:
        for pattern in _DIR_LISTING_PATTERNS:
            if pattern in res.text:
                result.findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Dizin Listeleme Açık",
                    evidence=f"URL: {url} | Tespit: '{pattern}'",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="A server-generated directory listing marker was observed in the response, "
                                "indicating directory contents are being enumerated to visitors.",
                    affected_url=url,
                    owasp=_OWASP_ACCESS_CONTROL,
                    cwe=_CWE_DIR_LISTING,
                    recommendation="Disable directory listing/autoindex at the web server level for this path.",
                ))
                return

    # --- Cookie bayrakları ---

    def _raw_cookie_headers(self, res: requests.Response) -> list[str]:
        """Birden fazla Set-Cookie header'ını ayrı ayrı almaya çalışır; başarısız olursa tekil header'a düşer."""
        try:
            raw = res.raw.headers.getlist("Set-Cookie")
        except (AttributeError, TypeError):
            raw = None
        if isinstance(raw, list) and raw:
            return raw
        single = res.headers.get("set-cookie", "")
        return [single] if single else []

    def _check_cookies(self, res: requests.Response, target: str,
                        is_https: bool, result: ScanResult) -> None:
        for raw_cookie in self._raw_cookie_headers(res):
            if not raw_cookie:
                continue
            name_match = re.match(r'^([^=]+)=', raw_cookie)
            cookie_name = name_match.group(1).strip() if name_match else "Cookie"
            lower = raw_cookie.lower()

            base_severity, base_confidence = _cookie_risk_profile(cookie_name)
            any_issue = False

            if "httponly" not in lower:
                any_issue = True
                result.findings.append(Finding(
                    severity=base_severity,
                    title=f"Cookie HttpOnly eksik: {cookie_name}",
                    evidence="Flags eksik: HttpOnly",
                    confidence=base_confidence,
                    status=FindingStatus.CONFIRMED,
                    description="This cookie is not marked HttpOnly, so it is readable by JavaScript, "
                                "increasing the impact of any XSS on this site if the cookie is "
                                "session/authentication-related.",
                    affected_url=target,
                    parameter=cookie_name,
                    owasp=_OWASP_MISCONFIG,
                    cwe=_CWE_HTTPONLY,
                    recommendation="Set the HttpOnly attribute on session/authentication cookies.",
                ))

            if is_https and "secure" not in lower:
                any_issue = True
                result.findings.append(Finding(
                    severity=base_severity,
                    title=f"Cookie Secure eksik: {cookie_name}",
                    evidence="Flags eksik: Secure",
                    confidence=base_confidence,
                    status=FindingStatus.CONFIRMED,
                    description="This cookie is served over HTTPS but is not marked Secure, so it could "
                                "still be sent over a future plain-HTTP connection to the same host.",
                    affected_url=target,
                    parameter=cookie_name,
                    owasp=_OWASP_MISCONFIG,
                    cwe=_CWE_SECURE_FLAG,
                    recommendation="Set the Secure attribute on cookies served over HTTPS.",
                ))

            if "samesite" not in lower:
                any_issue = True
                result.findings.append(Finding(
                    severity=base_severity,
                    title=f"Cookie SameSite eksik: {cookie_name}",
                    evidence="Flags eksik: SameSite",
                    confidence=base_confidence,
                    status=FindingStatus.CONFIRMED,
                    description="This cookie has no SameSite attribute, relying on the browser's default "
                                "behavior for cross-site request handling, which increases CSRF exposure for "
                                "session/authentication cookies.",
                    affected_url=target,
                    parameter=cookie_name,
                    owasp=_OWASP_MISCONFIG,
                    recommendation="Set SameSite=Lax or SameSite=Strict on session/authentication cookies.",
                ))

            if not any_issue:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Cookie güvenlik bayrakları tam: {cookie_name}",
                    evidence="HttpOnly + Secure + SameSite mevcut",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.SECURE,
                    affected_url=target,
                    parameter=cookie_name,
                ))

    # --- HTTP metodlar ---

    def _check_http_methods(self, session: requests.Session,
                             url: str, result: ScanResult) -> None:
        # OPTIONS ile izin verilen metodları sorgula
        try:
            res = session.options(url, timeout=self.timeout)
            allow = (res.headers.get("Allow") or res.headers.get("Public") or "").upper()
            if allow:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title="İzin Verilen HTTP Metodları (OPTIONS)",
                    evidence=allow,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.INFORMATIONAL,
                    affected_url=url,
                ))
                dangerous = _DANGEROUS_METHODS & set(re.findall(r'[A-Z]+', allow))
                if "TRACE" in dangerous:
                    result.findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="HTTP TRACE metodu aktif (OPTIONS)",
                        evidence="Sunucu Allow listesinde TRACE'i bildiriyor",
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.MANUAL_REVIEW,
                        description="The server advertises TRACE support, which can enable Cross-Site "
                                    "Tracing (XST) in combination with other weaknesses. This is based on "
                                    "the advertised Allow header only, not a demonstrated exploit.",
                        affected_url=url,
                        owasp=_OWASP_MISCONFIG,
                        recommendation="Disable the TRACE method at the web server level if not required.",
                    ))
                for m in dangerous - {"TRACE"}:
                    result.findings.append(Finding(
                        severity=Severity.LOW,
                        title=f"Potentially Risky HTTP Method Enabled: {m}",
                        evidence=f"Sunucu Allow listesinde {m}'i bildiriyor",
                        confidence=Confidence.LOW,
                        status=FindingStatus.MANUAL_REVIEW,
                        description=f"The server advertises {m} support via the Allow header. An enabled "
                                    "method is not automatically vulnerable — this requires manual "
                                    "verification of whether it permits unauthorized state-changing actions.",
                        affected_url=url,
                        owasp=_OWASP_MISCONFIG,
                        recommendation=f"Confirm whether {m} is required; if not, disable it. If required, "
                                       "verify it enforces proper authentication/authorization.",
                    ))
        except requests.RequestException:
            pass

        # TRACE isteğini doğrudan gönder
        try:
            res = session.request("TRACE", url, timeout=self.timeout)
            if res.status_code == 200 and "TRACE" in res.text.upper():
                result.findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="HTTP TRACE aktif (doğrulandı)",
                    evidence=f"Sunucu TRACE isteğini HTTP {res.status_code} ile yansıttı",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="A direct TRACE request was echoed back by the server, confirming the "
                                "method is actually enabled (not just advertised).",
                    affected_url=url,
                    owasp=_OWASP_MISCONFIG,
                    recommendation="Disable the TRACE method at the web server level.",
                ))
        except requests.RequestException:
            pass

    # --- Hassas dizinler (dizin listeleme araması) ---

    def _check_probe_paths(self, session: requests.Session,
                            base: str, result: ScanResult) -> None:
        for path in _PROBE_PATHS:
            try:
                res = session.get(base + path, timeout=self.timeout,
                                  allow_redirects=True)
                if res.status_code != 200:
                    continue
                for pattern in _DIR_LISTING_PATTERNS:
                    if pattern in res.text:
                        result.findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title=f"Dizin listeleme açık: {path}",
                            evidence=f"Tespit: '{pattern}' — dosyalar listelenebilir",
                            confidence=Confidence.HIGH,
                            status=FindingStatus.CONFIRMED,
                            description="A server-generated directory listing marker was observed for this "
                                        "path, indicating its contents are enumerable.",
                            affected_url=base + path,
                            owasp=_OWASP_ACCESS_CONTROL,
                            cwe=_CWE_DIR_LISTING,
                            recommendation="Disable directory listing/autoindex at the web server level for this path.",
                        ))
                        break
            except requests.RequestException:
                continue
