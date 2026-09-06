"""
OWASP Top 10 — A07: Identification and Authentication Failures

Kontroller:
- Login sayfası tespiti
- HTTPS üzerinde login zorunluluğu (sayfa + form gönderim hedefi ayrı değerlendirilir)
- Parola alanı autocomplete
- CAPTCHA varlığı
- Brute-force / rate-limit koruması (5 deneme, bounded)
- Varsayılan kimlik bilgileri (minimal set, bounded)
"""
import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_OWASP_AUTH = "A07:2021 - Identification and Authentication Failures"
_CWE_CLEARTEXT = "CWE-319"  # Cleartext Transmission of Sensitive Information

_LOGIN_PATHS = [
    "/login", "/login/", "/signin", "/signin/",
    "/login.php", "/wp-login.php",
    "/admin/login", "/user/login", "/account/login",
    "/auth/login", "/members/login",
]

# Test edilecek varsayılan kimlik bilgileri (minimal, genişletilmedi)
_DEFAULT_CREDS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("root",          "root"),
    ("administrator", "administrator"),
]

_CAPTCHA_RE = re.compile(
    r"(recaptcha|hcaptcha|captcha|g-recaptcha|cf-turnstile|turnstile)",
    re.I,
)

_RATE_LIMIT_RE = re.compile(
    r"(too many (attempts|requests)|rate.?limit|slow down|"
    r"account (locked|is locked|temporarily locked)|"
    r"try again later|blocked|suspicious activity)",
    re.I,
)

_SUCCESS_RE = re.compile(
    r"(dashboard|logout|sign.?out|my.?account|account.?settings|welcome\b|profile)",
    re.I,
)

_CSRF_NAMES = frozenset({
    "csrf", "csrftoken", "_token", "authenticity_token",
    "__requestverificationtoken",
})


def _is_csrf(name: str) -> bool:
    return any(c in name.lower() for c in _CSRF_NAMES)


class AuthScanner(Scanner):
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

    def _post(self, session: requests.Session, url: str,
              data: dict) -> requests.Response | None:
        try:
            return session.post(url, data=data,
                                timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    # --- Ana tarama ---

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="auth", target=target)
        session = self._make_session()

        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base += f":{parsed.port}"

        login_url, login_res = self._find_login(session, base, target)

        if not login_url:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Login sayfası bulunamadı",
                evidence=f"Taranan yollar: {', '.join(_LOGIN_PATHS)}",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="No login interface was found among the tested common paths. This does not "
                            "confirm the absence of authentication — it may use a path not in this list.",
                affected_url=target,
            ))
            return result

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Login sayfası tespit edildi",
            evidence=login_url,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=login_url,
        ))

        soup = BeautifulSoup(login_res.text, "html.parser")
        form, user_field, pass_field = self._find_login_form(soup)

        self._check_https(login_url, result)
        self._check_autocomplete(soup, login_url, result)
        captcha_present = self._check_captcha(login_res.text, login_url, result)

        if not form or not pass_field:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Login formu ayrıştırılamadı",
                evidence="Parola alanı tespit edilemedi — aktif testler atlandı",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=login_url,
            ))
            return result

        action_url = urljoin(login_url, form.get("action") or login_url)
        method     = form.get("method", "post").lower()

        self._check_form_submission_transport(action_url, result)
        self._check_rate_limit(session, action_url, method, form,
                               user_field, pass_field, captcha_present, result)
        self._check_default_creds(session, action_url, method, form,
                                   user_field, pass_field, result)
        return result

    # --- Login sayfası bulma ---

    def _find_login(self, session, base, target):
        # Önce ana sayfada parola formu ara
        res = self._get(session, target)
        if res:
            soup = BeautifulSoup(res.text, "html.parser")
            form, _, pass_f = self._find_login_form(soup)
            if form and pass_f:
                return target, res

        # Bilinen yolları tara
        for path in _LOGIN_PATHS:
            res = self._get(session, base + path)
            if not res or res.status_code != 200:
                continue
            soup = BeautifulSoup(res.text, "html.parser")
            form, _, pass_f = self._find_login_form(soup)
            if pass_f:
                return res.url, res

        return None, None

    def _find_login_form(self, soup):
        """Parola alanı içeren form + (kullanıcı_adı_alanı, parola_alanı) döner."""
        for form in soup.find_all("form"):
            pass_inp = form.find("input", attrs={"type": "password"})
            if not pass_inp:
                continue
            pass_field = pass_inp.get("name") or "password"

            # Kullanıcı adı alanını bul
            user_field = None
            for inp in form.find_all("input"):
                t    = inp.get("type", "text").lower()
                name = (inp.get("name") or "").lower()
                if t in ("text", "email") or any(
                    k in name for k in ("user", "email", "login", "name")
                ):
                    user_field = inp.get("name")
                    break
            if not user_field:
                first = form.find("input", attrs={"type": ["text", "email"]})
                user_field = first.get("name") if first else None

            return form, user_field, pass_field

        return None, None, None

    def _build_data(self, form, user_field, pass_field,
                    username: str, password: str) -> dict:
        data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            if name == user_field:
                data[name] = username
            elif name == pass_field:
                data[name] = password
            else:
                data[name] = inp.get("value") or ""
        return data

    def _submit(self, session, url, method, data):
        try:
            if method == "post":
                return session.post(url, data=data,
                                    timeout=self.timeout, allow_redirects=True)
            return session.get(url, params=data,
                               timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    # --- Güvenlik kontrolleri ---

    def _check_https(self, login_url: str, result: ScanResult) -> None:
        if login_url.startswith("http://"):
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Login sayfası HTTP üzerinde",
                evidence=f"{login_url}",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The login page itself is served over plain HTTP, so its content (including the "
                            "form) could be tampered with in transit even if the form later posts to HTTPS. "
                            "See the separate finding for the actual credential-submission transport.",
                affected_url=login_url,
                owasp=_OWASP_AUTH,
                cwe=_CWE_CLEARTEXT,
                recommendation="Serve the login page itself over HTTPS.",
            ))
        else:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Login HTTPS üzerinde",
                evidence=login_url,
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=login_url,
            ))

    def _check_form_submission_transport(self, action_url: str, result: ScanResult) -> None:
        """Kimlik bilgilerinin GERÇEKTEN gönderildiği hedefin şemasını doğrular."""
        if action_url.startswith("http://"):
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Authentication Form Uses Unencrypted Transport",
                evidence=f"Form action: {action_url}",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The login form's action target uses plain HTTP, so submitted credentials would "
                            "travel unencrypted over the network.",
                affected_url=action_url,
                owasp=_OWASP_AUTH,
                cwe=_CWE_CLEARTEXT,
                recommendation="Require HTTPS and redirect all authentication traffic to TLS-protected endpoints.",
            ))

    def _check_autocomplete(self, soup, login_url: str, result: ScanResult) -> None:
        for inp in soup.find_all("input", attrs={"type": "password"}):
            ac = (inp.get("autocomplete") or "").lower()
            if ac not in ("off", "new-password", "current-password"):
                result.findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"Parola alanında autocomplete kapalı değil: {inp.get('name', '?')}",
                    evidence="autocomplete='off' veya 'new-password' olmalı — tarayıcı önbelleğe alabilir",
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.CONFIRMED,
                    affected_url=login_url,
                    recommendation="Set autocomplete='new-password' (or 'off') on the password field.",
                ))

    def _check_captcha(self, html: str, login_url: str, result: ScanResult) -> bool:
        """CAPTCHA tespit edilirse True döner — rate-limit değerlendirmesinde bağlam olarak kullanılır."""
        if _CAPTCHA_RE.search(html):
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="CAPTCHA koruması mevcut",
                evidence="Login sayfasında CAPTCHA tespit edildi",
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=login_url,
            ))
            return True

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="CAPTCHA yok",
            evidence="Login sayfasında CAPTCHA gözlemlenmedi",
            confidence=Confidence.MEDIUM,
            status=FindingStatus.INFORMATIONAL,
            description="Missing CAPTCHA alone is not a vulnerability. It becomes more meaningful only in "
                        "combination with weak rate limiting or lockout behavior — see the rate-limit finding.",
            affected_url=login_url,
        ))
        return False

    def _check_rate_limit(self, session, url, method, form,
                          user_field, pass_field, captcha_present: bool,
                          result: ScanResult) -> None:
        """5 hızlı başarısız deneme ile rate-limit / brute-force koruması testi (bounded, no lockout risk)."""
        rate_limited = False
        for i in range(5):
            data = self._build_data(
                form, user_field, pass_field,
                f"wronguser_{i}_xyz", f"wrongpass_{i}_xyz",
            )
            res = self._submit(session, url, method, data)
            if not res:
                continue

            if res.status_code in (429, 503):
                retry = res.headers.get("Retry-After", "")
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title="Rate-limit koruması aktif (HTTP status)",
                    evidence=f"HTTP {res.status_code}"
                             + (f" | Retry-After: {retry}" if retry else ""),
                    confidence=Confidence.HIGH,
                    status=FindingStatus.SECURE,
                    affected_url=url,
                ))
                rate_limited = True
                break

            rl_headers = [h for h in res.headers
                          if "ratelimit" in h.lower() or "retry-after" in h.lower()]
            if rl_headers:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title="Rate-limit koruması aktif (header)",
                    evidence=", ".join(f"{h}: {res.headers[h]}" for h in rl_headers),
                    confidence=Confidence.HIGH,
                    status=FindingStatus.SECURE,
                    affected_url=url,
                ))
                rate_limited = True
                break

            m = _RATE_LIMIT_RE.search(res.text)
            if m:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title="Hesap kilidi / rate-limit koruması aktif",
                    evidence=f"Yanıtta tespit: '{m.group(0)}'",
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.SECURE,
                    affected_url=url,
                ))
                rate_limited = True
                break

        if not rate_limited:
            description = (
                "No blocking/slowdown was observed after 5 quick failed attempts. This is a bounded, "
                "conservative test — 5 requests are not enough to reliably conclude rate limiting is fully "
                "absent, so this should be manually verified rather than treated as confirmed."
            )
            if not captcha_present:
                description += " No CAPTCHA was observed either, which further reduces resistance to " \
                                "automated login attempts."
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Potential Lack of Authentication Rate Limiting",
                evidence="5 başarısız denemeden sonra engelleme veya yavaşlama tespit edilmedi",
                confidence=Confidence.LOW,
                status=FindingStatus.MANUAL_REVIEW,
                description=description,
                affected_url=url,
                owasp=_OWASP_AUTH,
                recommendation="Manually verify rate limiting / account lockout behavior with a broader, "
                               "controlled test, and implement one if genuinely absent.",
            ))

    def _check_default_creds(self, session, url, method, form,
                              user_field, pass_field, result: ScanResult) -> None:
        """Yaygın varsayılan kimlik bilgilerini test eder (sabit, küçük liste — genişletilmedi)."""
        # Baseline: açıkça yanlış credentials
        baseline = self._submit(
            session, url, method,
            self._build_data(form, user_field, pass_field,
                             "baseline_xyz_wrong", "baseline_xyz_wrong"),
        )
        if not baseline:
            return
        baseline_url = baseline.url

        for username, password in _DEFAULT_CREDS:
            data = self._build_data(form, user_field, pass_field, username, password)
            res  = self._submit(session, url, method, data)
            if not res:
                continue

            # Başarı: login/signin dışı farklı URL'e yönlendirme
            redirected = (
                res.url != baseline_url
                and res.url != url
                and not any(k in res.url.lower() for k in ("login", "signin", "error"))
            )
            has_success = bool(_SUCCESS_RE.search(res.text))

            if redirected or has_success:
                result.findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Varsayılan kimlik bilgileri geçerli",
                    # Parola değeri kanıt olarak sızdırılmaz — yalnızca hangi kullanıcı adının çalıştığı belirtilir
                    evidence=f"Kullanıcı: {username} | Parola: [gizlendi — test edilen bilinen varsayılan "
                             f"değer] | Hedef: {res.url}",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="A well-known default credential combination was accepted, granting access "
                                "without the operator having changed the default password.",
                    affected_url=url,
                    parameter=user_field,
                    owasp=_OWASP_AUTH,
                    recommendation="Change or disable default credentials immediately and enforce a strong "
                                   "password policy on account creation.",
                ))
                return

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Varsayılan kimlik bilgileri geçersiz",
            evidence=f"Test edilen {len(_DEFAULT_CREDS)} kombinasyon başarısız",
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=url,
        ))
