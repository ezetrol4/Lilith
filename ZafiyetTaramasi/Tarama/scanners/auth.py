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
from ..services.auth_validation import (
    AttemptKind, LoginComparison, classify_attempt, compare_login, describe_response,
    invalid_credentials,
)
from ..services.safe_http import SafeSession, safe_session


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

_CSRF_NAMES = frozenset({
    "csrf", "csrftoken", "_token", "authenticity_token",
    "__requestverificationtoken",
})


def _is_csrf(name: str) -> bool:
    return any(c in name.lower() for c in _CSRF_NAMES)


class AuthScanner(Scanner):
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _make_session(self) -> SafeSession:
        s = safe_session()
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
                               user_field, pass_field, captcha_present, login_res.text, result)
        self._check_default_creds(login_url, action_url, user_field, login_res.text, result)
        return result

    # --- Login sayfası bulma ---

    def _find_login(self, session, base, target):
        # Önce ana sayfada parola formu ara
        res = self._get(session, target)
        if res is not None:  # 401/403 ana sayfa da giriş formu taşıyabilir (Response truthiness kullanılmaz)
            soup = BeautifulSoup(res.text, "html.parser")
            form, _, pass_f = self._find_login_form(soup)
            if form and pass_f:
                return target, res

        # Bilinen yolları tara
        for path in _LOGIN_PATHS:
            res = self._get(session, base + path)
            if res is None or res.status_code != 200:
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
                          login_page_text: str, result: ScanResult) -> None:
        """5 hızlı başarısız deneme ile rate-limit / brute-force koruması testi (bounded, no lockout risk).

        Her yanıt açıkça sınıflandırılır (auth_validation.classify_attempt): yalnızca 429,
        kanıtlı 503, Retry-After / tükenmiş limit başlığı veya login sayfasında ve ilk
        yanıtta OLMAYAN hız sınırlama metni rate limiting sayılır. Genel 5xx, WAF/challenge
        ve ağ hatası rate limiting DEĞİLDİR ve "rate limiting yok" iddiasına da dönüşmez.
        """
        counts = {kind: 0 for kind in AttemptKind}
        reference = [login_page_text]
        blocked_reason = ""

        for i in range(5):
            data = self._build_data(
                form, user_field, pass_field,
                f"wronguser_{i}_xyz", f"wrongpass_{i}_xyz",
            )
            res = self._submit(session, url, method, data)
            attempt = classify_attempt(res, tuple(reference))
            counts[attempt.kind] += 1

            if attempt.kind == AttemptKind.RATE_LIMITED:
                if res.status_code in (429, 503):
                    title, confidence = "Rate-limit koruması aktif (HTTP status)", Confidence.HIGH
                elif "Retry-After" in attempt.reason or "ratelimit" in attempt.reason.lower():
                    title, confidence = "Rate-limit koruması aktif (header)", Confidence.HIGH
                else:
                    title, confidence = "Hesap kilidi / rate-limit koruması aktif", Confidence.MEDIUM
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=title,
                    evidence=f"{i + 1}. başarısız denemede: {attempt.reason}",
                    confidence=confidence,
                    status=FindingStatus.SECURE,
                    affected_url=url,
                ))
                return

            if attempt.kind == AttemptKind.BLOCKED and not blocked_reason:
                blocked_reason = attempt.reason
            if attempt.kind == AttemptKind.NORMAL and len(reference) == 1:
                reference.append(res.text)  # ilk olağan yanıt: statik metin referansı

        summary = (f"5 başarısız deneme — olağan yanıt: {counts[AttemptKind.NORMAL]}, "
                   f"engelleme/challenge: {counts[AttemptKind.BLOCKED]}, "
                   f"sunucu hatası: {counts[AttemptKind.SERVER_ERROR]}, "
                   f"yanıt yok: {counts[AttemptKind.NETWORK_FAILURE]}")

        if counts[AttemptKind.BLOCKED]:
            # WAF/challenge bir engelleme biçimidir ama rate limiting kanıtı değildir
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Rate-limit testi sonuçsuz: WAF/challenge yanıtı",
                evidence=f"{summary} | İlk engelleme: {blocked_reason}",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="Login attempts received a WAF/challenge or forbidden response. This indicates "
                            "some request filtering, but it is not evidence of authentication rate limiting, "
                            "and it prevented assessing whether rate limiting is absent.",
                affected_url=url,
            ))
            return

        if counts[AttemptKind.NORMAL] == 0:
            # Hiç olağan yanıt gözlemlenmedi (ağ/sunucu hatası) — "rate limit yok" iddia edilemez
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Rate-limit testi sonuçsuz",
                evidence=summary,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="No normal login response was observed (network failures or transient server "
                            "errors), so rate limiting could neither be confirmed nor ruled out.",
                affected_url=url,
            ))
            return

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
            evidence=f"5 başarısız denemeden sonra engelleme veya yavaşlama tespit edilmedi | {summary}",
            confidence=Confidence.LOW,
            status=FindingStatus.MANUAL_REVIEW,
            description=description,
            affected_url=url,
            owasp=_OWASP_AUTH,
            recommendation="Manually verify rate limiting / account lockout behavior with a broader, "
                           "controlled test, and implement one if genuinely absent.",
        ))

    # --- Varsayılan kimlik bilgileri ---

    def _attempt_login(self, login_url: str, username: str, password: str):
        """Tek bir giriş denemesi — YALITILMIŞ oturumla.

        Her senaryo (baseline ve her aday) yeni bir SafeSession ile login sayfasını yeniden
        alır: taze CSRF/hidden değerler, önceki denemelerden cookie/flash durumu yok.
        Başarılı bir girişin oturumu başka hiçbir istekte kullanılmaz. Gönderilen giriş
        denemesi sayısı değişmez (her senaryo bir gönderim).
        Döner: (yanıt veya None, action_url veya None)
        """
        session = self._make_session()
        page = self._get(session, login_url)
        if page is None:
            return None, None
        form, user_field, pass_field = self._find_login_form(BeautifulSoup(page.text, "html.parser"))
        if not form or not pass_field:
            return None, None
        action_url = urljoin(login_url, form.get("action") or login_url)
        method = form.get("method", "post").lower()
        data = self._build_data(form, user_field, pass_field, username, password)
        return self._submit(session, action_url, method, data), action_url

    def _check_default_creds(self, login_url: str, action_url: str, user_field,
                             login_page_text: str, result: ScanResult) -> None:
        """Sabit, küçük varsayılan kimlik bilgisi listesini başarısız-giriş baseline'ına göre test eder.

        Liste genişletilmez; kimlik bilgisi türetme/uyarlama yoktur. Engelleme veya hız
        sınırlaması görülürse denemeler DURUR (atlatma denenmez).
        """
        base_user, base_pass = invalid_credentials()   # kalıcı değil, kanıta yazılmaz
        baseline, base_action = self._attempt_login(login_url, base_user, base_pass)
        base_class = classify_attempt(baseline, (login_page_text,))
        if base_class.kind != AttemptKind.NORMAL:
            # Baseline yoksa adaylar değerlendirilemez — varsayılan kimlik bilgisi kabul edilmez
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Varsayılan kimlik bilgisi testi yapılmadı",
                evidence=f"Başarısız-giriş baseline'ı kurulamadı: {base_class.reason or 'login iş akışı'}",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="A known failed-login response could not be established, so default "
                            "credentials were not tested. This is not evidence either way.",
                affected_url=action_url,
            ))
            return
        action_url = base_action or action_url
        baseline_desc = describe_response(baseline, action_url)

        best = None          # en güçlü onaylanmamış sonuç: (evidence, username, candidate_desc)
        inconclusive = []
        for username, password in _DEFAULT_CREDS:
            res, cand_action = self._attempt_login(login_url, username, password)
            attempt = classify_attempt(res, (login_page_text, baseline.text))
            if attempt.kind in (AttemptKind.RATE_LIMITED, AttemptKind.BLOCKED):
                inconclusive.append(f"{username}: {attempt.reason} — denemeler durduruldu")
                break
            if attempt.kind != AttemptKind.NORMAL:
                inconclusive.append(f"{username}: {attempt.reason}")
                continue
            if res.status_code == 401:
                continue  # açık kimlik doğrulama reddi

            evidence = compare_login(baseline, res, action_url=cand_action or action_url,
                                     baseline_username=base_user, candidate_username=username)
            candidate_desc = describe_response(res, cand_action or action_url)
            if evidence.confirmed:
                self._add_default_cred_finding(result, action_url, user_field, username,
                                               baseline_desc, candidate_desc, evidence, confirmed=True)
                return
            if evidence.comparison != LoginComparison.MATCHES_FAILED_LOGIN:
                rank = (evidence.potential, len(evidence.strong_signals))
                if best is None or rank > (best[0].potential, len(best[0].strong_signals)):
                    best = (evidence, username, candidate_desc)

        if best is not None:
            evidence, username, candidate_desc = best
            self._add_default_cred_finding(result, action_url, user_field, username,
                                           baseline_desc, candidate_desc, evidence, confirmed=False)
            return

        if inconclusive:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Varsayılan kimlik bilgisi testi tamamlanamadı",
                evidence=f"Baseline: {baseline_desc} | Sonuçsuz: {'; '.join(inconclusive)}",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="Some default-credential attempts could not be evaluated (rate limiting, "
                            "blocking, server errors or network failures). No successful default "
                            "credential was observed, but the test was not complete.",
                affected_url=action_url,
            ))
            return

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Varsayılan kimlik bilgileri geçersiz",
            evidence=f"Test edilen {len(_DEFAULT_CREDS)} kombinasyon başarısız-giriş baseline'ı ile eşleşti "
                     f"| Baseline: {baseline_desc}",
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=action_url,
        ))

    def _add_default_cred_finding(self, result, action_url, user_field, username,
                                  baseline_desc, candidate_desc, evidence, confirmed: bool) -> None:
        signals = evidence.strong_signals + evidence.supporting_signals
        # Parola değeri kanıt olarak sızdırılmaz — yalnızca hangi kullanıcı adının denendiği belirtilir
        text = (f"Kullanıcı: {username} | Parola: [gizlendi — test edilen bilinen varsayılan değer] "
                f"| Başarısız-giriş baseline'ı: {baseline_desc} | Aday: {candidate_desc} "
                f"| Kimliği doğrulanmış durum sinyalleri: {', '.join(signals) or 'yok (yalnızca yanıt farkı)'}")
        if confirmed:
            severity, title, confidence, status = (Severity.CRITICAL, "Varsayılan kimlik bilgileri geçerli",
                                                   Confidence.HIGH, FindingStatus.CONFIRMED)
            description = ("A well-known default credential combination was accepted: the response differs "
                           "from a known failed-login response and shows independent authenticated-state "
                           "signals (listed in the evidence).")
        elif evidence.potential:
            severity, title, confidence, status = (Severity.HIGH, "Varsayılan kimlik bilgileri muhtemelen geçerli",
                                                   Confidence.MEDIUM, FindingStatus.POTENTIAL)
            description = ("The response to a default credential differs from a known failed-login response "
                           "and shows one authenticated-state signal, which is not enough to confirm a "
                           "successful login. Manual verification is required.")
        else:
            severity, title, confidence, status = (Severity.MEDIUM,
                                                   "Varsayılan kimlik bilgisi yanıtı farklı — doğrulama gerekli",
                                                   Confidence.LOW, FindingStatus.MANUAL_REVIEW)
            description = ("The response to a default credential differs from a known failed-login response, "
                           "but no authenticated-state evidence was observed (it may be a different error, "
                           "an MFA step or a password-change prompt). Manual verification is required.")
        result.findings.append(Finding(
            severity=severity, title=title, evidence=text, confidence=confidence, status=status,
            description=description, affected_url=action_url, parameter=user_field, owasp=_OWASP_AUTH,
            recommendation="Change or disable default credentials immediately and enforce a strong "
                           "password policy on account creation.",
        ))
