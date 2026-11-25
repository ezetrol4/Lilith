"""
OWASP Top 10 — A07: Identification and Authentication Failures

Pasif kontroller (her zaman):
- Login sayfası tespiti
- HTTPS üzerinde login zorunluluğu (sayfa + form gönderim hedefi ayrı değerlendirilir)
- Parola alanı autocomplete
- CAPTCHA varlığı

Aktif kontroller (P0-4.1: varsayılan olarak KAPALI — yalnızca kodla verilen, origin'e
bağlı ActiveAuthAuthorization ile kontrollü lab'da; bkz. services/auth_safety.py):
- Brute-force / rate-limit koruması (5 deneme, bounded)
- Varsayılan kimlik bilgileri (minimal set, bounded, başarısız-giriş baseline'ı ile)

Throttle, challenge, şüpheli kilit, sunucu hatası veya yanıt alınamaması değerlendirmedeki
TÜM sonraki aktif gönderimleri durdurur. Yürütülmeyen / tamamlanamayan test asla SECURE değildir.
"""
import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from . import owasp as owasp_2025
from ..services.auth_safety import (
    ActiveAuthAssessment, ActiveAuthAuthorization, ActiveAuthTest, AuthOutcome,
    OriginBoundaryViolation, outcome_evidence, outcome_for_stop,
)
from ..services.auth_validation import (
    AttemptClass, AttemptKind, LoginComparison, classify_attempt, compare_login, describe_response,
    invalid_credentials,
)
from ..services.safe_http import SafeSession, safe_session


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_OWASP_AUTH = owasp_2025.A07_AUTHENTICATION_FAILURES
# Kimlik bilgisinin şifresiz taşınması: CWE-319 → A04 ("doesn't use or enforce TLS")
_OWASP_TRANSPORT = owasp_2025.A04_CRYPTOGRAPHIC_FAILURES
_CWE_CLEARTEXT = "CWE-319"  # Cleartext Transmission of Sensitive Information
# Parola alanlı formun HTTP hedefine gönderimi gözlendi → kimlik bilgisinin korumasız taşınması
_CWE_CREDENTIAL_TRANSPORT = "CWE-523"  # Unprotected Transport of Credentials (A04:2025 listesi)
_CWE_EXCESSIVE_AUTH_ATTEMPTS = "CWE-307"  # Improper Restriction of Excessive Authentication Attempts
_CWE_DEFAULT_CREDENTIALS = "CWE-1392"     # Use of Default Credentials

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

_RATE_LIMIT_ATTEMPTS = 5
# Değerlendirme başına mutlak üst sınır: rate-limit + baseline + önceden tanımlı liste
_MAX_ACTIVE_SUBMISSIONS = _RATE_LIMIT_ATTEMPTS + 1 + len(_DEFAULT_CREDS)

_CAPTCHA_RE = re.compile(
    r"(recaptcha|hcaptcha|captcha|g-recaptcha|cf-turnstile|turnstile)",
    re.I,
)

_CSRF_NAMES = frozenset({
    "csrf", "csrftoken", "_token", "authenticity_token",
    "__requestverificationtoken",
})

_NOT_EXECUTED_DESCRIPTION = (
    "This active authentication test was not performed, so it provides no evidence either way. "
    "Active credential submissions are disabled by default and run only under an explicit, "
    "in-code authorization for a controlled lab target; they also stop after any throttle, "
    "challenge, suspected lockout or server failure. This is not a SECURE result."
)


def _is_csrf(name: str) -> bool:
    return any(c in name.lower() for c in _CSRF_NAMES)


class AuthScanner(Scanner):
    def __init__(self, timeout: float = 10.0, *, authorization: ActiveAuthAuthorization | None = None):
        # Yetki yalnızca kodla verilen ActiveAuthAuthorization olabilir: bool/str/dict gibi
        # istekten türetilmiş "bayraklar" aktif testleri açamaz.
        if authorization is not None and not isinstance(authorization, ActiveAuthAuthorization):
            raise TypeError("authorization yalnızca ActiveAuthAuthorization olabilir")
        self.timeout = timeout
        self.authorization = authorization

    def _make_session(self) -> SafeSession:
        s = safe_session()
        s.headers["User-Agent"] = _USER_AGENT
        return s

    def _get(self, session: requests.Session, url: str) -> requests.Response | None:
        try:
            return session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    # --- Ana tarama ---

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="auth", target=target)
        session = self._make_session()
        # Tek değerlendirmeye ait aktif gönderim durumu (paylaşılmaz, kalıcı değil)
        assessment = ActiveAuthAssessment(self.authorization, target, _MAX_ACTIVE_SUBMISSIONS)

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
        self._check_rate_limit(assessment, session, action_url, method, form,
                               user_field, pass_field, captcha_present, login_res.text, result)
        self._check_default_creds(assessment, login_url, action_url, user_field, login_res.text, result)
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

    def _submit(self, assessment: ActiveAuthAssessment, test: ActiveAuthTest,
                session, url, method, data):
        """TEK kimlik bilgisi gönderim noktası. Yetki/durdurma/bütçe kontrolü isteğin hemen
        önünde yapılır (SubmissionRefused → istek gönderilmez). Her yönlendirme adımı takip
        edilmeden önce yetkili origin'e karşı doğrulanır; dışarı çıkan yönlendirme takip
        edilmez ve değerlendirme BLOCKED olarak durur (None döner, durdurma kaydedilir)."""
        assessment.claim(test, url)
        guard = assessment.redirect_guard()
        try:
            if method == "post":
                return session.post(url, data=data, timeout=self.timeout,
                                    allow_redirects=True, redirect_guard=guard)
            return session.get(url, params=data, timeout=self.timeout,
                               allow_redirects=True, redirect_guard=guard)
        except OriginBoundaryViolation as violation:
            assessment.record_boundary_violation(violation)
            return None
        except requests.RequestException:
            return None

    @staticmethod
    def _attempt_class(assessment: ActiveAuthAssessment, response, reference_texts) -> AttemptClass:
        """Gönderim sonucunu sınıflandırır. Yanıt yoksa ve gönderim değerlendirmeyi durdurduysa
        (origin dışı yönlendirme) o durdurma nedeni kullanılır — 'yanıt yok' sayılmaz."""
        if response is None and assessment.stopped:
            return assessment.stop
        return classify_attempt(response, reference_texts)

    @staticmethod
    def _not_executed(title: str, reason: str, url: str, skipped: str) -> Finding:
        return Finding(
            severity=Severity.INFO,
            title=title,
            evidence=outcome_evidence(AuthOutcome.NOT_EXECUTED, f"{reason} | Gönderilmeyen: {skipped}"),
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            description=_NOT_EXECUTED_DESCRIPTION,
            affected_url=url,
        )

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
                owasp=_OWASP_TRANSPORT,
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
        """Kimlik bilgilerinin GERÇEKTEN gönderileceği hedefin şemasını doğrular (pasif)."""
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
                owasp=_OWASP_TRANSPORT,
                cwe=_CWE_CREDENTIAL_TRANSPORT,
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

    def _check_rate_limit(self, assessment: ActiveAuthAssessment, session, url, method, form,
                          user_field, pass_field, captcha_present: bool,
                          login_page_text: str, result: ScanResult) -> None:
        """En fazla 5 hızlı başarısız deneme ile rate-limit / brute-force koruması testi (AKTİF).

        Her yanıt açıkça sınıflandırılır (auth_validation.classify_attempt): yalnızca 429,
        kanıtlı 503, Retry-After / tükenmiş limit başlığı, kilit sayfasına yönlendirme veya
        login sayfasında ve ilk yanıtta OLMAYAN hız sınırlama metni rate limiting sayılır.
        Throttle, challenge, sunucu hatası veya yanıt yokluğu denemeleri (ve değerlendirmenin
        sonraki tüm aktif gönderimlerini) DURDURUR; bu durumlar "rate limiting yok" iddiasına
        dönüşmez.
        """
        refusal = assessment.refusal(ActiveAuthTest.RATE_LIMIT_PROBE, url)
        if refusal:
            result.findings.append(self._not_executed(
                "Rate-limit testi yürütülmedi", refusal, url,
                f"{_RATE_LIMIT_ATTEMPTS} başarısız giriş denemesi"))
            return

        counts = {kind: 0 for kind in AttemptKind}
        reference = [login_page_text]
        sent = 0

        for i in range(_RATE_LIMIT_ATTEMPTS):
            data = self._build_data(
                form, user_field, pass_field,
                f"wronguser_{i}_xyz", f"wrongpass_{i}_xyz",
            )
            res = self._submit(assessment, ActiveAuthTest.RATE_LIMIT_PROBE, session, url, method, data)
            sent += 1
            attempt = self._attempt_class(assessment, res, tuple(reference))
            counts[attempt.kind] += 1
            assessment.record(attempt)

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
                    evidence=outcome_evidence(
                        AuthOutcome.CONTROL_RESPONSE_OBSERVED,
                        f"{i + 1}. başarısız denemede: {attempt.reason} | sonraki aktif gönderimler durduruldu"),
                    confidence=confidence,
                    status=FindingStatus.SECURE,
                    affected_url=url,
                ))
                return

            if assessment.stopped:
                break
            if attempt.kind == AttemptKind.NORMAL and len(reference) == 1:
                reference.append(res.text)  # ilk olağan yanıt: statik metin referansı

        summary = (f"{sent}/{_RATE_LIMIT_ATTEMPTS} başarısız deneme gönderildi — "
                   f"olağan yanıt: {counts[AttemptKind.NORMAL]}, "
                   f"engelleme/challenge: {counts[AttemptKind.BLOCKED]}, "
                   f"sunucu hatası: {counts[AttemptKind.SERVER_ERROR]}, "
                   f"yanıt yok: {counts[AttemptKind.NETWORK_FAILURE]}")

        if assessment.boundary_violation:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Rate-limit testi durduruldu: yetkili origin dışına yönlendirme",
                evidence=outcome_evidence(
                    AuthOutcome.BLOCKED,
                    f"{summary} | {assessment.stop.reason} | sonraki aktif gönderimler durduruldu"),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description="A login submission was redirected outside the authorized lab origin. The "
                            "redirect was not followed (no request, body, cookie or URL state reached the "
                            "destination) and all further active authentication submissions were stopped. "
                            "Rate limiting was not assessed.",
                affected_url=url,
            ))
            return

        if assessment.stopped and assessment.stop.kind == AttemptKind.BLOCKED:
            # WAF/challenge bir engelleme biçimidir ama rate limiting kanıtı değildir
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Rate-limit testi sonuçsuz: WAF/challenge yanıtı",
                evidence=outcome_evidence(
                    AuthOutcome.BLOCKED,
                    f"{summary} | Engelleme: {assessment.stop.reason} | sonraki aktif gönderimler durduruldu"),
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="Login attempts received a WAF/challenge or forbidden response, so all further "
                            "active authentication submissions were stopped. This indicates some request "
                            "filtering, but it is not evidence of authentication rate limiting, and it "
                            "prevented assessing whether rate limiting is absent.",
                affected_url=url,
            ))
            return

        if assessment.stopped or counts[AttemptKind.NORMAL] == 0:
            # Sunucu hatası / yanıt yok — "rate limit yok" iddia edilemez
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Rate-limit testi sonuçsuz",
                evidence=outcome_evidence(
                    AuthOutcome.INCOMPLETE, f"{summary} | sonraki aktif gönderimler durduruldu"),
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="A server error or missing response stopped the test (and all further active "
                            "authentication submissions), so rate limiting could neither be confirmed nor "
                            "ruled out.",
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
            evidence=outcome_evidence(
                AuthOutcome.AUTHENTICATION_NOT_ESTABLISHED,
                f"5 başarısız denemeden sonra kontrol yanıtı (engelleme veya yavaşlama) gözlenmedi | {summary}"),
            confidence=Confidence.LOW,
            status=FindingStatus.MANUAL_REVIEW,
            description=description,
            affected_url=url,
            owasp=_OWASP_AUTH,
            cwe=_CWE_EXCESSIVE_AUTH_ATTEMPTS,
            recommendation="Manually verify rate limiting / account lockout behavior with a broader, "
                           "controlled test, and implement one if genuinely absent.",
        ))

    # --- Varsayılan kimlik bilgileri ---

    def _attempt_login(self, assessment: ActiveAuthAssessment, login_url: str,
                       username: str, password: str):
        """Tek bir giriş denemesi — YALITILMIŞ oturumla.

        Her senaryo (baseline ve her aday) yeni bir SafeSession ile login sayfasını yeniden
        alır: taze CSRF/hidden değerler, önceki denemelerden cookie/flash durumu yok.
        Başarılı bir girişin oturumu başka hiçbir istekte kullanılmaz. Gönderim hedefi
        (taze form action) gönderimden önce yetki/durdurma kontrolünden geçer.
        Döner: (yanıt veya None, action_url veya None, gönderilmediyse (AuthOutcome, neden))
        """
        session = self._make_session()
        page = self._get(session, login_url)
        if page is None:
            return None, None, None   # yanıt yok → NETWORK_FAILURE (durdurma koşulu)
        form, user_field, pass_field = self._find_login_form(BeautifulSoup(page.text, "html.parser"))
        if not form or not pass_field:
            return None, None, (AuthOutcome.INCOMPLETE, "login formu yeniden alınamadı")
        action_url = urljoin(login_url, form.get("action") or login_url)
        refusal = assessment.refusal(ActiveAuthTest.DEFAULT_CREDENTIALS, action_url)
        if refusal:
            return None, action_url, (AuthOutcome.NOT_EXECUTED, refusal)
        method = form.get("method", "post").lower()
        data = self._build_data(form, user_field, pass_field, username, password)
        res = self._submit(assessment, ActiveAuthTest.DEFAULT_CREDENTIALS, session, action_url, method, data)
        return res, action_url, None

    def _check_default_creds(self, assessment: ActiveAuthAssessment, login_url: str, action_url: str,
                             user_field, login_page_text: str, result: ScanResult) -> None:
        """Sabit, küçük varsayılan kimlik bilgisi listesini başarısız-giriş baseline'ına göre test eder (AKTİF).

        Liste genişletilmez; kimlik bilgisi türetme/uyarlama yoktur. Durdurma koşulu
        (throttle, challenge, şüpheli kilit, sunucu hatası, yanıt yok) görülürse sonraki tüm
        gönderimler DURUR (yeniden deneme, kimlik değiştirme, atlatma yok).
        """
        total = len(_DEFAULT_CREDS)
        refusal = assessment.refusal(ActiveAuthTest.DEFAULT_CREDENTIALS, action_url)
        if refusal:
            result.findings.append(self._not_executed(
                "Varsayılan kimlik bilgisi testi yapılmadı", refusal, action_url,
                f"başarısız-giriş baseline'ı ve {total} önceden tanımlı kimlik bilgisi"))
            return

        base_user, base_pass = invalid_credentials()   # kalıcı değil, kanıta yazılmaz
        baseline, base_action, problem = self._attempt_login(assessment, login_url, base_user, base_pass)
        if problem is None:
            base_class = self._attempt_class(assessment, baseline, (login_page_text,))
            assessment.record(base_class)
            if base_class.kind != AttemptKind.NORMAL:
                problem = (outcome_for_stop(base_class.kind),
                           f"{base_class.reason} | sonraki aktif gönderimler durduruldu")
        if problem is not None:
            # Baseline yoksa adaylar değerlendirilemez — varsayılan kimlik bilgisi gönderilmez
            outcome, reason = problem
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Varsayılan kimlik bilgisi testi yapılmadı",
                evidence=outcome_evidence(
                    outcome, f"Başarısız-giriş baseline'ı kurulamadı: {reason} | "
                             f"Gönderilmeyen: {total} önceden tanımlı kimlik bilgisi"),
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
        incomplete = None    # (AuthOutcome, neden)
        attempted = 0
        for username, password in _DEFAULT_CREDS:
            res, cand_action, problem = self._attempt_login(assessment, login_url, username, password)
            if problem is not None:
                incomplete = (problem[0], f"{username}: {problem[1]}")
                break
            attempted += 1
            attempt = self._attempt_class(assessment, res, (login_page_text, baseline.text))
            assessment.record(attempt)
            if attempt.kind != AttemptKind.NORMAL:
                incomplete = (outcome_for_stop(attempt.kind),
                              f"{username}: {attempt.reason} — sonraki aktif gönderimler durduruldu")
                break
            if res.status_code == 401:
                continue  # açık kimlik doğrulama reddi

            evidence = compare_login(baseline, res, action_url=cand_action or action_url,
                                     baseline_username=base_user, candidate_username=username)
            candidate_desc = describe_response(res, cand_action or action_url)
            if evidence.confirmed:
                # Kimliği doğrulanmış durum kuruldu — başka gönderim yapılmaz
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

        if incomplete is not None:
            outcome, reason = incomplete
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Varsayılan kimlik bilgisi testi tamamlanamadı",
                evidence=outcome_evidence(
                    outcome, f"{reason} | Denenen: {attempted}/{total} | Baseline: {baseline_desc}"),
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="The default-credential test stopped before completion (rate limiting, "
                            "blocking, a server error, a network failure or a refused submission). "
                            "Remaining credentials were not submitted. No authenticated state was "
                            "established by the attempts that ran, but the test was not complete.",
                affected_url=action_url,
            ))
            return

        if best is not None:
            return

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Varsayılan kimlik bilgileri geçersiz",
            evidence=outcome_evidence(
                AuthOutcome.AUTHENTICATION_NOT_ESTABLISHED,
                f"Test edilen {total} kombinasyon başarısız-giriş baseline'ı ile eşleşti veya açıkça "
                f"reddedildi | Baseline: {baseline_desc}"),
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=action_url,
        ))

    def _add_default_cred_finding(self, result, action_url, user_field, username,
                                  baseline_desc, candidate_desc, evidence, confirmed: bool) -> None:
        signals = evidence.strong_signals + evidence.supporting_signals
        if confirmed:
            outcome = outcome_evidence(AuthOutcome.AUTHENTICATED_STATE_ESTABLISHED)
        else:
            outcome = outcome_evidence(AuthOutcome.AUTHENTICATION_NOT_ESTABLISHED,
                                       "yanıt başarısız girişten farklı; kimliği doğrulanmış durum kanıtı yetersiz")
        # Parola değeri kanıt olarak sızdırılmaz — yalnızca hangi kullanıcı adının denendiği belirtilir
        text = (f"{outcome} | Kullanıcı: {username} | Parola: [gizlendi — test edilen bilinen varsayılan değer] "
                f"| Başarısız-giriş baseline'ı: {baseline_desc} | Aday: {candidate_desc} "
                f"| Kimliği doğrulanmış durum sinyalleri: {', '.join(signals) or 'yok (yalnızca yanıt farkı)'}")
        if evidence.negative_signals:
            text += f" | Kimliği doğrulanmamış durum işaretleri: {', '.join(evidence.negative_signals)}"
        if confirmed:
            severity, title, confidence, status = (Severity.CRITICAL, "Varsayılan kimlik bilgileri geçerli",
                                                   Confidence.HIGH, FindingStatus.CONFIRMED)
            description = ("A well-known default credential combination was accepted: the response differs "
                           "from a known failed-login response, a logout control appeared that the failed "
                           "login does not show, and an independent transition signal was observed "
                           "(listed in the evidence).")
        elif evidence.potential:
            severity, title, confidence, status = (Severity.HIGH, "Varsayılan kimlik bilgileri muhtemelen geçerli",
                                                   Confidence.MEDIUM, FindingStatus.POTENTIAL)
            description = ("The response to a default credential differs from a known failed-login response "
                           "and shows authenticated-state indications (e.g. a redirect and a missing login "
                           "form), but no credible authenticated-state evidence such as a newly visible "
                           "logout control. Manual verification is required.")
        else:
            severity, title, confidence, status = (Severity.MEDIUM,
                                                   "Varsayılan kimlik bilgisi yanıtı farklı — doğrulama gerekli",
                                                   Confidence.LOW, FindingStatus.MANUAL_REVIEW)
            description = ("The response to a default credential differs from a known failed-login response, "
                           "but no authenticated-state evidence was observed, or the page looks like an "
                           "error, maintenance, consent, challenge/MFA or password-change screen, or an "
                           "unexpected redirect. Manual verification is required.")
        result.findings.append(Finding(
            severity=severity, title=title, evidence=text, confidence=confidence, status=status,
            description=description, affected_url=action_url, parameter=user_field, owasp=_OWASP_AUTH,
            cwe=_CWE_DEFAULT_CREDENTIALS,
            recommendation="Change or disable default credentials immediately and enforce a strong "
                           "password policy on account creation.",
        ))
