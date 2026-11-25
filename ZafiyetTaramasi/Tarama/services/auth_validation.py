"""
Kimlik doğrulama yanıtı doğrulaması — başarısız-giriş baseline'ı ve kimliği doğrulanmış
durum kanıtı.

İlke: bir giriş denemesi ancak yanıtı BİLİNEN bir başarısız-giriş yanıtından anlamlı
biçimde farklıysa VE kimliği doğrulanmış duruma işaret eden kanıt taşıyorsa başarılıdır.
HTTP 200, "Welcome"/"Dashboard" gibi tek bir kelime ya da hata kelimesinin yokluğu
başarı kanıtı DEĞİLDİR.

P0-4.1: "yönlendirme + giriş formunun kaybolması" da başarı kanıtı DEĞİLDİR — hata,
bakım, onay, challenge ve parola değiştirme ekranları da formsuzdur. CONFIRMED için
güvenilir kimliği doğrulanmış durum kanıtı (yeni beliren çıkış kontrolü) + bağımsız bir
geçiş sinyali gerekir ve kimliği doğrulanmamış durum işareti OLMAMALIDIR.

Yanıt karşılaştırması P0-3'ün `path_baseline.signature` / `compare_signatures`
fonksiyonlarını yeniden kullanır (durum, yönlendirme hedefi, içerik türü, başlık,
dinamik değerleri normalize edilmiş gövde benzerliği); path_baseline değiştirilmez.

Bu modül ağ erişimi yapmaz ve bulgu üretmez — yalnızca sınıflandırır.
"""
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from types import SimpleNamespace
from urllib.parse import urlsplit

from .path_baseline import Relation, compare_signatures, signature


# --- Deneme sınıflandırması (rate limit / engelleme / hata / ağ) ---

class AttemptKind(Enum):
    NORMAL = "NORMAL"                     # uygulamanın olağan yanıtı (başarılı/başarısız giriş)
    RATE_LIMITED = "RATE_LIMITED"         # açık hız sınırlaması / hesap kilidi
    BLOCKED = "BLOCKED"                   # WAF / challenge / 403 / CSRF-iş akışı reddi
    SERVER_ERROR = "SERVER_ERROR"         # geçici sunucu hatası (rate limit kanıtı değil)
    NETWORK_FAILURE = "NETWORK_FAILURE"   # yanıt yok (istek hatası, SSRF engeli, zaman aşımı)


@dataclass(frozen=True)
class AttemptClass:
    kind: AttemptKind
    reason: str = ""


# Hız sınırlaması / kilit metni (rate limiting'in kendi mesajları)
_THROTTLE_TEXT_RE = re.compile(
    r"too many (?:login )?(?:attempts|requests)|rate.?limit|throttl|slow down|"
    r"try again (?:later|in \d+)|account (?:is )?(?:temporarily )?locked",
    re.IGNORECASE,
)
# WAF / bot challenge metni — engelleme, ama rate limiting kanıtı DEĞİL
_CHALLENGE_TEXT_RE = re.compile(
    r"captcha challenge|verify you are (?:a )?human|attention required|access denied|"
    r"request (?:was )?blocked|you have been blocked|suspicious activity|challenge-platform|cf-chl",
    re.IGNORECASE,
)


# Yönlendirme sonrası nihai yol: şüpheli hesap kilidi / challenge
_LOCK_LOCATION_RE = re.compile(r"lock(?:ed|out)?|suspend|too-?many|rate-?limit|throttl", re.IGNORECASE)
_CHALLENGE_LOCATION_RE = re.compile(r"captcha|challenge|blocked|denied", re.IGNORECASE)


def _redirect_final_path(response) -> str:
    """Yanıt bir yönlendirme zincirinin sonuysa nihai yol, değilse ''."""
    history = getattr(response, "history", None)
    url = getattr(response, "url", None)
    if not isinstance(history, list) or not history or not isinstance(url, str):
        return ""
    return urlsplit(url).path or "/"


def _text(response) -> str:
    text = getattr(response, "text", "")
    return text if isinstance(text, str) else ""


def _header(response, name: str) -> str:
    headers = getattr(response, "headers", None)
    try:
        value = headers.get(name) if headers is not None else None
    except Exception:
        value = None
    return value if isinstance(value, str) else ""


def _header_items(response) -> list[tuple[str, str]]:
    headers = getattr(response, "headers", None)
    try:
        return [(k, v) for k, v in headers.items() if isinstance(k, str) and isinstance(v, str)]
    except Exception:
        return []


def _new_match(pattern: re.Pattern, text: str, reference_texts: tuple[str, ...]):
    """Eşleşme yalnızca referans metinlerde (login sayfası, ilk yanıt) YOKSA kanıttır —
    login sayfasındaki statik "5 denemeden sonra kilitlenir" metni sayılmaz."""
    match = pattern.search(text)
    if match and not any(pattern.search(ref) for ref in reference_texts if ref):
        return match
    return None


def classify_attempt(response, reference_texts: tuple[str, ...] = ()) -> AttemptClass:
    """Tek bir giriş denemesinin yanıtını sınıflandırır.

    - None → NETWORK_FAILURE (HTTP hata yanıtından ayrı tutulur)
    - 429 → RATE_LIMITED (güçlü kanıt)
    - 503 → yalnızca Retry-After veya hız sınırlama metniyle RATE_LIMITED; aksi halde SERVER_ERROR
    - diğer 5xx → SERVER_ERROR
    - Retry-After / sıfırlanmış X-RateLimit-Remaining başlığı → RATE_LIMITED
    - referansta olmayan hız sınırlama/kilit metni → RATE_LIMITED
    - yönlendirmeyle varılan kilit sayfası (P0-4.1) → RATE_LIMITED (şüpheli hesap kilidi)
    - yönlendirmeyle varılan challenge/captcha/blocked sayfası (P0-4.1) → BLOCKED
    - 403 / 419 veya referansta olmayan challenge metni → BLOCKED
    """
    if response is None:
        return AttemptClass(AttemptKind.NETWORK_FAILURE, "yanıt alınamadı")

    status = getattr(response, "status_code", 0)
    text = _text(response)
    retry_after = _header(response, "Retry-After")
    throttle = _new_match(_THROTTLE_TEXT_RE, text, reference_texts)

    if status == 429:
        return AttemptClass(AttemptKind.RATE_LIMITED,
                            "HTTP 429" + (f" | Retry-After: {retry_after}" if retry_after else ""))
    if status == 503:
        if retry_after:
            return AttemptClass(AttemptKind.RATE_LIMITED, f"HTTP 503 | Retry-After: {retry_after}")
        if throttle:
            return AttemptClass(AttemptKind.RATE_LIMITED, f"HTTP 503 | yanıtta: '{throttle.group(0)}'")
        return AttemptClass(AttemptKind.SERVER_ERROR, "HTTP 503 (hız sınırlama kanıtı yok)")
    if isinstance(status, int) and status >= 500:
        return AttemptClass(AttemptKind.SERVER_ERROR, f"HTTP {status}")

    if retry_after:
        return AttemptClass(AttemptKind.RATE_LIMITED, f"HTTP {status} | Retry-After: {retry_after}")
    exhausted = [k for k, v in _header_items(response)
                 if "ratelimit" in k.lower() and "remaining" in k.lower() and v.strip() == "0"]
    if exhausted:
        return AttemptClass(AttemptKind.RATE_LIMITED, f"HTTP {status} | {exhausted[0]}: 0")
    if throttle:
        return AttemptClass(AttemptKind.RATE_LIMITED, f"HTTP {status} | yanıtta: '{throttle.group(0)}'")

    # Yönlendirmeyle varılan kilit / challenge sayfası (gövde nötr olsa bile)
    redirected_to = _redirect_final_path(response)
    if redirected_to and _LOCK_LOCATION_RE.search(redirected_to):
        return AttemptClass(AttemptKind.RATE_LIMITED, f"HTTP {status} | kilit sayfasına yönlendirme")
    if redirected_to and _CHALLENGE_LOCATION_RE.search(redirected_to):
        return AttemptClass(AttemptKind.BLOCKED, f"HTTP {status} | challenge sayfasına yönlendirme")

    if status in (403, 419):
        return AttemptClass(AttemptKind.BLOCKED, f"HTTP {status}")
    challenge = _new_match(_CHALLENGE_TEXT_RE, text, reference_texts)
    if challenge:
        return AttemptClass(AttemptKind.BLOCKED, f"HTTP {status} | yanıtta: '{challenge.group(0)}'")

    return AttemptClass(AttemptKind.NORMAL)


# --- Başarısız-giriş baseline karşılaştırması ---

class LoginComparison(Enum):
    MATCHES_FAILED_LOGIN = "MATCHES_FAILED_LOGIN"
    DIFFERS_FROM_FAILED_LOGIN = "DIFFERS_FROM_FAILED_LOGIN"
    AMBIGUOUS = "AMBIGUOUS"


# Kimliği doğrulanmış durum sinyalleri (adayda VAR, başarısız baseline'da YOK)
SIGNAL_DISTINCT_LOCATION = "başarısız girişten farklı, giriş dışı bir konuma yönlendirme"
SIGNAL_FORM_DISAPPEARED = "giriş formu (parola alanı) kayboldu"
SIGNAL_LOGOUT_APPEARED = "çıkış (logout/sign out) kontrolü göründü"
SIGNAL_AUTH_MARKER = "kimliği doğrulanmış alan işareti göründü"

# Kimliği doğrulanmamış durum işaretleri (adayda YENİ). Biri bile varsa yanıt başarılı
# giriş sayılmaz: en fazla MANUAL_REVIEW (CONFIRMED / POTENTIAL değil).
NEG_CROSS_ORIGIN = "farklı origin'e beklenmeyen yönlendirme"
NEG_NON_AUTH_LOCATION = "giriş-dışı ara konuma yönlendirme (hata, kilit, MFA, onay, bakım ...)"
NEG_GENERIC_ERROR = "genel hata sayfası"
NEG_MAINTENANCE = "bakım / hizmet dışı sayfası"
NEG_CONSENT = "onay / koşul kabul ekranı"
NEG_CHALLENGE = "challenge / ek doğrulama adımı"
NEG_PASSWORD_CHANGE = "parola değiştirme / süresi dolmuş parola ekranı"

_PASSWORD_INPUT_RE = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password\b", re.IGNORECASE)
_LOGOUT_RE = re.compile(
    r"(?:href|action)\s*=\s*[\"'][^\"']*(?:log-?out|sign-?out|log-?off)"
    r"|>\s*(?:log\s?out|sign\s?out|log\s?off)\s*<",
    re.IGNORECASE,
)
# Tek başına KANIT DEĞİL — yalnızca güçlü bir sinyali destekler
_AUTH_MARKER_RE = re.compile(r"dashboard|my.?account|account.?settings|\bprofile\b|\bwelcome\b",
                             re.IGNORECASE)
# Bu yollara yönlendirme kimliği doğrulanmış durum sayılmaz (giriş, hata, kilit, challenge, MFA...)
_NON_AUTH_LOCATION_RE = re.compile(
    r"log-?in|sign-?in|auth|error|fail|denied|lock|captcha|challenge|block|limit|verify|"
    r"mfa|2fa|otp|reset|forgot|"
    r"maintenance|unavailable|oops|consent|terms|agree|interstitial|expired|change-?password",
    re.IGNORECASE,
)
# Görünür metinde YENİ beliren ara ekran ifadeleri. Dar tutulur: panodaki "Terms of
# Service" bağlantısı, çerez bildirimi veya "two-factor" ayar bağlantısı eşleşmez.
_INTERSTITIAL_TEXT = (
    (NEG_GENERIC_ERROR, re.compile(
        r"something went wrong|an? (?:unexpected |internal )?error (?:has )?occurred|unexpected error|"
        r"internal server error|bad request|page not found|404 not found|\boops\b|"
        r"traceback \(most recent|unhandled exception|exception (?:was )?thrown", re.IGNORECASE)),
    (NEG_MAINTENANCE, re.compile(
        r"under maintenance|down for maintenance|(?:scheduled |planned )?maintenance (?:mode|in progress|window)|"
        r"temporarily unavailable|service unavailable|be right back|under construction", re.IGNORECASE)),
    (NEG_CONSENT, re.compile(
        r"\bconsent to\b|give (?:your )?consent|review and accept|"
        r"(?:accept|agree to) (?:the |our )?(?:updated |new )?(?:terms|conditions|privacy policy)|"
        r"authori[sz]e (?:this |the )?(?:app|application)\b|(?:grant|allow) access to your account",
        re.IGNORECASE)),
    (NEG_CHALLENGE, re.compile(
        _CHALLENGE_TEXT_RE.pattern
        + r"|enter (?:the |your )?(?:verification |security |authentication |one-time )?code"
          r"|verification code (?:has been |was )?sent|we sent (?:you )?a code|verify (?:it'?s|it is) you"
          r"|verify your (?:identity|device|account)|complete (?:the )?(?:captcha|challenge)",
        re.IGNORECASE)),
    (NEG_PASSWORD_CHANGE, re.compile(
        r"password (?:has )?expired|must (?:change|reset|update) (?:your )?password|"
        r"(?:choose|set|create) a new password|(?:change|update) your password (?:to continue|before)",
        re.IGNORECASE)),
)
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass
class LoginEvidence:
    comparison: LoginComparison
    strong_signals: list[str] = field(default_factory=list)
    supporting_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)

    @property
    def authenticated_state(self) -> bool:
        """Güvenilir kimliği doğrulanmış durum kanıtı: başarısız girişte olmayan bir çıkış
        kontrolü belirdi ve kimliği doğrulanmamış durum işareti yok."""
        return SIGNAL_LOGOUT_APPEARED in self.strong_signals and not self.negative_signals

    @property
    def confirmed(self) -> bool:
        """CONFIRMED (P0-4.1): baseline'dan kesin fark + güvenilir kimliği doğrulanmış durum
        kanıtı + en az bir bağımsız geçiş sinyali (giriş-dışı konum veya formun kaybolması).
        Yönlendirme + formun kaybolması (+ genel kelime) tek başına YETMEZ."""
        return (self.comparison == LoginComparison.DIFFERS_FROM_FAILED_LOGIN
                and self.authenticated_state
                and len(self.strong_signals) >= 2)

    @property
    def potential(self) -> bool:
        """Kimliği doğrulanmamış durum işareti varsa en fazla MANUAL_REVIEW."""
        return (self.comparison != LoginComparison.MATCHES_FAILED_LOGIN
                and not self.negative_signals and bool(self.strong_signals))


def url_origin(url) -> tuple[str, str, int] | None:
    """(şema, host, etkin port) — yalnızca http/https; ayrıştırılamazsa None."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme, host = (parts.scheme or "").lower(), (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    return scheme, host, port or _DEFAULT_PORTS[scheme]


def _visible_text(html: str) -> str:
    return _TAG_RE.sub(" ", _SCRIPT_STYLE_RE.sub(" ", html))


def invalid_credentials() -> tuple[str, str]:
    """Var olması pratikte imkânsız kimlik bilgisi çifti (baseline için). Kalıcı değildir."""
    return f"__lilith_invalid_{secrets.token_hex(6)}", f"__lilith_invalid_{secrets.token_hex(12)}"


def _final_path(response, fallback_url: str) -> str:
    url = getattr(response, "url", None)
    return urlsplit(url if isinstance(url, str) else fallback_url).path or "/"


def has_login_form(response) -> bool:
    return bool(_PASSWORD_INPUT_RE.search(_text(response)))


def _without_username(response, username: str):
    """Sayfanın yansıttığı gönderilmiş kullanıcı adını karşılaştırma için nötrleştirir."""
    text = _text(response)
    if username and len(username) >= 3:
        text = text.replace(username, "{user}")
    return SimpleNamespace(
        status_code=getattr(response, "status_code", 0), text=text,
        url=getattr(response, "url", None), history=getattr(response, "history", None),
        headers=getattr(response, "headers", None),
    )


def compare_login(baseline, candidate, *, action_url: str,
                  baseline_username: str, candidate_username: str) -> LoginEvidence:
    """Aday yanıtını başarısız-giriş baseline'ıyla karşılaştırır ve kimliği doğrulanmış
    durum sinyallerini toplar."""
    path = urlsplit(action_url).path or "/"
    base_sig = signature(_without_username(baseline, baseline_username), action_url, path)
    cand_sig = signature(_without_username(candidate, candidate_username), action_url, path)
    relation = compare_signatures(cand_sig, base_sig)
    comparison = {
        Relation.MATCHES_BASELINE: LoginComparison.MATCHES_FAILED_LOGIN,
        Relation.DIFFERS_FROM_BASELINE: LoginComparison.DIFFERS_FROM_FAILED_LOGIN,
    }.get(relation, LoginComparison.AMBIGUOUS)

    evidence = LoginEvidence(comparison)
    if comparison == LoginComparison.MATCHES_FAILED_LOGIN:
        return evidence

    status = getattr(candidate, "status_code", 0)
    if not (isinstance(status, int) and 200 <= status < 300):
        return evidence  # 2xx olmayan nihai yanıt kimliği doğrulanmış durum değildir

    base_text, cand_text = _text(baseline), _text(candidate)
    base_path, cand_path = _final_path(baseline, action_url), _final_path(candidate, action_url)
    cand_url = getattr(candidate, "url", None)

    if isinstance(cand_url, str) and url_origin(cand_url) != url_origin(action_url):
        evidence.negative_signals.append(NEG_CROSS_ORIGIN)
    elif cand_path != base_path and cand_path != path:
        if _NON_AUTH_LOCATION_RE.search(cand_path):
            evidence.negative_signals.append(NEG_NON_AUTH_LOCATION)
        else:
            evidence.strong_signals.append(SIGNAL_DISTINCT_LOCATION)
    if has_login_form(baseline) and not has_login_form(candidate):
        evidence.strong_signals.append(SIGNAL_FORM_DISAPPEARED)
    if _LOGOUT_RE.search(cand_text) and not _LOGOUT_RE.search(base_text):
        evidence.strong_signals.append(SIGNAL_LOGOUT_APPEARED)
    if _AUTH_MARKER_RE.search(cand_text) and not _AUTH_MARKER_RE.search(base_text):
        evidence.supporting_signals.append(SIGNAL_AUTH_MARKER)

    cand_visible, base_visible = _visible_text(cand_text), _visible_text(base_text)
    for label, pattern in _INTERSTITIAL_TEXT:
        if _new_match(pattern, cand_visible, (base_visible,)):
            evidence.negative_signals.append(label)
    return evidence


def describe_response(response, action_url: str) -> str:
    """Kanıt için kısa, gizli değer içermeyen yanıt özeti (gövde/cookie/token yok)."""
    if response is None:
        return "yanıt yok"
    status = getattr(response, "status_code", "?")
    path = _final_path(response, action_url)
    redirected = path != (urlsplit(action_url).path or "/")
    return (f"HTTP {status}, {path}" + (" (yönlendirme)" if redirected else "")
            + f", giriş formu {'var' if has_login_form(response) else 'yok'}")
