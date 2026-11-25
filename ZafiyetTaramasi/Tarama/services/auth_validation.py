"""
Kimlik doğrulama yanıtı doğrulaması — başarısız-giriş baseline'ı ve kimliği doğrulanmış
durum kanıtı.

İlke: bir giriş denemesi ancak yanıtı BİLİNEN bir başarısız-giriş yanıtından anlamlı
biçimde farklıysa VE kimliği doğrulanmış duruma işaret eden kanıt taşıyorsa başarılıdır.
HTTP 200, "Welcome"/"Dashboard" gibi tek bir kelime ya da hata kelimesinin yokluğu
başarı kanıtı DEĞİLDİR.

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
    r"mfa|2fa|otp|reset|forgot",
    re.IGNORECASE,
)


@dataclass
class LoginEvidence:
    comparison: LoginComparison
    strong_signals: list[str] = field(default_factory=list)
    supporting_signals: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        """CONFIRMED için en az iki güçlü sinyal ya da farklı bir konuma yönlendirme +
        yeni bir kimliği doğrulanmış alan işareti gerekir."""
        if self.comparison == LoginComparison.MATCHES_FAILED_LOGIN:
            return False
        return len(self.strong_signals) >= 2 or (
            SIGNAL_DISTINCT_LOCATION in self.strong_signals and bool(self.supporting_signals)
        )

    @property
    def potential(self) -> bool:
        return self.comparison != LoginComparison.MATCHES_FAILED_LOGIN and bool(self.strong_signals)


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

    if cand_path != base_path and cand_path != path and not _NON_AUTH_LOCATION_RE.search(cand_path):
        evidence.strong_signals.append(SIGNAL_DISTINCT_LOCATION)
    if has_login_form(baseline) and not has_login_form(candidate):
        evidence.strong_signals.append(SIGNAL_FORM_DISAPPEARED)
    if _LOGOUT_RE.search(cand_text) and not _LOGOUT_RE.search(base_text):
        evidence.strong_signals.append(SIGNAL_LOGOUT_APPEARED)
    if _AUTH_MARKER_RE.search(cand_text) and not _AUTH_MARKER_RE.search(base_text):
        evidence.supporting_signals.append(SIGNAL_AUTH_MARKER)
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
