"""
Kimlik bilgisi işleyen yüzey koruması — enjeksiyon scanner'ları için (P0-4.1).

SQL / XSS / CMD / NoSQL scanner'ları varsayılan taramada login, kayıt, parola sıfırlama,
OTP/MFA ve benzeri kimlik bilgisi işleyen formlara veya JSON kimlik doğrulama uçlarına
payload GÖNDERMEZ: bu gönderimler kimlik doğrulama denemesidir (ör. `' OR 1=1--`,
`{"$ne": …}` kimlik doğrulama atlatma biçimleri) ve hesap kilidi, güvenlik alarmı veya
oturum yan etkisi doğurabilir. Atlanan yüzey "değerlendirilmedi" (INFORMATIONAL) olarak
kaydedilir — asla SECURE değildir.

Tanıma bilinçli olarak MUHAFAZAKÂRDIR (şüphede atla): yanlış atlama yalnızca kapsamı
daraltır; yanlış gönderim bir üretim hesabını etkileyebilir. Payload'lar, eşikler ve
kimlik bilgisi işlemeyen formların bulgu semantiği değişmez. Ağ erişimi yoktur.
"""
import re
from urllib.parse import urlsplit

from .base import Confidence, Finding, FindingStatus, Severity

# Yol / form özniteliği segmentleri (kelime sınırı: harf/rakam olmayan karakter)
_AUTH_TOKEN = (
    r"log[-_]?in|log[-_]?on|sign[-_]?in|sign[-_]?up|register|auth|authenticate|authori[sz]e|oauth2?|sso|saml|"
    r"sessions?|password|passwd|forgot|reset|mfa|2fa|otp|verify|token|credentials?"
)
_AUTH_PATH_RE = re.compile(rf"(?:^|[^a-z0-9])(?:{_AUTH_TOKEN})(?:$|[^a-z0-9])", re.IGNORECASE)
_AUTH_FORM_ATTR_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:log[-_]?in|log[-_]?on|sign[-_]?in|sign[-_]?up|register|auth|authentication|"
    r"credentials?|password|passwd|mfa|2fa|otp)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
# Alan adları: parola / PIN / tek kullanımlık kod
_CREDENTIAL_FIELD_RE = re.compile(
    r"password|passwd|passphrase|passcode|one.?time|verification.?code|security.?code|"
    r"auth(?:entication)?.?code|(?:^|[^a-z0-9])(?:pass|pwd|pin|otp|totp|mfa|2fa)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
_CREDENTIAL_AUTOCOMPLETE = frozenset({"current-password", "new-password", "one-time-code"})
_LOGIN_SUBMIT_RE = re.compile(r"^\s*(?:log\s?-?in|log\s?on|sign\s?-?in|sign\s?-?up|register)\b",
                              re.IGNORECASE)

NOT_ASSESSED_FORM_TITLE = "Kimlik doğrulama formu değerlendirilmedi"
NOT_ASSESSED_ENDPOINT_TITLE = "Kimlik doğrulama uç noktası değerlendirilmedi"
_NOT_ASSESSED_DESCRIPTION = (
    "This surface appears to handle credentials (login, registration, password reset or one-time "
    "codes). Default scans do not submit injection payloads to credential-handling forms or "
    "endpoints, because such submissions are authentication attempts that can lock accounts or "
    "trigger security controls. It was NOT assessed — this is not a SECURE result."
)


def _path(url: str) -> str:
    try:
        return urlsplit(url).path or ""
    except ValueError:
        return ""


def credential_endpoint_reason(url: str) -> str | None:
    """URL yolu kimlik doğrulama / kimlik bilgisi uç noktasına benziyorsa neden, değilse None."""
    if _AUTH_PATH_RE.search(_path(url)):
        return "kimlik doğrulama uç noktası yolu"
    return None


def credential_form_reason(form, action_url: str) -> str | None:
    """BeautifulSoup <form> kimlik bilgisi işliyorsa kısa, sabit neden; değilse None."""
    for inp in form.find_all("input"):
        if (inp.get("type") or "").strip().lower() == "password":
            return "parola alanı"
    for field in form.find_all(["input", "textarea", "select"]):
        autocomplete = (field.get("autocomplete") or "").strip().lower()
        if any(token in _CREDENTIAL_AUTOCOMPLETE for token in autocomplete.split()):
            return "kimlik bilgisi autocomplete alanı"
        for attr in ("name", "id"):
            if _CREDENTIAL_FIELD_RE.search(field.get(attr) or ""):
                return "parola / tek kullanımlık kod alanı"
    if credential_endpoint_reason(action_url):
        return "kimlik doğrulama gönderim hedefi"
    for attr in ("id", "name", "class"):
        value = form.get(attr)
        value = " ".join(value) if isinstance(value, list) else (value or "")
        if _AUTH_FORM_ATTR_RE.search(value):
            return "giriş formu işareti"
    for control in form.find_all(["button", "input"]):
        if control.name == "input" and (control.get("type") or "").lower() not in ("submit", "button"):
            continue
        label = control.get("value") if control.name == "input" else control.get_text(" ", strip=True)
        if _LOGIN_SUBMIT_RE.search(label or ""):
            return "giriş gönderim düğmesi"
    return None


def not_assessed_finding(url: str, reason: str, *, endpoint: bool = False) -> Finding:
    surface = "JSON kimlik doğrulama uç noktası" if endpoint else "kimlik bilgisi işleyen form"
    return Finding(
        severity=Severity.INFO,
        title=NOT_ASSESSED_ENDPOINT_TITLE if endpoint else NOT_ASSESSED_FORM_TITLE,
        evidence=(f"Sonuç: NOT_ASSESSED — {reason} | {surface} varsayılan taramada enjeksiyon "
                  f"payload'ı almaz"),
        confidence=Confidence.HIGH,
        status=FindingStatus.INFORMATIONAL,
        description=_NOT_ASSESSED_DESCRIPTION,
        affected_url=url,
    )
