"""
Aktif kimlik doğrulama gönderimleri için yetki, bütçe ve paylaşılan durdurma sınırı (P0-4.1).

Pasif kimlik doğrulama değerlendirmesi (login keşfi, HTTPS, form gönderim hedefi,
autocomplete, CAPTCHA) her zaman çalışır. Kimlik bilgisi GÖNDEREN testler (rate-limit
yoklaması, başarısız-giriş baseline'ı, varsayılan kimlik bilgileri) varsayılan olarak
KAPALIDIR.

Yetki kaynağı bilinçli olarak dardır:
- Aktif testler yalnızca KODLA oluşturulan bir `ActiveAuthAuthorization` ile açılır.
  HTTP isteği, form alanı, sorgu parametresi, Django ayarı veya ortam değişkeni bunları
  AÇAMAZ. `orchestrator.run_full_scan` ve view'lar AuthScanner'ı yetkisiz oluşturur.
- Yetki tek bir origin'e (şema://host:port) bağlıdır; hedef ve her gönderim hedefi
  (form action) bu origin içinde olmalıdır. Kontrollü lab / test harness'ı içindir —
  SSRF lab politikasıyla aynı ilke: yapılandırma ile açılabilen bir mod YOKTUR.
- Yetki SSRF korumasını gevşetmez; tüm gönderimler yine SafeSession'dan geçer.
- Gönderimin yönlendirmeleri de origin'e bağlıdır: her adım takip edilmeden ÖNCE
  (`SafeSession` `redirect_guard`) doğrulanır; dışarı çıkan yönlendirme takip edilmez,
  değerlendirme BLOCKED olarak durur (307/308 gövdesi dahil hiçbir şey taşınmaz).

Bu modül global bir güvenlik denetleyicisi değildir: `ActiveAuthAssessment` tek bir
AuthScanner.scan() çağrısına (tek değerlendirme) aittir, paylaşılmaz ve kalıcı değildir.
Ağ erişimi yapmaz, bulgu üretmez.
"""
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

from .auth_validation import AttemptClass, AttemptKind, url_origin


class ActiveAuthTest(Enum):
    RATE_LIMIT_PROBE = "RATE_LIMIT_PROBE"          # 5 başarısız giriş gönderimi
    DEFAULT_CREDENTIALS = "DEFAULT_CREDENTIALS"    # baseline + önceden tanımlı liste


class AuthOutcome(Enum):
    """Kanıtta açıkça belirtilen aktif test sonucu."""
    AUTHENTICATED_STATE_ESTABLISHED = "AUTHENTICATED_STATE_ESTABLISHED"
    AUTHENTICATION_NOT_ESTABLISHED = "AUTHENTICATION_NOT_ESTABLISHED"
    CONTROL_RESPONSE_OBSERVED = "CONTROL_RESPONSE_OBSERVED"   # rate limit / kilit kontrolü yanıt verdi
    BLOCKED = "BLOCKED"                                       # WAF / challenge / 403 / 419
    INCOMPLETE = "INCOMPLETE"                                 # sunucu/ağ hatası, akış tamamlanamadı
    NOT_EXECUTED = "NOT_EXECUTED"                             # yetki yok / kapsam dışı / önceki durdurma


# Bu sınıflardan biri görülünce değerlendirmedeki TÜM sonraki aktif gönderimler durur
# (yeniden deneme, kimlik değiştirme, atlatma yok).
STOP_KINDS = frozenset({
    AttemptKind.RATE_LIMITED,      # throttle / şüpheli hesap kilidi
    AttemptKind.BLOCKED,           # challenge / WAF
    AttemptKind.SERVER_ERROR,      # beklenmeyen sunucu hatası
    AttemptKind.NETWORK_FAILURE,   # yanıt yok (zaman aşımı, bağlantı hatası, SSRF engeli)
})


def outcome_for_stop(kind: AttemptKind) -> AuthOutcome:
    if kind == AttemptKind.RATE_LIMITED:
        return AuthOutcome.CONTROL_RESPONSE_OBSERVED
    if kind == AttemptKind.BLOCKED:
        return AuthOutcome.BLOCKED
    return AuthOutcome.INCOMPLETE


def outcome_evidence(outcome: AuthOutcome, detail: str = "") -> str:
    return f"Sonuç: {outcome.value}" + (f" — {detail}" if detail else "")


@dataclass(frozen=True)
class ActiveAuthAuthorization:
    """Kontrollü lab için, kodla verilen aktif kimlik doğrulama yetkisi.

    Her aktif test ayrıca açıkça etkinleştirilmelidir (varsayılan False). Yetki yalnızca
    `origin`'deki hedefi ve o origin'e giden gönderimleri kapsar.
    """
    origin: str
    rate_limit_probe: bool = False
    default_credentials: bool = False

    def __post_init__(self):
        for flag in (self.rate_limit_probe, self.default_credentials):
            if not isinstance(flag, bool):
                raise TypeError("ActiveAuthAuthorization bayrakları bool olmalıdır")
        try:
            parts = urlsplit(self.origin) if isinstance(self.origin, str) else None
        except ValueError:
            parts = None
        if (parts is None or url_origin(self.origin) is None or parts.username or parts.password
                or parts.path not in ("", "/") or parts.query or parts.fragment):
            raise ValueError("ActiveAuthAuthorization.origin yalnızca şema://host[:port] olmalıdır")

    def covers(self, url: str) -> bool:
        origin = url_origin(url)
        return origin is not None and origin == url_origin(self.origin)

    def permits(self, test: ActiveAuthTest) -> bool:
        if test == ActiveAuthTest.RATE_LIMIT_PROBE:
            return self.rate_limit_probe
        if test == ActiveAuthTest.DEFAULT_CREDENTIALS:
            return self.default_credentials
        return False


class SubmissionRefused(Exception):
    """Yetkisiz / durdurulmuş / bütçe dışı gönderim — istek GÖNDERİLMEDİ."""


class OriginBoundaryViolation(Exception):
    """Kimlik doğrulama gönderiminin yönlendirmesi yetkili origin dışına çıkıyor — yönlendirme
    TAKİP EDİLMEDİ (hedefe istek, gövde, cookie veya URL'deki durum gönderilmedi).
    Bilinçli olarak requests.RequestException DEĞİLDİR: genel istek hatası gibi yutulamaz."""

    def __init__(self, status):
        super().__init__(f"HTTP {status} yönlendirmesi yetkili lab origin'i dışına — takip edilmedi")


class ActiveAuthAssessment:
    """Tek bir değerlendirmenin aktif gönderim durumu: yetki, sabit bütçe, paylaşılan durdurma."""

    def __init__(self, authorization: ActiveAuthAuthorization | None, target: str, max_submissions: int):
        self.authorization = authorization
        self.target = target
        self.max_submissions = max_submissions
        self.submissions = 0
        self.stop: AttemptClass | None = None
        self.boundary_violation = False

    @property
    def stopped(self) -> bool:
        return self.stop is not None

    def redirect_guard(self):
        """SafeSession `redirect_guard`'ı: kimlik doğrulama gönderiminin HER yönlendirme adımı
        (301/302/303/307/308) takip edilmeden önce yetkili origin'e karşı doğrulanır."""
        def guard(status, current_url, next_url):
            if self.authorization is None or not self.authorization.covers(next_url):
                raise OriginBoundaryViolation(status)
        return guard

    def record_boundary_violation(self, violation: OriginBoundaryViolation) -> AttemptClass:
        """Origin dışı yönlendirme → BLOCKED durdurma; sonraki tüm gönderimler engellenir."""
        self.boundary_violation = True
        self.record(AttemptClass(AttemptKind.BLOCKED, str(violation)))
        return self.stop

    def refusal(self, test: ActiveAuthTest, url: str) -> str | None:
        """Gönderim yapılamayacaksa nedeni (sabit metin), yapılabilirse None."""
        if self.authorization is None:
            return "aktif kimlik doğrulama gönderimleri varsayılan olarak kapalı (lab yetkisi yok)"
        if not self.authorization.permits(test):
            return "lab yetkisi bu aktif testi kapsamıyor"
        if not self.authorization.covers(self.target) or not self.authorization.covers(url):
            return "hedef veya gönderim adresi yetkili lab origin'i dışında"
        if self.stop is not None:
            return f"değerlendirmede durdurma koşulu oluştu ({self.stop.reason or self.stop.kind.value})"
        if self.submissions >= self.max_submissions:
            return "aktif gönderim bütçesi tükendi"
        return None

    def claim(self, test: ActiveAuthTest, url: str) -> None:
        """Gönderimden HEMEN önce çağrılır (savunma derinliği): reddedilirse istek yapılmaz."""
        reason = self.refusal(test, url)
        if reason is not None:
            raise SubmissionRefused(reason)
        self.submissions += 1

    def record(self, attempt: AttemptClass) -> bool:
        """Gönderim sonucunu işler; durdurma koşuluysa sonraki tüm gönderimler engellenir."""
        if attempt.kind in STOP_KINDS and self.stop is None:
            self.stop = attempt
        return self.stopped
