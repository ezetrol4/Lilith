"""
Ham socket kullanan scanner'lar (ports, ssl_tls, dns_scan) için SSRF korumalı bağlantı.

Politika ssrf_guard.py'dekiyle aynıdır. Host bağlantıdan HEMEN önce çözümlenir, TÜM
adresler doğrulanır ve socket yalnızca az önce doğrulanmış bir IP literal'ine açılır —
connect sırasında hostname ikinci, denetimsiz bir kez çözümlenmez. TLS SNI / sertifika
doğrulaması için orijinal hostname çağıranda kalır.
"""
import socket

from .safe_http import OUTBOUND_BLOCKED_MESSAGE, record_blocked_destination
from .ssrf_guard import HostResolutionError, SSRFError, resolve_and_validate_host, validate_address


class OutboundConnectionBlocked(Exception):
    """SSRF politikası bir ham socket bağlantısını engelledi.

    Bilinçli olarak OSError alt sınıfı DEĞİLDİR: scanner'ların `except OSError` blokları
    engellenen bir hedefi "port kapalı" / "HTTPS yok" gibi yanıltıcı bir sonuca
    çevirmesin. str() sabit, sanitize edilmiş mesajdır; tanı detayı yalnızca `reason`'da.
    """

    def __init__(self, reason: str = ""):
        super().__init__(OUTBOUND_BLOCKED_MESSAGE)
        self.reason = reason


def resolve_public_addresses(host: str) -> list[str]:
    """Host'u çözümler ve doğrulanmış IP'leri döner.

    Çözümlenemeyen host → socket.gaierror (normal bağlantı hatası, engel değil).
    Herhangi bir adres politikayı ihlal ederse → OutboundConnectionBlocked.
    """
    try:
        return resolve_and_validate_host(host)
    except HostResolutionError as e:
        raise socket.gaierror(socket.EAI_NONAME, str(e)) from None
    except SSRFError as e:
        record_blocked_destination(host, str(e))
        raise OutboundConnectionBlocked(str(e)) from None


def check_public_address(address: str) -> str:
    """Önceden çözümlenmiş, güvenilmeyen bir adresi (ör. DNS yanıtındaki NS IP'si) doğrular."""
    try:
        return validate_address(address)
    except SSRFError as e:
        record_blocked_destination(address, str(e))
        raise OutboundConnectionBlocked(str(e)) from None


def connect_validated(host: str, port: int, timeout: float | None = None) -> socket.socket:
    """socket.create_connection((host, port)) yerine: yalnızca doğrulanan IP'lere bağlanır.

    socket.create_connection ile aynı semantik: adresler sırayla denenir, hiçbiri
    bağlanamazsa son hata fırlatılır.
    """
    last_error: OSError | None = None
    for address in resolve_public_addresses(host):
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as e:
            last_error = e
    raise last_error
