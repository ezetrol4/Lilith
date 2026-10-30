import ipaddress
import socket
from urllib.parse import urlparse


# Açıkça listelenen ağlar; ipaddress'in is_global/is_private sınıflandırmasına ek
# olarak tutulur (okunabilirlik + Python sürümleri arası davranış farklarına karşı).
_PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # AWS/GCP metadata + link-local
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),   # Shared address space (CGNAT, RFC 6598)
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

# NAT64 well-known prefix (RFC 6052) — son 32 bit gömülü bir IPv4 adresidir
_NAT64_PREFIX = ipaddress.ip_network('64:ff9b::/96')

_BLOCKED_HOSTS = {'localhost', 'localhost.localdomain', 'metadata.google.internal'}


class SSRFError(ValueError):
    pass


class HostResolutionError(SSRFError):
    """Host çözümlenemedi — politika ihlali değil, DNS hatası. validate_url için hâlâ
    bir SSRFError'dır (API davranışı aynı); giden bağlantı katmanları bunu normal bir
    bağlantı hatası olarak ele alır, 'engellendi' olarak değil."""


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4-mapped, 6to4 ve NAT64 adreslerinin taşıdığı IPv4 adresini döner."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Adres herkese açık (global unicast) değilse True döner."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None and is_blocked_ip(embedded):
            return True
        if ip.is_site_local:
            return True

    if any(ip.version == net.version and ip in net for net in _PRIVATE_NETWORKS):
        return True

    # is_global; loopback, private, link-local, unspecified, reserved, shared (100.64/10)
    # ve dokümantasyon/benchmark aralıklarını kapsar. Multicast is_global=True
    # döndürebildiği için ayrıca kontrol edilir.
    return (
        not ip.is_global
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        # IPv6 zone id (fe80::1%eth0) ipaddress tarafından kabul edilmez
        return ipaddress.ip_address(host.split('%', 1)[0])
    except ValueError:
        return None


def check_url_target(url: str) -> str:
    """DNS çözümlemesi YAPMADAN şema, host ve IP literal kontrolü uygular.

    Her yönlendirme adımında ağa çıkmadan önce kullanılır; hostname'in çözümlenen
    IP'leri ayrıca validate_url / resolve_and_validate_host ile denetlenir.
    Döner: doğrulanmış hostname (küçük harf).
    """
    parsed = urlparse(url)

    if parsed.scheme not in ('http', 'https'):
        raise SSRFError(f"Desteklenmeyen protokol: '{parsed.scheme}'. Sadece http ve https kabul edilir.")

    host = parsed.hostname
    if not host:
        raise SSRFError("Geçersiz URL: host bulunamadı.")

    host = host.lower().rstrip('.')
    if host in _BLOCKED_HOSTS:
        raise SSRFError("İç ağ adreslerine erişim engellendi.")

    literal = _parse_ip_literal(host)
    if literal is not None and is_blocked_ip(literal):
        raise SSRFError(f"Özel/dahili IP adreslerine erişim engellendi ({literal}).")

    return host


def resolve_and_validate_host(host: str) -> list[str]:
    """Host'u çözümler ve döndürülen TÜM adresleri doğrular.

    Tek bir engelli adres bile bulunursa (karışık public/private kayıtlar dahil)
    host tamamen reddedilir. Döner: bağlanılabilecek doğrulanmış IP'ler (sıralı).
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise HostResolutionError(f"Host çözümlenemedi: {e}") from e

    addresses: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip = _parse_ip_literal(sockaddr[0])
        if ip is None:
            raise SSRFError("Geçersiz adres yanıtı reddedildi.")
        if is_blocked_ip(ip):
            raise SSRFError(f"Özel/dahili IP adreslerine erişim engellendi ({ip}).")
        if str(ip) not in addresses:
            addresses.append(str(ip))

    if not addresses:
        raise HostResolutionError("Host çözümlenemedi: adres bulunamadı.")
    return addresses


def validate_address(address: str) -> str:
    """Önceden çözümlenmiş bir adresi (ör. DNS yanıtından gelen NS IP'si) doğrular."""
    ip = _parse_ip_literal(address)
    if ip is None:
        raise SSRFError("Geçersiz adres reddedildi.")
    if is_blocked_ip(ip):
        raise SSRFError(f"Özel/dahili IP adreslerine erişim engellendi ({ip}).")
    return str(ip)


def validate_url(url: str) -> str:
    """
    Validates that the URL is safe to fetch from the server side.
    Raises SSRFError if the URL targets a private/internal/metadata address.
    Returns the URL unchanged if valid.

    Hostname'in çözümlendiği TÜM adresler (A + AAAA) kontrol edilir. Bu fonksiyon
    yalnızca çağrıldığı andaki DNS durumunu doğrular — tarama sırasındaki her giden
    istek ayrıca services/safe_http.py tarafından yeniden doğrulanır.
    """
    host = check_url_target(url)
    if _parse_ip_literal(host) is None:
        resolve_and_validate_host(host)
    return url
