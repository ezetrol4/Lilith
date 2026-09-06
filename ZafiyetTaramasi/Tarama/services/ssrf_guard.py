import ipaddress
import socket
from urllib.parse import urlparse


_PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # AWS/GCP metadata + link-local
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

_BLOCKED_HOSTS = {'localhost', 'localhost.localdomain', 'metadata.google.internal'}


class SSRFError(ValueError):
    pass


def validate_url(url: str) -> str:
    """
    Validates that the URL is safe to fetch from the server side.
    Raises SSRFError if the URL targets a private/internal/metadata address.
    Returns the URL unchanged if valid.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ('http', 'https'):
        raise SSRFError(f"Desteklenmeyen protokol: '{parsed.scheme}'. Sadece http ve https kabul edilir.")

    host = parsed.hostname
    if not host:
        raise SSRFError("Geçersiz URL: host bulunamadı.")

    if host.lower() in _BLOCKED_HOSTS:
        raise SSRFError("İç ağ adreslerine erişim engellendi.")

    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except socket.gaierror as e:
        raise SSRFError(f"Host çözümlenemedi: {e}")

    for network in _PRIVATE_NETWORKS:
        try:
            if ip in network:
                raise SSRFError(f"Özel/dahili IP adreslerine erişim engellendi ({ip}).")
        except TypeError:
            continue

    return url
