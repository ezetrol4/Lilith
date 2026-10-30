import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from ..services.safe_http import OUTBOUND_BLOCKED_MESSAGE
from ..services.safe_socket import OutboundConnectionBlocked, connect_validated


_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_OWASP_CRYPTO = "A02:2021 - Cryptographic Failures"
_CWE_CLEARTEXT = "CWE-319"                # Cleartext Transmission of Sensitive Information
_CWE_MISSING_AUTH = "CWE-306"             # Missing Authentication for Critical Function

_PORT_INFO: dict[int, tuple[str, Severity, str]] = {
    21:    ("FTP",        Severity.MEDIUM,   "Sifrelenmemis dosya transferi — kimlik bilgileri aga acik gider"),
    22:    ("SSH",        Severity.INFO,     "Guvenli uzak erisim"),
    23:    ("Telnet",     Severity.HIGH,     "Sifrelenmemis uzak erisim — kimlik bilgileri dinlenebilir"),
    25:    ("SMTP",       Severity.LOW,      "E-posta gonderme sunucusu"),
    53:    ("DNS",        Severity.INFO,     "Alan adi cozumleme"),
    80:    ("HTTP",       Severity.INFO,     "Sifrelenmemis web sunucusu"),
    110:   ("POP3",       Severity.LOW,      "E-posta alma protokolu"),
    143:   ("IMAP",       Severity.LOW,      "E-posta erisim protokolu"),
    443:   ("HTTPS",      Severity.INFO,     "Guvenli web sunucusu"),
    445:   ("SMB",        Severity.HIGH,     "Windows dosya paylasimi — internete acikken WannaCry/EternalBlue gibi kitlesel istismarlarin hedefi olmustur"),
    1433:  ("MSSQL",      Severity.LOW,      "Microsoft SQL Server — veritabani portu dis erisime acik, kimlik dogrulama durumu dogrulanmadi"),
    3306:  ("MySQL",      Severity.LOW,      "MySQL veritabani — port dis erisime acik, kimlik dogrulama durumu dogrulanmadi"),
    3389:  ("RDP",        Severity.HIGH,     "Uzak masaustu — brute-force ve BlueKeep gibi kitlesel istismarlarin hedefi olmustur"),
    5432:  ("PostgreSQL", Severity.LOW,      "PostgreSQL veritabani — port dis erisime acik, kimlik dogrulama durumu dogrulanmadi"),
    5900:  ("VNC",        Severity.HIGH,     "Ekran paylasimi — genellikle zayif kimlik dogrulama"),
    6379:  ("Redis",      Severity.LOW,      "Redis — port dis erisime acik, kimlik dogrulama durumu banner ile dogrulanamadiysa varsayilamaz"),
    8080:  ("HTTP-Alt",   Severity.LOW,      "Alternatif HTTP — admin panel veya test ortami olabilir"),
    8443:  ("HTTPS-Alt",  Severity.LOW,      "Alternatif HTTPS"),
    27017: ("MongoDB",    Severity.LOW,      "MongoDB — port dis erisime acik, kimlik dogrulama durumu dogrulanmadi"),
}

_SCAN_PORTS  = sorted(_PORT_INFO.keys())
_HTTP_PORTS  = frozenset({80, 8080})
_HTTPS_PORTS = frozenset({443, 8443})

# Protokolun kendisi sifreli degildir — acikken her zaman anlamli bir bulgu
_CLEARTEXT_PROTOCOL_PORTS = frozenset({21, 23})
# Riski gercek yapilandirmaya (yama seviyesi, kimlik dogrulama) bagli servisler — kanit olmadan manuel inceleme
_CONFIG_DEPENDENT_PORTS = frozenset({445, 1433, 3306, 3389, 5432, 5900, 6379, 27017})


def _clean_banner(raw: bytes, port: int) -> str:
    text = raw.decode("utf-8", errors="replace")
    if port in _HTTP_PORTS | _HTTPS_PORTS:
        for line in text.split("\r\n"):
            if line.lower().startswith("server:"):
                return line.strip()[:120]
        first = text.split("\r\n")[0].strip()
        return first[:120] if first.startswith("HTTP") else ""
    first = text.split("\n")[0].strip()
    return " ".join(first.split())[:120]


class PortScanner(Scanner):
    def __init__(self, timeout: float = 3.0, max_workers: int = len(_SCAN_PORTS)):
        self.timeout = timeout
        self.max_workers = max_workers

    # --- Banner yardımcıları ---

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(1.5)
            if port in _HTTP_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 6379:
                sock.sendall(b"PING\r\n")
            raw = sock.recv(512)
            return _clean_banner(raw, port) if raw else ""
        except (socket.timeout, OSError):
            return ""

    def _grab_https_banner(self, host: str, sock: socket.socket, port: int) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host) as ssl_sock:
                ssl_sock.settimeout(1.5)
                ssl_sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                raw = ssl_sock.recv(512)
                return _clean_banner(raw, port) if raw else ""
        except Exception:
            # Kasıtlı geniş sınır: rastgele bir porta TLS handshake denemesi ssl.SSLError,
            # socket.timeout, ConnectionResetError, OSError gibi birçok farklı istisna
            # tipi üretebilir — banner alma en iyi çaba (best-effort), başarısızlık
            # sadece boş banner anlamına gelir, taramayı durdurmamalı.
            return ""

    # --- Tek port tarama ---

    def _probe(self, host: str, port: int) -> tuple[int, bool, str]:
        # OutboundConnectionBlocked bilinçli olarak yakalanmaz — engellenen hedef
        # "port kapalı" olarak raporlanmamalı (bkz. scan()).
        try:
            with connect_validated(host, port, timeout=self.timeout) as sock:
                if port in _HTTPS_PORTS:
                    banner = self._grab_https_banner(host, sock, port)
                else:
                    banner = self._grab_banner(sock, port)
                return port, True, banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            return port, False, ""

    # --- Ana tarama ---

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner="ports", target=target)
        parsed = urlparse(target)
        host = parsed.hostname or target.split("//")[-1].split("/")[0]

        try:
            socket.gethostbyname(host)
        except socket.gaierror as e:
            result.error = f"Host cozumlenemedi: {e}"
            return result

        try:
            resolved_name = socket.gethostbyaddr(host)[0]
        except socket.herror:
            resolved_name = host

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="host_name",
            evidence=resolved_name,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=target,
        ))

        open_results:   dict[int, bool] = {}
        banner_results: dict[int, str]  = {}
        blocked = False

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._probe, host, port): port for port in _SCAN_PORTS}
            for future in as_completed(futures):
                try:
                    port, is_open, banner = future.result()
                except OutboundConnectionBlocked:
                    blocked = True
                    continue
                open_results[port]   = is_open
                banner_results[port] = banner

        if blocked:
            # Host tarama sırasında engelli bir adrese çözümlendi (ör. DNS rebinding) —
            # port sonuçları güvenilir değildir ve iç ağa ait olabilir; raporlanmaz.
            result.error = OUTBOUND_BLOCKED_MESSAGE
            return result

        for port in _SCAN_PORTS:
            service, open_severity, description = _PORT_INFO[port]
            is_open = open_results[port]
            banner  = banner_results.get(port, "")

            if is_open:
                evidence = f"ACIK | {description}"
                if banner:
                    evidence += f" | {banner}"
                result.findings.append(self._build_open_finding(target, port, service, open_severity, evidence, banner))
            else:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"{port}/{service}",
                    evidence="KAPALI",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.INFORMATIONAL,
                    affected_url=target,
                ))

        return result

    def _build_open_finding(self, target: str, port: int, service: str, open_severity: Severity,
                             evidence: str, banner: str) -> Finding:
        title = f"{port}/{service}"

        if port == 6379 and banner.upper().startswith("+PONG"):
            # Redis kimlik dogrulama istemeden PING'e yanit verdi — auth eksikligi dogrudan kanitlandi
            return Finding(
                severity=Severity.CRITICAL,
                title=title,
                evidence=evidence,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="Redis responded to an unauthenticated PING with +PONG, confirming that no "
                            "authentication is required to interact with this instance.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                cwe=_CWE_MISSING_AUTH,
                recommendation="Require authentication (requirepass/ACL) and bind Redis to trusted "
                               "networks only — do not expose it directly to the internet.",
            )

        if port in _CLEARTEXT_PROTOCOL_PORTS:
            return Finding(
                severity=open_severity,
                title=title,
                evidence=evidence,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description=f"{service} transmits traffic, including credentials, without transport "
                            "encryption by design.",
                affected_url=target,
                owasp=_OWASP_CRYPTO,
                cwe=_CWE_CLEARTEXT,
                recommendation=f"Disable {service} and use an encrypted equivalent (e.g. SSH/SFTP) for "
                               "the same function.",
            )

        if port in _CONFIG_DEPENDENT_PORTS:
            return Finding(
                severity=open_severity,
                title=title,
                evidence=evidence,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.MANUAL_REVIEW,
                description=f"{service} is reachable from the network. An open port alone does not "
                            "confirm a vulnerability — actual risk depends on authentication, patch "
                            "level, and access-control configuration that this scan did not verify.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                recommendation=f"Restrict {service} to trusted networks/VPN, verify authentication is "
                               "enforced, and confirm the service is patched, unless public exposure is "
                               "an intentional requirement.",
            )

        # Genel/bilgi amaçlı servisler (SSH, HTTP(S), DNS, SMTP, POP3, IMAP, HTTP-Alt, HTTPS-Alt)
        return Finding(
            severity=open_severity,
            title=title,
            evidence=evidence,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=target,
        )
