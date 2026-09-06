import ssl
import socket
import time
from urllib.parse import urlparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus


_OWASP_CRYPTO = "A02:2021 - Cryptographic Failures"
_CWE_CLEARTEXT = "CWE-319"                  # Cleartext Transmission of Sensitive Information
_CWE_WEAK_CRYPTO_ALGO = "CWE-327"           # Use of a Broken or Risky Cryptographic Algorithm
_CWE_INADEQUATE_KEY_STRENGTH = "CWE-326"    # Inadequate Encryption Strength
_CWE_CERT_VALIDATION = "CWE-295"            # Improper Certificate Validation

# Protokol adi -> zayifligina gore severity. Listede olmayan protokoller (TLS 1.2/1.3) guncel kabul edilir.
_PROTOCOL_SEVERITY: dict[str, Severity] = {
    "SSLv2":   Severity.HIGH,
    "SSLv3":   Severity.HIGH,
    "TLSv1":   Severity.MEDIUM,
    "TLSv1.1": Severity.MEDIUM,
}
_WEAK_CIPHERS = frozenset({"RC4", "MD5", "DES", "3DES", "NULL", "EXPORT", "ANON", "ADH", "AECDH"})

_CERT_EXPIRY_WARNING_DAYS = 30


class SslScanner(Scanner):
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner="ssl", target=target)
        parsed = urlparse(target)
        host   = parsed.hostname or target.split("//")[-1].split("/")[0]
        port   = parsed.port or 443

        # HTTP hedefinde 443'ü dene
        if parsed.scheme == "http":
            try:
                socket.create_connection((host, 443), timeout=self.timeout).close()
                result.findings.append(Finding(
                    severity=Severity.LOW,
                    title="HTTPS mevcut ama kullanılmıyor",
                    evidence="Port 443 açık — tarama için https:// kullanın",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="An HTTPS listener is reachable on port 443, but the scanned URL uses "
                                "plain HTTP, so this session was not evaluated over an encrypted channel.",
                    affected_url=target,
                    owasp=_OWASP_CRYPTO,
                    recommendation="Serve the site over HTTPS by default and redirect HTTP requests to HTTPS.",
                ))
            except (socket.timeout, ConnectionRefusedError, OSError):
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="HTTPS desteklenmiyor",
                    evidence="Port 443 kapalı — tüm trafik şifresiz HTTP üzerinden akıyor",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="Port 443 is not reachable, so this host does not appear to offer an "
                                "HTTPS endpoint at all; all traffic to it travels unencrypted.",
                    affected_url=target,
                    owasp=_OWASP_CRYPTO,
                    cwe=_CWE_CLEARTEXT,
                    recommendation="Deploy and enforce HTTPS for this host.",
                ))
            result.error = "SSL ayrıntıları için https:// ile tarayın"
            return result

        # --- Aşama 1: Protokol + cipher (doğrulama olmadan bağlan) ---
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
                    protocol          = ssl_sock.version() or "Bilinmiyor"
                    cipher_name, _, cipher_bits = ssl_sock.cipher()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result.error = f"SSL bağlantısı başarısız: {e}"
            return result
        except ssl.SSLError as e:
            result.error = f"SSL hatası: {e}"
            return result

        # Protokol bulgusu
        weak_protocol_severity = _PROTOCOL_SEVERITY.get(protocol)
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="TLS Protokolü",
            evidence=protocol,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL if weak_protocol_severity else FindingStatus.SECURE,
            affected_url=target,
        ))
        if weak_protocol_severity:
            result.findings.append(Finding(
                severity=weak_protocol_severity,
                title=f"Zayıf protokol — {protocol}",
                evidence="TLS 1.0/1.1 ve SSLv2/v3 güvensiz kabul edilir — POODLE/BEAST gibi saldırılara "
                         "açık olabilir. TLS 1.2+ kullanın",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description=f"The server negotiated {protocol}, a deprecated TLS/SSL version with known "
                            "cryptographic weaknesses.",
                affected_url=target,
                owasp=_OWASP_CRYPTO,
                cwe=_CWE_WEAK_CRYPTO_ALGO,
                recommendation="Disable SSLv2/SSLv3/TLS 1.0/1.1 on the server and require TLS 1.2 or newer.",
            ))

        # Cipher bulgusu
        is_weak_key = bool(cipher_bits and cipher_bits < 128)
        weak_cipher_match = next((w for w in _WEAK_CIPHERS if w in cipher_name.upper()), None)
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Cipher Suite",
            evidence=f"{cipher_name} ({cipher_bits} bit)",
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL if (is_weak_key or weak_cipher_match) else FindingStatus.SECURE,
            affected_url=target,
        ))
        if is_weak_key:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Yetersiz anahtar uzunluğu",
                evidence=f"{cipher_bits} bit — en az 128 bit gerekli",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The negotiated cipher uses fewer than 128 bits of key strength, which is "
                            "considered insufficient by current standards.",
                affected_url=target,
                owasp=_OWASP_CRYPTO,
                cwe=_CWE_INADEQUATE_KEY_STRENGTH,
                recommendation="Disable ciphers with key lengths under 128 bits on the server.",
            ))
        if weak_cipher_match:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Zayıf cipher: {cipher_name}",
                evidence=f"{weak_cipher_match} içeren cipher suite kırılmış/güvensiz olarak kabul ediliyor",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description=f"The negotiated cipher suite includes {weak_cipher_match}, which is "
                            "considered broken or unsafe for modern use.",
                affected_url=target,
                owasp=_OWASP_CRYPTO,
                cwe=_CWE_WEAK_CRYPTO_ALGO,
                recommendation="Remove weak ciphers (RC4/MD5/DES/3DES/NULL/export/anonymous) from the "
                               "server's TLS configuration.",
            ))

        # --- Aşama 2: Sertifika doğrulama + ayrıntılar ---
        try:
            ctx2 = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                with ctx2.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
                    cert = ssl_sock.getpeercert()
            self._analyze_cert(cert, result)
        except ssl.SSLCertVerificationError as e:
            reason_text = str(getattr(e, "verify_message", None) or getattr(e, "reason", None) or e)
            is_hostname_mismatch = "hostname mismatch" in reason_text.lower() or "doesn't match" in reason_text.lower()
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Sertifika hostname uyuşmazlığı" if is_hostname_mismatch else "Sertifika doğrulanamadı",
                evidence=reason_text,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description=(
                    "The certificate's subject/SAN does not match the hostname being scanned."
                    if is_hostname_mismatch else
                    "The certificate chain could not be verified as trusted by a standard CA store."
                ),
                affected_url=target,
                owasp=_OWASP_CRYPTO,
                cwe=_CWE_CERT_VALIDATION,
                recommendation="Issue/renew a certificate that matches the scanned hostname and is signed "
                               "by a trusted CA.",
            ))
        except Exception:
            pass  # Aşama 1 başarılıysa sertifika analizi bonus; hata kritik değil

        return result

    def _analyze_cert(self, cert: dict, result: ScanResult) -> None:
        target = result.target

        # Geçerlilik süresi
        not_after = cert.get("notAfter", "")
        if not_after:
            expire_ts = ssl.cert_time_to_seconds(not_after)
            days_left = int((expire_ts - time.time()) / 86400)
            if days_left < 0:
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Sertifika süresi dolmuş",
                    evidence=f"{abs(days_left)} gün önce sona erdi ({not_after})",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="The TLS certificate's validity period has already ended, so clients may "
                                "reject the connection or display security warnings.",
                    affected_url=target,
                    owasp=_OWASP_CRYPTO,
                    recommendation="Renew the certificate immediately.",
                ))
            elif days_left < _CERT_EXPIRY_WARNING_DAYS:
                result.findings.append(Finding(
                    severity=Severity.LOW,
                    title="Sertifika yakında sona eriyor",
                    evidence=f"{days_left} gün kaldı ({not_after})",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description=f"The TLS certificate will expire within {_CERT_EXPIRY_WARNING_DAYS} days.",
                    affected_url=target,
                    recommendation="Renew the certificate before it expires to avoid an unplanned outage "
                                   "or browser warning.",
                ))
            else:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title="Sertifika geçerlilik süresi",
                    evidence=f"{days_left} gün kaldı ({not_after})",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.SECURE,
                    affected_url=target,
                ))

        # Self-signed kontrolü
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        if subject == issuer:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Self-signed sertifika",
                evidence="Sertifika bir CA tarafından imzalanmamış — tarayıcılar güvenlik uyarısı gösterir",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="The certificate's subject and issuer are identical, indicating it was not "
                            "signed by a recognized certificate authority.",
                affected_url=target,
                owasp=_OWASP_CRYPTO,
                cwe=_CWE_CERT_VALIDATION,
                recommendation="Replace the self-signed certificate with one issued by a trusted CA "
                               "(e.g. via Let's Encrypt or an organizational CA).",
            ))
        else:
            ca_name = issuer.get("organizationName") or issuer.get("commonName", "Bilinmiyor")
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Sertifika Yetkilisi (CA)",
                evidence=ca_name,
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=target,
            ))

        # CN
        cn = subject.get("commonName", "")
        if cn:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Sertifika CN",
                evidence=cn,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=target,
            ))

        # SAN'lar
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if sans:
            preview = ", ".join(sans[:5])
            if len(sans) > 5:
                preview += f" (+{len(sans) - 5} daha)"
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Subject Alternative Names",
                evidence=preview,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=target,
            ))
