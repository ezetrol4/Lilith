import socket
from urllib.parse import urlparse

import dns.resolver
import dns.query
import dns.zone
import dns.exception
import dns.rdatatype
import dns.name

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from ..services.safe_socket import OutboundConnectionBlocked, check_public_address


_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_CWE_INFO_EXPOSURE = "CWE-200"  # Exposure of Sensitive Information to an Unauthorized Actor

_DKIM_SELECTORS = ["default", "google", "mail", "k1", "selector1", "selector2", "dkim"]


class DnsScanner(Scanner):
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout

    def _query(self, name: str, rdtype: str) -> list[str]:
        try:
            answers = self._resolver.resolve(name, rdtype)
            return [r.to_text() for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.exception.DNSException):
            return []

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner="dns", target=target)
        parsed = urlparse(target)
        domain = parsed.hostname or target.split("//")[-1].split("/")[0]

        self._check_a_records(domain, result)
        self._check_ns_records(domain, result)
        self._check_mx_records(domain, result)
        self._check_spf(domain, result)
        self._check_dmarc(domain, result)
        self._check_dkim(domain, result)
        self._check_zone_transfer(domain, result)

        return result

    # --- A / AAAA ---

    def _check_a_records(self, domain: str, result: ScanResult) -> None:
        a_records = self._query(domain, "A")
        if a_records:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="A Kaydı (IPv4)",
                evidence=", ".join(a_records),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=domain,
            ))
        aaaa = self._query(domain, "AAAA")
        if aaaa:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="AAAA Kaydı (IPv6)",
                evidence=", ".join(aaaa),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=domain,
            ))
        if not a_records and not aaaa:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Alan adı çözümlenemedi",
                evidence=f"{domain} için A/AAAA kaydı bulunamadı",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description="No A or AAAA record was found for this domain. This is an availability/"
                            "configuration observation, not a security condition on its own.",
                affected_url=domain,
            ))

    # --- NS ---

    def _check_ns_records(self, domain: str, result: ScanResult) -> None:
        ns = self._query(domain, "NS")
        if ns:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="NS (İsim Sunucuları)",
                evidence=", ".join(ns),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=domain,
            ))

    # --- MX ---

    def _check_mx_records(self, domain: str, result: ScanResult) -> None:
        mx = self._query(domain, "MX")
        if mx:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="MX (Posta Sunucuları)",
                evidence=", ".join(mx),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=domain,
            ))
        else:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="MX kaydı yok",
                evidence="Alan adına ait posta sunucusu tanımlanmamış",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=domain,
            ))

    # --- SPF ---

    def _check_spf(self, domain: str, result: ScanResult) -> None:
        txt_records = self._query(domain, "TXT")
        spf = next((r for r in txt_records if "v=spf1" in r.lower()), None)

        if not spf:
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="SPF kaydı eksik",
                evidence="Gelen kutusu kimlik doğrulaması yok — e-posta sahteciliğine açık",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="No SPF (v=spf1) TXT record was found for this domain, so receiving mail "
                            "servers have no way to verify which hosts are authorized to send mail on "
                            "its behalf.",
                affected_url=domain,
                owasp=_OWASP_MISCONFIG,
                recommendation="Publish an SPF TXT record listing authorized sending hosts, ending in "
                               "-all (or ~all while validating sources).",
            ))
            return

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="SPF Kaydı",
            evidence=spf,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=domain,
        ))

        spf_lower = spf.lower()
        if "+all" in spf_lower:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="SPF '+all' — Herkese izin veriliyor",
                evidence="Herhangi bir sunucu bu alan adı adına e-posta gönderebilir",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="This SPF record ends in +all, which explicitly authorizes any host on the "
                            "internet to send mail as this domain.",
                affected_url=domain,
                owasp=_OWASP_MISCONFIG,
                recommendation="Replace +all with -all (or at minimum ~all) to prevent arbitrary senders "
                               "from spoofing this domain.",
            ))
        elif "?all" in spf_lower:
            result.findings.append(Finding(
                severity=Severity.LOW,
                title="SPF '?all' — Nötr politika",
                evidence="Doğrulanamayan gönderenler için net bir karar yok",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="This SPF record ends in ?all (neutral), so receiving servers make no "
                            "determination about unauthorized senders based on SPF alone.",
                affected_url=domain,
                owasp=_OWASP_MISCONFIG,
                recommendation="Move to ~all or -all once legitimate sending sources are fully identified.",
            ))
        elif "~all" in spf_lower:
            result.findings.append(Finding(
                severity=Severity.LOW,
                title="SPF '~all' — Softfail",
                evidence="Yetkisiz gönderenler reddedilmek yerine işaretlenir — '-all' daha güçlü",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="This SPF record ends in ~all (SoftFail), so unauthorized senders are marked "
                            "as suspicious rather than rejected outright.",
                affected_url=domain,
                owasp=_OWASP_MISCONFIG,
                recommendation="Consider migrating to -all once all legitimate sending sources are "
                               "confirmed, for a stronger fail policy.",
            ))
        elif "-all" in spf_lower:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="SPF '-all' — Strict Fail",
                evidence="Yetkisiz gönderenler reddedilir",
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=domain,
            ))

    # --- DMARC ---

    def _check_dmarc(self, domain: str, result: ScanResult) -> None:
        records = self._query(f"_dmarc.{domain}", "TXT")
        dmarc = next((r for r in records if "v=dmarc1" in r.lower()), None)

        if not dmarc:
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="DMARC kaydı eksik",
                evidence="E-posta kimlik doğrulama politikası tanımlanmamış",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="No DMARC (v=DMARC1) TXT record was found at _dmarc." + domain + ", so there "
                            "is no policy telling receiving servers how to handle mail that fails "
                            "SPF/DKIM checks.",
                affected_url=domain,
                owasp=_OWASP_MISCONFIG,
                recommendation="Publish a DMARC record (starting with p=none for monitoring) and "
                               "gradually move to p=quarantine or p=reject.",
            ))
            return

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="DMARC Kaydı",
            evidence=dmarc,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            affected_url=domain,
        ))

        dmarc_lower = dmarc.lower()
        if "p=none" in dmarc_lower:
            result.findings.append(Finding(
                severity=Severity.LOW,
                title="DMARC politikası: none (izleme modu)",
                evidence="Sahte e-postalar engellenmez, yalnızca raporlanır — 'p=quarantine' veya "
                         "'p=reject' kullanın",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="DMARC is configured in monitoring-only mode (p=none). This is not the same "
                            "as having no DMARC record — reports are collected but spoofed mail is not "
                            "yet blocked.",
                affected_url=domain,
                owasp=_OWASP_MISCONFIG,
                recommendation="Monitor authentication results before moving toward quarantine/reject, "
                               "according to the organization's mail architecture.",
            ))
        elif "p=quarantine" in dmarc_lower:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="DMARC politikası: quarantine",
                evidence="Şüpheli e-postalar karantinaya alınır",
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=domain,
            ))
        elif "p=reject" in dmarc_lower:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="DMARC politikası: reject (en güçlü)",
                evidence="Sahte e-postalar reddedilir",
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=domain,
            ))

    # --- DKIM ---

    def _check_dkim(self, domain: str, result: ScanResult) -> None:
        found_selectors = []
        for selector in _DKIM_SELECTORS:
            records = self._query(f"{selector}._domainkey.{domain}", "TXT")
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
                found_selectors.append(selector)

        if found_selectors:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="DKIM Kaydı",
                evidence=f"Bulunan selector'lar: {', '.join(found_selectors)}",
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=domain,
            ))
        else:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Yaygın DKIM selector'ları tespit edilemedi",
                evidence=f"Test edilen selector'lar: {', '.join(_DKIM_SELECTORS)}",
                confidence=Confidence.LOW,
                status=FindingStatus.INFORMATIONAL,
                description="DKIM configuration could not be confirmed using the tested common selectors. "
                            "This does not conclusively indicate that DKIM is not configured — the domain "
                            "may use a custom selector name that was not tested.",
                affected_url=domain,
                recommendation="Verify the domain's actual DKIM selector with the mail provider and check "
                               "the corresponding TXT record directly.",
            ))

    # --- Zone Transfer ---

    def _check_zone_transfer(self, domain: str, result: ScanResult) -> None:
        ns_records = self._query(domain, "NS")
        if not ns_records:
            return

        tested = False
        for ns_raw in ns_records[:3]:  # İlk 3 NS'i dene
            ns_host = ns_raw.rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                # NS adresi hedefin DNS yanıtından gelir — güvenilmez girdidir. AXFR
                # yalnızca doğrulanmış IP literal'ine yapılır (yeniden çözümleme yok).
                ns_ip = check_public_address(ns_ip)
            except OutboundConnectionBlocked:
                continue
            except Exception:
                # Çözümleme hatası mevcut davranışla aynı şekilde "denendi" sayılır
                tested = True
                continue

            tested = True
            try:
                zone  = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=3))
                if zone:
                    names = [str(n) for n in zone.nodes.keys()][:10]
                    result.findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Zone Transfer izin veriliyor (AXFR)",
                        evidence=f"NS: {ns_host} — Bulunan kayıtlar: {', '.join(names)}",
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED,
                        description=f"Name server {ns_host} allowed a full AXFR zone transfer, exposing "
                                    "the domain's internal DNS record layout to anyone who asks.",
                        affected_url=domain,
                        owasp=_OWASP_MISCONFIG,
                        cwe=_CWE_INFO_EXPOSURE,
                        recommendation="Restrict AXFR zone transfers to authorized secondary name servers only.",
                    ))
                    return
            except Exception:
                # Kasıtlı geniş sınır: dnspython AXFR denemesi ConnectionError,
                # dns.exception.FormError, EOFError, dns.query.TransferError gibi birçok
                # farklı istisna tipi üretebilir — herhangi biri sadece "bu nameserver
                # AXFR'ı reddetti/desteklemiyor" anlamına gelir, sıradaki NS'e geçilir.
                continue

        if not tested:
            # Tüm NS adresleri SSRF politikasınca reddedildi — hiçbir AXFR denenmedi,
            # bu yüzden "engellendi / doğru yapılandırma" iddiasında bulunulmaz.
            return

        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Zone Transfer engellendi",
            evidence="AXFR isteği reddedildi — doğru yapılandırma",
            confidence=Confidence.HIGH,
            status=FindingStatus.SECURE,
            affected_url=domain,
        ))
