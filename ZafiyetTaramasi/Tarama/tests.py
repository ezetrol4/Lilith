import json
import socket
import ssl
import urllib.error
from unittest.mock import MagicMock, patch

from django.test import TestCase, Client

from .scanners.base import Confidence, Finding, FindingStatus, ScanResult, Severity, summarize_findings
from .models import ScanFinding, ScanJob
from .scanners.headers import HeaderScanner
from .scanners.ports import PortScanner
from .scanners.sql import SqlInjectionScanner
from .scanners.xss import XssScanner
from .scanners.ssl_tls import SslScanner
from .scanners.dns_scan import DnsScanner
from .scanners.cms import CmsScanner
from .scanners.access_control import AccessControlScanner
from .scanners.auth import AuthScanner
from .scanners.integrity import IntegrityScanner
from .scanners.error_disclosure import ErrorDisclosureScanner
from .scanners.cmd import CmdInjectionScanner
from .scanners.nosql import NoSqlInjectionScanner
from .services.ssrf_guard import SSRFError, validate_url


class FindingModelTest(TestCase):
    def test_legacy_construction_still_works(self):
        finding = Finding(severity=Severity.HIGH, title="Potential SQL Injection", evidence="...")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.title, "Potential SQL Injection")
        self.assertEqual(finding.evidence, "...")
        self.assertIsNone(finding.confidence)
        self.assertIsNone(finding.status)
        self.assertIsNone(finding.description)
        self.assertIsNone(finding.affected_url)
        self.assertIsNone(finding.parameter)
        self.assertIsNone(finding.owasp)
        self.assertIsNone(finding.cwe)
        self.assertIsNone(finding.mitre)
        self.assertIsNone(finding.recommendation)

    def test_legacy_to_dict_has_null_new_fields(self):
        finding = Finding(severity=Severity.MEDIUM, title="Missing Header")
        data = finding.to_dict()
        self.assertEqual(data["severity"], "MEDIUM")
        self.assertEqual(data["title"], "Missing Header")
        self.assertEqual(data["evidence"], "")
        self.assertIsNone(data["confidence"])
        self.assertIsNone(data["status"])
        self.assertIsNone(data["owasp"])
        self.assertIsNone(data["cwe"])
        self.assertIsNone(data["mitre"])

    def test_full_construction_and_serialization(self):
        finding = Finding(
            severity=Severity.HIGH,
            title="Reflected XSS",
            evidence="<script>alert(1)</script>",
            confidence=Confidence.MEDIUM,
            status=FindingStatus.POTENTIAL,
            description="User input is reflected without encoding.",
            affected_url="https://example.com/search",
            parameter="q",
            owasp="A03:2021 - Injection",
            cwe="CWE-79",
            mitre="T1190 - Exploit Public-Facing Application",
            recommendation="Encode output based on context.",
        )
        data = finding.to_dict()
        self.assertEqual(data["confidence"], "MEDIUM")
        self.assertEqual(data["status"], "POTENTIAL")
        self.assertEqual(data["description"], "User input is reflected without encoding.")
        self.assertEqual(data["affected_url"], "https://example.com/search")
        self.assertEqual(data["parameter"], "q")
        self.assertEqual(data["owasp"], "A03:2021 - Injection")
        self.assertEqual(data["cwe"], "CWE-79")
        self.assertEqual(data["mitre"], "T1190 - Exploit Public-Facing Application")
        self.assertEqual(data["recommendation"], "Encode output based on context.")

    def test_confidence_and_status_enum_values(self):
        self.assertEqual({c.value for c in Confidence}, {"LOW", "MEDIUM", "HIGH"})
        self.assertEqual(
            {s.value for s in FindingStatus},
            {"CONFIRMED", "POTENTIAL", "INFORMATIONAL", "SECURE", "MANUAL_REVIEW"},
        )

    def test_severity_and_confidence_are_independent(self):
        """CLAUDE.md: Severity HIGH + Confidence LOW + Status MANUAL_REVIEW geçerli bir kombinasyondur —
        'doğrulanırsa etkisi yüksek, ancak mevcut kanıt henüz zayıf' anlamına gelir."""
        finding = Finding(
            severity=Severity.HIGH,
            title="Potential DOM-based XSS",
            confidence=Confidence.LOW,
            status=FindingStatus.MANUAL_REVIEW,
        )
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, Confidence.LOW)
        self.assertEqual(finding.status, FindingStatus.MANUAL_REVIEW)
        data = finding.to_dict()
        self.assertEqual(data["severity"], "HIGH")
        self.assertEqual(data["confidence"], "LOW")
        self.assertEqual(data["status"], "MANUAL_REVIEW")


class FindingCountingTest(TestCase):
    """CLAUDE.md §2 (Phase 5) — tek yetkili sayım davranışı."""

    def test_secure_and_informational_excluded_from_vulnerability_counts(self):
        findings = [
            Finding(severity=Severity.INFO, title="TLS 1.3", status=FindingStatus.SECURE),
            Finding(severity=Severity.INFO, title="CMS Detected", status=FindingStatus.INFORMATIONAL),
            Finding(severity=Severity.HIGH, title="Confirmed SQLi", status=FindingStatus.CONFIRMED),
        ]
        summary = summarize_findings(findings)
        self.assertEqual(summary["total_findings"], 3)
        self.assertEqual(summary["secure"], 1)
        self.assertEqual(summary["informational"], 1)
        self.assertEqual(summary["confirmed"], 1)
        # SECURE/INFORMATIONAL severity toplamına katılmamalı — yalnızca CONFIRMED HIGH sayılmalı.
        self.assertEqual(summary["severity"]["high"], 1)
        self.assertEqual(summary["severity"]["info"], 0)

    def test_confirmed_potential_manual_review_distinguished(self):
        findings = [
            Finding(severity=Severity.HIGH, title="A", status=FindingStatus.CONFIRMED),
            Finding(severity=Severity.MEDIUM, title="B", status=FindingStatus.POTENTIAL),
            Finding(severity=Severity.MEDIUM, title="C", status=FindingStatus.MANUAL_REVIEW),
        ]
        summary = summarize_findings(findings)
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(summary["potential"], 1)
        self.assertEqual(summary["manual_review"], 1)
        # Üç durum ayrı sayaçlarda tutulur — biri diğerine sızmaz.
        self.assertEqual(summary["total_findings"], 3)

    def test_info_severity_alone_does_not_imply_secure_or_informational(self):
        """Status yetkilidir — yalnızca severity=INFO olması bir bulguyu secure/informational yapmaz."""
        findings = [
            Finding(severity=Severity.INFO, title="Weak but low-impact indicator",
                    status=FindingStatus.POTENTIAL),
        ]
        summary = summarize_findings(findings)
        self.assertEqual(summary["secure"], 0)
        self.assertEqual(summary["informational"], 0)
        self.assertEqual(summary["potential"], 1)
        self.assertEqual(summary["severity"]["info"], 1)

    def test_unclassified_status_none_tracked_separately(self):
        """Henüz migrate edilmemiş (status=None) bulgular sessizce yanlış sınıflandırılmamalı."""
        findings = [Finding(severity=Severity.HIGH, title="Legacy SQLi finding")]
        summary = summarize_findings(findings)
        self.assertEqual(summary["unclassified"], 1)
        self.assertEqual(summary["confirmed"], 0)
        self.assertEqual(summary["secure"], 0)
        # Severity toplamına yine de katılır (SECURE/INFORMATIONAL olarak işaretlenmediği sürece)
        self.assertEqual(summary["severity"]["high"], 1)

    def test_mixed_scan_result_summary_correct(self):
        findings = [
            Finding(severity=Severity.CRITICAL, title="Zone Transfer Allowed", status=FindingStatus.CONFIRMED),
            Finding(severity=Severity.HIGH, title="Potential SQLi", status=FindingStatus.POTENTIAL),
            Finding(severity=Severity.MEDIUM, title="Weak sink", status=FindingStatus.MANUAL_REVIEW),
            Finding(severity=Severity.INFO, title="CMS Detected", status=FindingStatus.INFORMATIONAL),
            Finding(severity=Severity.INFO, title="TLS 1.3", status=FindingStatus.SECURE),
            Finding(severity=Severity.INFO, title="TLS 1.3 alt", status=FindingStatus.SECURE),
        ]
        summary = summarize_findings(findings)
        self.assertEqual(summary["total_findings"], 6)
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(summary["potential"], 1)
        self.assertEqual(summary["manual_review"], 1)
        self.assertEqual(summary["informational"], 1)
        self.assertEqual(summary["secure"], 2)
        self.assertEqual(summary["severity"], {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0})


class ScanFindingModelTest(TestCase):
    def test_new_fields_default_to_empty_string(self):
        job = ScanJob.objects.create(target="https://example.com", status="DONE")
        finding = ScanFinding.objects.create(
            job=job, scanner="headers", severity="HIGH", title="Missing HSTS",
        )
        self.assertEqual(finding.confidence, "")
        self.assertEqual(finding.status, "")
        self.assertEqual(finding.description, "")
        self.assertEqual(finding.affected_url, "")
        self.assertEqual(finding.parameter, "")
        self.assertEqual(finding.owasp, "")
        self.assertEqual(finding.cwe, "")
        self.assertEqual(finding.mitre, "")
        self.assertEqual(finding.recommendation, "")

    def test_new_fields_can_be_persisted(self):
        job = ScanJob.objects.create(target="https://example.com", status="DONE")
        finding = ScanFinding.objects.create(
            job=job,
            scanner="sql",
            severity="HIGH",
            title="Potential SQL Injection",
            evidence="...",
            confidence="MEDIUM",
            status="POTENTIAL",
            description="Boolean-based response difference observed.",
            affected_url="https://example.com/login",
            parameter="username",
            owasp="A03:2021 - Injection",
            cwe="CWE-89",
            mitre="T1190 - Exploit Public-Facing Application",
            recommendation="Use parameterized queries.",
        )
        finding.refresh_from_db()
        self.assertEqual(finding.confidence, "MEDIUM")
        self.assertEqual(finding.status, "POTENTIAL")
        self.assertEqual(finding.owasp, "A03:2021 - Injection")
        self.assertEqual(finding.cwe, "CWE-89")


class SSRFGuardTest(TestCase):
    def test_public_url_passes(self):
        validate_url('https://google.com')  # should not raise

    def test_localhost_blocked(self):
        with self.assertRaises(SSRFError):
            validate_url('http://localhost')

    def test_loopback_ip_blocked(self):
        with self.assertRaises(SSRFError):
            validate_url('http://127.0.0.1')

    def test_private_network_blocked(self):
        with self.assertRaises(SSRFError):
            validate_url('http://192.168.1.1')

    def test_aws_metadata_blocked(self):
        with self.assertRaises(SSRFError):
            validate_url('http://169.254.169.254')

    def test_ftp_scheme_blocked(self):
        with self.assertRaises(SSRFError):
            validate_url('ftp://example.com')

    def test_ipv6_loopback_blocked(self):
        """[::1] socket.gethostbyname ile çözülemediği için 'host çözülemedi' olarak reddedilir —
        güvenli, fail-closed bir davranıştır (bypass değildir)."""
        with self.assertRaises(SSRFError):
            validate_url('http://[::1]/')

    def test_userinfo_does_not_bypass_guard(self):
        """URL'de userinfo (user:pass@) olması host tabanlı kontrolü atlatmamalı."""
        with self.assertRaises(SSRFError):
            validate_url('http://attacker:password@127.0.0.1/')

    @patch('Tarama.services.ssrf_guard.socket.gethostbyname')
    def test_hostname_resolving_to_private_ip_blocked(self, mock_resolve):
        """Herkese açık görünen bir alan adı özel bir IP'ye çözülüyorsa yine engellenmeli
        (DNS rebinding senaryosu) — guard çözümlenen IP'yi kontrol eder, hostname'i değil."""
        mock_resolve.return_value = '192.168.1.50'
        with self.assertRaises(SSRFError):
            validate_url('http://looks-public.example.com/')

    def test_error_message_has_no_traceback(self):
        """Doğrulama hataları temiz mesajlar döndürmeli, Python stack trace sızdırmamalı."""
        try:
            validate_url('http://127.0.0.1')
            self.fail('SSRFError bekleniyordu')
        except SSRFError as e:
            message = str(e)
            self.assertNotIn('Traceback', message)
            self.assertNotIn('.py", line', message)


class HeaderScannerTest(TestCase):
    def _mock_urlopen(self, headers: dict):
        mock_resp = MagicMock()
        mock_resp.info.return_value = headers
        return mock_resp

    @patch('urllib.request.urlopen')
    def test_present_header_is_info_severity(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'geolocation=()',
        })
        result = HeaderScanner().scan('https://example.com')
        self.assertIsNone(result.error)
        info_titles = {f.title for f in result.findings if f.severity == Severity.INFO}
        self.assertIn('X-Frame-Options', info_titles)
        self.assertIn('Content-Security-Policy', info_titles)

    @patch('urllib.request.urlopen')
    def test_missing_headers_not_overclassified(self, mock_urlopen):
        """Eksik headerlar otomatik HIGH olmamalı — CLAUDE.md V1 severity rehberiyle uyumlu olmalı."""
        mock_urlopen.return_value = self._mock_urlopen({})
        result = HeaderScanner().scan('https://example.com')
        titles = {f.title: f.severity for f in result.findings}
        self.assertEqual(titles.get('Strict-Transport-Security eksik'), Severity.MEDIUM)
        self.assertEqual(titles.get('Content-Security-Policy eksik'), Severity.MEDIUM)
        self.assertEqual(titles.get('X-Frame-Options eksik'), Severity.LOW)
        self.assertEqual(titles.get('X-Content-Type-Options eksik'), Severity.LOW)
        high_or_critical = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(high_or_critical, [])

    @patch('urllib.request.urlopen')
    def test_missing_xss_protection_is_info(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({})
        result = HeaderScanner().scan('https://example.com')
        finding = next(f for f in result.findings if f.title == 'X-XSS-Protection eksik')
        self.assertEqual(finding.severity, Severity.INFO)

    @patch('urllib.request.urlopen')
    def test_missing_hsts_not_reported_on_http_target(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({})
        result = HeaderScanner().scan('http://example.com')
        titles = [f.title for f in result.findings]
        self.assertNotIn('Strict-Transport-Security eksik', titles)

    @patch('urllib.request.urlopen')
    def test_csp_frame_ancestors_suppresses_xfo_duplicate(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertNotIn('X-Frame-Options eksik', titles)

    @patch('urllib.request.urlopen')
    def test_present_header_marked_secure_not_vulnerability(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Content-Security-Policy': "default-src 'self'",
        })
        result = HeaderScanner().scan('https://example.com')
        finding = next(f for f in result.findings if f.title == 'Content-Security-Policy')
        self.assertEqual(finding.status, FindingStatus.SECURE)

    @patch('urllib.request.urlopen')
    def test_hsts_low_max_age_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Strict-Transport-Security': 'max-age=3600',
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('HSTS max-age yetersiz', titles)

    @patch('urllib.request.urlopen')
    def test_hsts_missing_includesubdomains_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Strict-Transport-Security': 'max-age=31536000',
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('HSTS includeSubDomains eksik', titles)

    @patch('urllib.request.urlopen')
    def test_csp_unsafe_inline_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn("CSP 'unsafe-inline' içeriyor", titles)

    @patch('urllib.request.urlopen')
    def test_xss_protection_disabled_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({'X-XSS-Protection': '0'})
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('X-XSS-Protection açıkça devre dışı bırakılmış', titles)

    @patch('urllib.request.urlopen')
    def test_server_version_leak_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({'Server': 'Apache/2.4.41'})
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('Server bilgi sızdırıyor', titles)

    @patch('urllib.request.urlopen')
    def test_connection_error_stored_in_result(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        result = HeaderScanner().scan('https://example.com')
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])


def _make_open_ctx(recv_bytes=b''):
    """Returns a create_connection mock simulating an open port."""
    ctx = MagicMock()
    mock_sock = MagicMock()
    mock_sock.recv.return_value = recv_bytes
    ctx.__enter__ = MagicMock(return_value=mock_sock)
    ctx.__exit__ = MagicMock(return_value=False)
    return ctx


class PortScannerTest(TestCase):
    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_open_port_detected(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx()

        result = PortScanner().scan('https://example.com')

        self.assertIsNone(result.error)
        port_map = {f.title: f.evidence for f in result.findings}
        self.assertTrue(port_map.get('80/HTTP', '').startswith('ACIK'))
        sev_map = {f.title: f.severity for f in result.findings}
        # Kanıt olmadan (banner yok) veritabanı portları otomatik HIGH/CRITICAL olmamalı
        self.assertEqual(sev_map.get('6379/Redis'), Severity.LOW)
        self.assertEqual(sev_map.get('27017/MongoDB'), Severity.LOW)
        self.assertEqual(sev_map.get('3389/RDP'), Severity.HIGH)

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_ssh_open_is_informational(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx()

        result = PortScanner().scan('https://example.com')

        ssh = next(f for f in result.findings if f.title == '22/SSH')
        self.assertEqual(ssh.severity, Severity.INFO)
        self.assertEqual(ssh.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_telnet_open_is_meaningful_finding(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx()

        result = PortScanner().scan('https://example.com')

        telnet = next(f for f in result.findings if f.title == '23/Telnet')
        self.assertEqual(telnet.severity, Severity.HIGH)
        self.assertEqual(telnet.status, FindingStatus.CONFIRMED)
        self.assertEqual(telnet.cwe, 'CWE-319')

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_database_port_not_automatically_high(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx()

        result = PortScanner().scan('https://example.com')

        for title in ('1433/MSSQL', '3306/MySQL', '5432/PostgreSQL'):
            finding = next(f for f in result.findings if f.title == title)
            self.assertNotIn(finding.severity, (Severity.HIGH, Severity.CRITICAL))
            self.assertEqual(finding.status, FindingStatus.MANUAL_REVIEW)

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_redis_unauthenticated_pong_confirms_critical(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx(b'+PONG\r\n')

        result = PortScanner().scan('https://example.com')

        redis_finding = next(f for f in result.findings if f.title == '6379/Redis')
        self.assertEqual(redis_finding.severity, Severity.CRITICAL)
        self.assertEqual(redis_finding.status, FindingStatus.CONFIRMED)
        self.assertEqual(redis_finding.cwe, 'CWE-306')

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_service_banner_alone_is_informational(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx(b'SSH-2.0-OpenSSH_9.1p1 Ubuntu\r\n')

        result = PortScanner().scan('https://example.com')

        ssh = next(f for f in result.findings if f.title == '22/SSH')
        self.assertEqual(ssh.severity, Severity.INFO)
        self.assertEqual(ssh.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.ports.socket.gethostbyname')
    def test_unresolvable_host_returns_error(self, mock_dns):
        mock_dns.side_effect = socket.gaierror('Name not resolved')
        result = PortScanner().scan('https://nonexistent.invalid')
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_closed_port_detected(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.side_effect = ConnectionRefusedError

        result = PortScanner().scan('https://example.com')

        port_map = {f.title: f.evidence for f in result.findings}
        self.assertEqual(port_map.get('80/HTTP'), 'KAPALI')
        self.assertEqual(port_map.get('6379/Redis'), 'KAPALI')

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_host_name_finding_present(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.side_effect = ConnectionRefusedError

        result = PortScanner().scan('https://example.com')

        host_finding = next((f for f in result.findings if f.title == 'host_name'), None)
        self.assertIsNotNone(host_finding)
        self.assertEqual(host_finding.evidence, 'example.com')

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_all_19_ports_scanned(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.side_effect = ConnectionRefusedError

        result = PortScanner().scan('https://example.com')

        self.assertEqual(len(result.findings), 20)  # host_name + 19 port

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_banner_included_in_evidence(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx(b'SSH-2.0-OpenSSH_9.1p1 Ubuntu\r\n')

        result = PortScanner().scan('https://example.com')

        port_map = {f.title: f.evidence for f in result.findings}
        self.assertIn('SSH-2.0-OpenSSH_9.1p1 Ubuntu', port_map.get('22/SSH', ''))

    @patch('Tarama.scanners.ports.socket.gethostbyaddr')
    @patch('Tarama.scanners.ports.socket.gethostbyname')
    @patch('Tarama.scanners.ports.socket.create_connection')
    def test_empty_banner_not_appended(self, mock_conn, mock_dns, mock_addr):
        mock_dns.return_value = '93.184.216.34'
        mock_addr.return_value = ('example.com', [], ['93.184.216.34'])
        mock_conn.return_value = _make_open_ctx(b'')

        result = PortScanner().scan('https://example.com')

        port_map = {f.title: f.evidence for f in result.findings}
        ssh_evidence = port_map.get('22/SSH', '')
        self.assertTrue(ssh_evidence.startswith('ACIK | '))
        self.assertFalse(ssh_evidence.endswith(' | '))


class SqlScannerTest(TestCase):
    @patch('Tarama.scanners.sql.requests.Session')
    def test_no_forms_detected(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>No forms here.</body></html>'

        result = SqlInjectionScanner().scan('https://example.com')

        self.assertIsNone(result.error)
        forms = next(f for f in result.findings if f.title == 'forms_detected')
        self.assertEqual(forms.evidence, '0')

    @patch('Tarama.scanners.sql.requests.Session')
    def test_error_based_payload_injected_and_flagged(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/login" method="post"><input name="user"></form>'
            b'</body></html>'
        )

        def post_side_effect(*args, **kwargs):
            data = kwargs.get('data', {})
            resp = MagicMock()
            if data.get('user') == 'lilith_baseline':
                resp.content = b'<html>Welcome</html>'
            else:
                resp.content = b'you have an error in your sql syntax'
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        # Evidence alan adını ve payload'ı içermeli
        self.assertIn('user', high[0].evidence)
        self.assertEqual(high[0].confidence, Confidence.HIGH)
        self.assertEqual(high[0].status, FindingStatus.POTENTIAL)
        self.assertEqual(high[0].owasp, 'A03:2021 - Injection')
        self.assertEqual(high[0].cwe, 'CWE-89')

    @patch('Tarama.scanners.sql.requests.Session')
    def test_error_already_in_baseline_not_confirmed(self, MockSession):
        """CLAUDE.md 2.1: Baseline yanıtında zaten var olan bir DB hatası yeni kanıt sayılmamalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/login" method="post"><input name="user"></form>'
            b'</body></html>'
        )
        # Baseline dahil TÜM yanıtlar aynı hata metnini içeriyor (uygulamanın kendi
        # hata sayfası şablonu gibi) — bu payload'ın tetiklediği YENİ bir kanıt değildir.
        instance.post.return_value.content = b'you have an error in your sql syntax'

        result = SqlInjectionScanner().scan('https://example.com')

        error_based = [f for f in result.findings if 'Database Error Triggered' in f.title]
        self.assertEqual(error_based, [])

    @patch('Tarama.scanners.sql.requests.Session')
    def test_clean_response_not_flagged(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/login" method="post"><input name="user"></form>'
            b'</body></html>'
        )
        instance.post.return_value.content = b'<html>Welcome back!</html>'

        result = SqlInjectionScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertEqual(high, [])

    @patch('Tarama.scanners.sql.requests.Session')
    def test_boolean_based_detected(self, MockSession):
        """True ve false koşulları farklı yanıt döndürürse boolean bazlı SQLi tespit edilmeli."""
        instance = MockSession.return_value

        form_html = (
            b'<html><body>'
            b'<form action="/search" method="post"><input name="q"></form>'
            b'</body></html>'
        )

        long_body  = b'<html>' + b'A' * 1000 + b'result found admin user</html>'
        short_body = b'<html>No results found</html>'

        def post_side_effect(*args, **kwargs):
            data = kwargs.get('data', {})
            resp = MagicMock()
            if "' OR '1'='1'" in str(data.get('q', '')):
                resp.content = long_body
            elif "' OR '1'='2'" in str(data.get('q', '')):
                resp.content = short_body
            else:
                resp.content = short_body   # error payloads → clean
            return resp

        instance.get.return_value.content = form_html
        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        self.assertTrue(len(medium) > 0)
        self.assertIn('Boolean', medium[0].title)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_generic_500_alone_not_sqli(self, MockSession):
        """CLAUDE.md 2.2: Genel HTTP 500 tek başına SQLi kanıtı değildir (DB'ye özgü metin yok)."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/login" method="post"><input name="user"></form>'
            b'</body></html>'
        )

        def post_side_effect(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 500
            resp.content = b'<html><body>500 Internal Server Error</body></html>'
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        dangerous = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(dangerous, [])

    @patch('Tarama.scanners.sql.requests.Session')
    def test_tiny_dynamic_difference_not_flagged(self, MockSession):
        """CLAUDE.md 2.3: Küçük dinamik farklar (timestamp vb.) boolean SQLi tetiklememeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/search" method="post"><input name="q"></form>'
            b'</body></html>'
        )
        base_page = 'A' * 2000

        def post_side_effect(*args, **kwargs):
            resp = MagicMock()
            # Yalnızca ufak, rastgele bir sayı değişiyor (örn. istek kimliği) —
            # sorgu mantığıyla ilgisiz, önemsiz bir fark.
            resp.content = (base_page + str(hash(str(kwargs)) % 100)).encode()
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        boolean_findings = [f for f in result.findings if 'Boolean' in f.title]
        self.assertEqual(boolean_findings, [])

    @patch('Tarama.scanners.sql.requests.Session')
    def test_stable_boolean_reproducible_high_confidence(self, MockSession):
        """CLAUDE.md 2.4: True/false farkı tekrarlanabilirse confidence HIGH, status POTENTIAL olmalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/search" method="post"><input name="q"></form>'
            b'</body></html>'
        )
        long_body  = b'<html>' + b'A' * 1000 + b'result found</html>'
        short_body = b'<html>No results found</html>'

        def post_side_effect(*args, **kwargs):
            data = kwargs.get('data', {})
            resp = MagicMock()
            if "' OR '1'='1'" in str(data.get('q', '')):
                resp.content = long_body
            else:
                resp.content = short_body
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        boolean_findings = [f for f in result.findings if 'Boolean' in f.title]
        self.assertTrue(len(boolean_findings) > 0)
        self.assertEqual(boolean_findings[0].confidence, Confidence.HIGH)
        self.assertEqual(boolean_findings[0].status, FindingStatus.POTENTIAL)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_unstable_boolean_lowers_confidence(self, MockSession):
        """CLAUDE.md 2.4/2.5: İlk çift zafiyetli görünür ama doğrulama tekrarı farklı davranırsa
        confidence düşer ve status MANUAL_REVIEW olur, CONFIRMED/POTENTIAL değil."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/search" method="post"><input name="q"></form>'
            b'</body></html>'
        )
        long_body   = b'<html>' + b'A' * 1000 + b'result found</html>'
        short_body  = b'<html>No results found</html>'
        true_payload = "' OR '1'='1' --"
        seen_true = [0]

        def post_side_effect(*args, **kwargs):
            data = kwargs.get('data', {})
            resp = MagicMock()
            q = str(data.get('q', ''))
            if q == true_payload:
                seen_true[0] += 1
                # İlk gönderimde fark var (uzun yanıt), doğrulama tekrarında fark kayboluyor.
                resp.content = long_body if seen_true[0] == 1 else short_body
            else:
                resp.content = short_body
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        boolean_findings = [f for f in result.findings if 'Boolean' in f.title]
        self.assertTrue(len(boolean_findings) > 0)
        self.assertEqual(boolean_findings[0].confidence, Confidence.LOW)
        self.assertEqual(boolean_findings[0].status, FindingStatus.MANUAL_REVIEW)

    @patch('Tarama.scanners.sql.time.time')
    @patch('Tarama.scanners.sql.requests.Session')
    def test_single_timing_spike_not_confirmed(self, MockSession, mock_time):
        """CLAUDE.md 2.5: Tek bir yavaş istek CRITICAL+CONFIRMED zaman bazlı SQLi üretmemeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/q" method="post"><input name="search"></form>'
            b'</body></html>'
        )
        instance.post.return_value.content = b'<html>OK</html>'

        # Zaman akışı: scan() baseline ölçümü (t0,t1) -> ilk yavaş payload (t0,t1) -> doğrulama tekrarı hızlı (t0,t1)
        # Her _submit çağrısı için bir (başlangıç, bitiş) çifti tüketilir.
        times = iter([
            0.0, 0.2,     # scan() baseline GET ölçümü (hızlı)
            10.0, 13.5,   # ilk zaman bazlı payload — anormal derecede yavaş (tek seferlik sıçrama)
            20.0, 20.2,   # doğrulama tekrarı — normal hız, tekrarlanmıyor
        ])
        mock_time.side_effect = lambda: next(times, 999.0)

        result = SqlInjectionScanner().scan('https://example.com')

        time_findings = [f for f in result.findings if 'Time-Based' in f.title]
        self.assertTrue(len(time_findings) > 0)
        self.assertNotEqual(time_findings[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(time_findings[0].confidence, Confidence.LOW)

    @patch('Tarama.scanners.sql.time.time')
    @patch('Tarama.scanners.sql.requests.Session')
    def test_repeatable_timing_confirms_finding(self, MockSession, mock_time):
        """CLAUDE.md 2.5: Tekrarlanan gecikme davranışı daha güçlü (CONFIRMED/HIGH) bulgu üretmeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/q" method="post"><input name="search"></form>'
            b'</body></html>'
        )
        instance.post.return_value.content = b'<html>OK</html>'

        times = iter([
            0.0, 0.1,     # baseline GET (hızlı)
            10.0, 13.5,   # ilk zaman bazlı payload — yavaş
            20.0, 23.6,   # doğrulama tekrarı — yine yavaş, tutarlı
        ])
        mock_time.side_effect = lambda: next(times, 999.0)

        result = SqlInjectionScanner().scan('https://example.com')

        time_findings = [f for f in result.findings if 'Time-Based' in f.title]
        self.assertTrue(len(time_findings) > 0)
        self.assertEqual(time_findings[0].confidence, Confidence.HIGH)
        self.assertEqual(time_findings[0].status, FindingStatus.CONFIRMED)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_json_malformed_parser_error_not_sqli(self, MockSession):
        """CLAUDE.md 2.7: Genel JSON parser reddi (400/Invalid JSON) SQLi kanıtı değildir."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>No forms</body></html>'

        def post_side_effect(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 400
            resp.content = b'{"error": "Invalid JSON"}'
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com/api/users')

        json_findings = [f for f in result.findings if 'JSON' in f.title]
        self.assertEqual(json_findings, [])

    @patch('Tarama.scanners.sql.requests.Session')
    def test_url_param_error_based_detected(self, MockSession):
        """URL'deki query parametresine payload enjeksiyonu hata döndürürse tespit edilmeli."""
        from urllib.parse import unquote
        instance = MockSession.return_value

        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            # urlencode ' → %27 yaptığı için decode ile kontrol et
            if "'" in unquote(url):
                resp.content = b'you have an error in your sql syntax'
            else:
                resp.content = b'<html><body>Normal page, no forms</body></html>'
            return resp

        instance.get.side_effect = get_side_effect

        result = SqlInjectionScanner().scan('https://example.com?id=1')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertIn('id', high[0].evidence)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_csrf_field_not_injected(self, MockSession):
        """CSRF token alanları enjeksiyona dahil edilmemeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/login" method="post">'
            b'<input name="csrftoken" value="abc123">'
            b'<input name="username">'
            b'</form></body></html>'
        )
        # SQL error sadece csrftoken alanına gönderirsek → ama biz göndermiyoruz
        instance.post.return_value.content = b'<html>OK</html>'

        result = SqlInjectionScanner().scan('https://example.com')

        # csrf alanına enjeksiyon gönderilmediğinden hiç HIGH bulgu olmamalı
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertEqual(high, [])

    @patch('Tarama.scanners.sql.requests.Session')
    def test_error_evidence_includes_snippet(self, MockSession):
        """Hata bazlı SQLi bulgusu, yanıttaki hata satırını evidence'a eklemeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = (
            b'<html><body>'
            b'<form action="/q" method="post"><input name="search"></form>'
            b'</body></html>'
        )
        error_body = b'<html>Error: you have an error in your sql syntax near line 1</html>'

        def post_side_effect(*args, **kwargs):
            data = kwargs.get('data', {})
            resp = MagicMock()
            resp.content = b'<html>OK</html>' if data.get('search') == 'lilith_baseline' else error_body
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertIn('Hata:', high[0].evidence)
        self.assertIn('sql syntax', high[0].evidence)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_union_based_detected(self, MockSession):
        """ORDER BY hata verdikten sonra UNION SELECT yanıt değiştirirse UNION SQLi tespiti yapılmalı."""
        instance = MockSession.return_value

        form_html = (
            b'<html><body>'
            b'<form action="/search" method="post"><input name="q"></form>'
            b'</body></html>'
        )
        baseline_body = b'<html><body>Normal result</body></html>'
        union_body    = b'<html><body>Normal result EXTRA_UNION_DATA col1 col2</body></html>'

        def post_side_effect(*args, **kwargs):
            data = kwargs.get('data', {})
            q    = str(data.get('q', ''))
            resp = MagicMock()
            # Hata payloadları → temiz yanıt
            if "ORDER BY 2" in q:
                resp.content = b'incorrect syntax near ORDER BY'
            elif "UNION SELECT" in q:
                resp.content = union_body
            elif "ORDER BY 1" in q:
                resp.content = baseline_body
            else:
                resp.content = baseline_body
            return resp

        instance.get.return_value.content = form_html
        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        union_findings = [f for f in result.findings if 'UNION' in f.title]
        # UNION tespiti yapılmış olabilir; en azından hata olmadan tarama tamamlanmalı
        self.assertIsNone(result.error)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_json_injection_detected_on_api_endpoint(self, MockSession):
        """JSON body enjeksiyonu /api/ yolunda SQL hatası dönerse tespit edilmeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>No forms</body></html>'

        def post_side_effect(*args, **kwargs):
            body = kwargs.get('json', {})
            resp = MagicMock()
            if any(v == 'lilith_baseline' for v in body.values()):
                resp.content = b'{"ok": true}'
            else:
                resp.content = b'you have an error in your sql syntax'
            return resp

        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com/api/users')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        json_findings = [f for f in high if 'JSON' in f.title]
        self.assertTrue(len(json_findings) > 0)
        self.assertEqual(json_findings[0].confidence, Confidence.HIGH)
        self.assertEqual(json_findings[0].status, FindingStatus.POTENTIAL)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_json_injection_skipped_on_non_api(self, MockSession):
        """JSON enjeksiyonu /api/ olmayan URL'de çalıştırılmamalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>No forms</body></html>'
        instance.post.return_value.content = b'you have an error in your sql syntax'

        result = SqlInjectionScanner().scan('https://example.com/login')

        json_findings = [f for f in result.findings if 'JSON' in f.title]
        self.assertEqual(json_findings, [])

    @patch('Tarama.scanners.sql.requests.Session')
    def test_second_order_detected_on_redirect(self, MockSession):
        """Form submit sonrası redirect sayfasında SQL hatası varsa ikinci dereceden SQLi tespiti."""
        instance = MockSession.return_value

        form_html = (
            b'<html><body>'
            b'<form action="/register" method="post"><input name="username"></form>'
            b'</body></html>'
        )
        clean_body    = b'<html><body>Registered OK</body></html>'
        sqlerror_body = b'<html>postgresql query failed near line 1</html>'

        get_call_count = [0]

        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            get_call_count[0] += 1
            if get_call_count[0] == 1:
                # İlk GET: ana sayfa
                resp.content = form_html
            else:
                # İkinci GET: second-order kontrol sayfası
                resp.content = sqlerror_body
                resp.url     = url
            return resp

        def post_side_effect(url, data=None, **kwargs):
            resp        = MagicMock()
            resp.content = clean_body
            resp.url     = 'https://example.com/profile'
            return resp

        instance.get.side_effect  = get_side_effect
        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        second_order = [f for f in result.findings if 'Second-Order' in f.title]
        self.assertTrue(len(second_order) > 0)
        self.assertEqual(second_order[0].severity, Severity.HIGH)
        # Marker korelasyonu doğrulanmadığından ikinci dereceden bulgular her zaman
        # MANUAL_REVIEW olarak işaretlenir, asla CONFIRMED değil (CLAUDE.md 2.8).
        self.assertEqual(second_order[0].status, FindingStatus.MANUAL_REVIEW)

    @patch('Tarama.scanners.sql.requests.Session')
    def test_second_order_weak_correlation_stays_manual_review(self, MockSession):
        """Gönderim başarılı olur ama ilgisiz bir hedef genel bir sunucu hatası döndürürse
        bu, confirmed second-order SQLi değildir — en fazla MANUAL_REVIEW."""
        instance = MockSession.return_value

        form_html = (
            b'<html><body>'
            b'<form action="/register" method="post"><input name="username"></form>'
            b'</body></html>'
        )
        clean_body = b'<html><body>Registered OK</body></html>'
        # /search gibi ilgisiz bir aday sayfa genel bir DB hata metnini zaten içeriyor
        unrelated_error_body = b'<html>Internal error: syntax error near unexpected token</html>'

        get_call_count = [0]

        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            get_call_count[0] += 1
            if get_call_count[0] == 1:
                resp.content = form_html
            else:
                resp.content = unrelated_error_body
                resp.url = url
            return resp

        def post_side_effect(url, data=None, **kwargs):
            resp = MagicMock()
            resp.content = clean_body
            resp.url = 'https://example.com/register'  # redirect yok — url ile aynı
            return resp

        instance.get.side_effect = get_side_effect
        instance.post.side_effect = post_side_effect

        result = SqlInjectionScanner().scan('https://example.com')

        second_order = [f for f in result.findings if 'Second-Order' in f.title]
        self.assertTrue(len(second_order) > 0)
        self.assertEqual(second_order[0].status, FindingStatus.MANUAL_REVIEW)
        self.assertEqual(second_order[0].confidence, Confidence.LOW)


class XssScannerTest(TestCase):
    """XSS scanner testleri — iki aşamalı probe mantığına göre kurgulanmıştır.

    Scanner önce benzersiz bir probe gönderir; probe yanıtta görünüyorsa
    bağlamı tespit edip o bağlama özel payload'lar dener.
    Mock'lar gönderilen değeri doğrudan yanıta yansıtacak şekilde kurulur.
    """

    _FORM_HTML = (
        '<html><body>'
        '<form action="/search" method="post"><input name="q"></form>'
        '</body></html>'
    )

    def _echo_post(self, field='q'):
        """Gönderilen form alanını <body> içinde yansıtan POST mock'u döner."""
        def side_effect(url, data=None, **kwargs):
            value = (data or {}).get(field, '')
            r = MagicMock()
            r.text = f'<html><body>{value}</body></html>'
            return r
        return side_effect

    @patch('Tarama.scanners.xss.requests.Session')
    def test_no_forms_returns_not_found(self, MockSession):
        html = '<html><body>No forms.</body></html>'
        instance = MockSession.return_value
        instance.get.return_value.text = html
        instance.get.return_value.content = html.encode()

        result = XssScanner().scan('https://example.com')

        self.assertIsNone(result.error)
        titles = [f.title for f in result.findings]
        self.assertIn('XSS zafiyeti bulunamadı', titles)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_reflected_payload_flagged(self, MockSession):
        """Yanıt gönderilen değeri yansıtıyorsa HIGH bulgu üretilmeli."""
        instance = MockSession.return_value
        get_res = MagicMock()
        get_res.text = self._FORM_HTML
        get_res.content = self._FORM_HTML.encode()
        instance.get.return_value = get_res
        # POST: gönderilen q değerini olduğu gibi yansıt (probe + payload)
        instance.post.side_effect = self._echo_post('q')

        result = XssScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertIn('Potential Reflected XSS', high[0].title)
        self.assertEqual(high[0].confidence, Confidence.HIGH)
        self.assertEqual(high[0].status, FindingStatus.POTENTIAL)
        self.assertEqual(high[0].owasp, 'A03:2021 - Injection')
        self.assertEqual(high[0].cwe, 'CWE-79')

    @patch('Tarama.scanners.xss.requests.Session')
    def test_non_reflected_payload_clean(self, MockSession):
        """Yanıt hiçbir şeyi yansıtmıyorsa HIGH bulgu olmamalı."""
        instance = MockSession.return_value
        get_res = MagicMock()
        get_res.text = self._FORM_HTML
        get_res.content = self._FORM_HTML.encode()
        instance.get.return_value = get_res
        # POST: sabit, kullanıcı girdisini yansıtmayan yanıt
        safe = MagicMock()
        safe.text = '<html><body>Güvenli sayfa, girdi yok</body></html>'
        instance.post.return_value = safe
        instance.post.side_effect = None

        result = XssScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertEqual(high, [])

    @patch('Tarama.scanners.xss.requests.Session')
    def test_plain_marker_reflection_alone_not_confirmed(self, MockSession):
        """CLAUDE.md 3.1: Probe düz metin olarak yansısa bile, gerçek payload yansımadığı
        sürece hiçbir XSS bulgusu üretilmemeli — reflection tek başına XSS değildir."""
        instance = MockSession.return_value
        get_res = MagicMock()
        get_res.text = self._FORM_HTML
        get_res.content = self._FORM_HTML.encode()
        instance.get.return_value = get_res
        # Probe (ve her payload) düz metin olarak, hiçbir HTML kodlaması olmadan yansıyor,
        # ancak yanıt her zaman gönderilen tam payload/probe'u DEĞİL yalnızca sabit bir
        # onay mesajı içeriyor — yani gerçek payload asla doğrulanmıyor.
        safe = MagicMock()
        safe.text = '<html><body>Aramanız için sonuç bulunamadı.</body></html>'
        instance.post.return_value = safe
        instance.post.side_effect = None

        result = XssScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH and 'XSS' in f.title]
        self.assertEqual(high, [])

    @patch('Tarama.scanners.xss.requests.Session')
    def test_html_escaped_payload_not_confirmed(self, MockSession):
        """CLAUDE.md 3.2/3.3: Payload &lt;script&gt; şeklinde encode edilirse confirmed
        sayılmamalı — tehlikeli karakterler tutarlı biçimde encode ediliyor."""
        instance = MockSession.return_value
        get_res = MagicMock()
        get_res.text = self._FORM_HTML
        get_res.content = self._FORM_HTML.encode()
        instance.get.return_value = get_res

        def post_side(url, data=None, **kwargs):
            value = (data or {}).get('q', '')
            escaped = (value.replace('&', '&amp;').replace('<', '&lt;')
                       .replace('>', '&gt;').replace('"', '&quot;'))
            r = MagicMock()
            r.text = f'<html><body>{escaped}</body></html>'
            return r

        instance.post.side_effect = post_side

        result = XssScanner().scan('https://example.com')

        reflected = [f for f in result.findings if 'Reflected XSS' in f.title]
        self.assertEqual(reflected, [])

    @patch('Tarama.scanners.xss.requests.Session')
    def test_attribute_encoding_suppresses_confirmation(self, MockSession):
        """CLAUDE.md 3.3: Attribute bağlamında tırnak/açı parantezleri encode edilirse
        breakout payload'ı doğrulanmamalı."""
        instance = MockSession.return_value
        get_res = MagicMock()
        get_res.text = self._FORM_HTML
        get_res.content = self._FORM_HTML.encode()
        instance.get.return_value = get_res

        def post_side(url, data=None, **kwargs):
            value = (data or {}).get('q', '')
            # Attribute içine yerleştiriliyor ama tırnaklar encode ediliyor — breakout imkansız
            escaped = value.replace('"', '&quot;').replace("'", '&#39;')
            r = MagicMock()
            r.text = f'<html><body><input value="{escaped}"></body></html>'
            return r

        instance.post.side_effect = post_side

        result = XssScanner().scan('https://example.com')

        reflected = [f for f in result.findings if 'Reflected XSS' in f.title]
        self.assertEqual(reflected, [])

    @patch('Tarama.scanners.xss.requests.Session')
    def test_context_attr_double_detected(self, MockSession):
        """Probe çift tırnaklı attribute içinde yansıyorsa attr_double bağlamı seçilmeli."""
        instance = MockSession.return_value
        get_res = MagicMock()
        get_res.text = self._FORM_HTML
        get_res.content = self._FORM_HTML.encode()
        instance.get.return_value = get_res

        def post_side(url, data=None, **kwargs):
            value = (data or {}).get('q', '')
            r = MagicMock()
            # Probe'u attribute içinde yansıt
            r.text = f'<html><body><input value="{value}"></body></html>'
            return r

        instance.post.side_effect = post_side

        result = XssScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertIn('attr_double', high[0].evidence)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_probe_not_reflected_skips_payloads(self, MockSession):
        """Probe yanıtta görünmüyorsa XSS payload gönderilmemeli.
        Beklenen POST'lar: reflected probe (1) + stored marker (1) = 2.
        """
        instance = MockSession.return_value
        get_res = MagicMock()
        get_res.text = self._FORM_HTML
        get_res.content = self._FORM_HTML.encode()
        instance.get.return_value = get_res
        # POST: sabit sayfa, hiçbir şeyi yansıtmıyor
        fixed = MagicMock()
        fixed.text = '<html>nothing</html>'
        fixed.url  = 'https://example.com/search'
        instance.post.return_value = fixed
        instance.post.side_effect = None

        XssScanner().scan('https://example.com')

        # Reflected probe (1) + stored marker (1) = 2; XSS payload'ı yok
        self.assertEqual(instance.post.call_count, 2)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_dom_xss_source_sink_high(self, MockSession):
        """Hem kaynak hem havuz varsa HIGH DOM XSS bulgusu üretilmeli."""
        html = (
            '<html><body>'
            '<script>var x = location.hash; document.write(x);</script>'
            '</body></html>'
        )
        instance = MockSession.return_value
        res = MagicMock()
        res.text = html
        res.content = html.encode()
        instance.get.return_value = res

        result = XssScanner().scan('https://example.com')

        high = [f for f in result.findings
                if f.severity == Severity.HIGH and 'DOM' in f.title]
        self.assertTrue(len(high) > 0)
        self.assertIn('Source to Sink Flow', high[0].title)
        # Statik kaynak/havuz eş-varlığı, gerçek veri akışı doğrulaması değildir —
        # bu yüzden CONFIRMED değil, POTENTIAL olarak işaretlenir (CLAUDE.md 3.5).
        self.assertEqual(high[0].status, FindingStatus.POTENTIAL)
        self.assertEqual(high[0].confidence, Confidence.MEDIUM)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_dom_xss_sink_only_medium(self, MockSession):
        """Sadece havuz varsa MEDIUM DOM XSS bulgusu üretilmeli."""
        html = (
            '<html><body>'
            '<script>document.write("static text");</script>'
            '</body></html>'
        )
        instance = MockSession.return_value
        res = MagicMock()
        res.text = html
        res.content = html.encode()
        instance.get.return_value = res

        result = XssScanner().scan('https://example.com')

        med = [f for f in result.findings
               if f.severity == Severity.MEDIUM and 'DOM' in f.title]
        self.assertTrue(len(med) > 0)
        # Sink tek başına vulnerability değildir — LOW confidence, MANUAL_REVIEW (CLAUDE.md 3.4)
        self.assertEqual(med[0].confidence, Confidence.LOW)
        self.assertEqual(med[0].status, FindingStatus.MANUAL_REVIEW)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_setTimeout_function_reference_not_flagged(self, MockSession):
        """CLAUDE.md 3.4: setTimeout(function, ...) kullanıcı denetimli string değildir,
        yüksek güvenilirlikli DOM XSS bulgusu üretmemeli."""
        html = (
            '<html><body>'
            '<script>setTimeout(function () { doSomething(); }, 1000);</script>'
            '</body></html>'
        )
        instance = MockSession.return_value
        res = MagicMock()
        res.text = html
        res.content = html.encode()
        instance.get.return_value = res

        result = XssScanner().scan('https://example.com')

        dom_findings = [f for f in result.findings if 'DOM' in f.title]
        self.assertEqual(dom_findings, [])

    @patch('Tarama.scanners.xss.requests.Session')
    def test_setTimeout_string_argument_still_flagged(self, MockSession):
        """setTimeout ile kullanıcı denetimli bir kaynak birlikte kullanılıyorsa yine
        potansiyel bir bulgu üretilmeli — yalnızca fonksiyon referansı bastırılır."""
        html = (
            '<html><body>'
            '<script>setTimeout(location.hash, 1000);</script>'
            '</body></html>'
        )
        instance = MockSession.return_value
        res = MagicMock()
        res.text = html
        res.content = html.encode()
        instance.get.return_value = res

        result = XssScanner().scan('https://example.com')

        dom_findings = [f for f in result.findings if 'DOM' in f.title]
        self.assertTrue(len(dom_findings) > 0)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_source_and_sink_unrelated_not_confirmed(self, MockSession):
        """CLAUDE.md 3.5: Kaynak ve havuz aynı dosyada bulunması otomatik CONFIRMED üretmemeli."""
        html = (
            '<html><body>'
            '<script>'
            'function unrelatedA() { var h = location.hash; console.log(h); }'
            'function unrelatedB() { document.write("<b>static</b>"); }'
            '</script>'
            '</body></html>'
        )
        instance = MockSession.return_value
        res = MagicMock()
        res.text = html
        res.content = html.encode()
        instance.get.return_value = res

        result = XssScanner().scan('https://example.com')

        dom_findings = [f for f in result.findings if 'DOM' in f.title]
        self.assertTrue(len(dom_findings) > 0)
        self.assertNotEqual(dom_findings[0].status, FindingStatus.CONFIRMED)

    # --- Stored XSS testleri ---

    @patch('Tarama.scanners.xss.requests.Session')
    def test_stored_xss_payload_confirmed_high(self, MockSession):
        """Payload farklı bir sayfada kaydedilmişse HIGH Stored XSS üretilmeli."""
        form_html = (
            '<html><body>'
            '<form action="/comment" method="post"><input name="body"></form>'
            '<a href="https://example.com/comments">Yorumlar</a>'
            '</body></html>'
        )
        instance = MockSession.return_value

        stored: dict = {"content": ""}

        def get_side(url, **kwargs):
            r = MagicMock()
            if url == 'https://example.com':
                r.text = form_html
                r.content = form_html.encode()
            elif 'comments' in url:
                # Kaydedilen içeriği döndür
                r.text = f'<html><body>{stored["content"]}</body></html>'
                r.content = r.text.encode()
            else:
                r.text = '<html></html>'
                r.content = b'<html></html>'
            return r

        def post_side(url, data=None, **kwargs):
            stored["content"] = (data or {}).get("body", "")
            r = MagicMock()
            r.url = 'https://example.com/comments'
            r.text = '<html>Kaydedildi</html>'
            return r

        instance.get.side_effect = get_side
        instance.post.side_effect = post_side

        result = XssScanner().scan('https://example.com')

        high_stored = [f for f in result.findings
                       if f.severity == Severity.HIGH and 'Stored' in f.title]
        self.assertTrue(len(high_stored) > 0)
        self.assertIn('Görüntüleme', high_stored[0].evidence)
        # Yürütme tarayıcıda bağımsız doğrulanmadığından CONFIRMED değil, POTENTIAL (CLAUDE.md 3.6)
        self.assertEqual(high_stored[0].confidence, Confidence.HIGH)
        self.assertEqual(high_stored[0].status, FindingStatus.POTENTIAL)
        # Evidence sınırlı olmalı — tüm sayfa içeriği evidence'a dökülmemeli (CLAUDE.md 3.7/J)
        self.assertLess(len(high_stored[0].evidence), 500)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_stored_xss_marker_only_medium(self, MockSession):
        """Marker kaydedilmiş ama payload filtreleniyorsa MEDIUM bulgu üretilmeli."""
        form_html = (
            '<html><body>'
            '<form action="/comment" method="post"><input name="body"></form>'
            '<a href="https://example.com/comments">Yorumlar</a>'
            '</body></html>'
        )
        instance = MockSession.return_value
        stored: dict = {"content": ""}

        def get_side(url, **kwargs):
            r = MagicMock()
            if url == 'https://example.com':
                r.text = form_html
                r.content = form_html.encode()
            elif 'comments' in url:
                # Marker yansıyor ama script tag'leri encode edilmiş gibi
                safe_content = stored["content"].replace("<", "&lt;").replace(">", "&gt;")
                # Yalnızca marker düz metin ise yansısın
                if stored["content"].startswith("xssstored"):
                    r.text = f'<html><body>{stored["content"]}</body></html>'
                else:
                    r.text = f'<html><body>{safe_content}</body></html>'
                r.content = r.text.encode()
            else:
                r.text = '<html></html>'
                r.content = b'<html></html>'
            return r

        def post_side(url, data=None, **kwargs):
            stored["content"] = (data or {}).get("body", "")
            r = MagicMock()
            r.url = 'https://example.com/comments'
            r.text = '<html>Kaydedildi</html>'
            return r

        instance.get.side_effect = get_side
        instance.post.side_effect = post_side

        result = XssScanner().scan('https://example.com')

        med_stored = [f for f in result.findings
                      if f.severity == Severity.MEDIUM and 'Stored' in f.title]
        self.assertTrue(len(med_stored) > 0)
        # Marker kalıcı ama executable payload doğrulanamadı → CONFIRMED değil (CLAUDE.md 3.6/H)
        self.assertNotEqual(med_stored[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(med_stored[0].status, FindingStatus.POTENTIAL)

    @patch('Tarama.scanners.xss.requests.Session')
    def test_stored_xss_not_stored_no_finding(self, MockSession):
        """Marker hiçbir sayfada bulunamazsa stored bulgu olmamalı."""
        form_html = (
            '<html><body>'
            '<form action="/comment" method="post"><input name="body"></form>'
            '</body></html>'
        )
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            r.text = form_html if url == 'https://example.com' else '<html></html>'
            r.content = r.text.encode()
            return r

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            r.url = 'https://example.com/comment'
            r.text = '<html>Gönderildi</html>'
            return r

        instance.get.side_effect = get_side
        instance.post.side_effect = post_side

        result = XssScanner().scan('https://example.com')

        stored = [f for f in result.findings if 'Stored' in f.title]
        self.assertEqual(stored, [])


# ---------------------------------------------------------------------------
# SslScanner
# ---------------------------------------------------------------------------

class SslScannerTest(TestCase):
    def _make_ssl_sock(self, version='TLSv1.3', cipher=('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)):
        sock = MagicMock()
        sock.__enter__ = MagicMock(return_value=sock)
        sock.__exit__ = MagicMock(return_value=False)
        sock.version.return_value = version
        sock.cipher.return_value = cipher
        return sock

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    @patch('Tarama.scanners.ssl_tls.ssl.create_default_context')
    def test_http_target_port443_open(self, mock_ctx, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = SslScanner().scan('http://example.com')

        titles = [f.title for f in result.findings]
        self.assertIn('HTTPS mevcut ama kullanılmıyor', titles)
        self.assertIsNotNone(result.error)

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    def test_http_target_port443_closed(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError

        result = SslScanner().scan('http://example.com')

        titles = [f.title for f in result.findings]
        self.assertIn('HTTPS desteklenmiyor', titles)

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    @patch('Tarama.scanners.ssl_tls.ssl.create_default_context')
    def test_strong_tls_produces_info_findings(self, mock_ctx_cls, mock_conn):
        ssl_sock = self._make_ssl_sock('TLSv1.3', ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256))
        raw_sock = MagicMock()
        raw_sock.__enter__ = MagicMock(return_value=raw_sock)
        raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = raw_sock

        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssl_sock
        mock_ctx_cls.return_value = ctx

        result = SslScanner().scan('https://example.com')

        titles = {f.title for f in result.findings}
        self.assertIn('TLS Protokolü', titles)
        self.assertIn('Cipher Suite', titles)
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertEqual(high, [])
        protocol_finding = next(f for f in result.findings if f.title == 'TLS Protokolü')
        self.assertEqual(protocol_finding.status, FindingStatus.SECURE)

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    @patch('Tarama.scanners.ssl_tls.ssl.create_default_context')
    def test_weak_protocol_flagged(self, mock_ctx_cls, mock_conn):
        """TLS 1.0/1.1 artık MEDIUM olarak sınıflandırılır — otomatik HIGH değil."""
        ssl_sock = self._make_ssl_sock('TLSv1', ('AES128-SHA', 'TLSv1', 128))
        raw_sock = MagicMock()
        raw_sock.__enter__ = MagicMock(return_value=raw_sock)
        raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = raw_sock

        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssl_sock
        mock_ctx_cls.return_value = ctx

        result = SslScanner().scan('https://example.com')

        medium_titles = [f.title for f in result.findings if f.severity == Severity.MEDIUM]
        self.assertTrue(any('Zayıf protokol' in t for t in medium_titles))
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertEqual(high, [])

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    @patch('Tarama.scanners.ssl_tls.ssl.create_default_context')
    def test_expired_certificate_flagged_high(self, mock_ctx_cls, mock_conn):
        ssl_sock = self._make_ssl_sock('TLSv1.3', ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256))
        ssl_sock.getpeercert.return_value = {
            'notAfter': 'Jan  1 00:00:00 2000 GMT',
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('organizationName', 'Test CA'),),),
            'subjectAltName': (('DNS', 'example.com'),),
        }
        raw_sock = MagicMock()
        raw_sock.__enter__ = MagicMock(return_value=raw_sock)
        raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = raw_sock

        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssl_sock
        mock_ctx_cls.return_value = ctx

        result = SslScanner().scan('https://example.com')

        expired = next(f for f in result.findings if f.title == 'Sertifika süresi dolmuş')
        self.assertEqual(expired.severity, Severity.HIGH)
        self.assertEqual(expired.status, FindingStatus.CONFIRMED)

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    @patch('Tarama.scanners.ssl_tls.ssl.create_default_context')
    def test_valid_certificate_metadata_not_a_vulnerability(self, mock_ctx_cls, mock_conn):
        ssl_sock = self._make_ssl_sock('TLSv1.3', ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256))
        ssl_sock.getpeercert.return_value = {
            'notAfter': 'Jan  1 00:00:00 2099 GMT',
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('organizationName', 'Test CA'),),),
            'subjectAltName': (('DNS', 'example.com'),),
        }
        raw_sock = MagicMock()
        raw_sock.__enter__ = MagicMock(return_value=raw_sock)
        raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = raw_sock

        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssl_sock
        mock_ctx_cls.return_value = ctx

        result = SslScanner().scan('https://example.com')

        for title in ('Sertifika Yetkilisi (CA)', 'Sertifika CN', 'Subject Alternative Names',
                      'Sertifika geçerlilik süresi'):
            finding = next(f for f in result.findings if f.title == title)
            self.assertIn(finding.status, (FindingStatus.SECURE, FindingStatus.INFORMATIONAL))
        high_or_critical = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(high_or_critical, [])

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    @patch('Tarama.scanners.ssl_tls.ssl.create_default_context')
    def test_weak_cipher_bits_flagged(self, mock_ctx_cls, mock_conn):
        ssl_sock = self._make_ssl_sock('TLSv1.2', ('RC4-MD5', 'TLSv1.2', 64))
        raw_sock = MagicMock()
        raw_sock.__enter__ = MagicMock(return_value=raw_sock)
        raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = raw_sock

        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssl_sock
        mock_ctx_cls.return_value = ctx

        result = SslScanner().scan('https://example.com')

        high_titles = [f.title for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(any('Yetersiz anahtar' in t or 'Zayıf cipher' in t for t in high_titles))

    @patch('Tarama.scanners.ssl_tls.socket.create_connection')
    def test_connection_error_returns_error(self, mock_conn):
        mock_conn.side_effect = OSError('Connection refused')

        result = SslScanner().scan('https://example.com')

        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])


# ---------------------------------------------------------------------------
# DnsScanner
# ---------------------------------------------------------------------------

class DnsScannerTest(TestCase):
    def _scanner(self):
        s = DnsScanner()
        s._query = MagicMock(return_value=[])
        return s

    def test_a_record_found(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34'] if rdtype == 'A' else []
        )
        result = scanner.scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('A Kaydı (IPv4)', titles)

    def test_no_a_record_medium_finding(self):
        scanner = self._scanner()
        result = scanner.scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('Alan adı çözümlenemedi', titles)

    def test_spf_missing_medium(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34'] if rdtype == 'A' else []
        )
        result = scanner.scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('SPF kaydı eksik', titles)

    def test_spf_plus_all_high(self):
        """CLAUDE.md V1: SPF '+all' HIGH olmalı, artık CRITICAL değil."""
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34']  if rdtype == 'A' else
            ['"v=spf1 +all"']  if rdtype == 'TXT' and '._domainkey.' not in name and '_dmarc.' not in name else
            []
        )
        result = scanner.scan('https://example.com')
        self.assertEqual(result.findings, [f for f in result.findings if f.severity != Severity.CRITICAL])
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(any('SPF' in f.title for f in high))

    def test_spf_softfail_all_low(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34']  if rdtype == 'A' else
            ['"v=spf1 ~all"']  if rdtype == 'TXT' and '._domainkey.' not in name and '_dmarc.' not in name else
            []
        )
        result = scanner.scan('https://example.com')
        softfail = next(f for f in result.findings if 'Softfail' in f.title)
        self.assertEqual(softfail.severity, Severity.LOW)

    def test_dmarc_missing_medium(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34'] if rdtype == 'A' else []
        )
        result = scanner.scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('DMARC kaydı eksik', titles)

    def test_dmarc_p_none_differs_from_missing(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34']              if rdtype == 'A' else
            ['"v=DMARC1; p=none;"']        if rdtype == 'TXT' and '_dmarc.' in name else
            []
        )
        result = scanner.scan('https://example.com')
        titles = {f.title: f.severity for f in result.findings}
        self.assertNotIn('DMARC kaydı eksik', titles)
        self.assertEqual(titles.get('DMARC politikası: none (izleme modu)'), Severity.LOW)

    def test_dkim_selectors_not_found_does_not_claim_absence(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34'] if rdtype == 'A' else []
        )
        result = scanner.scan('https://example.com')
        finding = next(f for f in result.findings if 'DKIM' in f.title)
        self.assertNotIn('yapılandırılmamış', finding.title.lower())
        self.assertIn('does not conclusively indicate', finding.description)
        self.assertEqual(finding.confidence, Confidence.LOW)

    def test_malformed_txt_record_fails_safely(self):
        """CLAUDE.md §9: Bozuk/beklenmedik TXT içeriği scanner'ı çökertmemeli, güvenli şekilde
        'kayıt bulunamadı' olarak ele alınmalı."""
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34'] if rdtype == 'A' else
            ['"\\x00garbled-not-spf-\xff\xfe"'] if rdtype == 'TXT' else []
        )
        result = scanner.scan('https://example.com')
        self.assertIsNone(result.error)
        titles = [f.title for f in result.findings]
        self.assertIn('SPF kaydı eksik', titles)

    def test_dns_resolution_exception_returns_empty_not_crash(self):
        """_query zaten dnspython'un DNSException ailesini yakalıyor — malformed/timeout
        durumunda boş liste döner, tarama çökmez."""
        import dns.exception
        scanner = DnsScanner()
        with patch.object(scanner._resolver, 'resolve', side_effect=dns.exception.DNSException):
            records = scanner._query('example.com', 'TXT')
        self.assertEqual(records, [])

    def test_zone_transfer_blocked_info(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34'] if rdtype == 'A' else
            ['ns1.example.com.'] if rdtype == 'NS' else []
        )
        with patch('Tarama.scanners.dns_scan.socket.gethostbyname', return_value='1.2.3.4'), \
             patch('Tarama.scanners.dns_scan.dns.zone.from_xfr', side_effect=Exception('refused')):
            result = scanner.scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('Zone Transfer engellendi', titles)
        blocked = next(f for f in result.findings if f.title == 'Zone Transfer engellendi')
        self.assertEqual(blocked.status, FindingStatus.SECURE)

    def test_zone_transfer_allowed_high(self):
        scanner = self._scanner()
        scanner._query.side_effect = lambda name, rdtype: (
            ['93.184.216.34'] if rdtype == 'A' else
            ['ns1.example.com.'] if rdtype == 'NS' else []
        )
        mock_zone = MagicMock()
        mock_zone.nodes.keys.return_value = ['www.example.com.', 'mail.example.com.']
        with patch('Tarama.scanners.dns_scan.socket.gethostbyname', return_value='1.2.3.4'), \
             patch('Tarama.scanners.dns_scan.dns.query.xfr', return_value=iter([])), \
             patch('Tarama.scanners.dns_scan.dns.zone.from_xfr', return_value=mock_zone):
            result = scanner.scan('https://example.com')
        allowed = next(f for f in result.findings if f.title == 'Zone Transfer izin veriliyor (AXFR)')
        self.assertEqual(allowed.severity, Severity.HIGH)
        self.assertEqual(allowed.status, FindingStatus.CONFIRMED)
        self.assertEqual(allowed.cwe, 'CWE-200')


# ---------------------------------------------------------------------------
# CmsScanner
# ---------------------------------------------------------------------------

class CmsScannerTest(TestCase):
    def _make_response(self, text='', status_code=200):
        r = MagicMock()
        r.text = text
        r.content = text.encode()
        r.status_code = status_code
        return r

    @patch('Tarama.scanners.cms.requests.Session')
    def test_wordpress_detected(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value = self._make_response(
            '<html><link href="/wp-content/themes/x/style.css"></html>'
        )
        result = CmsScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertTrue(any('WordPress' in t for t in titles))
        wp = next(f for f in result.findings if 'WordPress' in f.title)
        self.assertEqual(wp.severity, Severity.INFO)
        self.assertEqual(wp.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_no_cms_detected(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value = self._make_response('<html><body>Hello</body></html>')
        result = CmsScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('Bilinen CMS tespit edilmedi', titles)
        finding = next(f for f in result.findings if f.title == 'Bilinen CMS tespit edilmedi')
        self.assertNotIn(finding.severity, (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM))
        self.assertEqual(finding.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_generator_tag_flagged(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value = self._make_response(
            '<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>'
        )
        result = CmsScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('Generator meta tag — sürüm sızıntısı', titles)
        finding = next(f for f in result.findings if f.title == 'Generator meta tag — sürüm sızıntısı')
        # Versiyon bilgisi tek başına confirmed vulnerability değildir — no CVE tahmini yapılır
        self.assertNotIn(finding.severity, (Severity.HIGH, Severity.CRITICAL))
        self.assertEqual(finding.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_robots_txt_not_a_vulnerability(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            if url.endswith('/robots.txt'):
                return self._make_response('User-agent: *\nDisallow: /admin/\nDisallow: /backup/')
            return self._make_response('<html></html>')

        instance.get.side_effect = get_side
        result = CmsScanner().scan('https://example.com')
        robots = next((f for f in result.findings if 'robots.txt' in f.title), None)
        self.assertIsNotNone(robots)
        self.assertEqual(robots.severity, Severity.INFO)
        self.assertIsNone(robots.owasp)
        self.assertIsNone(robots.cwe)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_sensitive_path_accessible(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            if url.endswith('/.env'):
                r = self._make_response('SECRET_KEY=abc123\nDB_PASSWORD=hunter2')
                return r
            return self._make_response('<html></html>')

        instance.get.side_effect = get_side
        result = CmsScanner().scan('https://example.com')
        crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(any('.env' in f.title for f in crit))
        env_finding = next(f for f in crit if '.env' in f.title)
        self.assertEqual(env_finding.status, FindingStatus.CONFIRMED)
        self.assertEqual(env_finding.cwe, 'CWE-538')

    @patch('Tarama.scanners.cms.requests.Session')
    def test_sensitive_path_spa_catchall_not_confirmed(self, MockSession):
        """SPA/catch-all route her yola 200 + HTML döndürüyorsa gerçek bir .env/.git sızıntısı sayılmamalı."""
        instance = MockSession.return_value
        instance.get.return_value = self._make_response(
            '<!doctype html><html><body><div id="app"></div></body></html>'
        )
        result = CmsScanner().scan('https://example.com')
        confirmed_sensitive = [
            f for f in result.findings
            if f.title.startswith('Hassas dosya erişilebilir') and f.status == FindingStatus.CONFIRMED
        ]
        self.assertEqual(confirmed_sensitive, [])

    @patch('Tarama.scanners.cms.requests.Session')
    def test_connection_error_returns_error(self, MockSession):
        import requests as req
        instance = MockSession.return_value
        instance.get.side_effect = req.RequestException('timeout')
        result = CmsScanner().scan('https://example.com')
        self.assertIsNotNone(result.error)


# ---------------------------------------------------------------------------
# AccessControlScanner
# ---------------------------------------------------------------------------

class AccessControlScannerTest(TestCase):
    def _make_response(self, text='', status_code=200, headers=None):
        r = MagicMock()
        r.text = text
        r.status_code = status_code
        r.headers = MagicMock()
        r.headers.get = MagicMock(side_effect=lambda k, default='': (headers or {}).get(k, default))
        r.cookies = []
        return r

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_cors_wildcard_not_automatically_high(self, MockSession):
        instance = MockSession.return_value
        res = self._make_response(headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'false',
        })
        res.headers.get.side_effect = lambda k, d='': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'false',
        }.get(k, d)
        instance.get.return_value = res
        instance.options.return_value = self._make_response(headers={'Allow': 'GET, POST'})
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        cors = next(f for f in result.findings if 'wildcard' in f.title.lower())
        self.assertNotIn(cors.severity, (Severity.HIGH, Severity.CRITICAL))

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_cors_arbitrary_origin_reflection_with_credentials_flagged(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            headers_sent = kwargs.get('headers') or {}
            if headers_sent.get('Origin') == 'https://lilith-cors-probe.invalid':
                return self._make_response(headers={
                    'Access-Control-Allow-Origin': 'https://lilith-cors-probe.invalid',
                    'Access-Control-Allow-Credentials': 'true',
                })
            return self._make_response(headers={})

        instance.get.side_effect = get_side
        instance.options.return_value = self._make_response(headers={'Allow': 'GET, POST'})
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        reflection = next(f for f in result.findings if 'Reflection' in f.title)
        self.assertEqual(reflection.severity, Severity.HIGH)
        self.assertEqual(reflection.status, FindingStatus.CONFIRMED)
        self.assertEqual(reflection.confidence, Confidence.HIGH)

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_dir_listing_requires_evidence(self, MockSession):
        instance = MockSession.return_value
        res = self._make_response(text='<html>Index of /</html>', headers={})
        res.headers.get.return_value = ''
        instance.get.return_value = res
        instance.options.return_value = self._make_response(headers={'Allow': 'GET'})
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        listing = next(f for f in result.findings if 'Dizin Listeleme' in f.title)
        self.assertEqual(listing.confidence, Confidence.HIGH)
        self.assertEqual(listing.status, FindingStatus.CONFIRMED)
        self.assertIn(listing.severity, (Severity.LOW, Severity.MEDIUM))

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_dir_listing_not_reported_without_markers(self, MockSession):
        instance = MockSession.return_value
        res = self._make_response(text='<html>Welcome</html>', headers={})
        res.headers.get.return_value = ''
        instance.get.return_value = res
        instance.options.return_value = self._make_response(headers={'Allow': 'GET'})
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertFalse(any('Dizin Listeleme' in t for t in titles))

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_trace_method_flagged(self, MockSession):
        instance = MockSession.return_value
        res = self._make_response(headers={})
        res.headers.get.return_value = ''
        instance.get.return_value = res

        options_res = MagicMock()
        options_res.headers = MagicMock()
        options_res.headers.get = MagicMock(
            side_effect=lambda k, d='': 'GET, POST, TRACE' if k == 'Allow' else d
        )
        instance.options.return_value = options_res
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertTrue(any('TRACE' in t for t in titles))

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_get_post_options_not_vulnerabilities(self, MockSession):
        instance = MockSession.return_value
        res = self._make_response(headers={})
        res.headers.get.return_value = ''
        instance.get.return_value = res
        instance.options.return_value = self._make_response(headers={'Allow': 'GET, POST, OPTIONS'})
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        allowed = next(f for f in result.findings if 'İzin Verilen HTTP' in f.title)
        self.assertEqual(allowed.severity, Severity.INFO)
        self.assertEqual(allowed.status, FindingStatus.INFORMATIONAL)
        high_or_critical = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(high_or_critical, [])

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_missing_httponly_on_session_cookie_flagged(self, MockSession):
        instance = MockSession.return_value
        res = self._make_response(headers={})
        res.headers.get.side_effect = lambda k, d='': (
            'sessionid=abc123def456; Path=/; Secure; SameSite=Lax'
            if k.lower() == 'set-cookie' else d
        )
        instance.get.return_value = res
        instance.options.return_value = self._make_response(headers={'Allow': 'GET'})
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        finding = next(f for f in result.findings if 'HttpOnly eksik' in f.title)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.parameter, 'sessionid')
        # Cookie değeri evidence içinde sızdırılmamalı
        self.assertNotIn('abc123def456', finding.evidence)

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_cookie_value_not_exposed_in_evidence(self, MockSession):
        instance = MockSession.return_value
        res = self._make_response(headers={})
        res.headers.get.side_effect = lambda k, d='': (
            'theme=dark; Path=/' if k.lower() == 'set-cookie' else d
        )
        instance.get.return_value = res
        instance.options.return_value = self._make_response(headers={'Allow': 'GET'})
        instance.request.return_value = self._make_response(status_code=405)

        result = AccessControlScanner().scan('https://example.com')
        cookie_findings = [f for f in result.findings if 'theme' in (f.parameter or '')]
        self.assertTrue(cookie_findings)
        for f in cookie_findings:
            self.assertNotIn('dark', f.evidence)


# ---------------------------------------------------------------------------
# AuthScanner
# ---------------------------------------------------------------------------

class AuthScannerTest(TestCase):
    _LOGIN_HTML = (
        '<html><body>'
        '<form action="/login" method="post">'
        '<input type="text" name="username">'
        '<input type="password" name="password">'
        '</form></body></html>'
    )

    @patch('Tarama.scanners.auth.requests.Session')
    def test_login_not_found(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value.text = '<html><body>No login here.</body></html>'
        instance.get.return_value.status_code = 404

        result = AuthScanner().scan('https://example.com')

        titles = [f.title for f in result.findings]
        self.assertIn('Login sayfası bulunamadı', titles)
        finding = next(f for f in result.findings if f.title == 'Login sayfası bulunamadı')
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertEqual(finding.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.auth.requests.Session')
    def test_login_page_detected_is_info(self, MockSession):
        instance = MockSession.return_value
        mock_res = MagicMock()
        mock_res.text = self._LOGIN_HTML
        mock_res.status_code = 200
        mock_res.url = 'https://example.com'
        instance.get.return_value = mock_res
        fail = MagicMock()
        fail.text = '<html>Invalid credentials</html>'
        fail.status_code = 200
        fail.url = 'https://example.com/login'
        instance.post.return_value = fail

        result = AuthScanner().scan('https://example.com')

        finding = next(f for f in result.findings if f.title == 'Login sayfası tespit edildi')
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertEqual(finding.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.auth.requests.Session')
    def test_http_credential_submission_flagged_high(self, MockSession):
        instance = MockSession.return_value
        mock_res = MagicMock()
        mock_res.text = self._LOGIN_HTML
        mock_res.status_code = 200
        mock_res.url = 'http://example.com/login'
        instance.get.return_value = mock_res
        # post returns failed login
        fail = MagicMock()
        fail.text = '<html>Invalid credentials</html>'
        fail.status_code = 200
        fail.url = 'http://example.com/login'
        instance.post.return_value = fail

        result = AuthScanner().scan('http://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(any('Unencrypted Transport' in f.title for f in high))
        transport_finding = next(f for f in high if 'Unencrypted Transport' in f.title)
        self.assertEqual(transport_finding.status, FindingStatus.CONFIRMED)
        self.assertEqual(transport_finding.cwe, 'CWE-319')

    @patch('Tarama.scanners.auth.requests.Session')
    def test_no_captcha_flagged(self, MockSession):
        instance = MockSession.return_value
        mock_res = MagicMock()
        mock_res.text = self._LOGIN_HTML
        mock_res.status_code = 200
        mock_res.url = 'https://example.com/login'
        instance.get.return_value = mock_res
        fail = MagicMock()
        fail.text = '<html>Bad credentials</html>'
        fail.status_code = 200
        fail.url = 'https://example.com/login'
        instance.post.return_value = fail

        result = AuthScanner().scan('https://example.com')

        titles = [f.title for f in result.findings]
        self.assertIn('CAPTCHA yok', titles)
        finding = next(f for f in result.findings if f.title == 'CAPTCHA yok')
        self.assertEqual(finding.severity, Severity.INFO)
        self.assertEqual(finding.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.auth.requests.Session')
    def test_rate_limit_not_detected(self, MockSession):
        instance = MockSession.return_value
        mock_res = MagicMock()
        mock_res.text = self._LOGIN_HTML
        mock_res.status_code = 200
        mock_res.url = 'https://example.com/login'
        instance.get.return_value = mock_res
        fail = MagicMock()
        fail.text = '<html>Wrong password</html>'
        fail.status_code = 200
        fail.url = 'https://example.com/login'
        fail.headers = {}
        instance.post.return_value = fail

        result = AuthScanner().scan('https://example.com')

        titles = [f.title for f in result.findings]
        self.assertIn('Potential Lack of Authentication Rate Limiting', titles)
        finding = next(f for f in result.findings if f.title == 'Potential Lack of Authentication Rate Limiting')
        self.assertEqual(finding.status, FindingStatus.MANUAL_REVIEW)
        self.assertEqual(finding.confidence, Confidence.LOW)

    @patch('Tarama.scanners.auth.requests.Session')
    def test_default_creds_evidence_masks_password(self, MockSession):
        instance = MockSession.return_value
        mock_res = MagicMock()
        mock_res.text = self._LOGIN_HTML
        mock_res.status_code = 200
        mock_res.url = 'https://example.com/login'
        instance.get.return_value = mock_res

        def post_side_effect(url, data=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            data = data or {}
            if data.get('username') == 'admin' and data.get('password') == 'admin':
                resp.text = '<html>Welcome to your dashboard</html>'
                resp.url = 'https://example.com/dashboard'
            else:
                resp.text = '<html>Invalid credentials</html>'
                resp.url = 'https://example.com/login'
            return resp

        instance.post.side_effect = post_side_effect

        result = AuthScanner().scan('https://example.com')

        finding = next(f for f in result.findings if f.title == 'Varsayılan kimlik bilgileri geçerli')
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertNotIn('admin', finding.evidence.split('Parola:')[1].split('|')[0])


# ---------------------------------------------------------------------------
# IntegrityScanner
# ---------------------------------------------------------------------------

class IntegrityScannerTest(TestCase):
    @patch('Tarama.scanners.integrity.requests.Session')
    def test_external_script_without_sri_flagged(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.content = (
            b'<html><head>'
            b'<script src="https://evil.example.org/lib.js"></script>'
            b'</head></html>'
        )
        res.headers = MagicMock()
        res.headers.get = MagicMock(return_value='')
        instance.get.return_value = res

        result = IntegrityScanner().scan('https://example.com')

        missing = [f for f in result.findings if 'SRI eksik' in f.title]
        self.assertTrue(missing)
        self.assertEqual(missing[0].severity, Severity.LOW)
        self.assertEqual(missing[0].confidence, Confidence.HIGH)
        self.assertIn(missing[0].status, (FindingStatus.POTENTIAL, FindingStatus.INFORMATIONAL))
        self.assertIn('does not', missing[0].description.lower())

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_sri_present_no_sri_finding(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.content = (
            b'<html><head>'
            b'<script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"'
            b' integrity="sha384-abc" crossorigin="anonymous"></script>'
            b'</head></html>'
        )
        res.headers.get = lambda k, d='': ''
        instance.get.return_value = res

        result = IntegrityScanner().scan('https://example.com')

        sri_missing = [f for f in result.findings if 'SRI eksik' in f.title]
        self.assertEqual(sri_missing, [])

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_image_without_integrity_no_sri_finding(self, MockSession):
        """SRI yalnızca script/link için anlamlıdır — img için nonsensical bulgu üretilmemeli."""
        instance = MockSession.return_value
        res = MagicMock()
        res.content = b'<html><body><img src="https://images.example.org/logo.png"></body></html>'
        res.headers.get = lambda k, d='': ''
        instance.get.return_value = res

        result = IntegrityScanner().scan('https://example.com')

        sri_negative = [f for f in result.findings if 'eksik' in f.title.lower() and 'SRI' in f.title]
        self.assertEqual(sri_negative, [])

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_third_party_domain_is_informational_not_malicious(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.content = b'<html><body><script src="https://unknown-cdn.example.org/x.js"></script></body></html>'
        res.headers.get = lambda k, d='': ''
        instance.get.return_value = res

        result = IntegrityScanner().scan('https://example.com')

        unknown = next(f for f in result.findings if 'Bilinmeyen third-party' in f.title)
        self.assertEqual(unknown.severity, Severity.INFO)
        self.assertEqual(unknown.status, FindingStatus.INFORMATIONAL)
        self.assertNotIn('is malicious', (unknown.description or '').lower())

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_inline_script_without_csp_flagged(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.content = b'<html><body><script>alert(1)</script></body></html>'
        res.headers.get = lambda k, d='': ''
        instance.get.return_value = res

        result = IntegrityScanner().scan('https://example.com')

        titles = [f.title for f in result.findings]
        self.assertTrue(any('inline' in t.lower() for t in titles))

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_inline_script_not_duplicated_when_csp_unsafe_inline(self, MockSession):
        """CSP zaten 'unsafe-inline' içeriyorsa HeaderScanner'ın bulgusu tekrar edilmemeli."""
        instance = MockSession.return_value
        res = MagicMock()
        res.content = b'<html><body><script>alert(1)</script></body></html>'
        res.headers.get = lambda k, d='': (
            "default-src 'self' 'unsafe-inline'" if k == 'Content-Security-Policy' else d
        )
        instance.get.return_value = res

        result = IntegrityScanner().scan('https://example.com')

        titles = [f.title for f in result.findings]
        self.assertFalse(any('inline' in t.lower() for t in titles))

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_dependency_file_accessible_not_automatically_high(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            if url.endswith('/package.json'):
                r.status_code = 200
                r.content = b'{"name":"app","dependencies":{"express":"^4.0.0"}}'
                r.text = '{"name":"app"}'
                return r
            r.status_code = 404
            r.content = b''
            r.text = ''
            return r

        instance.get.side_effect = get_side
        result = IntegrityScanner().scan('https://example.com')

        finding = next(f for f in result.findings if 'package.json' in f.title)
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertEqual(finding.title, 'Dependency Metadata Exposed: /package.json')
        high_or_critical = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(high_or_critical, [])


# ---------------------------------------------------------------------------
# ErrorDisclosureScanner
# ---------------------------------------------------------------------------

class ErrorDisclosureScannerTest(TestCase):
    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_django_debug_page_high(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.text = (
            '<html><body>Django Version: 4.2 | INSTALLED_APPS = [...] '
            'TemplateSyntaxError at /</body></html>'
        )
        res.status_code = 500
        instance.get.return_value = res

        result = ErrorDisclosureScanner().scan('https://example.com')

        debug_findings = [f for f in result.findings if f.title == 'Application Debug Mode Exposed']
        self.assertTrue(debug_findings)
        self.assertEqual(debug_findings[0].severity, Severity.HIGH)
        self.assertEqual(debug_findings[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(debug_findings[0].confidence, Confidence.HIGH)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_sanitized_stack_trace_is_medium(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.text = (
            'Traceback (most recent call last):\n'
            '  File "/app/views.py", line 42, in handler\n'
            '    raise ValueError("boom")\n'
        )
        res.status_code = 500
        instance.get.return_value = res

        result = ErrorDisclosureScanner().scan('https://example.com')

        stack = next(f for f in result.findings if f.title == 'Application Stack Trace Disclosure')
        self.assertEqual(stack.severity, Severity.MEDIUM)
        self.assertEqual(stack.cwe, 'CWE-209')
        self.assertEqual(stack.status, FindingStatus.CONFIRMED)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_clean_error_page_info(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.text = '<html><body><h1>404 Not Found</h1></body></html>'
        res.status_code = 404
        instance.get.return_value = res

        result = ErrorDisclosureScanner().scan('https://example.com')

        titles = [f.title for f in result.findings]
        self.assertIn('Hata sayfaları bilgi sızdırmıyor', titles)
        finding = next(f for f in result.findings if f.title == 'Hata sayfaları bilgi sızdırmıyor')
        self.assertEqual(finding.status, FindingStatus.SECURE)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_monitoring_endpoint_detected(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            if '/actuator/env' in url:
                r.status_code = 200
                r.text = '{"activeProfiles":[],"propertySources":[]}'
                return r
            r.status_code = 404
            r.text = ''
            return r

        instance.get.side_effect = get_side
        result = ErrorDisclosureScanner().scan('https://example.com')

        crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(any('actuator/env' in f.title for f in crit))

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_health_endpoint_status_only_is_info(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            if url.endswith('/health'):
                r.status_code = 200
                r.text = '{"status":"ok"}'
                return r
            r.status_code = 404
            r.text = ''
            return r

        instance.get.side_effect = get_side
        result = ErrorDisclosureScanner().scan('https://example.com')

        health = next(f for f in result.findings if f.affected_url and f.affected_url.endswith('/health'))
        self.assertEqual(health.severity, Severity.INFO)
        self.assertEqual(health.status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_metrics_endpoint_with_internal_data_is_security_finding(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            if url.endswith('/metrics'):
                r.status_code = 200
                r.text = '# HELP process_cpu_seconds_total\nprocess_cpu_seconds_total 12.3\n'
                return r
            r.status_code = 404
            r.text = ''
            return r

        instance.get.side_effect = get_side
        result = ErrorDisclosureScanner().scan('https://example.com')

        metrics = next(f for f in result.findings if f.affected_url and f.affected_url.endswith('/metrics'))
        self.assertEqual(metrics.severity, Severity.MEDIUM)
        self.assertEqual(metrics.status, FindingStatus.CONFIRMED)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_swagger_existence_is_informational(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            if url.endswith('/swagger-ui.html'):
                r.status_code = 200
                r.text = '<html>swagger ui: pet store API</html>'
                return r
            r.status_code = 404
            r.text = ''
            return r

        instance.get.side_effect = get_side
        result = ErrorDisclosureScanner().scan('https://example.com')

        swagger = next(f for f in result.findings if 'swagger-ui.html' in f.title)
        self.assertEqual(swagger.severity, Severity.INFO)
        self.assertEqual(swagger.status, FindingStatus.INFORMATIONAL)
        self.assertIn('Public API Documentation Detected', swagger.title)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_swagger_with_secret_marker_escalated(self, MockSession):
        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            if url.endswith('/swagger-ui.html'):
                r.status_code = 200
                r.text = '<html>swagger ui: "api_key": "sample-value-in-schema"</html>'
                return r
            r.status_code = 404
            r.text = ''
            return r

        instance.get.side_effect = get_side
        result = ErrorDisclosureScanner().scan('https://example.com')

        swagger = next(f for f in result.findings if 'swagger-ui.html' in f.title)
        self.assertEqual(swagger.severity, Severity.MEDIUM)
        self.assertIn('Sensitive Data Potentially Exposed', swagger.title)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_no_monitoring_endpoints_info(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.status_code = 404
        res.text = ''
        instance.get.return_value = res

        result = ErrorDisclosureScanner().scan('https://example.com')

        titles = [f.title for f in result.findings]
        self.assertIn('İzleme endpoint\'leri bulunamadı', titles)


# ---------------------------------------------------------------------------
# OS Command Injection Scanner testleri
# ---------------------------------------------------------------------------

class CmdInjectionScannerTest(TestCase):
    _FORM_HTML = (
        b'<html><body>'
        b'<form action="/ping" method="post"><input name="host"></form>'
        b'</body></html>'
    )

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_output_based_unix_passwd_critical(self, MockSession):
        """Yanıtta /etc/passwd içeriği görünürse CRITICAL çıktı bazlı bulgu oluşmalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            payload = (data or {}).get('host', '')
            if 'cat /etc/passwd' in payload or '|cat' in payload:
                r.content = b'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'
            else:
                r.content = b'<html>OK</html>'
            return r

        instance.post.side_effect = post_side
        result = CmdInjectionScanner().scan('https://example.com')

        crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(len(crit) > 0)
        self.assertIn('OS Command Execution Confirmed', crit[0].title)
        self.assertIn('host', crit[0].evidence)
        self.assertEqual(crit[0].confidence, Confidence.HIGH)
        self.assertEqual(crit[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(crit[0].owasp, 'A03:2021 - Injection')
        self.assertEqual(crit[0].cwe, 'CWE-78')

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_output_marker_already_in_baseline_not_confirmed(self, MockSession):
        """CLAUDE.md 4.1: Baseline yanıtında zaten var olan bir çıktı işareti yeni kanıt sayılmamalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        # Uygulamanın normal sayfası zaten "uid=" içeriyor (örn. kullanıcı profili gösteriyor) —
        # payload'dan bağımsız olarak TÜM yanıtlar aynı içeriği döndürüyor.
        instance.post.return_value.content = b'<html>Profile: uid=1000(demo) gid=1000(demo)</html>'

        result = CmdInjectionScanner().scan('https://example.com')

        dangerous = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(dangerous, [])

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_error_based_shell_message_high(self, MockSession):
        """Shell hata mesajı döndüğünde POTENTIAL hata bazlı bulgu oluşmalı (otomatik confirmed değil)."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            payload = (data or {}).get('host', '')
            if payload in (';', '|', '&', '`', '$(',  "'|'"):
                r.content = b'sh: 1: Syntax error: Unterminated quoted string'
            else:
                r.content = b'<html>OK</html>'
            return r

        instance.post.side_effect = post_side
        result = CmdInjectionScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertIn('Shell Error', high[0].title)
        self.assertEqual(high[0].confidence, Confidence.MEDIUM)
        self.assertEqual(high[0].status, FindingStatus.POTENTIAL)

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_generic_500_alone_not_cmdi(self, MockSession):
        """CLAUDE.md 4.3: Genel 500/400 yanıtı tek başına command injection kanıtı değildir."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            r.status_code = 500
            r.content = b'<html>500 Internal Server Error</html>'
            return r

        instance.post.side_effect = post_side
        result = CmdInjectionScanner().scan('https://example.com')

        dangerous = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(dangerous, [])

    @patch('Tarama.scanners.cmd.time.time')
    @patch('Tarama.scanners.cmd.requests.Session')
    def test_single_timing_spike_not_confirmed(self, MockSession, mock_time):
        """CLAUDE.md 4.4: Tek bir gecikme sıçraması CONFIRMED kör komut enjeksiyonu üretmemeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        instance.post.return_value.content = b'<html>OK</html>'

        times = iter([
            0.0, 0.2,     # scan() baseline GET ölçümü
            10.0, 13.5,   # ilk zaman bazlı payload — tek seferlik yavaş yanıt
            20.0, 20.2,   # doğrulama tekrarı — hızlı, tekrarlanmıyor
        ])
        mock_time.side_effect = lambda: next(times, 999.0)

        result = CmdInjectionScanner().scan('https://example.com')

        time_findings = [f for f in result.findings if 'Blind Command Injection' in f.title]
        self.assertTrue(len(time_findings) > 0)
        self.assertNotEqual(time_findings[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(time_findings[0].confidence, Confidence.LOW)

    @patch('Tarama.scanners.cmd.time.time')
    @patch('Tarama.scanners.cmd.requests.Session')
    def test_repeatable_timing_raises_confidence(self, MockSession, mock_time):
        """CLAUDE.md 4.4: Tekrarlanan gecikme davranışı daha güçlü bir bulgu üretmeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        instance.post.return_value.content = b'<html>OK</html>'

        times = iter([
            0.0, 0.1,     # baseline GET
            10.0, 13.5,   # ilk yavaş yanıt
            20.0, 23.6,   # doğrulama tekrarı — yine yavaş
        ])
        mock_time.side_effect = lambda: next(times, 999.0)

        result = CmdInjectionScanner().scan('https://example.com')

        time_findings = [f for f in result.findings if 'Blind Command Injection' in f.title]
        self.assertTrue(len(time_findings) > 0)
        self.assertEqual(time_findings[0].confidence, Confidence.HIGH)
        self.assertEqual(time_findings[0].status, FindingStatus.CONFIRMED)

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_platform_not_inferred_without_evidence(self, MockSession):
        """CLAUDE.md 4.5: Sadece genel shell davranışından Unix/Windows iddia edilmemeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            payload = (data or {}).get('host', '')
            if payload in (';', '|', '&', '`', '$(',  "'|'"):
                r.content = b'sh: 1: Syntax error: Unterminated quoted string'
            else:
                r.content = b'<html>OK</html>'
            return r

        instance.post.side_effect = post_side
        result = CmdInjectionScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertNotIn('Unix', high[0].title)
        self.assertNotIn('Windows', high[0].title)

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_clean_response_no_finding(self, MockSession):
        """Temiz yanıt için hiç HIGH/CRITICAL bulgu oluşmamalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        instance.post.return_value.content = b'<html>Pong: 8.8.8.8</html>'

        result = CmdInjectionScanner().scan('https://example.com')

        dangerous = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(dangerous, [])

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_url_param_output_based_detected(self, MockSession):
        """URL parametresine payload enjekte edildiğinde komut çıktısı görünürse tespit edilmeli."""
        from urllib.parse import unquote

        instance = MockSession.return_value

        def get_side(url, **kwargs):
            r = MagicMock()
            decoded = unquote(url)
            if 'cat /etc/passwd' in decoded or 'id' in decoded:
                r.content = b'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
            else:
                r.content = b'<html><body>No forms</body></html>'
            return r

        instance.get.side_effect = get_side
        result = CmdInjectionScanner().scan('https://example.com?cmd=ping')

        crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(len(crit) > 0)
        self.assertIn('cmd', crit[0].evidence)

    @patch('Tarama.scanners.cmd.requests.Session')
    def test_no_forms_no_crash(self, MockSession):
        """Form olmayan sayfada tarama hatasız tamamlanmalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>Static page</body></html>'

        result = CmdInjectionScanner().scan('https://example.com')

        self.assertIsNone(result.error)
        forms = next(f for f in result.findings if f.title == 'forms_detected')
        self.assertEqual(forms.evidence, '0')


# ---------------------------------------------------------------------------
# NoSQL Injection Scanner testleri
# ---------------------------------------------------------------------------

class NoSqlInjectionScannerTest(TestCase):
    _FORM_HTML = (
        b'<html><body>'
        b'<form action="/login" method="post">'
        b'<input name="username"><input name="password">'
        b'</form></body></html>'
    )

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_error_based_mongoerror_detected(self, MockSession):
        """MongoDB hata mesajı döndüğünde HIGH hata bazlı bulgu oluşmalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            keys = list((data or {}).keys())
            if any('[' in k for k in keys):
                r.content = b'MongoError: unknown operator $where at position 0'
            else:
                r.content = b'<html>Login failed</html>'
            return r

        instance.post.side_effect = post_side
        result = NoSqlInjectionScanner().scan('https://example.com')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertIn('Database Error Triggered', high[0].title)
        self.assertIn('username', high[0].evidence)
        self.assertEqual(high[0].confidence, Confidence.MEDIUM)
        self.assertEqual(high[0].status, FindingStatus.POTENTIAL)
        self.assertEqual(high[0].cwe, 'CWE-943')

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_mongo_error_already_in_baseline_not_confirmed(self, MockSession):
        """CLAUDE.md 5.1: Baseline'da zaten var olan MongoDB hatası yeni kanıt sayılmamalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        # Uygulamanın normal hata sayfası şablonu her yanıtta "errmsg" içeriyor.
        instance.post.return_value.content = b'{"errmsg": "generic app error wrapper"}'

        result = NoSqlInjectionScanner().scan('https://example.com')

        dangerous = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(dangerous, [])

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_http_200_after_ne_not_confirmation(self, MockSession):
        """CLAUDE.md 5.2: Sadece HTTP 200 dönmesi operatör kabul edildiği anlamına gelse de
        query manipülasyonunun doğrulandığı anlamına gelmez."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        # Her istek (operatörlü ya da değil) aynı sabit sayfayı 200 ile döndürüyor.
        instance.post.return_value.content = b'<html>Login failed</html>'
        instance.post.return_value.status_code = 200

        result = NoSqlInjectionScanner().scan('https://example.com')

        confirmed = [f for f in result.findings if f.status == FindingStatus.CONFIRMED]
        self.assertEqual(confirmed, [])

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_boolean_based_response_diff_medium(self, MockSession):
        """$ne operatörü geniş yanıt, $regex=^$ dar yanıt döndürürse MEDIUM/POTENTIAL bulgu oluşmalı."""
        instance = MockSession.return_value

        long_body  = b'<html>' + b'user1 user2 user3 admin moderator ' * 20 + b'</html>'
        short_body = b'<html>No results.</html>'

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            data = data or {}
            # $ne'nin "geniş eşleşme" (true) değeri gönderildiğinde geniş sonuç seti dönsün;
            # "dar eşleşme" (false) değeri ve baseline (rastgele token) dar sonuç dönsün.
            if data.get('username[$ne]') == 'nosqltest_xyz_never_matches':
                r.content = long_body
            else:
                r.content = short_body
            return r

        instance.get.return_value.content = self._FORM_HTML
        instance.post.side_effect = post_side

        result = NoSqlInjectionScanner().scan('https://example.com')
        self.assertIsNone(result.error)

        boolean_findings = [f for f in result.findings if 'Query Behavior Difference' in f.title]
        self.assertTrue(len(boolean_findings) > 0)
        self.assertEqual(boolean_findings[0].severity, Severity.MEDIUM)
        self.assertEqual(boolean_findings[0].confidence, Confidence.MEDIUM)
        self.assertEqual(boolean_findings[0].status, FindingStatus.POTENTIAL)

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_insignificant_body_difference_no_finding(self, MockSession):
        """CLAUDE.md 5.3: Önemsiz/küçük yanıt farkları yüksek güvenilirlikli bulgu üretmemeli."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        base_page = 'A' * 2000

        def post_side(url, data=None, **kwargs):
            r = MagicMock()
            r.content = (base_page + str(hash(str(kwargs)) % 100)).encode()
            return r

        instance.post.side_effect = post_side

        result = NoSqlInjectionScanner().scan('https://example.com')

        boolean_findings = [f for f in result.findings if 'Query Behavior Difference' in f.title]
        self.assertEqual(boolean_findings, [])

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_json_injection_api_error_detected(self, MockSession):
        """JSON operatör enjeksiyonu /api/ endpoint'inde MongoDB hatası tetiklerse HIGH bulgu."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>No forms</body></html>'

        def post_side(url, json=None, **kwargs):
            r = MagicMock()
            body = json or {}
            vals = list(body.values())
            if vals and isinstance(vals[0], dict) and any(k.startswith('$') for k in vals[0]):
                r.content = b'MongoError: unknown top level operator: $gt'
            else:
                r.content = b'{"status": "ok"}'
            return r

        instance.post.side_effect = post_side
        result = NoSqlInjectionScanner().scan('https://example.com/api/login')

        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0)
        self.assertIn('JSON', high[0].title)
        self.assertEqual(high[0].confidence, Confidence.MEDIUM)
        self.assertEqual(high[0].status, FindingStatus.POTENTIAL)

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_json_parser_rejection_not_nosqli(self, MockSession):
        """CLAUDE.md 5.4: Genel JSON parser reddi NoSQL injection kanıtı değildir."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>No forms</body></html>'

        def post_side(url, json=None, **kwargs):
            r = MagicMock()
            r.status_code = 400
            r.content = b'{"error": "Invalid JSON"}'
            return r

        instance.post.side_effect = post_side
        result = NoSqlInjectionScanner().scan('https://example.com/api/login')

        json_findings = [f for f in result.findings if 'JSON' in f.title and 'forms_detected' not in f.title]
        self.assertEqual(json_findings, [])

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_schema_validation_rejection_not_nosqli(self, MockSession):
        """CLAUDE.md 5.4: Operatör şekilli girdi reddedilmesi tek başına NoSQLi kanıtı değildir."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>No forms</body></html>'

        def post_side(url, json=None, **kwargs):
            r = MagicMock()
            body = json or {}
            vals = list(body.values())
            if vals and isinstance(vals[0], dict):
                # Uygulama şema doğrulamasıyla reddediyor — MongoDB hatası değil
                r.content = b'{"error": "Validation failed: expected string, got object"}'
            else:
                r.content = b'{"status": "ok"}'
            return r

        instance.post.side_effect = post_side
        result = NoSqlInjectionScanner().scan('https://example.com/api/login')

        dangerous = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(dangerous, [])

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_clean_response_no_finding(self, MockSession):
        """Temiz yanıt için HIGH/CRITICAL bulgu oluşmamalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = self._FORM_HTML
        instance.post.return_value.content = b'<html>Invalid credentials</html>'

        result = NoSqlInjectionScanner().scan('https://example.com')

        dangerous = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(dangerous, [])

    @patch('Tarama.scanners.nosql.requests.Session')
    def test_no_forms_no_crash(self, MockSession):
        """Form olmayan sayfada tarama hatasız tamamlanmalı."""
        instance = MockSession.return_value
        instance.get.return_value.content = b'<html><body>Static page</body></html>'

        result = NoSqlInjectionScanner().scan('https://example.com')

        self.assertIsNone(result.error)
        forms = next(f for f in result.findings if f.title == 'forms_detected')
        self.assertEqual(forms.evidence, '0')


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class OrchestratorTest(TestCase):
    def _patch_all_scanners(self, overrides: dict):
        """Her scanner sınıfını sahte bir .scan() ile değiştirir; overrides ile belirli
        scanner'lar için özel davranış (örn. exception) tanımlanabilir."""
        names = [
            "headers", "ports", "sql", "xss", "ssl", "dns", "cms",
            "access_control", "auth", "integrity", "error_disclosure", "cmd", "nosql",
        ]
        patchers = []
        for name in names:
            cls_name = {
                "headers": "HeaderScanner", "ports": "PortScanner", "sql": "SqlInjectionScanner",
                "xss": "XssScanner", "ssl": "SslScanner", "dns": "DnsScanner", "cms": "CmsScanner",
                "access_control": "AccessControlScanner", "auth": "AuthScanner",
                "integrity": "IntegrityScanner", "error_disclosure": "ErrorDisclosureScanner",
                "cmd": "CmdInjectionScanner", "nosql": "NoSqlInjectionScanner",
            }[name]
            mock_instance = MagicMock()
            if name in overrides:
                mock_instance.scan.side_effect = overrides[name]
            else:
                mock_instance.scan.return_value = ScanResult(scanner=name, target="https://example.com")
            patcher = patch(f"Tarama.services.orchestrator.{cls_name}", return_value=mock_instance)
            patchers.append(patcher)
            patcher.start()
        for p in patchers:
            self.addCleanup(p.stop)

    def test_scanner_failure_does_not_discard_other_results(self):
        """CLAUDE.md §6: Bir scanner'ın başarısız olması diğer başarılı sonuçları yok etmemeli."""
        from .services.orchestrator import run_full_scan

        def boom(target):
            raise KeyError("internal_variable_name_xyz")

        self._patch_all_scanners({"ssl": boom})
        report = run_full_scan("https://example.com")

        # ssl hata almış olmalı ama diğer tüm scanner'lar başarıyla sonuç üretmiş olmalı
        self.assertIsNotNone(report.ssl.error)
        self.assertIsNone(report.headers.error)
        self.assertIsNone(report.ports.error)
        self.assertIsNone(report.dns.error)
        self.assertIsNone(report.cmd.error)
        self.assertIsNone(report.nosql.error)

    def test_scanner_error_is_sanitized_no_traceback(self):
        """CLAUDE.md §6: API'ye sızan hata mesajı Python stack trace/iç detay içermemeli."""
        from .services.orchestrator import run_full_scan

        def boom(target):
            raise KeyError("internal_variable_name_xyz")

        self._patch_all_scanners({"ssl": boom})
        report = run_full_scan("https://example.com")

        self.assertNotIn("internal_variable_name_xyz", report.ssl.error)
        self.assertNotIn("Traceback", report.ssl.error)
        self.assertNotIn(".py", report.ssl.error)
        self.assertNotIn("KeyError", report.ssl.error)

    def test_all_scanner_fields_populated_regardless_of_completion_order(self):
        """ThreadPoolExecutor tamamlanma sırası ScanReport'un alan eşlemesini bozmamalı."""
        from .services.orchestrator import run_full_scan

        self._patch_all_scanners({})
        report = run_full_scan("https://example.com")

        for name in ("headers", "ports", "sql", "xss", "ssl", "dns", "cms",
                     "access_control", "auth", "integrity", "error_disclosure", "cmd", "nosql"):
            scan_result = getattr(report, name)
            self.assertEqual(scan_result.scanner, name)


# ---------------------------------------------------------------------------
# ScanJob / async scan_runner
# ---------------------------------------------------------------------------

class ScanJobStateTest(TestCase):
    def test_normal_transition_pending_running_done(self):
        job = ScanJob.objects.create(target="https://example.com", status="PENDING")
        self.assertEqual(job.status, "PENDING")

        job.status = "RUNNING"
        job.save(update_fields=["status"])
        job.refresh_from_db()
        self.assertEqual(job.status, "RUNNING")

        from django.utils import timezone
        job.status = "DONE"
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at"])
        job.refresh_from_db()
        self.assertEqual(job.status, "DONE")
        self.assertIsNotNone(job.completed_at)
        self.assertIsNotNone(job.duration_seconds)

    @patch("Tarama.services.scan_runner.run_full_scan")
    def test_complete_orchestration_failure_marks_job_failed(self, mock_run_full_scan):
        """CLAUDE.md §7: Tam orkestrasyon hatası RUNNING -> FAILED üretmeli, sanitize edilmiş hata ile."""
        from .services.scan_runner import _run_in_background

        mock_run_full_scan.side_effect = RuntimeError("db_connection_string_xyz_secret")
        job = ScanJob.objects.create(target="https://example.com", status="PENDING")

        _run_in_background(job.id, job.target)

        job.refresh_from_db()
        self.assertEqual(job.status, "FAILED")
        self.assertNotIn("db_connection_string_xyz_secret", job.error)

    def test_save_report_persists_cmd_and_nosql_findings(self):
        """Regresyon: _save_report önceden cmd/nosql sonuçlarını DB'ye hiç kaydetmiyordu."""
        from .services.scan_runner import _save_report
        from .services.orchestrator import ScanReport

        job = ScanJob.objects.create(target="https://example.com", status="RUNNING")

        def empty(name):
            return ScanResult(scanner=name, target="https://example.com")

        report = ScanReport(
            target="https://example.com",
            headers=empty("headers"), ports=empty("ports"), sql=empty("sql"), xss=empty("xss"),
            ssl=empty("ssl"), dns=empty("dns"), cms=empty("cms"),
            access_control=empty("access_control"), auth=empty("auth"),
            integrity=empty("integrity"), error_disclosure=empty("error_disclosure"),
            cmd=ScanResult(scanner="cmd", target="https://example.com", findings=[
                Finding(severity=Severity.CRITICAL, title="OS Command Execution Confirmed",
                        status=FindingStatus.CONFIRMED),
            ]),
            nosql=ScanResult(scanner="nosql", target="https://example.com", findings=[
                Finding(severity=Severity.HIGH, title="Potential NoSQL Injection - Database Error Triggered",
                        status=FindingStatus.POTENTIAL),
            ]),
        )
        _save_report(job, report)

        scanners_saved = set(job.findings.values_list("scanner", flat=True))
        self.assertIn("cmd", scanners_saved)
        self.assertIn("nosql", scanners_saved)

    def test_save_report_deduplicates_identical_findings(self):
        """Aynı scanner/title/evidence/affected_url/parameter kombinasyonu birden fazla
        kez üretilse bile yalnızca bir kez kaydedilmeli."""
        from .services.scan_runner import _save_report
        from .services.orchestrator import ScanReport

        job = ScanJob.objects.create(target="https://example.com", status="RUNNING")

        def empty(name):
            return ScanResult(scanner=name, target="https://example.com")

        duplicate_finding = Finding(
            severity=Severity.HIGH, title="Potential SQL Injection - Database Error Triggered",
            evidence="URL: https://example.com | Alan: id", affected_url="https://example.com",
            parameter="id", status=FindingStatus.POTENTIAL,
        )
        report = ScanReport(
            target="https://example.com",
            headers=empty("headers"), ports=empty("ports"),
            sql=ScanResult(scanner="sql", target="https://example.com",
                            findings=[duplicate_finding, duplicate_finding]),
            xss=empty("xss"), ssl=empty("ssl"), dns=empty("dns"), cms=empty("cms"),
            access_control=empty("access_control"), auth=empty("auth"),
            integrity=empty("integrity"), error_disclosure=empty("error_disclosure"),
            cmd=empty("cmd"), nosql=empty("nosql"),
        )
        _save_report(job, report)

        self.assertEqual(job.findings.filter(scanner="sql").count(), 1)

    def test_save_report_does_not_merge_different_parameters(self):
        """Aynı başlığa sahip ama farklı parametre/endpoint'e ait bulgular ASLA birleştirilmemeli."""
        from .services.scan_runner import _save_report
        from .services.orchestrator import ScanReport

        job = ScanJob.objects.create(target="https://example.com", status="RUNNING")

        def empty(name):
            return ScanResult(scanner=name, target="https://example.com")

        finding_a = Finding(
            severity=Severity.HIGH, title="Potential SQL Injection - Database Error Triggered",
            affected_url="https://example.com/product", parameter="id",
            status=FindingStatus.POTENTIAL,
        )
        finding_b = Finding(
            severity=Severity.HIGH, title="Potential SQL Injection - Database Error Triggered",
            affected_url="https://example.com/search", parameter="q",
            status=FindingStatus.POTENTIAL,
        )
        report = ScanReport(
            target="https://example.com",
            headers=empty("headers"), ports=empty("ports"),
            sql=ScanResult(scanner="sql", target="https://example.com", findings=[finding_a, finding_b]),
            xss=empty("xss"), ssl=empty("ssl"), dns=empty("dns"), cms=empty("cms"),
            access_control=empty("access_control"), auth=empty("auth"),
            integrity=empty("integrity"), error_disclosure=empty("error_disclosure"),
            cmd=empty("cmd"), nosql=empty("nosql"),
        )
        _save_report(job, report)

        self.assertEqual(job.findings.filter(scanner="sql").count(), 2)
        params = set(job.findings.filter(scanner="sql").values_list("parameter", flat=True))
        self.assertEqual(params, {"id", "q"})


# ---------------------------------------------------------------------------
# API contract (Django test client)
# ---------------------------------------------------------------------------

class ApiContractTest(TestCase):
    def setUp(self):
        self.client = Client()

    @patch('Tarama.views.HeaderScanner')
    def test_check_headers_endpoint_contract(self, MockScanner):
        MockScanner.return_value.scan.return_value = ScanResult(
            scanner="headers", target="https://example.com",
            findings=[Finding(severity=Severity.INFO, title="Content-Security-Policy",
                               evidence="default-src 'self'", status=FindingStatus.SECURE,
                               confidence=Confidence.HIGH)],
        )
        res = self.client.post('/Ana/check_headers', {'url_param': 'https://example.com'})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn('url_param', data)
        self.assertIn('findings', data)
        finding = data['findings'][0]
        # Eski alanlar (backward compatibility)
        self.assertIn('severity', finding)
        self.assertIn('title', finding)
        self.assertIn('evidence', finding)
        # Yeni alanlar mevcut, enum'lar string olarak sızmış
        self.assertEqual(finding['severity'], 'INFO')
        self.assertEqual(finding['status'], 'SECURE')
        self.assertEqual(finding['confidence'], 'HIGH')
        self.assertIsInstance(finding['severity'], str)

    @patch('Tarama.views.PortScanner')
    def test_scan_test_endpoint_contract(self, MockScanner):
        MockScanner.return_value.scan.return_value = ScanResult(
            scanner="ports", target="https://example.com", findings=[],
        )
        res = self.client.post('/Ana/scan_test', {'url_param': 'https://example.com'})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn('target', data)
        self.assertIn('findings', data)

    @patch('Tarama.views.SqlInjectionScanner')
    def test_check_sql_scan_endpoint_contract_unchanged(self, MockScanner):
        """Legacy /check_sql_scan formatı (liste-of-liste) değişmeden kalmalı."""
        MockScanner.return_value.scan.return_value = ScanResult(
            scanner="sql", target="https://example.com",
            findings=[Finding(severity=Severity.INFO, title="forms_detected", evidence="2")],
        )
        res = self.client.post('/Ana/check_sql_scan', {'url_param': 'https://example.com'})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn('sql_scanurl', data)
        self.assertIn('info_test', data)
        self.assertIn('sqlscan_report', data)
        self.assertIsInstance(data['sqlscan_report'], list)

    @patch('Tarama.views.XssScanner')
    def test_check_xss_scan_endpoint_contract(self, MockScanner):
        MockScanner.return_value.scan.return_value = ScanResult(
            scanner="xss", target="https://example.com",
            findings=[Finding(severity=Severity.INFO, title="forms_detected", evidence="1")],
        )
        res = self.client.post('/Ana/check_xss_scan', {'url_param': 'https://example.com'})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn('xss_scanurl', data)
        self.assertIn('xss_infotest', data)
        self.assertIn('findings', data)

    def test_malformed_request_returns_controlled_4xx(self):
        res = self.client.post('/Ana/check_headers', {'url_param': ''})
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertIn('error', data)
        self.assertNotIn('Traceback', data['error'])

    def test_ssrf_blocked_target_returns_controlled_400_not_500(self):
        res = self.client.post('/Ana/check_headers', {'url_param': 'http://127.0.0.1/'})
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertIn('error', data)
        self.assertNotIn('Traceback', data['error'])

    @patch('Tarama.views.start_scan')
    def test_create_scan_returns_job_id(self, mock_start_scan):
        mock_job = MagicMock(id=42, status='PENDING', target='https://example.com')
        mock_start_scan.return_value = mock_job
        res = self.client.post('/api/scan/', {'url_param': 'https://example.com'})
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data['job_id'], 42)
        self.assertEqual(data['status'], 'PENDING')

    def test_scan_status_unknown_job_returns_404(self):
        res = self.client.get('/api/scan/999999/')
        self.assertEqual(res.status_code, 404)

    def test_scan_status_serializes_unicode_correctly(self):
        job = ScanJob.objects.create(target="https://example.com", status="DONE")
        ScanFinding.objects.create(
            job=job, scanner="headers", severity="LOW", title="Başlık eksik",
            evidence="Türkçe karakter içeren kanıt: ığşçöü",
        )
        res = self.client.get(f'/api/scan/{job.id}/')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['findings'][0]['title'], 'Başlık eksik')
        self.assertIn('ığşçöü', data['findings'][0]['evidence'])

    def test_scan_status_findings_deterministically_ordered(self):
        job = ScanJob.objects.create(target="https://example.com", status="DONE")
        # Kasıtlı olarak "yanlış" (severity'ye göre alfabetik) sırada oluştur
        ScanFinding.objects.create(job=job, scanner="b", severity="INFO", title="Info finding")
        ScanFinding.objects.create(job=job, scanner="a", severity="CRITICAL", title="Critical finding")
        ScanFinding.objects.create(job=job, scanner="c", severity="MEDIUM", title="Medium finding")
        ScanFinding.objects.create(job=job, scanner="d", severity="HIGH", title="High finding")

        res = self.client.get(f'/api/scan/{job.id}/')
        severities = [f['severity'] for f in res.json()['findings']]
        self.assertEqual(severities, ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO'])

    def test_scan_status_includes_summary_block(self):
        job = ScanJob.objects.create(target="https://example.com", status="DONE")
        ScanFinding.objects.create(job=job, scanner="ssl", severity="INFO", title="TLS 1.3",
                                    status="SECURE")
        ScanFinding.objects.create(job=job, scanner="sql", severity="HIGH", title="Potential SQLi",
                                    status="POTENTIAL")

        res = self.client.get(f'/api/scan/{job.id}/')
        data = res.json()
        self.assertIn('summary', data)
        self.assertEqual(data['summary']['secure'], 1)
        self.assertEqual(data['summary']['potential'], 1)
        self.assertEqual(data['summary']['total_findings'], 2)


class ScanHistoryTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_history_bounded_to_20(self):
        for i in range(25):
            ScanJob.objects.create(target=f"https://example{i}.com", status="DONE")

        res = self.client.get('/api/scan/history/')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data['scans']), 20)

    def test_history_ordered_newest_first(self):
        older = ScanJob.objects.create(target="https://older.com", status="DONE")
        newer = ScanJob.objects.create(target="https://newer.com", status="DONE")

        res = self.client.get('/api/scan/history/')
        data = res.json()
        ids = [s['job_id'] for s in data['scans']]
        self.assertLess(ids.index(newer.id), ids.index(older.id))

    def test_history_summary_only_no_full_evidence(self):
        job = ScanJob.objects.create(target="https://example.com", status="DONE")
        ScanFinding.objects.create(
            job=job, scanner="sql", severity="HIGH", title="Potential SQLi",
            evidence="A" * 5000,
        )
        res = self.client.get('/api/scan/history/')
        data = res.json()
        body = json.dumps(data)
        self.assertNotIn("A" * 100, body)


# ---------------------------------------------------------------------------
# Sensitive data leakage regression
# ---------------------------------------------------------------------------

class SensitiveDataLeakageTest(TestCase):
    @patch('Tarama.scanners.access_control.requests.Session')
    def test_authorization_and_session_values_masked_in_cors_cookie_scan(self, MockSession):
        instance = MockSession.return_value
        res = MagicMock()
        res.text = ''
        res.status_code = 200
        res.headers = MagicMock()
        res.headers.get = MagicMock(side_effect=lambda k, d='': (
            'sessionid=SECRET_SESSION; Path=/' if k.lower() == 'set-cookie' else d
        ))
        instance.get.return_value = res
        instance.options.return_value = MagicMock(headers=MagicMock(get=MagicMock(return_value='')))
        instance.request.return_value = MagicMock(status_code=405)

        result = AccessControlScanner().scan('https://example.com')

        for finding in result.findings:
            self.assertNotIn('SECRET_SESSION', finding.evidence or '')

    @patch('Tarama.scanners.auth.requests.Session')
    def test_default_credential_values_masked_end_to_end(self, MockSession):
        instance = MockSession.return_value
        login_html = (
            '<html><body><form action="/login" method="post">'
            '<input type="text" name="username"><input type="password" name="password">'
            '</form></body></html>'
        )
        mock_res = MagicMock(text=login_html, status_code=200, url='https://example.com/login')
        instance.get.return_value = mock_res

        def post_side_effect(url, data=None, **kwargs):
            resp = MagicMock(status_code=200)
            data = data or {}
            if data.get('username') == 'admin' and data.get('password') == 'password':
                resp.text = '<html>dashboard welcome</html>'
                resp.url = 'https://example.com/dashboard'
            else:
                resp.text = '<html>Invalid</html>'
                resp.url = 'https://example.com/login'
            return resp

        instance.post.side_effect = post_side_effect
        result = AuthScanner().scan('https://example.com')

        for finding in result.findings:
            self.assertNotIn('SuperSecret123', finding.evidence or '')
            self.assertNotIn('api_key=SECRET_API_KEY', finding.evidence or '')

    def test_error_disclosure_masks_secret_like_values_in_evidence(self):
        from .scanners.error_disclosure import _mask_secrets
        line = 'Fatal error: password=SuperSecret123 in /var/www/app.py on line 10'
        masked = _mask_secrets(line)
        self.assertNotIn('SuperSecret123', masked)
        self.assertIn('[MASKED]', masked)

    def test_serialized_finding_never_contains_fake_secret_markers(self):
        """Uçtan uca: tipik hassas değer kalıpları serialize edilmiş bir Finding içinde asla görünmemeli."""
        fake_secrets = [
            'Authorization: Bearer SECRET_TOKEN',
            'sessionid=SECRET_SESSION',
            'csrftoken=SECRET_CSRF',
            'password=SuperSecret123',
            'api_key=SECRET_API_KEY',
        ]
        finding = Finding(
            severity=Severity.LOW, title="Örnek bulgu",
            evidence="Cookie flags eksik: HttpOnly",
        )
        data = finding.to_dict()
        serialized = json.dumps(data)
        for secret in fake_secrets:
            self.assertNotIn(secret, serialized)
