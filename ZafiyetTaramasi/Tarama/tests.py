import json
import logging
import socket
import ssl
from unittest.mock import MagicMock, patch

import requests
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


# ---------------------------------------------------------------------------
# Ağ tripwire'ı — test suite hiçbir koşulda gerçek DNS / ağ erişimi yapmamalı
# ---------------------------------------------------------------------------

class NetworkAccessAttempted(BaseException):
    """Bir test gerçek DNS çözümlemesi veya socket bağlantısı denedi.

    BaseException alt sınıfıdır: scanner'ların kasıtlı geniş `except Exception`
    blokları bu hatayı yutup testi sessizce geçirmesin."""


def _network_tripwire(name: str):
    def _blocked(*args, **kwargs):
        raise NetworkAccessAttempted(f"Test gerçek ağ erişimi denedi: socket.{name}{args!r}")
    return _blocked


# Bir test bu fonksiyonları kendisi mock'larsa yalnızca o testin süresince tripwire'ın
# önüne geçer; mock kalkınca tripwire geri gelir.
_NETWORK_TRIPWIRES = [
    patch(f'socket.{name}', new=_network_tripwire(name))
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'create_connection')
] + [
    patch.object(socket.socket, name, new=_network_tripwire(name))
    for name in ('connect', 'connect_ex')
]


def setUpModule():
    for tripwire in _NETWORK_TRIPWIRES:
        tripwire.start()


def tearDownModule():
    for tripwire in reversed(_NETWORK_TRIPWIRES):
        tripwire.stop()


def _http_response(status: int, text: str = '', url: str = 'https://example.com/',
                   headers: dict | None = None) -> requests.Response:
    """Gerçek requests.Response: bool(r) == r.ok — 4xx/5xx yanıtlar FALSY'dir.

    Kalıcı olarak truthy olan MagicMock'ların gizlediği 'if not res' hatalarını
    yakalamak için HTTP durum semantiği önemli olan testlerde kullanılır."""
    from requests.structures import CaseInsensitiveDict
    response = requests.Response()
    response.status_code = status
    response.reason = {200: 'OK', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
                       429: 'Too Many Requests', 500: 'Internal Server Error',
                       503: 'Service Unavailable'}.get(status, '')
    response._content = text.encode()
    response.encoding = 'utf-8'
    response.url = url
    response.headers = CaseInsensitiveDict(headers or {})
    return response


def _public_dns(ip: str = '93.184.216.34'):
    """getaddrinfo yerine: her host'u verilen public IP'ye çözer (gerçek DNS yok)."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip, port or 0))]
    return patch('socket.getaddrinfo', side_effect=fake_getaddrinfo)


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
        # Eskiden google.com için gerçek DNS çözümlemesi yapıyordu — artık mock'lu
        with _public_dns() as mock_resolve:
            validate_url('https://google.com')  # should not raise
        mock_resolve.assert_called()

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
        """[::1] bir IPv6 loopback literal'idir — DNS'e gidilmeden doğrudan reddedilir."""
        with self.assertRaises(SSRFError):
            validate_url('http://[::1]/')

    def test_userinfo_does_not_bypass_guard(self):
        """URL'de userinfo (user:pass@) olması host tabanlı kontrolü atlatmamalı."""
        with self.assertRaises(SSRFError):
            validate_url('http://attacker:password@127.0.0.1/')

    @patch('Tarama.services.ssrf_guard.socket.getaddrinfo')
    def test_hostname_resolving_to_private_ip_blocked(self, mock_resolve):
        """Herkese açık görünen bir alan adı özel bir IP'ye çözülüyorsa yine engellenmeli
        (DNS rebinding senaryosu) — guard çözümlenen IP'yi kontrol eder, hostname'i değil."""
        mock_resolve.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.50', 0))]
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
        """HeaderScanner artık SSRF korumalı safe_http oturumunu kullanır (eskiden urllib).
        Dönen değer mock'lanan requests.Session örneğidir: get() verilen header'larla
        HTTP 200 yanıtı döner."""
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(status_code=200, reason='OK', headers=headers)
        return mock_session

    @patch('Tarama.scanners.headers.requests.Session')
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

    @patch('Tarama.scanners.headers.requests.Session')
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

    @patch('Tarama.scanners.headers.requests.Session')
    def test_missing_xss_protection_is_info(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({})
        result = HeaderScanner().scan('https://example.com')
        finding = next(f for f in result.findings if f.title == 'X-XSS-Protection eksik')
        self.assertEqual(finding.severity, Severity.INFO)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_missing_hsts_not_reported_on_http_target(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({})
        result = HeaderScanner().scan('http://example.com')
        titles = [f.title for f in result.findings]
        self.assertNotIn('Strict-Transport-Security eksik', titles)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_csp_frame_ancestors_suppresses_xfo_duplicate(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertNotIn('X-Frame-Options eksik', titles)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_present_header_marked_secure_not_vulnerability(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Content-Security-Policy': "default-src 'self'",
        })
        result = HeaderScanner().scan('https://example.com')
        finding = next(f for f in result.findings if f.title == 'Content-Security-Policy')
        self.assertEqual(finding.status, FindingStatus.SECURE)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_hsts_low_max_age_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Strict-Transport-Security': 'max-age=3600',
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('HSTS max-age yetersiz', titles)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_hsts_missing_includesubdomains_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            'Strict-Transport-Security': 'max-age=31536000',
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('HSTS includeSubDomains eksik', titles)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_csp_unsafe_inline_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        })
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn("CSP 'unsafe-inline' içeriyor", titles)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_xss_protection_disabled_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({'X-XSS-Protection': '0'})
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('X-XSS-Protection açıkça devre dışı bırakılmış', titles)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_server_version_leak_flagged(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({'Server': 'Apache/2.4.41'})
        result = HeaderScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertIn('Server bilgi sızdırıyor', titles)

    @patch('Tarama.scanners.headers.requests.Session')
    def test_connection_error_stored_in_result(self, mock_urlopen):
        mock_urlopen.return_value.get.side_effect = requests.ConnectionError("Connection refused")
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
    def setUp(self):
        # Port bağlantıları artık safe_socket.connect_validated üzerinden: host her
        # bağlantıdan önce getaddrinfo ile çözümlenip doğrulanır (mock'lu, gerçek DNS yok).
        dns = _public_dns()
        dns.start()
        self.addCleanup(dns.stop)

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
    def setUp(self):
        # TLS bağlantıları artık safe_socket.connect_validated üzerinden (mock'lu DNS).
        dns = _public_dns()
        dns.start()
        self.addCleanup(dns.stop)

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
        # Gerçek Response: HTTP 500 falsy'dir (MagicMock bu hatayı gizliyordu)
        instance.get.return_value = _http_response(500, (
            '<html><body>Django Version: 4.2 | INSTALLED_APPS = [...] '
            'TemplateSyntaxError at /</body></html>'
        ))

        result = ErrorDisclosureScanner().scan('https://example.com')

        debug_findings = [f for f in result.findings if f.title == 'Application Debug Mode Exposed']
        self.assertTrue(debug_findings)
        self.assertEqual(debug_findings[0].severity, Severity.HIGH)
        self.assertEqual(debug_findings[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(debug_findings[0].confidence, Confidence.HIGH)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_sanitized_stack_trace_is_medium(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value = _http_response(500, (
            'Traceback (most recent call last):\n'
            '  File "/app/views.py", line 42, in handler\n'
            '    raise ValueError("boom")\n'
        ))

        result = ErrorDisclosureScanner().scan('https://example.com')

        stack = next(f for f in result.findings if f.title == 'Application Stack Trace Disclosure')
        self.assertEqual(stack.severity, Severity.MEDIUM)
        self.assertEqual(stack.cwe, 'CWE-209')
        self.assertEqual(stack.status, FindingStatus.CONFIRMED)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_clean_error_page_info(self, MockSession):
        instance = MockSession.return_value
        instance.get.return_value = _http_response(404, '<html><body><h1>404 Not Found</h1></body></html>')

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
        # views._parse_target → validate_url eskiden example.com için gerçek DNS yapıyordu
        dns = _public_dns()
        dns.start()
        self.addCleanup(dns.stop)

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
        # P0-2: tek, tutarlı redaksiyon işareti ([MASKED] yerine)
        self.assertIn('[REDACTED]', masked)

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


# ---------------------------------------------------------------------------
# P0-1: Giden istek SSRF zorlaması (services/safe_http.py)
# ---------------------------------------------------------------------------

import io

from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from .services import safe_http
from .services.safe_http import (
    MAX_REDIRECTS, OUTBOUND_BLOCKED_MESSAGE, OutboundRequestBlocked, SafeSession,
    SSRFGuardAdapter, safe_session,
)
from .services.ssrf_guard import is_blocked_ip

_PUBLIC_IP = '93.184.216.34'
_PUBLIC_IP_2 = '93.184.216.35'


def _addrinfo(ip: str):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip, 0))


class _FakeTransport:
    """HTTPAdapter.send yerine geçer: ağa çıkmaz, URL → (status, headers, body) eşlemesi döner.
    Tanımsız URL'ler 404 döner. Gönderilen her (method, url) kaydedilir."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.requested: list[tuple[str, str]] = []

    def __call__(self, adapter, request, *args, **kwargs):
        self.requested.append((request.method, request.url))
        route = self.routes.get(request.url, (404, {}, ''))
        if callable(route):
            route = route(request)
        status, headers, body = route
        resp = requests.Response()
        resp.status_code = status
        resp.reason = 'Found' if 300 <= status < 400 else 'OK'
        resp.headers = CaseInsensitiveDict(headers)
        resp._content = body.encode() if isinstance(body, str) else body
        resp._content_consumed = True
        resp.raw = io.BytesIO(b'')
        resp.url = request.url
        resp.request = request
        return resp

    def hosts(self) -> set:
        from urllib.parse import urlsplit
        return {urlsplit(url).hostname for _method, url in self.requested}


class _SafeHttpTestBase(TestCase):
    """Gerçek ağ erişimi imkânsız: DNS + transport mock'lanır, socket.connect ve
    gethostbyname çağrılırsa test başarısız olur."""

    def setUp(self):
        self._start(patch.object(socket.socket, 'connect',
                                 side_effect=AssertionError('gerçek ağ bağlantısı denendi')))
        self._start(patch('socket.gethostbyname',
                          side_effect=AssertionError('gerçek DNS çözümlemesi denendi')))
        self._start(patch('requests.utils.proxy_bypass', return_value=False))
        # Engellenen istekler WARNING loglar — test çıktısını kirletmemesi için susturulur
        self._start(patch.object(safe_http.logger, 'disabled', True))

    def _start(self, patcher):
        mocked = patcher.start()
        self.addCleanup(patcher.stop)
        return mocked

    def _dns(self, mapping: dict):
        """host → [ip, ...] veya host → çağrılabilir (her çağrıda farklı yanıt için)."""
        def fake_getaddrinfo(host, port, *args, **kwargs):
            ips = mapping.get(host)
            if callable(ips):
                ips = ips()
            if ips is None:
                raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
            return [_addrinfo(ip) for ip in ips]
        return self._start(patch('Tarama.services.ssrf_guard.socket.getaddrinfo',
                                 side_effect=fake_getaddrinfo))

    def _transport(self, routes: dict) -> _FakeTransport:
        """Test başına tek patch; tekrar çağrılırsa rotalar ve kayıt sıfırlanır (subTest döngüleri)."""
        transport = getattr(self, '_fake_transport', None)
        if transport is None:
            transport = self._fake_transport = _FakeTransport(routes)
            self._start(patch.object(HTTPAdapter, 'send', autospec=True, side_effect=transport))
        else:
            transport.routes = routes
            transport.requested = []
        return transport


class SsrfPolicyRangeTest(TestCase):
    """B, C, D, E, P: adres sınıflandırması — engellenmesi gerekenler ve public kalanlar."""

    def test_blocked_addresses(self):
        import ipaddress
        blocked = [
            '10.0.0.1', '172.16.5.4', '192.168.1.1',             # private
            '127.0.0.1', '127.1.2.3',                            # loopback
            '169.254.169.254', '169.254.0.1',                    # link-local / metadata
            '100.64.0.1', '100.100.100.200', '100.127.255.254',  # shared address space
            '0.0.0.0', '224.0.0.1', '239.255.255.250',           # unspecified, multicast
            '240.0.0.1', '255.255.255.255',                      # reserved, broadcast
            '::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'fec0::1', 'ff02::1',
            '::ffff:127.0.0.1', '::ffff:10.0.0.1',               # IPv4-mapped
            '2002:7f00:1::', '2002:a00:1::',                     # 6to4 içinde loopback/private
            '64:ff9b::a00:1', '64:ff9b::7f00:1',                 # NAT64 içinde private/loopback
        ]
        for value in blocked:
            with self.subTest(ip=value):
                self.assertTrue(is_blocked_ip(ipaddress.ip_address(value)))

    def test_public_addresses_not_blocked(self):
        import ipaddress
        for value in ('8.8.8.8', '1.1.1.1', _PUBLIC_IP, '100.63.255.255', '100.128.0.1',
                      '2606:4700:4700::1111', '2a00:1450:4001::64'):
            with self.subTest(ip=value):
                self.assertFalse(is_blocked_ip(ipaddress.ip_address(value)))

    def test_shared_address_space_rejected_by_validate_url(self):
        """E: 100.64.0.0/10 önceden reddedilmiyordu."""
        for url in ('http://100.64.0.1/', 'http://100.100.100.200/latest/meta-data/'):
            with self.subTest(url=url), self.assertRaises(SSRFError):
                validate_url(url)

    def test_ipv6_private_literals_rejected_by_validate_url(self):
        """P: IPv6 literal'leri DNS'e gitmeden reddedilir."""
        for url in ('http://[::1]/', 'http://[fc00::1]/', 'http://[fe80::1]/',
                    'http://[::ffff:127.0.0.1]/', 'http://[64:ff9b::a00:1]/'):
            with self.subTest(url=url), self.assertRaises(SSRFError):
                validate_url(url)

    @patch('Tarama.services.ssrf_guard.socket.getaddrinfo')
    def test_hostname_with_any_private_record_rejected(self, mock_resolve):
        """A + AAAA kayıtlarından biri bile private ise host reddedilir."""
        mock_resolve.return_value = [_addrinfo(_PUBLIC_IP), _addrinfo('::1')]
        with self.assertRaises(SSRFError):
            validate_url('https://mixed.example/')

    @patch('Tarama.services.ssrf_guard.socket.getaddrinfo')
    def test_hostname_resolving_to_ipv6_private_rejected(self, mock_resolve):
        mock_resolve.return_value = [_addrinfo('fd00::5')]
        with self.assertRaises(SSRFError):
            validate_url('https://v6-internal.example/')


class SafeSessionRequestTest(_SafeHttpTestBase):
    """A, B, C, D, E: tekil istekler safe session üzerinden."""

    def test_public_target_allowed(self):
        """A"""
        self._dns({'public.example': [_PUBLIC_IP]})
        transport = self._transport({'https://public.example/': (200, {}, 'ok')})

        res = safe_session().get('https://public.example/', timeout=5)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(transport.requested, [('GET', 'https://public.example/')])

    def test_private_loopback_link_local_and_shared_literals_rejected(self):
        """B, C, D, E: ağa hiç çıkılmaz."""
        self._dns({})
        transport = self._transport({})
        session = safe_session()
        for url in ('http://10.0.0.5/', 'http://192.168.1.10/', 'http://127.0.0.1:8000/',
                    'http://169.254.169.254/latest/meta-data/', 'http://100.64.0.1/',
                    'http://[::1]/', 'http://[fd00::1]/'):
            with self.subTest(url=url), self.assertRaises(OutboundRequestBlocked):
                session.get(url, timeout=5)
        self.assertEqual(transport.requested, [])

    def test_hostname_resolving_to_private_ip_rejected_before_send(self):
        self._dns({'intranet.example': ['10.0.0.7']})
        transport = self._transport({})
        with self.assertRaises(OutboundRequestBlocked):
            safe_session().get('https://intranet.example/', timeout=5)
        self.assertEqual(transport.requested, [])

    def test_non_http_scheme_rejected(self):
        self._transport({})
        for url in ('file:///etc/passwd', 'gopher://public.example/', 'ftp://public.example/'):
            with self.subTest(url=url), self.assertRaises(OutboundRequestBlocked):
                safe_session().get(url)

    def test_post_options_and_trace_also_enforced(self):
        self._dns({})
        transport = self._transport({})
        session = safe_session()
        with self.assertRaises(OutboundRequestBlocked):
            session.post('http://10.0.0.5/login', data={'u': 'x'})
        with self.assertRaises(OutboundRequestBlocked):
            session.options('http://127.0.0.1/')
        with self.assertRaises(OutboundRequestBlocked):
            session.request('TRACE', 'http://169.254.169.254/')
        self.assertEqual(transport.requested, [])

    def test_blocked_error_message_is_sanitized(self):
        """İç IP detayı yalnızca sunucu tarafı `reason`'da, str() sabit mesaj."""
        self._transport({})
        with self.assertRaises(OutboundRequestBlocked) as ctx:
            safe_session().get('http://10.9.8.7/')
        self.assertEqual(str(ctx.exception), OUTBOUND_BLOCKED_MESSAGE)
        self.assertNotIn('10.9.8.7', str(ctx.exception))
        self.assertIn('10.9.8.7', ctx.exception.reason)
        self.assertIsInstance(ctx.exception, requests.RequestException)

    def test_blocked_request_is_logged_server_side(self):
        self._transport({})
        with patch.object(safe_http.logger, 'disabled', False), \
                self.assertLogs('Tarama.services.safe_http', level='WARNING') as logs:
            with self.assertRaises(OutboundRequestBlocked):
                safe_session().get('http://127.0.0.1/secret?token=abc')
        self.assertIn('127.0.0.1', logs.output[0])
        self.assertNotIn('token=abc', logs.output[0])  # payload/query loga taşınmaz


class SafeSessionRedirectTest(_SafeHttpTestBase):
    """F–L: yönlendirmeler requests'e bırakılmaz; her hedef ağa çıkmadan doğrulanır."""

    def test_redirect_to_loopback_rejected(self):
        """F"""
        self._dns({'public.example': [_PUBLIC_IP]})
        transport = self._transport({
            'https://public.example/': (302, {'Location': 'http://127.0.0.1/admin'}, ''),
        })
        with self.assertRaises(OutboundRequestBlocked):
            safe_session().get('https://public.example/')
        self.assertNotIn('127.0.0.1', transport.hosts())

    def test_redirect_to_metadata_rejected(self):
        """G"""
        self._dns({'public.example': [_PUBLIC_IP]})
        transport = self._transport({
            'https://public.example/': (301, {'Location': 'http://169.254.169.254/latest/meta-data/'}, ''),
        })
        with self.assertRaises(OutboundRequestBlocked):
            safe_session().get('https://public.example/')
        self.assertNotIn('169.254.169.254', transport.hosts())

    def test_redirect_to_private_10_network_rejected(self):
        """H"""
        self._dns({'public.example': [_PUBLIC_IP]})
        transport = self._transport({
            'https://public.example/': (307, {'Location': 'http://10.1.2.3/internal'}, ''),
        })
        with self.assertRaises(OutboundRequestBlocked):
            safe_session().post('https://public.example/', data={'a': '1'})
        self.assertNotIn('10.1.2.3', transport.hosts())

    def test_redirect_to_hostname_resolving_private_rejected(self):
        self._dns({'public.example': [_PUBLIC_IP], 'internal.example': ['192.168.0.9']})
        transport = self._transport({
            'https://public.example/': (302, {'Location': 'https://internal.example/'}, ''),
        })
        with self.assertRaises(OutboundRequestBlocked):
            safe_session().get('https://public.example/')
        self.assertNotIn('internal.example', transport.hosts())

    def test_redirect_to_file_scheme_rejected(self):
        self._dns({'public.example': [_PUBLIC_IP]})
        self._transport({'https://public.example/': (302, {'Location': 'file:///etc/passwd'}, '')})
        with self.assertRaises(OutboundRequestBlocked):
            safe_session().get('https://public.example/')

    def test_public_to_public_redirect_followed(self):
        """I"""
        self._dns({'a.example': [_PUBLIC_IP], 'b.example': [_PUBLIC_IP_2]})
        transport = self._transport({
            'https://a.example/': (302, {'Location': 'https://b.example/final'}, ''),
            'https://b.example/final': (200, {}, 'landed'),
        })
        res = safe_session().get('https://a.example/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.url, 'https://b.example/final')
        self.assertEqual(res.text, 'landed')
        self.assertEqual(len(res.history), 1)
        self.assertEqual([url for _m, url in transport.requested],
                         ['https://a.example/', 'https://b.example/final'])

    def test_relative_redirect_followed(self):
        """J"""
        self._dns({'a.example': [_PUBLIC_IP]})
        transport = self._transport({
            'https://a.example/start/page': (301, {'Location': '../next?x=1'}, ''),
            'https://a.example/next?x=1': (200, {}, 'ok'),
        })
        res = safe_session().get('https://a.example/start/page')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(transport.requested[-1], ('GET', 'https://a.example/next?x=1'))

    def test_303_after_post_becomes_get_without_body(self):
        """requests ile aynı yöntem kuralı: 303 → GET, gövde taşınmaz."""
        self._dns({'a.example': [_PUBLIC_IP]})
        seen_bodies = []

        def home(request):
            seen_bodies.append(request.body)
            return (200, {}, 'home')

        transport = self._transport({
            'https://a.example/login': (303, {'Location': '/home'}, ''),
            'https://a.example/home': home,
        })
        res = safe_session().post('https://a.example/login', data={'user': 'x'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(transport.requested, [('POST', 'https://a.example/login'),
                                               ('GET', 'https://a.example/home')])
        self.assertEqual(seen_bodies, [None])

    def test_allow_redirects_false_returns_3xx_without_following(self):
        self._dns({'a.example': [_PUBLIC_IP]})
        transport = self._transport({
            'https://a.example/': (302, {'Location': 'http://127.0.0.1/'}, ''),
        })
        res = safe_session().get('https://a.example/', allow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertEqual(len(transport.requested), 1)

    def test_redirect_loop_stops_safely(self):
        """K"""
        self._dns({'a.example': [_PUBLIC_IP]})
        transport = self._transport({
            'https://a.example/a': (302, {'Location': '/b'}, ''),
            'https://a.example/b': (302, {'Location': '/a'}, ''),
        })
        with self.assertRaises(requests.TooManyRedirects):
            safe_session().get('https://a.example/a')
        self.assertLessEqual(len(transport.requested), 4)

    def test_self_redirect_once_is_allowed(self):
        """'Cookie set et → kendine yönlendir' gibi meşru akış döngü sayılmaz."""
        self._dns({'a.example': [_PUBLIC_IP]})
        calls = {'n': 0}

        def page(request):
            calls['n'] += 1
            return (302, {'Location': '/page'}, '') if calls['n'] == 1 else (200, {}, 'ok')

        self._transport({'https://a.example/page': page})
        res = safe_session().get('https://a.example/page')
        self.assertEqual(res.status_code, 200)

    def test_excessive_redirects_stop_safely(self):
        """L"""
        self._dns({'a.example': [_PUBLIC_IP]})
        routes = {f'https://a.example/r{i}': (302, {'Location': f'/r{i + 1}'}, '') for i in range(50)}
        transport = self._transport(routes)
        with self.assertRaises(requests.TooManyRedirects):
            safe_session().get('https://a.example/r0')
        self.assertEqual(len(transport.requested), MAX_REDIRECTS + 1)


class SafeSessionDnsRevalidationTest(_SafeHttpTestBase):
    """O: DNS her giden istekte yeniden doğrulanır; bağlantı doğrulanan IP'ye sabitlenir."""

    def test_host_rebinding_to_private_on_later_request_rejected(self):
        answers = iter([[_PUBLIC_IP], ['127.0.0.1']])
        self._dns({'rebind.example': lambda: next(answers)})
        transport = self._transport({'https://rebind.example/': (200, {}, 'ok')})
        session = safe_session()

        self.assertEqual(session.get('https://rebind.example/').status_code, 200)
        with self.assertRaises(OutboundRequestBlocked):
            session.get('https://rebind.example/')
        self.assertEqual(len(transport.requested), 1)

    def test_rebinding_between_redirect_hops_rejected(self):
        answers = iter([[_PUBLIC_IP], ['10.0.0.1']])
        self._dns({'rebind.example': lambda: next(answers)})
        transport = self._transport({
            'https://rebind.example/': (302, {'Location': '/again'}, ''),
        })
        with self.assertRaises(OutboundRequestBlocked):
            safe_session().get('https://rebind.example/')
        self.assertEqual(transport.requested, [('GET', 'https://rebind.example/')])

    def test_pinned_connection_validates_and_connects_only_to_validated_ip(self):
        """Soket açılırken host yeniden çözümlenir ve YALNIZCA doğrulanan IP'ye bağlanılır."""
        from .services.safe_http import _PinnedHTTPConnection
        self._dns({'pin.example': [_PUBLIC_IP]})
        with patch('Tarama.services.safe_http.urllib3_connection.create_connection') as mock_connect:
            _PinnedHTTPConnection('pin.example', 80, timeout=3)._new_conn()
        self.assertEqual(mock_connect.call_args[0][0], (_PUBLIC_IP, 80))

    def test_pinned_connection_blocks_private_resolution_at_connect_time(self):
        """Adapter kontrolü ile soket açılışı arasında rebinding olsa bile bağlanılmaz."""
        from urllib3.exceptions import NewConnectionError
        from .services.safe_http import _PinnedHTTPSConnection
        self._dns({'pin.example': ['169.254.169.254']})
        with patch('Tarama.services.safe_http.urllib3_connection.create_connection') as mock_connect:
            with self.assertRaises(NewConnectionError):
                _PinnedHTTPSConnection('pin.example', 443, timeout=3)._new_conn()
        mock_connect.assert_not_called()

    def _full_stack_session(self):
        session = safe_session(requests.Session())
        session._inner.trust_env = False  # ortam proxy ayarları testi etkilemesin
        return session

    def test_full_stack_request_connects_only_to_validated_ip(self):
        """Gerçek requests → adapter → urllib3 → pinned bağlantı zinciri (soket mock'lu)."""
        self._dns({'pin.example': [_PUBLIC_IP]})
        with patch('Tarama.services.safe_http.urllib3_connection.create_connection',
                   side_effect=ConnectionRefusedError) as mock_connect:
            with self.assertRaises(requests.ConnectionError):
                self._full_stack_session().get('http://pin.example/', timeout=3)
        self.assertEqual(mock_connect.call_args[0][0], (_PUBLIC_IP, 80))

    def test_full_stack_rebinding_between_check_and_connect_rejected(self):
        """Adapter kontrolünde public, soket açılışında private → bağlantı kurulmaz."""
        answers = iter([[_PUBLIC_IP], ['127.0.0.1']])
        self._dns({'rebind.example': lambda: next(answers)})
        with patch('Tarama.services.safe_http.urllib3_connection.create_connection') as mock_connect:
            with self.assertRaises(requests.ConnectionError):
                self._full_stack_session().get('https://rebind.example/', timeout=3)
        mock_connect.assert_not_called()

    def test_adapter_uses_pinned_connection_pools(self):
        from .services.safe_http import _PinnedHTTPConnectionPool, _PinnedHTTPSConnectionPool
        pools = SSRFGuardAdapter().poolmanager.pool_classes_by_scheme
        self.assertIs(pools['http'], _PinnedHTTPConnectionPool)
        self.assertIs(pools['https'], _PinnedHTTPSConnectionPool)


class ScannerOutboundEnforcementTest(_SafeHttpTestBase):
    """M, N + tüm HTTP scanner'larının korumalı oturum kullandığının doğrulanması."""

    _TARGET = 'https://public.example/'

    def _page_with_form(self, action: str) -> str:
        return (f'<html><body><form action="{action}" method="post">'
                f'<input name="q"></form></body></html>')

    def test_every_http_scanner_uses_safe_session(self):
        for scanner_cls in (AccessControlScanner, AuthScanner, CmsScanner, ErrorDisclosureScanner,
                            IntegrityScanner, SqlInjectionScanner, CmdInjectionScanner,
                            NoSqlInjectionScanner, XssScanner):
            with self.subTest(scanner=scanner_cls.__name__):
                self.assertIsInstance(scanner_cls()._make_session(), SafeSession)

    def test_injected_raw_session_is_wrapped(self):
        for scanner_cls in (SqlInjectionScanner, CmdInjectionScanner, NoSqlInjectionScanner, XssScanner):
            with self.subTest(scanner=scanner_cls.__name__):
                session = scanner_cls(session=requests.Session())._make_session()
                self.assertIsInstance(session, SafeSession)

    def test_form_action_to_private_ip_never_requested(self):
        """M: form action güvenilmeyen girdidir — iç adrese gönderim yapılmaz, tarama çökmez."""
        self._dns({'public.example': [_PUBLIC_IP]})
        for scanner_cls in (XssScanner, SqlInjectionScanner, CmdInjectionScanner, NoSqlInjectionScanner):
            with self.subTest(scanner=scanner_cls.__name__):
                transport = self._transport({
                    self._TARGET: (200, {'Content-Type': 'text/html'},
                                   self._page_with_form('http://10.0.0.5/submit')),
                })
                result = scanner_cls().scan(self._TARGET)
                self.assertIsNone(result.error)
                self.assertNotIn('10.0.0.5', transport.hosts())

    def test_form_action_to_host_resolving_private_never_requested(self):
        self._dns({'public.example': [_PUBLIC_IP], 'intranet.example': ['172.16.0.3']})
        transport = self._transport({
            self._TARGET: (200, {}, self._page_with_form('https://intranet.example/api/login')),
        })
        result = XssScanner().scan(self._TARGET)
        self.assertIsNone(result.error)
        self.assertNotIn('intranet.example', transport.hosts())

    def test_auth_form_action_to_private_ip_never_requested(self):
        self._dns({'public.example': [_PUBLIC_IP]})
        login = ('<html><body><form action="http://192.168.0.10/do-login" method="post">'
                 '<input name="username"><input type="password" name="password"></form></body></html>')
        transport = self._transport({self._TARGET: (200, {}, login)})
        AuthScanner().scan(self._TARGET)
        self.assertNotIn('192.168.0.10', transport.hosts())

    def test_relative_form_action_resolves_against_page_and_is_submitted(self):
        """N"""
        self._dns({'public.example': [_PUBLIC_IP]})
        transport = self._transport({self._TARGET: (200, {}, self._page_with_form('/search'))})
        XssScanner().scan(self._TARGET)
        self.assertIn(('POST', 'https://public.example/search'), transport.requested)

    def test_target_redirecting_to_internal_address_not_followed(self):
        """Tarama sırasında hedefin kendisi iç adrese yönlendirirse hiçbir scanner takip etmez."""
        self._dns({'public.example': [_PUBLIC_IP]})
        transport = self._transport({
            self._TARGET: (302, {'Location': 'http://169.254.169.254/latest/meta-data/'}, ''),
        })
        for scanner_cls in (HeaderScanner, CmsScanner, IntegrityScanner, ErrorDisclosureScanner,
                            AccessControlScanner, AuthScanner, XssScanner, SqlInjectionScanner):
            with self.subTest(scanner=scanner_cls.__name__):
                scanner_cls().scan(self._TARGET)
        self.assertNotIn('169.254.169.254', transport.hosts())

    def test_header_scanner_blocked_redirect_sets_sanitized_error(self):
        self._dns({'public.example': [_PUBLIC_IP]})
        self._transport({self._TARGET: (302, {'Location': 'http://127.0.0.1/'}, '')})
        result = HeaderScanner().scan(self._TARGET)
        self.assertEqual(result.findings, [])
        self.assertIn(OUTBOUND_BLOCKED_MESSAGE, result.error)
        self.assertNotIn('127.0.0.1', result.error)


class OutboundBlockReportingTest(_SafeHttpTestBase):
    """Engellenen istek yanıltıcı bir MEDIUM bulguya dönüşmemeli, iç IP API'ye sızmamalı."""

    def test_orchestrator_replaces_blocked_error_with_sanitized_message(self):
        from .services.orchestrator import _run_scanner
        self._dns({'public.example': [_PUBLIC_IP]})
        self._transport({'https://public.example/': (302, {'Location': 'http://10.0.0.1/'}, '')})

        result = _run_scanner(CmsScanner(), 'https://public.example/')

        self.assertEqual(result.error, OUTBOUND_BLOCKED_MESSAGE)
        self.assertEqual(result.findings, [])

    def test_orchestrator_keeps_unrelated_errors_unchanged(self):
        from .services.orchestrator import _run_scanner
        scanner = MagicMock()
        scanner.scan.return_value = ScanResult(scanner='x', target='https://public.example/',
                                               error='Ana sayfa alınamadı')
        self.assertEqual(_run_scanner(scanner, 'https://public.example/').error, 'Ana sayfa alınamadı')

    def test_blocked_scan_error_persisted_as_informational_not_medium(self):
        from .services.scan_runner import _save_report
        from .services.orchestrator import ScanReport

        job = ScanJob.objects.create(target='https://public.example/', status='RUNNING')

        def empty(name):
            return ScanResult(scanner=name, target='https://public.example/')

        report = ScanReport(
            target='https://public.example/',
            headers=ScanResult(scanner='headers', target='https://public.example/',
                               error=OUTBOUND_BLOCKED_MESSAGE),
            ports=empty('ports'), sql=empty('sql'), xss=empty('xss'), ssl=empty('ssl'),
            dns=empty('dns'),
            cms=ScanResult(scanner='cms', target='https://public.example/', error='Ana sayfa alınamadı'),
            access_control=empty('access_control'), auth=empty('auth'), integrity=empty('integrity'),
            error_disclosure=empty('error_disclosure'), cmd=empty('cmd'), nosql=empty('nosql'),
        )
        _save_report(job, report)

        blocked = job.findings.get(scanner='headers')
        self.assertEqual(blocked.severity, 'INFO')
        self.assertEqual(blocked.status, 'INFORMATIONAL')
        # İlgisiz tarama hataları mevcut davranışını korur
        self.assertEqual(job.findings.get(scanner='cms').severity, 'MEDIUM')

        summary = summarize_findings(list(job.findings.all()))
        self.assertEqual(summary['severity']['info'], 0)
        self.assertEqual(summary['informational'], 1)


# ---------------------------------------------------------------------------
# P0-1 (devam): ham socket SSRF, proxy ortamı, redirect semantiği, ağ tripwire'ı
# ---------------------------------------------------------------------------

import os

from .services.safe_socket import (
    OutboundConnectionBlocked, check_public_address, connect_validated, resolve_public_addresses,
)


def _sequenced_dns(*answers):
    """Her getaddrinfo çağrısında sıradaki yanıtı, sonra son yanıtı döner (rebinding)."""
    remaining = list(answers)

    def next_answer():
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]
    return next_answer


class NetworkTripwireTest(TestCase):
    """K: test suite gerçek DNS / socket bağlantısı yapamaz."""

    def test_real_dns_resolution_is_blocked(self):
        for call in (lambda: socket.getaddrinfo('example.com', 443),
                     lambda: socket.gethostbyname('example.com'),
                     lambda: socket.gethostbyaddr('example.com')):
            with self.assertRaises(NetworkAccessAttempted):
                call()

    def test_real_socket_connection_is_blocked(self):
        with self.assertRaises(NetworkAccessAttempted):
            socket.create_connection(('93.184.216.34', 80), timeout=1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaises(NetworkAccessAttempted):
                sock.connect(('93.184.216.34', 80))
        finally:
            sock.close()

    def test_tripwire_cannot_be_swallowed_by_broad_except(self):
        """Scanner'lardaki `except Exception` blokları tripwire'ı yutamaz."""
        self.assertFalse(issubclass(NetworkAccessAttempted, Exception))


class SafeSocketHelperTest(_SafeHttpTestBase):

    def test_connect_validated_uses_validated_ip_literal(self):
        self._dns({'svc.example': [_PUBLIC_IP]})
        with patch('socket.create_connection') as mock_connect:
            connect_validated('svc.example', 25, timeout=2)
        mock_connect.assert_called_once_with((_PUBLIC_IP, 25), timeout=2)

    def test_connect_validated_rejects_if_any_address_private(self):
        self._dns({'mixed.example': [_PUBLIC_IP, '10.0.0.8']})
        with patch('socket.create_connection') as mock_connect:
            with self.assertRaises(OutboundConnectionBlocked):
                connect_validated('mixed.example', 22, timeout=2)
        mock_connect.assert_not_called()

    def test_connect_validated_tries_next_validated_address(self):
        self._dns({'multi.example': [_PUBLIC_IP, _PUBLIC_IP_2]})
        with patch('socket.create_connection',
                   side_effect=[ConnectionRefusedError, MagicMock()]) as mock_connect:
            connect_validated('multi.example', 443, timeout=2)
        self.assertEqual([c.args[0] for c in mock_connect.call_args_list],
                         [(_PUBLIC_IP, 443), (_PUBLIC_IP_2, 443)])

    def test_unresolvable_host_is_connection_error_not_policy_block(self):
        """DNS hatası 'engellendi' olarak raporlanmaz — mevcut 'bağlantı yok' davranışı korunur."""
        self._dns({})
        with self.assertRaises(socket.gaierror):
            resolve_public_addresses('nx.example')
        with safe_http.track_blocked_requests() as tracker:
            with self.assertRaises(requests.ConnectionError) as ctx:
                safe_session().get('https://nx.example/')
        self.assertNotIsInstance(ctx.exception, OutboundRequestBlocked)
        self.assertEqual(tracker.blocked, 0)

    def test_blocked_exception_is_not_oserror_and_is_sanitized(self):
        """OSError olsaydı scanner'ların `except OSError` blokları onu 'port kapalı' sayardı."""
        with self.assertRaises(OutboundConnectionBlocked) as ctx:
            check_public_address('169.254.169.254')
        self.assertNotIsInstance(ctx.exception, OSError)
        self.assertEqual(str(ctx.exception), OUTBOUND_BLOCKED_MESSAGE)


class PortScannerSsrfTest(_SafeHttpTestBase):

    def _scan(self, host='rebind.example', conn_side_effect=None):
        with patch('Tarama.scanners.ports.socket.gethostbyname', return_value=_PUBLIC_IP), \
             patch('Tarama.scanners.ports.socket.gethostbyaddr', return_value=(host, [], [_PUBLIC_IP])), \
             patch('socket.create_connection', side_effect=conn_side_effect) as mock_connect:
            result = PortScanner().scan(f'https://{host}')
        return result, mock_connect

    def test_dns_rebinding_after_api_validation_blocked(self):
        """A: API girişinde public, port taraması sırasında private → hiçbir bağlantı yok."""
        self._dns({'rebind.example': _sequenced_dns([_PUBLIC_IP], ['10.0.0.5'])})
        validate_url('https://rebind.example/')  # API girişi: geçer

        result, mock_connect = self._scan()

        mock_connect.assert_not_called()
        self.assertEqual(result.error, OUTBOUND_BLOCKED_MESSAGE)
        self.assertFalse(any('/' in f.title and f.title != 'host_name' for f in result.findings),
                         'Engellenen hedef için port sonucu raporlanmamalı')
        self.assertNotIn('10.0.0.5', result.error)

    def test_rebinding_mid_scan_blocks_whole_result(self):
        self._dns({'rebind.example': _sequenced_dns(*([[_PUBLIC_IP]] * 5 + [['127.0.0.1']]))})

        result, mock_connect = self._scan(conn_side_effect=ConnectionRefusedError)

        self.assertEqual(result.error, OUTBOUND_BLOCKED_MESSAGE)
        for call in mock_connect.call_args_list:
            self.assertEqual(call.args[0][0], _PUBLIC_IP)

    def test_public_destination_still_scanned_via_validated_ip(self):
        """B: public hedefte port taraması aynen çalışır; bağlantı hostname'e değil IP'ye."""
        self._dns({'public.example': [_PUBLIC_IP]})

        def connect(address, timeout=None):
            if address[1] == 22:
                return _make_open_ctx(b'SSH-2.0-OpenSSH_9.6\r\n')
            raise ConnectionRefusedError

        result, mock_connect = self._scan(host='public.example', conn_side_effect=connect)

        self.assertIsNone(result.error)
        evidence = {f.title: f.evidence for f in result.findings}
        self.assertTrue(evidence['22/SSH'].startswith('ACIK'))
        self.assertEqual(evidence['80/HTTP'], 'KAPALI')
        self.assertEqual(mock_connect.call_count, 19)
        self.assertEqual({c.args[0][0] for c in mock_connect.call_args_list}, {_PUBLIC_IP})
        self.assertTrue(all(c.kwargs['timeout'] == PortScanner().timeout for c in mock_connect.call_args_list))

    def test_blocked_port_scan_persisted_as_informational(self):
        from .services.orchestrator import _run_scanner
        self._dns({'rebind.example': ['192.168.1.1']})
        with patch('Tarama.scanners.ports.socket.gethostbyname', return_value=_PUBLIC_IP), \
             patch('Tarama.scanners.ports.socket.gethostbyaddr', side_effect=socket.herror), \
             patch('socket.create_connection') as mock_connect:
            result = _run_scanner(PortScanner(), 'https://rebind.example')
        mock_connect.assert_not_called()
        self.assertEqual(result.error, OUTBOUND_BLOCKED_MESSAGE)


class SslScannerSsrfTest(_SafeHttpTestBase):

    def _tls_mocks(self):
        ssl_sock = MagicMock()
        ssl_sock.__enter__ = MagicMock(return_value=ssl_sock)
        ssl_sock.__exit__ = MagicMock(return_value=False)
        ssl_sock.version.return_value = 'TLSv1.3'
        ssl_sock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        ssl_sock.getpeercert.return_value = {}
        raw_sock = MagicMock()
        raw_sock.__enter__ = MagicMock(return_value=raw_sock)
        raw_sock.__exit__ = MagicMock(return_value=False)
        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssl_sock
        return raw_sock, ctx

    def test_https_target_rebinding_to_private_blocked(self):
        """C"""
        self._dns({'rebind.example': _sequenced_dns([_PUBLIC_IP], ['169.254.169.254'])})
        validate_url('https://rebind.example/')

        with patch('socket.create_connection') as mock_connect, \
             patch('Tarama.scanners.ssl_tls.ssl.create_default_context') as mock_ctx:
            result = SslScanner().scan('https://rebind.example')

        mock_connect.assert_not_called()
        mock_ctx.return_value.wrap_socket.assert_not_called()
        self.assertEqual(result.error, OUTBOUND_BLOCKED_MESSAGE)
        self.assertEqual(result.findings, [])

    def test_http_target_rebinding_not_reported_as_https_missing(self):
        """Engellenen 443 kontrolü yanlış bir 'HTTPS desteklenmiyor' HIGH bulgusu üretmemeli."""
        self._dns({'rebind.example': ['127.0.0.1']})
        with patch('socket.create_connection') as mock_connect:
            result = SslScanner().scan('http://rebind.example')
        mock_connect.assert_not_called()
        self.assertEqual(result.error, OUTBOUND_BLOCKED_MESSAGE)
        self.assertEqual(result.findings, [])

    def test_connects_to_validated_ip_but_sni_uses_original_hostname(self):
        """D"""
        self._dns({'tls.example': [_PUBLIC_IP]})
        raw_sock, ctx = self._tls_mocks()
        with patch('socket.create_connection', return_value=raw_sock) as mock_connect, \
             patch('Tarama.scanners.ssl_tls.ssl.create_default_context', return_value=ctx):
            result = SslScanner().scan('https://tls.example')

        self.assertIsNone(result.error)
        self.assertGreaterEqual(mock_connect.call_count, 2)  # protokol + sertifika aşaması
        for call in mock_connect.call_args_list:
            self.assertEqual(call.args[0], (_PUBLIC_IP, 443))
        self.assertGreaterEqual(ctx.wrap_socket.call_count, 2)
        for call in ctx.wrap_socket.call_args_list:
            self.assertIs(call.args[0], raw_sock)
            self.assertEqual(call.kwargs['server_hostname'], 'tls.example')

    def test_certificate_stage_rebinding_does_not_connect(self):
        """Protokol aşamasından sonra rebinding olursa sertifika aşaması bağlanmaz."""
        self._dns({'tls.example': _sequenced_dns([_PUBLIC_IP], ['10.1.1.1'])})
        raw_sock, ctx = self._tls_mocks()
        with patch('socket.create_connection', return_value=raw_sock) as mock_connect, \
             patch('Tarama.scanners.ssl_tls.ssl.create_default_context', return_value=ctx):
            SslScanner().scan('https://tls.example')
        self.assertEqual(mock_connect.call_count, 1)
        self.assertEqual(mock_connect.call_args.args[0], (_PUBLIC_IP, 443))


class DnsZoneTransferSsrfTest(_SafeHttpTestBase):
    """E–H: DNS yanıtından gelen NS adresleri güvenilmez girdidir."""

    def _scan(self, ns_ips: dict):
        scanner = DnsScanner()
        scanner._query = MagicMock(side_effect=lambda name, rdtype: (
            sorted(f'{ns}.' for ns in ns_ips) if rdtype == 'NS' else []
        ))
        mock_zone = MagicMock()
        mock_zone.nodes.keys.return_value = ['www.example.com.']
        with patch('Tarama.scanners.dns_scan.socket.gethostbyname',
                   side_effect=lambda host: ns_ips[host]), \
             patch('Tarama.scanners.dns_scan.dns.query.xfr', return_value=iter([])) as mock_xfr, \
             patch('Tarama.scanners.dns_scan.dns.zone.from_xfr', return_value=mock_zone):
            result = scanner.scan('https://victim.example')
        return result, mock_xfr

    def _assert_no_axfr_and_no_claim(self, result, mock_xfr):
        mock_xfr.assert_not_called()
        titles = [f.title for f in result.findings]
        self.assertNotIn('Zone Transfer izin veriliyor (AXFR)', titles)
        self.assertNotIn('Zone Transfer engellendi', titles)

    def test_nameserver_loopback_rejected(self):
        """E"""
        self._assert_no_axfr_and_no_claim(*self._scan({'ns1.victim.example': '127.0.0.1'}))

    def test_nameserver_rfc1918_rejected(self):
        """F"""
        for ip in ('10.0.0.53', '172.20.0.53', '192.168.1.53'):
            with self.subTest(ip=ip):
                self._assert_no_axfr_and_no_claim(*self._scan({'ns1.victim.example': ip}))

    def test_nameserver_metadata_link_local_rejected(self):
        """G"""
        self._assert_no_axfr_and_no_claim(*self._scan({'ns1.victim.example': '169.254.169.254'}))

    def test_nameserver_shared_and_reserved_rejected(self):
        for ip in ('100.64.0.53', '240.0.0.1', '0.0.0.0'):
            with self.subTest(ip=ip):
                self._assert_no_axfr_and_no_claim(*self._scan({'ns1.victim.example': ip}))

    def test_public_nameserver_still_tested(self):
        """H: public NS'e AXFR denenir ve mevcut bulgu semantiği aynen korunur."""
        result, mock_xfr = self._scan({'ns1.victim.example': '1.2.3.4'})
        mock_xfr.assert_called_once()
        self.assertEqual(mock_xfr.call_args.args[0], '1.2.3.4')
        allowed = next(f for f in result.findings if f.title == 'Zone Transfer izin veriliyor (AXFR)')
        self.assertEqual(allowed.status, FindingStatus.CONFIRMED)

    def test_private_nameserver_skipped_public_one_still_tested(self):
        result, mock_xfr = self._scan({'ns1.victim.example': '10.0.0.53',
                                       'ns2.victim.example': '1.2.3.4'})
        self.assertEqual([c.args[0] for c in mock_xfr.call_args_list], ['1.2.3.4'])


class SafeSessionProxyEnvironmentTest(_SafeHttpTestBase):
    """I: ortamdaki proxy değişkenleri SafeSession trafiğini yönlendiremez."""

    _PROXY_ENV = {
        'HTTP_PROXY': 'http://10.0.0.1:3128', 'HTTPS_PROXY': 'http://10.0.0.1:3128',
        'ALL_PROXY': 'socks5://10.0.0.1:1080', 'http_proxy': 'http://10.0.0.1:3128',
        'https_proxy': 'http://10.0.0.1:3128', 'NO_PROXY': '', 'no_proxy': '',
    }

    def test_safe_session_does_not_trust_environment(self):
        self.assertFalse(safe_session()._inner.trust_env)
        self.assertFalse(safe_session(requests.Session())._inner.trust_env)

    def test_environment_proxy_not_passed_to_transport(self):
        self._dns({'public.example': [_PUBLIC_IP]})
        transport = self._transport({'https://public.example/': (200, {}, 'ok')})
        with patch.dict(os.environ, self._PROXY_ENV):
            safe_session().get('https://public.example/')
        send_mock = HTTPAdapter.send
        self.assertEqual(send_mock.call_args.kwargs.get('proxies'), {})
        self.assertEqual(transport.requested, [('GET', 'https://public.example/')])

    def test_environment_proxy_does_not_redirect_connection(self):
        """Bağlantı proxy'ye değil, doğrulanmış hedef IP'ye açılır (tam urllib3 zinciri)."""
        self._dns({'public.example': [_PUBLIC_IP]})
        with patch.dict(os.environ, self._PROXY_ENV), \
             patch('Tarama.services.safe_http.urllib3_connection.create_connection',
                   side_effect=ConnectionRefusedError) as mock_connect:
            with self.assertRaises(requests.ConnectionError):
                safe_session().get('http://public.example/', timeout=3)
        self.assertEqual([c.args[0] for c in mock_connect.call_args_list], [(_PUBLIC_IP, 80)])

    def test_scanner_traffic_ignores_environment_proxy(self):
        self._dns({'public.example': [_PUBLIC_IP]})
        self._transport({'https://public.example/': (200, {}, '<html></html>')})
        with patch.dict(os.environ, self._PROXY_ENV):
            CmsScanner().scan('https://public.example/')
        for call in HTTPAdapter.send.call_args_list:
            self.assertEqual(call.kwargs.get('proxies'), {})


class SafeSessionRedirectSemanticsTest(_SafeHttpTestBase):
    """J: 301/302/303/307/308 — SafeSession, requests'in kendi yönlendirme davranışıyla
    (ezbere değil, aynı senaryoda gerçek requests.Session çalıştırılarak) karşılaştırılır."""

    _START = 'https://a.example/start'

    def _record_hops(self, status: int, client_call) -> list:
        hops = []

        def start(request):
            hops.append((request.method, request.body))
            return (status, {'Location': '/next'}, '')

        def nxt(request):
            hops.append((request.method, request.body))
            return (200, {}, 'ok')

        self._transport({self._START: start, 'https://a.example/next': nxt})
        client_call()
        return hops

    def _hops(self, client, status: int, method: str) -> list:
        data = {'k': 'v'} if method in ('POST', 'PUT') else None
        return self._record_hops(
            status, lambda: client.request(method, self._START, data=data, allow_redirects=True))

    def test_matches_requests_for_all_redirect_codes_and_methods(self):
        self._dns({'a.example': [_PUBLIC_IP]})
        reference = requests.Session()
        reference.trust_env = False
        for status in (301, 302, 303, 307, 308):
            for method in ('GET', 'POST', 'PUT', 'HEAD'):
                with self.subTest(status=status, method=method):
                    expected = self._hops(reference, status, method)
                    actual = self._hops(safe_session(), status, method)
                    self.assertEqual(actual, expected)

    def test_post_redirect_semantics_explicit(self):
        """POST için beklenen davranış açıkça da doğrulanır."""
        self._dns({'a.example': [_PUBLIC_IP]})
        expected = {
            301: ('GET', None), 302: ('GET', None), 303: ('GET', None),
            307: ('POST', 'k=v'), 308: ('POST', 'k=v'),
        }
        for status, second_hop in expected.items():
            with self.subTest(status=status):
                hops = self._hops(safe_session(), status, 'POST')
                self.assertEqual(hops[0], ('POST', 'k=v'))
                self.assertEqual(hops[1], second_hop)

    def test_put_301_keeps_method_but_drops_body_like_requests(self):
        self._dns({'a.example': [_PUBLIC_IP]})
        hops = self._hops(safe_session(), 301, 'PUT')
        self.assertEqual(hops[1], ('PUT', None))

    def test_every_redirect_code_still_validates_hop(self):
        self._dns({'a.example': [_PUBLIC_IP]})
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                transport = self._transport({self._START: (status, {'Location': 'http://10.0.0.1/'}, '')})
                with self.assertRaises(OutboundRequestBlocked):
                    safe_session().post(self._START, data={'k': 'v'})
                self.assertNotIn('10.0.0.1', transport.hosts())


# ---------------------------------------------------------------------------
# P0-2: Hassas kanıt redaksiyonu (services/evidence_redaction.py)
# Tüm değerler SAHTEDİR.
# ---------------------------------------------------------------------------

from .services.evidence_redaction import REDACTED, redact_sensitive_text, redact_then_truncate


class EvidenceRedactionPatternTest(TestCase):
    """A–P: yüksek güvenli gizli değer bağlamları redakte edilir, bağlam korunur."""

    def assertRedacted(self, text: str, secret: str, keep: tuple = ()):
        out = redact_sensitive_text(text)
        self.assertNotIn(secret, out)
        self.assertIn(REDACTED, out)
        for fragment in keep:
            self.assertIn(fragment, out)
        return out

    def test_a_db_password_key_value_preserves_other_lines(self):
        out = self.assertRedacted(
            'DB_HOST=db.internal\nDB_USER=app\nDB_PASSWORD=FakePass_A1\nDEBUG=True',
            'FakePass_A1', keep=('DB_HOST=db.internal', 'DB_USER=app', 'DEBUG=True'))
        self.assertIn('DB_PASSWORD=[REDACTED]', out)

    def test_b_lowercase_and_variant_password_keys(self):
        for text, secret in (('password=FakePass_B1', 'FakePass_B1'),
                             ('passwd=FakePass_B2', 'FakePass_B2'),
                             ('PWD=FakePass_B3', 'FakePass_B3'),
                             ('DATABASE_PASSWORD=FakePass_B4', 'FakePass_B4'),
                             ('MAIL_PASS=FakePass_B5', 'FakePass_B5')):
            with self.subTest(text=text):
                self.assertRedacted(text, secret)

    def test_c_secret_key_variants(self):
        for text, secret in (('SECRET_KEY=FakeSecret_C1', 'FakeSecret_C1'),
                             ('DJANGO_SECRET_KEY=FakeSecret_C2', 'FakeSecret_C2'),
                             ('SECRET=FakeSecret_C3', 'FakeSecret_C3'),
                             ('CLIENT_SECRET=FakeSecret_C4', 'FakeSecret_C4'),
                             ('AWS_SECRET_ACCESS_KEY=FakeSecret_C5', 'FakeSecret_C5')):
            with self.subTest(text=text):
                self.assertRedacted(text, secret)

    def test_d_api_key_and_token_variants(self):
        for text, secret in (('API_KEY=FakeKey_D1', 'FakeKey_D1'),
                             ('APIKEY=FakeKey_D2', 'FakeKey_D2'),
                             ('api-key: FakeKey_D3', 'FakeKey_D3'),
                             ('TOKEN=FakeTok_D4', 'FakeTok_D4'),
                             ('ACCESS_TOKEN=FakeTok_D5', 'FakeTok_D5'),
                             ('REFRESH_TOKEN=FakeTok_D6', 'FakeTok_D6'),
                             ('PRIVATE_KEY=FakeKey_D7', 'FakeKey_D7')):
            with self.subTest(text=text):
                self.assertRedacted(text, secret)

    def test_e_bearer_token(self):
        self.assertRedacted('Authorization: Bearer FakeBearer_E1abcdefghij', 'FakeBearer_E1',
                            keep=('Authorization: Bearer [REDACTED]',))
        self.assertRedacted('sent header Bearer FakeBearer9E2abcdefghijk', 'FakeBearer9E2')

    def test_f_basic_and_proxy_authorization(self):
        self.assertRedacted('Authorization: Basic RmFrZVVzZXI6RmFrZVBhc3M=', 'RmFrZVVzZXI6RmFrZVBhc3M=',
                            keep=('Authorization: Basic [REDACTED]',))
        self.assertRedacted('Proxy-Authorization: Basic RmFrZVByb3h5', 'RmFrZVByb3h5',
                            keep=('Proxy-Authorization: Basic',))

    def test_g_json_password_field(self):
        out = self.assertRedacted('{"user": "app", "password": "FakeJson_G1", "host": "db"}', 'FakeJson_G1',
                                  keep=('"user": "app"', '"host": "db"'))
        self.assertIn('"password": "[REDACTED]"', out)

    def test_h_yaml_password_field(self):
        self.assertRedacted('database:\n  user: app\n  password: FakeYaml_H1\n  host: db', 'FakeYaml_H1',
                            keep=('user: app', 'host: db', 'password: [REDACTED]'))

    def test_i_ini_config_password(self):
        self.assertRedacted('[database]\npassword = FakeIni_I1\nport = 5432', 'FakeIni_I1',
                            keep=('[database]', 'port = 5432', 'password = [REDACTED]'))

    def test_j_connection_string_password(self):
        out = self.assertRedacted('Server=db;User ID=sa;Password=FakeConn_J1;Database=app;', 'FakeConn_J1',
                                  keep=('Server=db', 'User ID=sa', 'Database=app'))
        self.assertIn('Password=[REDACTED];', out)
        self.assertRedacted('Driver={x};Pwd=FakeConn_J2;', 'FakeConn_J2')

    def test_k_credential_bearing_url(self):
        out = self.assertRedacted('https://admin:FakeUrl_K1@example.com/', 'FakeUrl_K1')
        self.assertEqual(out, 'https://admin:[REDACTED]@example.com/')
        out = self.assertRedacted('DATABASE_URL=postgres://app:FakeUrl_K2@db.internal:5432/app', 'FakeUrl_K2')
        self.assertIn('postgres://app:[REDACTED]@db.internal:5432/app', out)

    def test_l_pem_private_key_body(self):
        for label in ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY'):
            with self.subTest(label=label):
                text = f'-----BEGIN {label}-----\nMIIFakeKeyBodyL1\nFakeKeyBodyL2==\n-----END {label}-----'
                out = redact_sensitive_text(text)
                self.assertEqual(out, f'-----BEGIN {label}-----\n[REDACTED]\n-----END {label}-----')

    def test_l_unterminated_private_key_body(self):
        out = redact_sensitive_text('-----BEGIN PRIVATE KEY-----\nMIIFakeTruncatedBody')
        self.assertNotIn('MIIFakeTruncatedBody', out)
        self.assertEqual(out, '-----BEGIN PRIVATE KEY-----\n[REDACTED]')

    def test_l_public_certificate_unchanged(self):
        cert = '-----BEGIN CERTIFICATE-----\nMIIPublicCertBody\n-----END CERTIFICATE-----'
        self.assertEqual(redact_sensitive_text(cert), cert)
        pub = '-----BEGIN PUBLIC KEY-----\nMIIPublicKeyBody\n-----END PUBLIC KEY-----'
        self.assertEqual(redact_sensitive_text(pub), pub)

    def test_m_benign_prose_word_password_not_destroyed(self):
        for text in ('Please enter your password to continue. The password field is required.',
                     'Forgot your password? Reset it from the account page.',
                     '<label for="password">Password:</label>',
                     'Bearer token required',
                     'Basic authentication is enabled',
                     'Access-Control-Allow-Origin: * ile Access-Control-Allow-Credentials: true',
                     '["username", "password", "email"]',
                     'Password::Hash::make($value)'):
            with self.subTest(text=text):
                self.assertEqual(redact_sensitive_text(text), text)

    def test_n_hashes_and_identifiers_unchanged(self):
        for text in ('sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
                     'md5 d41d8cd98f00b204e9800998ecf8427e',
                     '550e8400-e29b-41d4-a716-446655440000',
                     'commit 2884ebf1c0ffee'):
            with self.subTest(text=text):
                self.assertEqual(redact_sensitive_text(text), text)

    def test_n_security_signals_unchanged(self):
        """SQL/XSS/CMD kanıtı, durum kodları, CWE/OWASP, yollar ve IP'ler korunur."""
        for text in ("You have an error in your SQL syntax near ''' OR '1'='1' --'",
                     "URL: https://example.com/login | Alan: q | Payload: ' OR SLEEP(4)-- -",
                     '<img src=x onerror=alert(1)>', '" onmouseover="alert(1)',
                     'root:x:0:0:root:/root:/bin/bash uid=0(root) gid=0(root)',
                     'HTTP 500 | CWE-89 | A03:2021 - Injection | /api/v1/users | 10.0.0.1',
                     'Strict-Transport-Security: max-age=31536000; includeSubDomains',
                     'Kullanıcı: admin | Parola: [gizlendi — test edilen bilinen varsayılan değer]'):
            with self.subTest(text=text):
                self.assertEqual(redact_sensitive_text(text), text)

    def test_o_existing_marker_unchanged(self):
        for text in ('[REDACTED]', 'DB_PASSWORD=[REDACTED]', '"password": "[REDACTED]"',
                     'Authorization: Bearer [REDACTED]', 'https://u:[REDACTED]@h/'):
            with self.subTest(text=text):
                self.assertEqual(redact_sensitive_text(text), text)

    def test_p_idempotent(self):
        samples = [
            'DB_PASSWORD=FakeIdem1\nAPI_KEY=FakeIdem2',
            'Authorization: Bearer FakeIdem3abcdefghijklm',
            '{"secret": "FakeIdem4", "token": "FakeIdem5"}',
            'Set-Cookie: sessionid=FakeIdem6; Path=/; Secure; HttpOnly',
            '-----BEGIN RSA PRIVATE KEY-----\nFakeIdem7\n-----END RSA PRIVATE KEY-----',
            '-----BEGIN PRIVATE KEY-----\nFakeIdem8',
            'mysql://root:FakeIdem9@db/app', 'Plain text without secrets.',
        ]
        for text in samples:
            with self.subTest(text=text):
                once = redact_sensitive_text(text)
                self.assertEqual(redact_sensitive_text(once), once)

    def test_non_string_values_pass_through(self):
        self.assertIsNone(redact_sensitive_text(None))
        self.assertEqual(redact_sensitive_text(''), '')

    def test_cookie_values_redacted_attributes_kept(self):
        out = redact_sensitive_text('Set-Cookie: sessionid=FakeCookie1; Path=/; Secure; HttpOnly; SameSite=Lax')
        self.assertEqual(out, 'Set-Cookie: sessionid=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax')
        out = redact_sensitive_text('Cookie: sessionid=FakeCookie2; csrftoken=FakeCookie3; theme=dark')
        self.assertNotIn('FakeCookie2', out)
        self.assertNotIn('FakeCookie3', out)
        self.assertIn('sessionid=[REDACTED]', out)

    def test_session_and_csrf_key_values(self):
        for text, secret in (('PHPSESSID=FakeSess1', 'FakeSess1'), ('csrftoken=FakeCsrf1', 'FakeCsrf1'),
                             ('session_id: FakeSess2', 'FakeSess2'), ('?token=FakeQuery1&page=2', 'FakeQuery1')):
            with self.subTest(text=text):
                self.assertRedacted(text, secret)

    def test_php_define_sql_and_phpinfo_contexts(self):
        self.assertRedacted("define('DB_PASSWORD', 'FakeDefine1');", 'FakeDefine1', keep=("define('DB_PASSWORD'",))
        self.assertRedacted("$db_password = \"FakePhpVar1\";", 'FakePhpVar1')
        self.assertRedacted("INSERT INTO settings VALUES ('smtp_password','FakeSqlKv1');", 'FakeSqlKv1')
        self.assertRedacted("CREATE USER 'app'@'%' IDENTIFIED BY 'FakeIdent1';", 'FakeIdent1')
        self.assertRedacted('<td class="e">DB_PASSWORD </td><td class="v">FakePhpinfo1 </td>', 'FakePhpinfo1')

    def test_high_confidence_token_formats(self):
        jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.FakeJwtSignature123'
        for token in (jwt, 'ghp_' + 'F' * 36, 'github_pat_' + 'F' * 30, 'AKIA' + 'FAKEFAKEFAKEFAKE',
                      'xoxb-0000-FakeSlackTok', 'sk_live_' + 'F' * 24, 'AIza' + 'F' * 35,
                      'sk-ant-' + 'F' * 30, '$2y$10$' + 'F' * 53):
            with self.subTest(token=token[:12]):
                out = redact_sensitive_text(f'value {token} end')
                self.assertNotIn(token, out)
                self.assertEqual(out, 'value [REDACTED] end')


class EvidenceRedactionBeforeTruncationTest(TestCase):
    """V: redaksiyon kırpmadan ÖNCE yapılır — aksi halde kesim bağlamı koparıp sızdırır."""

    def test_prefix_truncation_cannot_split_token(self):
        token = 'ghp_' + 'FakeTruncTok' * 3
        text = 'x' * 180 + ' ' + token
        naive = redact_sensitive_text(text[:200])          # yanlış sıra
        self.assertIn(token[:15], naive)                    # eski sıra sızdırırdı
        safe = redact_then_truncate(text, 200)              # doğru sıra
        self.assertNotIn(token[:15], safe)
        self.assertLessEqual(len(safe), 200)

    def test_window_start_cannot_cut_key_from_value(self):
        """Pencere başlangıcı anahtarın ortasına düşse bile değer sızmaz (cmd snippet)."""
        from .scanners.cmd import _extract_snippet
        body = 'MY_DB_PASSWORD=FakeWindowSecret root:x:0:0:root:/root:/bin/bash'
        naive_window = body[body.find('root:x') - 20:]
        self.assertIn('FakeWindowSecret', redact_sensitive_text(naive_window))  # eski sıra sızdırırdı
        self.assertNotIn('FakeWindowSecret', _extract_snippet(body, 'root:x:0:0'))

    def test_all_window_snippet_helpers_redact_first(self):
        from .scanners.cmd import _extract_snippet as cmd_snippet
        from .scanners.nosql import _extract_snippet as nosql_snippet
        from .scanners.sql import _extract_error_snippet
        from .scanners.xss import _extract_snippet as xss_snippet
        body = 'ERR password=FakeHelperPw mongoerror you have an error in your sql syntax <svg onload=1>'
        self.assertNotIn('FakeHelperPw', cmd_snippet(body, 'mongoerror'))
        self.assertNotIn('FakeHelperPw', nosql_snippet(body, 'mongoerror'))
        self.assertNotIn('FakeHelperPw', _extract_error_snippet(body))
        self.assertNotIn('FakeHelperPw', xss_snippet(body, '<svg onload=1>'))
        self.assertIn('<svg onload=1>', xss_snippet(body, '<svg onload=1>'))

    def test_pem_block_longer_than_snippet(self):
        text = '-----BEGIN PRIVATE KEY-----\n' + 'FakeLongKeyMaterial' * 40 + '\n-----END PRIVATE KEY-----'
        out = redact_then_truncate(text, 60)
        self.assertNotIn('FakeLongKeyMaterial', out)


class _ScannerResponseMixin:
    @staticmethod
    def _resp(text='', status=200):
        r = MagicMock()
        r.text = text
        r.content = text.encode()
        r.status_code = status
        r.url = 'https://example.com/'
        r.headers = {}
        return r

    def _route(self, MockSession, routes: dict, default_status=404):
        def get(url, **kwargs):
            for suffix, (text, status) in routes.items():
                if url.endswith(suffix):
                    return self._resp(text, status)
            return self._resp('', default_status)
        MockSession.return_value.get.side_effect = get


class CmsEvidenceRedactionTest(_ScannerResponseMixin, TestCase):
    """Q, R, S: açık hassas dosyalar hâlâ bulgu üretir ama gerçek değerler saklanmaz."""

    def _finding_for(self, MockSession, path, content):
        self._route(MockSession, {'example.com/': ('<html></html>', 200), path: (content, 200)})
        result = CmsScanner().scan('https://example.com/')
        return next(f for f in result.findings if f.title == f'Hassas dosya erişilebilir: {path}')

    @patch('Tarama.scanners.cms.requests.Session')
    def test_q_env_file_evidence_contains_no_secret(self, MockSession):
        env = ('APP_NAME=lilith-lab\nDB_HOST=db.internal\nDB_PASSWORD=FakeEnvPass_Q1\n'
               'SECRET_KEY=FakeEnvSecret_Q2\nAWS_SECRET_ACCESS_KEY=FakeEnvAws_Q3\nDEBUG=True\n')
        finding = self._finding_for(MockSession, '/.env', env)
        for secret in ('FakeEnvPass_Q1', 'FakeEnvSecret_Q2', 'FakeEnvAws_Q3'):
            self.assertNotIn(secret, finding.evidence)
        self.assertIn('DB_PASSWORD=[REDACTED]', finding.evidence)
        self.assertIn('DB_HOST=db.internal', finding.evidence)
        # Bulgu semantiği değişmedi
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.status, FindingStatus.CONFIRMED)
        self.assertEqual(finding.affected_url, 'https://example.com/.env')

    @patch('Tarama.scanners.cms.requests.Session')
    def test_r_config_file_evidence_contains_no_secret(self, MockSession):
        config = ("<?php\ndefine('DB_NAME', 'app');\ndefine('DB_PASSWORD', 'FakeConfig_R1');\n"
                  "$db_password = \"FakeConfig_R2\";\n$api_key = 'FakeConfig_R3';\n")
        finding = self._finding_for(MockSession, '/config.php', config)
        for secret in ('FakeConfig_R1', 'FakeConfig_R2', 'FakeConfig_R3'):
            self.assertNotIn(secret, finding.evidence)
        self.assertIn("define('DB_NAME', 'app')", finding.evidence)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_s_sql_dump_evidence_contains_no_credential_values(self, MockSession):
        bcrypt = '$2y$10$' + 'FakeBcryptHashValueForLilithTestsOnly0123456789abcdef'[:53]
        dump = ("-- MySQL dump\nCREATE TABLE users (id int, pw varchar(60));\n"
                f"INSERT INTO users VALUES (1,'admin','{bcrypt}');\n"
                "INSERT INTO settings VALUES ('smtp_password','FakeDump_S1');\n"
                "CREATE USER 'app'@'%' IDENTIFIED BY 'FakeDump_S2';\n")
        finding = self._finding_for(MockSession, '/backup.sql', dump)
        for secret in (bcrypt, 'FakeDump_S1', 'FakeDump_S2'):
            self.assertNotIn(secret, finding.evidence)
        self.assertIn('CREATE TABLE users', finding.evidence)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_git_config_remote_credentials_redacted(self, MockSession):
        git = ('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n'
               '\turl = https://deploy:FakeGitToken_1@git.example.com/org/repo.git\n')
        finding = self._finding_for(MockSession, '/.git/config', git)
        self.assertNotIn('FakeGitToken_1', finding.evidence)
        self.assertIn('git.example.com/org/repo.git', finding.evidence)


class IntegrityEvidenceRedactionTest(_ScannerResponseMixin, TestCase):

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_t_debug_log_evidence_contains_no_secret(self, MockSession):
        log = ('[31-Oct-2026] PHP Warning: db connect failed password=FakeLog_T1\n'
               'Authorization: Bearer FakeLogBearer_T2abcdefgh\n'
               'DATABASE_URL=postgres://app:FakeLog_T3@db/app\n')
        self._route(MockSession, {'example.com/': ('<html></html>', 200), '/wp-content/debug.log': (log, 200)})
        result = IntegrityScanner().scan('https://example.com/')
        finding = next(f for f in result.findings if 'debug.log' in f.title)
        for secret in ('FakeLog_T1', 'FakeLog_T2', 'FakeLog_T3'):
            self.assertNotIn(secret, finding.evidence)
        self.assertIn('db connect failed', finding.evidence)
        self.assertIn('Authorization: Bearer [REDACTED]', finding.evidence)
        self.assertEqual(finding.status, FindingStatus.CONFIRMED)


class ErrorDisclosureEvidenceRedactionTest(_ScannerResponseMixin, TestCase):

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_u_stack_trace_line_secret_redacted(self, MockSession):
        # Gizli değerler, kanıt olarak alınan eşleşme satırının KENDİSİNDEdir
        trace = ('<html><body>\nFatal error: Uncaught PDOException password=FakeTrace_U1 '
                 'dsn=mysql://app:FakeTrace_U2@db/app in /var/www/app/db.php on line 12\n</body></html>')
        self._route(MockSession, {'/this-page-does-not-exist-xyz-12345': (trace, 500)})
        result = ErrorDisclosureScanner().scan('https://example.com/')
        traces = [f for f in result.findings if f.title == 'Application Stack Trace Disclosure']
        self.assertTrue(traces)
        for finding in traces:
            self.assertNotIn('FakeTrace_U1', finding.evidence)
            self.assertNotIn('FakeTrace_U2', finding.evidence)
            self.assertIn('db.php', finding.evidence)
            self.assertIn('Fatal error', finding.evidence)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_u_monitoring_endpoint_snippet_redacted_before_truncation(self, MockSession):
        env = '{"activeProfiles":[],"spring.datasource.password":"FakeActuator_U3","x":"' + 'y' * 300 + '"}'
        self._route(MockSession, {'/actuator/env': (env, 200)})
        result = ErrorDisclosureScanner().scan('https://example.com/')
        finding = next(f for f in result.findings if f.title == 'İzleme endpoint\'i bulundu: /actuator/env')
        self.assertNotIn('FakeActuator_U3', finding.evidence)
        self.assertIn('[REDACTED]', finding.evidence)
        self.assertEqual(finding.severity, Severity.CRITICAL)


class EvidenceBoundaryTest(TestCase):
    """W, X, Y, Z: kalıcılık, API, frontend ve log sınırları."""

    _SECRET = 'FakeBoundarySecret_W1'

    def test_finding_construction_redacts_only_evidence(self):
        finding = Finding(
            severity=Severity.HIGH, title='password=TitleIsNotTouched',
            evidence=f'DB_PASSWORD={self._SECRET}',
            affected_url='https://example.com/?token=UrlIsNotTouched',
            recommendation='Rotate SECRET_KEY=RecommendationIsNotTouched',
        )
        self.assertEqual(finding.evidence, 'DB_PASSWORD=[REDACTED]')
        self.assertEqual(finding.title, 'password=TitleIsNotTouched')
        self.assertEqual(finding.affected_url, 'https://example.com/?token=UrlIsNotTouched')
        self.assertEqual(finding.recommendation, 'Rotate SECRET_KEY=RecommendationIsNotTouched')
        self.assertNotIn(self._SECRET, json.dumps(finding.to_dict()))

    def test_w_persisted_scan_finding_contains_no_secret(self):
        from .services.scan_runner import _save_report
        from .services.orchestrator import ScanReport

        job = ScanJob.objects.create(target='https://example.com', status='RUNNING')
        finding = Finding(severity=Severity.HIGH, title='x', evidence='placeholder')
        finding.evidence = f'api_key={self._SECRET}'   # oluşturulduktan sonra değiştirilmiş

        def empty(name):
            return ScanResult(scanner=name, target='https://example.com')

        report = ScanReport(
            target='https://example.com', headers=empty('headers'), ports=empty('ports'),
            sql=empty('sql'), xss=empty('xss'), ssl=empty('ssl'), dns=empty('dns'),
            cms=ScanResult(scanner='cms', target='https://example.com', findings=[finding]),
            access_control=empty('access_control'), auth=empty('auth'), integrity=empty('integrity'),
            error_disclosure=empty('error_disclosure'), cmd=empty('cmd'),
            nosql=ScanResult(scanner='nosql', target='https://example.com',
                             error=f'Connection failed: https://u:{self._SECRET}@db.example.com/'),
        )
        _save_report(job, report)

        for row in job.findings.all():
            self.assertNotIn(self._SECRET, row.evidence)
        self.assertEqual(job.findings.get(scanner='cms').evidence, 'api_key=[REDACTED]')

    def test_x_api_serialization_redacts_even_historical_raw_rows(self):
        """P0-2 öncesinde ham kaydedilmiş bir satır API'den gizli değer taşımaz."""
        job = ScanJob.objects.create(target='https://example.com', status='DONE')
        ScanFinding.objects.create(job=job, scanner='cms', severity='CRITICAL', title='Hassas dosya',
                                   evidence=f'DB_PASSWORD={self._SECRET}', status='CONFIRMED')
        with _public_dns():
            res = Client().get(f'/api/scan/{job.id}/')
        self.assertEqual(res.status_code, 200)
        self.assertNotIn(self._SECRET, res.content.decode())
        self.assertIn('DB_PASSWORD=[REDACTED]', res.json()['findings'][0]['evidence'])

    @patch('Tarama.views.XssScanner')
    @patch('Tarama.views.SqlInjectionScanner')
    def test_y_frontend_responses_contain_no_secret(self, MockSql, MockXss):
        secret_result = lambda name: ScanResult(
            scanner=name, target='https://example.com',
            findings=[Finding(severity=Severity.HIGH, title='t', evidence=f'token={self._SECRET}')],
            error=f'Bağlantı hatası: https://u:{self._SECRET}@example.com/',
        )
        MockXss.return_value.scan.return_value = secret_result('xss')
        MockSql.return_value.scan.return_value = secret_result('sql')
        client = Client()
        with _public_dns():
            xss = client.post('/Ana/check_xss_scan', {'url_param': 'https://example.com'})
            sql = client.post('/Ana/check_sql_scan', {'url_param': 'https://example.com'})
        for res in (xss, sql):
            self.assertEqual(res.status_code, 200)
            self.assertNotIn(self._SECRET, res.content.decode())

    def test_z_orchestrator_log_does_not_contain_target_password(self):
        from .services.orchestrator import run_full_scan
        OrchestratorTest._patch_all_scanners(self, {'cms': RuntimeError('boom')})
        with self.assertLogs('Tarama.services.orchestrator', level='ERROR') as logs:
            run_full_scan(f'https://admin:{self._SECRET}@example.com/')
        rendered = '\n'.join(logging.Formatter().format(r) for r in logs.records)
        self.assertNotIn(self._SECRET, rendered)
        self.assertIn('admin:[REDACTED]@example.com', rendered)

    @patch('Tarama.services.scan_runner.run_full_scan', side_effect=RuntimeError('boom'))
    def test_z_scan_runner_log_does_not_contain_target_password(self, _mock):
        from .services.scan_runner import _run_in_background
        job = ScanJob.objects.create(target='https://example.com', status='PENDING')
        with self.assertLogs('Tarama.services.scan_runner', level='ERROR') as logs:
            _run_in_background(job.id, f'https://admin:{self._SECRET}@example.com/')
        rendered = '\n'.join(logging.Formatter().format(r) for r in logs.records)
        self.assertNotIn(self._SECRET, rendered)


# ---------------------------------------------------------------------------
# P0-2 (devam): kimlik bilgisi taşıyan URL'ler — ağ URL'si ≠ güvenli görüntüleme URL'si
# Tüm değerler SAHTEDİR.
# ---------------------------------------------------------------------------

from .services.evidence_redaction import redact_sensitive_url

_RAW_TARGET = 'https://admin:FakeUrlPw_1@example.com/api?token=FakeUrlTok_2&lang=en&api_key=FakeUrlKey_3'
_SAFE_TARGET = 'https://admin:[REDACTED]@example.com/api?token=[REDACTED]&lang=en&api_key=[REDACTED]'
_URL_SECRETS = ('FakeUrlPw_1', 'FakeUrlTok_2', 'FakeUrlKey_3')


class SensitiveUrlRedactionTest(TestCase):

    def test_spec_example(self):
        self.assertEqual(redact_sensitive_url('https://admin:secret@example.com/api?token=abc&lang=en'),
                         'https://admin:[REDACTED]@example.com/api?token=[REDACTED]&lang=en')

    def test_userinfo_password_redacted_username_host_port_path_kept(self):
        self.assertEqual(redact_sensitive_url('https://deploy:FakePw@git.example.com:8443/org/repo.git'),
                         'https://deploy:[REDACTED]@git.example.com:8443/org/repo.git')
        self.assertEqual(redact_sensitive_url('redis://:FakePw@cache.example.com:6379/0'),
                         'redis://:[REDACTED]@cache.example.com:6379/0')

    def test_token_query_parameters_redacted(self):
        for name in ('token', 'access_token', 'refresh_token', 'id_token', 'auth_token', 'TOKEN'):
            with self.subTest(param=name):
                out = redact_sensitive_url(f'https://example.com/cb?{name}=FakeTok&page=2')
                self.assertEqual(out, f'https://example.com/cb?{name}=[REDACTED]&page=2')

    def test_api_key_and_secret_query_parameters_redacted(self):
        for name in ('api_key', 'apikey', 'api-key', 'client_secret', 'password', 'X-Amz-Signature',
                     'X-Amz-Security-Token', 'sig', 'signature'):
            with self.subTest(param=name):
                out = redact_sensitive_url(f'https://example.com/f?{name}=FakeVal&v=1')
                self.assertNotIn('FakeVal', out)
                self.assertIn('v=1', out)

    def test_benign_query_parameters_intact(self):
        for url in ('https://example.com/search?q=password&keyword=token&page=2&sort=name',
                    'https://example.com/?id=1&lang=en&utm_source=x',
                    'https://example.com/path/to/page.php?cat=1#section-2',
                    'https://example.com', 'https://example.com/?'):
            with self.subTest(url=url):
                self.assertEqual(redact_sensitive_url(url), url)

    def test_fragment_token_redacted(self):
        self.assertEqual(redact_sensitive_url('https://example.com/cb#access_token=FakeFrag&state=xyz'),
                         'https://example.com/cb#access_token=[REDACTED]&state=xyz')

    def test_known_token_username_redacted(self):
        url = 'https://ghp_' + 'F' * 36 + '@github.com/org/repo'
        self.assertEqual(redact_sensitive_url(url), 'https://[REDACTED]@github.com/org/repo')

    def test_idempotent_and_non_string(self):
        for url in (_RAW_TARGET, _SAFE_TARGET, 'https://example.com/?sig=x', 'https://[bad'):
            with self.subTest(url=url):
                once = redact_sensitive_url(url)
                self.assertEqual(redact_sensitive_url(once), once)
        self.assertIsNone(redact_sensitive_url(None))
        self.assertEqual(redact_sensitive_url(''), '')
        self.assertEqual(redact_sensitive_url(_RAW_TARGET), _SAFE_TARGET)

    def test_text_redaction_applies_url_policy_to_embedded_urls(self):
        text = 'Request failed for https://s3.example.com/f?X-Amz-Signature=FakeSigText&X-Amz-Expires=60'
        out = redact_sensitive_text(text)
        self.assertNotIn('FakeSigText', out)
        self.assertIn('X-Amz-Expires=60', out)
        self.assertEqual(redact_sensitive_text(out), out)

    def test_evidence_redaction_remains_idempotent_with_urls(self):
        evidence = (f'URL: {_RAW_TARGET} | DB_PASSWORD=FakeIdemPw | '
                    'Payload: <script>alert(1)</script> | https://example.com/?q=1')
        once = redact_sensitive_text(evidence)
        self.assertEqual(redact_sensitive_text(once), once)
        for secret in _URL_SECRETS + ('FakeIdemPw',):
            self.assertNotIn(secret, once)
        self.assertIn('<script>alert(1)</script>', once)
        self.assertIn('https://example.com/?q=1', once)


class TargetUrlBoundaryTest(TestCase):
    """Ağ URL'si scanner'a değişmeden gider; DB/API/geçmiş/frontend/log güvenli URL görür."""

    def _assert_no_url_secret(self, text: str):
        for secret in _URL_SECRETS:
            self.assertNotIn(secret, text)

    @patch('Tarama.services.scan_runner.threading.Thread')
    def test_create_scan_persists_safe_url_but_thread_gets_raw_url(self, MockThread):
        with _public_dns():
            res = Client().post('/api/scan/', {'url_param': _RAW_TARGET})
        self.assertEqual(res.status_code, 201)
        self._assert_no_url_secret(res.content.decode())

        job = ScanJob.objects.get(id=res.json()['job_id'])
        self.assertEqual(job.target, _SAFE_TARGET)
        self.assertEqual(MockThread.call_args.kwargs['args'], (job.id, _RAW_TARGET))
        self._assert_no_url_secret(str(job))

    @patch('Tarama.services.scan_runner.run_full_scan')
    def test_background_job_scans_original_unmodified_url(self, mock_run_full_scan):
        from .services.orchestrator import ScanReport
        from .services.scan_runner import _run_in_background

        def empty(name):
            return ScanResult(scanner=name, target=_RAW_TARGET)
        mock_run_full_scan.return_value = ScanReport(
            target=_RAW_TARGET, headers=empty('headers'), ports=empty('ports'), sql=empty('sql'),
            xss=empty('xss'), ssl=empty('ssl'), dns=empty('dns'), cms=empty('cms'),
            access_control=empty('access_control'), auth=empty('auth'), integrity=empty('integrity'),
            error_disclosure=empty('error_disclosure'), cmd=empty('cmd'), nosql=empty('nosql'),
        )
        job = ScanJob.objects.create(target=_SAFE_TARGET, status='PENDING')

        _run_in_background(job.id, _RAW_TARGET)

        mock_run_full_scan.assert_called_once_with(_RAW_TARGET)
        job.refresh_from_db()
        self.assertEqual(job.status, 'DONE')
        self.assertEqual(job.target, _SAFE_TARGET)

    @patch('Tarama.views.SqlInjectionScanner')
    @patch('Tarama.views.HeaderScanner')
    def test_single_scanner_endpoints_scan_raw_url_and_display_safe_url(self, MockHeaders, MockSql):
        MockHeaders.return_value.scan.return_value = ScanResult(scanner='headers', target=_RAW_TARGET)
        MockSql.return_value.scan.return_value = ScanResult(scanner='sql', target=_RAW_TARGET)
        client = Client()
        with _public_dns():
            headers = client.post('/Ana/check_headers', {'url_param': _RAW_TARGET})
            sql = client.post('/Ana/check_sql_scan', {'url_param': _RAW_TARGET})

        MockHeaders.return_value.scan.assert_called_once_with(_RAW_TARGET)
        MockSql.return_value.scan.assert_called_once_with(_RAW_TARGET)
        self.assertEqual(headers.json()['url_param'], _SAFE_TARGET)
        for res in (headers, sql):
            self._assert_no_url_secret(res.content.decode())

    def test_ana_page_never_receives_raw_target(self):
        """P0-2 kapanışı: eski `/Ana/?url=<ham>` gezinmesi kaldırıldı — ham hedef sayfaya
        hiç ulaşmaz; görüntüleme kaydedilmiş güvenli hedeften gelir (bkz. ScanIdNavigationTest)."""
        res = Client().get('/Ana/', {'url': _RAW_TARGET})
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res['Location'], '/index')
        self._assert_no_url_secret(res.content.decode())

    def test_history_and_status_never_expose_url_credentials(self):
        # P0-2 öncesinde ham kaydedilmiş tarihsel bir iş dahil
        historical = ScanJob.objects.create(target=_RAW_TARGET, status='DONE')
        ScanFinding.objects.create(job=historical, scanner='sql', severity='HIGH', title='t',
                                   affected_url=_RAW_TARGET, evidence='e', status='POTENTIAL')
        client = Client()
        history = client.get('/api/scan/history/')
        status = client.get(f'/api/scan/{historical.id}/')
        for res in (history, status):
            self.assertEqual(res.status_code, 200)
            self._assert_no_url_secret(res.content.decode())
        self.assertEqual(status.json()['target'], _SAFE_TARGET)
        self.assertEqual(status.json()['findings'][0]['affected_url'], _SAFE_TARGET)

    def test_affected_url_serialization_and_persistence_safe_object_unchanged(self):
        from .services.scan_runner import _save_report
        from .services.orchestrator import ScanReport

        finding = Finding(severity=Severity.HIGH, title='t', evidence='e', affected_url=_RAW_TARGET)
        self.assertEqual(finding.affected_url, _RAW_TARGET)                  # nesne değişmez
        self.assertEqual(finding.to_dict()['affected_url'], _SAFE_TARGET)    # serileştirme güvenli

        job = ScanJob.objects.create(target=_SAFE_TARGET, status='RUNNING')

        def empty(name):
            return ScanResult(scanner=name, target=_RAW_TARGET)
        report = ScanReport(
            target=_RAW_TARGET, headers=empty('headers'), ports=empty('ports'),
            sql=ScanResult(scanner='sql', target=_RAW_TARGET, findings=[finding]),
            xss=empty('xss'), ssl=empty('ssl'), dns=empty('dns'), cms=empty('cms'),
            access_control=empty('access_control'), auth=empty('auth'), integrity=empty('integrity'),
            error_disclosure=empty('error_disclosure'), cmd=empty('cmd'), nosql=empty('nosql'),
        )
        _save_report(job, report)
        self.assertEqual(job.findings.get(scanner='sql').affected_url, _SAFE_TARGET)

    def test_orchestrator_log_never_exposes_url_credentials(self):
        from .services.orchestrator import run_full_scan
        OrchestratorTest._patch_all_scanners(self, {'cms': RuntimeError('boom')})
        with self.assertLogs('Tarama.services.orchestrator', level='ERROR') as logs:
            run_full_scan(_RAW_TARGET)
        rendered = '\n'.join(logging.Formatter().format(r) for r in logs.records)
        self._assert_no_url_secret(rendered)
        self.assertIn('lang=en', rendered)

    @patch('Tarama.services.scan_runner.run_full_scan', side_effect=RuntimeError('boom'))
    def test_scan_runner_log_never_exposes_url_credentials(self, _mock):
        from .services.scan_runner import _run_in_background
        job = ScanJob.objects.create(target=_SAFE_TARGET, status='PENDING')
        with self.assertLogs('Tarama.services.scan_runner', level='ERROR') as logs:
            _run_in_background(job.id, _RAW_TARGET)
        rendered = '\n'.join(logging.Formatter().format(r) for r in logs.records)
        self._assert_no_url_secret(rendered)


# ---------------------------------------------------------------------------
# P0-2 (kapanış): ham hedef asla tarayıcı URL'sine konmaz — gezinme yalnızca scan_id ile
# Tüm değerler SAHTEDİR. Tarayıcı otomasyonu yok: landing/dashboard JS'si render edilmiş
# şablon üzerinden, backend akışı gerçek view'lar üzerinden doğrulanır.
# ---------------------------------------------------------------------------

import re as _re


class ScanIdNavigationTest(TestCase):

    _BENIGN = 'https://example.com/search?q=test'

    def _assert_no_secret(self, text: str):
        for secret in _URL_SECRETS:
            self.assertNotIn(secret, text)

    def _landing_html(self) -> str:
        res = Client().get('/index')
        self.assertEqual(res.status_code, 200)
        return res.content.decode()

    @patch('Tarama.services.scan_runner.threading.Thread')
    def _create_scan(self, url, MockThread):
        """Landing JS'sinin yaptığı isteğin aynısı: hedef GÖVDEDE, POST /api/scan/."""
        with _public_dns():
            res = Client().post('/api/scan/', {'url_param': url})
        return res, MockThread

    # --- A, B, D, G, H: landing sayfası ---

    def test_a_landing_never_builds_raw_url_navigation(self):
        html = self._landing_html()
        self.assertNotIn('/Ana/?url=', html)
        self.assertNotIn('?url=', html)
        self.assertIsNone(_re.search(r'location(\.href)?\s*=\s*[^;]*value', html),
                          'Girilen değer gezinme URL\'sine konmamalı')

    def test_b_landing_posts_raw_target_in_request_body(self):
        html = self._landing_html()
        self.assertRegex(html, r"url:\s*'/api/scan/'")
        self.assertRegex(html, r"method:\s*'POST'")
        self.assertRegex(html, r"data:\s*\{\s*url_param:\s*value\s*\}")
        # JS devre dışıysa yerel form gönderimi de GET (sorgu dizesi) olmamalı
        self.assertRegex(html, r'<form[^>]*id="targetForm"[^>]*method="post"')

    def test_d_landing_navigates_with_scan_id_only(self):
        html = self._landing_html()
        navigations = _re.findall(r"location\.(?:assign|replace|href)\s*\(?\s*=?\s*([^;\n]+)", html)
        self.assertEqual(len(navigations), 1)
        self.assertIn("'/Ana/?scan_id=' + encodeURIComponent(res.job_id)", navigations[0])

    # --- C, E, F, G, H: uçtan uca backend akışı ---

    def test_c_e_f_g_h_credential_target_flow(self):
        res, MockThread = self._create_scan(_RAW_TARGET)
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertIsInstance(body['job_id'], int)                       # C
        self._assert_no_secret(res.content.decode())

        job_id = body['job_id']
        self.assertEqual(MockThread.call_args.kwargs['args'], (job_id, _RAW_TARGET))   # F

        browser_url = f'/Ana/?scan_id={job_id}'                           # landing'in gideceği URL
        self._assert_no_secret(browser_url)                               # G, H
        self.assertNotIn('admin:', browser_url)

        page = Client().get(browser_url)
        self.assertEqual(page.status_code, 200)
        html = page.content.decode()
        self._assert_no_secret(html)                                      # E
        self.assertEqual(page.context['target_display_url'], _SAFE_TARGET)
        self.assertIn(f'var scanId = {job_id};', html)
        self.assertNotIn('/api/scan/\',\n        method: \'POST\'', html)  # dashboard tarama başlatmaz

    def test_e_dashboard_display_comes_from_persisted_target_even_if_historically_raw(self):
        job = ScanJob.objects.create(target=_RAW_TARGET, status='DONE')   # P0-2 öncesi ham kayıt
        page = Client().get(f'/Ana/?scan_id={job.id}')
        self.assertEqual(page.context['target_display_url'], _SAFE_TARGET)
        self._assert_no_secret(page.content.decode())

    def test_i_benign_target_flow_still_works(self):
        res, MockThread = self._create_scan(self._BENIGN)
        self.assertEqual(res.status_code, 201)
        job_id = res.json()['job_id']
        self.assertEqual(MockThread.call_args.kwargs['args'], (job_id, self._BENIGN))
        self.assertEqual(ScanJob.objects.get(id=job_id).target, self._BENIGN)
        page = Client().get(f'/Ana/?scan_id={job_id}')
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.context['target_display_url'], self._BENIGN)

    def test_i_bare_hostname_is_still_normalized(self):
        res, MockThread = self._create_scan('example.com')
        self.assertEqual(MockThread.call_args.kwargs['args'][1], 'https://example.com')

    def test_invalid_target_is_rejected_on_landing_without_navigation(self):
        with _public_dns():
            res = Client().post('/api/scan/', {'url_param': 'http://127.0.0.1/'})
        self.assertEqual(res.status_code, 400)
        self.assertIn('error', res.json())
        self.assertFalse(ScanJob.objects.exists())

    def test_dashboard_reload_does_not_start_new_scan(self):
        job = ScanJob.objects.create(target='https://example.com', status='RUNNING')
        with patch('Tarama.services.scan_runner.threading.Thread') as MockThread:
            Client().get(f'/Ana/?scan_id={job.id}')
            Client().get(f'/Ana/?scan_id={job.id}')
        MockThread.assert_not_called()
        self.assertEqual(ScanJob.objects.count(), 1)

    # --- J: tarayıcı/sunucu tarafında ikinci bir kopya yok ---

    def test_j_no_client_or_session_persistence_of_raw_target(self):
        landing = self._landing_html()
        dashboard_job = ScanJob.objects.create(target=_SAFE_TARGET, status='DONE')
        dashboard = Client().get(f'/Ana/?scan_id={dashboard_job.id}').content.decode()
        for html in (landing, dashboard):
            # API kullanımı aranır (yorumdaki "localStorage'a yazılmaz" ifadesi değil)
            self.assertIsNone(_re.search(r'(?:local|session)Storage\s*[.\[]', html),
                              'Web Storage kullanılmamalı')
            self.assertIsNone(_re.search(r'document\.cookie\s*=(?!=)', html), 'cookie yazımı olmamalı')
            self.assertNotIn('history.pushState', html)
            self.assertNotIn('history.replaceState', html)

        client = Client()
        with _public_dns(), patch('Tarama.services.scan_runner.threading.Thread'):
            res = client.post('/api/scan/', {'url_param': _RAW_TARGET})
        for morsel in res.cookies.values():
            self._assert_no_secret(morsel.value)
        self.assertEqual(dict(client.session), {})                       # Django session'a yazılmadı
        self._assert_no_secret(json.dumps(list(ScanJob.objects.values())[0], default=str))

    # --- K: eski ?url= gezinmesi ---

    def test_k_legacy_url_navigation_redirects_without_exposure(self):
        with patch('Tarama.services.scan_runner.threading.Thread') as MockThread, \
                self.assertNoLogs('Tarama', level='DEBUG'):
            res = Client().get('/Ana/', {'url': _RAW_TARGET})
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res['Location'], '/index')                      # hedef geri yansıtılmaz
        self.assertEqual(res.content, b'')
        MockThread.assert_not_called()                                    # GET tarama başlatmaz
        self.assertFalse(ScanJob.objects.exists())

    def test_k_invalid_or_unknown_scan_id_redirects(self):
        for query in ({}, {'scan_id': 'abc'}, {'scan_id': '-1'}, {'scan_id': '²'},
                      {'scan_id': '999999'}, {'scan_id': '1 OR 1=1'}):
            with self.subTest(query=query):
                res = Client().get('/Ana/', query)
                self.assertEqual(res.status_code, 302)
                self.assertEqual(res['Location'], '/index')

    def test_dashboard_scan_id_is_rendered_as_integer_literal(self):
        job = ScanJob.objects.create(target='https://example.com', status='DONE')
        html = Client().get(f'/Ana/?scan_id={job.id}').content.decode()
        self.assertRegex(html, rf'var scanId = {job.id};')


# ---------------------------------------------------------------------------
# P0-3: Path-probe baseline / soft-404 yanlış pozitif azaltımı (services/path_baseline.py)
# Tüm HTTP sahte transport ile (gerçek SafeSession üzerinden), DNS mock'lu; ağ yok.
# ---------------------------------------------------------------------------

from .services.path_baseline import (
    BASELINE_SAMPLES, MATCH_THRESHOLD, DIFFER_THRESHOLD, PathBaseline, Relation,
    random_probe_path, signature,
)

_SITE = 'https://public.example'
_PROBE_PREFIX = '/__lilith_probe_'

_SPA_SHELL = ('<!doctype html><html><head><title>Acme Portal</title>'
              '<link rel="stylesheet" href="/static/index.css"></head><body><div id="root"></div>'
              '<script src="/static/js/main.4f9a1c2e8b7d6a5f.js"></script></body></html>')
_DEBUG_PAGE = ('<!doctype html><html><head><title>Django Debug Toolbar</title></head><body>'
               '<h1>SQL queries</h1><table>'
               + '<tr><td>SELECT * FROM auth_user WHERE id = 1</td><td>3.2ms</td></tr>' * 15
               + '</table></body></html>')


def _custom_404(path: str, request_id: str) -> str:
    return (f'<html><head><title>Page not found</title></head><body><h1>Sorry!</h1>'
            f'<p>The page {path} could not be found.</p><small>Request ID: {request_id}</small></body></html>')


class _Site(dict):
    """Sahte site: tanımlı yollar + tanımsız (var olmayan) yollar için davranış."""

    def __init__(self, routes: dict, default):
        super().__init__({_SITE + path: response for path, response in routes.items()})
        self.default = default

    def get(self, url, fallback=None):
        return super().get(url, self.default)


def _resp(text='', status=200, url='https://public.example/x', history=None, ctype='text/html'):
    r = MagicMock()
    r.text, r.status_code, r.url = text, status, url
    r.history = history or []
    r.headers = {'Content-Type': ctype}
    return r


class PathBaselineUnitTest(TestCase):
    """Karşılaştırma sinyalleri ve eşikler (mock yanıtlar, ağ yok)."""

    def _baseline(self, *responses):
        samples = []
        for response in responses:
            path = random_probe_path()
            samples.append(signature(response, _SITE + path, path))
        return PathBaseline(samples)

    def test_random_probe_paths_are_unique_high_entropy_and_not_common_routes(self):
        paths = {random_probe_path() for _ in range(50)}
        self.assertEqual(len(paths), 50)
        for path in paths:
            self.assertRegex(path, r'^/__lilith_probe_[0-9a-f]{24}__$')
            self.assertNotIn(path, ('/404', '/notfound', '/test'))

    def test_a_normal_404_baseline_real_200_endpoint_differs(self):
        baseline = self._baseline(_resp('Not Found', 404), _resp('Not Found', 404))
        self.assertTrue(baseline.stable)
        self.assertEqual(baseline.classify(_resp(_DEBUG_PAGE), _SITE + '/debug', '/debug'),
                         Relation.DIFFERS_FROM_BASELINE)

    def test_b_spa_returning_200_for_every_path_matches(self):
        baseline = self._baseline(_resp(_SPA_SHELL), _resp(_SPA_SHELL))
        self.assertEqual(baseline.classify(_resp(_SPA_SHELL), _SITE + '/debug', '/debug'),
                         Relation.MATCHES_BASELINE)

    def test_c_custom_200_not_found_page_echoing_path_matches(self):
        p1, p2 = random_probe_path(), random_probe_path()
        baseline = PathBaseline([
            signature(_resp(_custom_404(p1, 'a1b2c3d4-0000-4000-8000-000000000001')), _SITE + p1, p1),
            signature(_resp(_custom_404(p2, 'a1b2c3d4-0000-4000-8000-000000000002')), _SITE + p2, p2),
        ])
        candidate = _resp(_custom_404('/actuator', 'ffffffff-1111-4111-8111-111111111111'))
        self.assertEqual(baseline.classify(candidate, _SITE + '/actuator', '/actuator'),
                         Relation.MATCHES_BASELINE)

    def test_d_same_status_clearly_different_body_differs(self):
        """FN kuralı: aynı durum kodu (200) bulguyu tek başına bastırmaz."""
        baseline = self._baseline(_resp(_SPA_SHELL), _resp(_SPA_SHELL))
        self.assertEqual(baseline.classify(_resp(_DEBUG_PAGE), _SITE + '/__debug__/', '/__debug__/'),
                         Relation.DIFFERS_FROM_BASELINE)

    def test_e_small_dynamic_request_id_and_token_differences_still_match(self):
        def page(request_id, csrf, ts):
            return (_SPA_SHELL.replace('</body>', f'<meta name="csrf" content="{csrf}">'
                                       f'<!-- req {request_id} at {ts} --></body>'))
        baseline = self._baseline(
            _resp(page('0f1e2d3c-4b5a-4968-8776-655443322110', 'Q' * 40, '2026-10-31T10:00:00Z')),
            _resp(page('11111111-2222-4333-8444-555555555555', 'W' * 40, '2026-10-31T10:00:01Z')),
        )
        candidate = _resp(page('99999999-8888-4777-8666-555555555555', 'E' * 40, '2026-10-31T10:00:02Z'))
        self.assertEqual(baseline.classify(candidate, _SITE + '/debug', '/debug'), Relation.MATCHES_BASELINE)

    def test_f_redirect_catch_all_matches_and_distinct_redirect_differs(self):
        p1, p2 = random_probe_path(), random_probe_path()
        login = 'https://public.example/login?next='
        baseline = PathBaseline([
            signature(_resp('<html>Sign in</html>', url=login + p1, history=[MagicMock()]), _SITE + p1, p1),
            signature(_resp('<html>Sign in</html>', url=login + p2, history=[MagicMock()]), _SITE + p2, p2),
        ])
        same = _resp('<html>Sign in</html>', url=login + '/debug', history=[MagicMock()])
        self.assertEqual(baseline.classify(same, _SITE + '/debug', '/debug'), Relation.MATCHES_BASELINE)
        distinct = _resp('<html>Kibana</html>', url='https://public.example/kibana/app/home',
                         history=[MagicMock()])
        self.assertEqual(baseline.classify(distinct, _SITE + '/kibana', '/kibana'),
                         Relation.DIFFERS_FROM_BASELINE)

    def test_content_type_difference_is_a_signal(self):
        baseline = self._baseline(_resp(_SPA_SHELL), _resp(_SPA_SHELL))
        json_body = _resp('{"activeProfiles": []}', ctype='application/json')
        self.assertEqual(baseline.classify(json_body, _SITE + '/actuator/env', '/actuator/env'),
                         Relation.DIFFERS_FROM_BASELINE)

    def test_unstable_baseline_makes_body_only_difference_ambiguous(self):
        baseline = self._baseline(_resp(_SPA_SHELL), _resp('<html><title>X</title>' + 'random ' * 200 + '</html>'))
        self.assertFalse(baseline.stable)
        self.assertEqual(baseline.classify(_resp(_DEBUG_PAGE), _SITE + '/debug', '/debug'), Relation.AMBIGUOUS)

    def test_n_unavailable_baseline_is_never_treated_as_difference(self):
        baseline = PathBaseline([])
        self.assertFalse(baseline.available)
        self.assertEqual(baseline.classify(_resp(_DEBUG_PAGE), _SITE + '/debug', '/debug'),
                         Relation.BASELINE_UNAVAILABLE)

    def test_n_build_tolerates_request_failures_and_is_bounded(self):
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError('down')
        baseline = PathBaseline.build(session, _SITE, timeout=3)
        self.assertFalse(baseline.available)
        self.assertEqual(session.get.call_count, BASELINE_SAMPLES)
        for call in session.get.call_args_list:
            self.assertTrue(call.args[0].startswith(_SITE + _PROBE_PREFIX))

    def test_thresholds_are_explicit_and_ordered(self):
        self.assertGreater(MATCH_THRESHOLD, DIFFER_THRESHOLD)
        self.assertEqual(BASELINE_SAMPLES, 2)


class _BaselineScannerTestBase(_SafeHttpTestBase):
    """Gerçek SafeSession + sahte transport; her istek P0-1 katmanından geçer."""

    _HOME = (200, {'Content-Type': 'text/html'}, '<html><head><title>Home</title></head><body>home</body></html>')

    def _serve(self, routes: dict, default):
        self._dns({'public.example': [_PUBLIC_IP]})
        # cms/integrity önce ana sayfayı alır; tanımsızsa normal bir ana sayfa döner
        routes = {'/': self._HOME, **routes} if not callable(default) and default[0] != 200 else routes
        return self._transport(_Site(routes, default))

    def _baseline_requests(self, transport):
        return [url for _m, url in transport.requested if _PROBE_PREFIX in url]

    def _vulnerabilities(self, result):
        return [f for f in result.findings
                if f.status in (FindingStatus.CONFIRMED, FindingStatus.POTENTIAL, FindingStatus.MANUAL_REVIEW)]


class ErrorDisclosureBaselineTest(_BaselineScannerTestBase):

    def _monitoring(self, result):
        return [f for f in result.findings
                if f.title.startswith("İzleme endpoint'i bulundu") or 'API Documentation' in f.title]

    def test_a_g_normal_404_real_debug_endpoint_confirmed(self):
        transport = self._serve({'/__debug__/': (200, {'Content-Type': 'text/html'}, _DEBUG_PAGE)},
                                default=(404, {}, 'Not Found'))
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        debug = next(f for f in result.findings if f.affected_url == _SITE + '/__debug__/')
        self.assertEqual(debug.status, FindingStatus.CONFIRMED)
        self.assertEqual(debug.severity, Severity.HIGH)
        self.assertIn("baseline'ından farklı", debug.evidence)
        self.assertEqual(len(self._baseline_requests(transport)), BASELINE_SAMPLES)   # O, bounded

    def test_b_spa_returning_200_everywhere_produces_no_monitoring_findings(self):
        """Önceden: /debug, /kibana, /pma, /redis-commander, /_cat/indices ('index') … HIGH/CRITICAL CONFIRMED."""
        self._serve({}, default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        self.assertEqual(self._monitoring(result), [])
        self.assertIn("İzleme endpoint'leri bulunamadı", [f.title for f in result.findings])

    def test_c_custom_200_not_found_page_produces_no_monitoring_findings(self):
        counter = iter(range(10_000))

        def not_found(request):
            path = request.url[len(_SITE):]
            return (200, {'Content-Type': 'text/html'},
                    _custom_404(path, f'{next(counter):08x}-0000-4000-8000-000000000000'))
        self._serve({}, default=not_found)
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        self.assertEqual(self._monitoring(result), [])

    def test_d_real_debug_endpoint_behind_spa_catch_all_still_confirmed(self):
        self._serve({'/__debug__/': (200, {'Content-Type': 'text/html'}, _DEBUG_PAGE)},
                    default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        reported = {f.affected_url: f for f in self._monitoring(result)}
        self.assertEqual(list(reported), [_SITE + '/__debug__/'])
        self.assertEqual(reported[_SITE + '/__debug__/'].status, FindingStatus.CONFIRMED)

    def test_h_real_actuator_endpoint_behind_spa_still_confirmed(self):
        body = '{"activeProfiles":[],"propertySources":[{"name":"systemEnvironment"}]}'
        self._serve({'/actuator/env': (200, {'Content-Type': 'application/json'}, body)},
                    default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        env = next(f for f in result.findings if f.affected_url == _SITE + '/actuator/env')
        self.assertEqual((env.severity, env.status), (Severity.CRITICAL, FindingStatus.CONFIRMED))

    def test_e_f_redirect_catch_all_produces_no_monitoring_findings(self):
        self._serve({'/': (200, {'Content-Type': 'text/html'}, _SPA_SHELL)},
                    default=(302, {'Location': '/'}, ''))
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        self.assertEqual(self._monitoring(result), [])

    def test_f_redirect_to_distinct_real_page_is_classified_by_evidence(self):
        kibana = '<html><head><title>Kibana</title></head><body>' + 'kibana dashboard ' * 40 + '</body></html>'
        self._serve({'/': (200, {'Content-Type': 'text/html'}, _SPA_SHELL),
                     '/kibana': (302, {'Location': '/kibana/app/home'}, ''),
                     '/kibana/app/home': (200, {'Content-Type': 'text/html'}, kibana)},
                    default=(302, {'Location': '/'}, ''))
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        reported = {f.affected_url: f for f in self._monitoring(result)}
        self.assertEqual(list(reported), [_SITE + '/kibana'])
        self.assertEqual(reported[_SITE + '/kibana'].status, FindingStatus.CONFIRMED)

    def test_catch_all_403_produces_no_endpoint_existence_findings(self):
        self._serve({}, default=(403, {'Content-Type': 'text/html'}, '<html>Forbidden</html>'))
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        self.assertEqual(self._monitoring(result), [])

    def test_unstable_baseline_keywordless_endpoint_is_potential_not_confirmed(self):
        counter = iter(range(10_000))

        def random_page(request):
            n = next(counter)
            return (200, {'Content-Type': 'text/html'},
                    f'<html><title>T{n}</title><body>' + f'item{n} unique{n} ' * (20 + n * 7) + '</body></html>')
        self._serve({'/debug': (200, {'Content-Type': 'text/html'}, _DEBUG_PAGE)}, default=random_page)
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        debug = next(f for f in result.findings if f.affected_url == _SITE + '/debug')
        self.assertEqual(debug.status, FindingStatus.POTENTIAL)
        self.assertEqual(debug.confidence, Confidence.LOW)
        self.assertEqual(debug.severity, Severity.HIGH)   # severity değişmez/artmaz

    def test_n_baseline_failure_never_confirms_or_creates_vulnerability(self):
        def handler(request):
            if _PROBE_PREFIX in request.url:
                raise requests.ConnectionError('baseline probe failed')
            if request.url == _SITE + '/debug':
                return (200, {'Content-Type': 'text/html'}, _DEBUG_PAGE)
            return (404, {}, '')
        self._serve({}, default=handler)
        result = ErrorDisclosureScanner().scan(_SITE + '/')
        self.assertIsNone(result.error)
        debug = next(f for f in result.findings if f.affected_url == _SITE + '/debug')
        self.assertEqual(debug.status, FindingStatus.POTENTIAL)
        self.assertIn("baseline'ı alınamadı", debug.evidence)
        confirmed = [f for f in result.findings if f.status == FindingStatus.CONFIRMED]
        self.assertEqual(confirmed, [])


class IntegrityBaselineTest(_BaselineScannerTestBase):

    def _file_findings(self, result):
        return [f for f in result.findings
                if f.title.startswith(('Dependency Metadata Exposed', 'Hata log dosyası', 'Yol erişilebilir'))]

    def test_k_spa_returning_homepage_for_all_files_produces_no_findings(self):
        """Önceden: 13 manifest + debug.log için 14 CONFIRMED bulgu."""
        transport = self._serve({}, default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = IntegrityScanner().scan(_SITE + '/')
        self.assertEqual(self._file_findings(result), [])
        self.assertEqual(len(self._baseline_requests(transport)), BASELINE_SAMPLES)

    def test_l_p_real_debug_log_confirmed_and_redacted(self):
        log = ('[31-Oct-2026 10:00:00 UTC] PHP Warning: mysqli_connect(): password=FakeBaselineLogPw '
               'in /var/www/html/wp-includes/db.php on line 12\n')
        self._serve({'/wp-content/debug.log': (200, {'Content-Type': 'text/plain'}, log)},
                    default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = IntegrityScanner().scan(_SITE + '/')
        found = self._file_findings(result)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].severity, found[0].status), (Severity.MEDIUM, FindingStatus.CONFIRMED))
        self.assertNotIn('FakeBaselineLogPw', found[0].evidence)
        self.assertIn('PHP Warning', found[0].evidence)

    def test_real_package_json_behind_spa_confirmed(self):
        manifest = '{"name": "acme", "dependencies": {"express": "^4.19.2"}}'
        self._serve({'/package.json': (200, {'Content-Type': 'application/json'}, manifest)},
                    default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = IntegrityScanner().scan(_SITE + '/')
        found = self._file_findings(result)
        self.assertEqual([f.title for f in found], ['Dependency Metadata Exposed: /package.json'])
        self.assertEqual(found[0].status, FindingStatus.CONFIRMED)

    def test_distinct_html_page_at_manifest_path_is_not_the_file(self):
        self._serve({'/composer.json': (200, {'Content-Type': 'text/html'}, _DEBUG_PAGE)},
                    default=(404, {}, 'Not Found'))
        result = IntegrityScanner().scan(_SITE + '/')
        self.assertEqual(self._file_findings(result), [])

    def test_unrecognized_non_html_content_is_manual_review_not_confirmed(self):
        self._serve({'/go.mod': (200, {'Content-Type': 'text/plain'}, 'maintenance mode, try again later')},
                    default=(404, {}, 'Not Found'))
        result = IntegrityScanner().scan(_SITE + '/')
        found = self._file_findings(result)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].status, found[0].confidence, found[0].severity),
                         (FindingStatus.MANUAL_REVIEW, Confidence.LOW, Severity.LOW))

    def test_n_baseline_failure_keeps_content_validated_file_only(self):
        manifest = 'module example.com/acme\n\ngo 1.22\n'

        def handler(request):
            if _PROBE_PREFIX in request.url:
                raise requests.Timeout('baseline timeout')
            if request.url == _SITE + '/go.mod':
                return (200, {'Content-Type': 'text/plain'}, manifest)
            return (200, {'Content-Type': 'text/html'}, _SPA_SHELL)
        self._serve({}, default=handler)
        result = IntegrityScanner().scan(_SITE + '/')
        self.assertEqual([f.title for f in self._file_findings(result)], ['Dependency Metadata Exposed: /go.mod'])


class CmsBaselineTest(_BaselineScannerTestBase):

    def _path_findings(self, result):
        return [f for f in result.findings
                if f.title.startswith(('Hassas dosya', 'Yol erişilebilir', 'Admin paneli', 'Sürüm bilgisi'))]

    def test_i_fake_env_returning_homepage_is_not_reported(self):
        self._serve({}, default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = CmsScanner().scan(_SITE + '/')
        self.assertEqual(self._path_findings(result), [])   # admin/sürüm gürültüsü dahil

    def test_plain_text_catch_all_no_longer_creates_manual_review_noise(self):
        """Önceden: 200 'Not found' düz metin catch-all → 10 sensitive path MANUAL_REVIEW."""
        self._serve({}, default=(200, {'Content-Type': 'text/plain'}, 'Not found - nothing to see here.'))
        result = CmsScanner().scan(_SITE + '/')
        self.assertEqual(self._path_findings(result), [])

    def test_catch_all_containing_weak_sql_marker_is_not_critical_dump(self):
        """Önceden: catch-all sayfası 'insert into' içeriyorsa /backup.sql + /db.sql CRITICAL CONFIRMED."""
        page = ('Documentation: use INSERT INTO statements and CREATE TABLE carefully. '
                'This text is served for every unknown path.')
        self._serve({}, default=(200, {'Content-Type': 'text/plain'}, page))
        result = CmsScanner().scan(_SITE + '/')
        self.assertEqual([f for f in result.findings if f.severity == Severity.CRITICAL], [])

    def test_j_p_real_env_content_still_detected_and_redacted(self):
        env = 'APP_ENV=production\nDB_HOST=db.internal\nDB_PASSWORD=FakeBaselineEnvPw\n'
        self._serve({'/.env': (200, {'Content-Type': 'text/plain'}, env)},
                    default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = CmsScanner().scan(_SITE + '/')
        env_finding = next(f for f in result.findings if f.title == 'Hassas dosya erişilebilir: /.env')
        self.assertEqual((env_finding.severity, env_finding.status), (Severity.CRITICAL, FindingStatus.CONFIRMED))
        self.assertNotIn('FakeBaselineEnvPw', env_finding.evidence)
        self.assertIn('DB_PASSWORD=[REDACTED]', env_finding.evidence)

    def test_m_real_git_config_still_detected(self):
        git = '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://git.example.com/a/b.git\n'
        self._serve({'/.git/config': (200, {'Content-Type': 'text/plain'}, git)},
                    default=(404, {}, 'Not Found'))
        result = CmsScanner().scan(_SITE + '/')
        git_finding = next(f for f in result.findings if f.title == 'Hassas dosya erişilebilir: /.git/config')
        self.assertEqual(git_finding.status, FindingStatus.CONFIRMED)

    def test_real_admin_page_behind_spa_still_reported_spa_paths_not(self):
        admin_html = ('<html><head><title>WordPress Login</title></head><body>'
                      + '<form id="loginform">wp-submit user_login user_pass</form>' * 5 + '</body></html>')
        self._serve({'/wp-admin/': (200, {'Content-Type': 'text/html'}, admin_html)},
                    default=(200, {'Content-Type': 'text/html'}, _SPA_SHELL))
        result = CmsScanner().scan(_SITE + '/')
        admin = [f.affected_url for f in result.findings if f.title.startswith('Admin paneli bulundu')]
        self.assertEqual(admin, [_SITE + '/wp-admin/'])


# ---------------------------------------------------------------------------
# requests.Response truthiness: 4xx/5xx yanıtları "yanıt yok" sayılmamalı
# Tüm yanıtlar GERÇEK requests.Response'tur (bool(r) == r.ok); MagicMock kullanılmaz.
# ---------------------------------------------------------------------------

_HOME_WITH_LOGIN = ('<html><body><form action="/login" method="post">'
                    '<input type="text" name="username"><input type="password" name="password">'
                    '</form></body></html>')


def _routes(table: dict, default=(404, 'Not Found')):
    """URL sonekine göre gerçek Response döndüren get/post side_effect'i."""
    def handler(url, **kwargs):
        for suffix, (status, text, *rest) in table.items():
            if url.endswith(suffix):
                return _http_response(status, text, url=url, headers=(rest[0] if rest else None))
        if callable(default):
            return default(url, **kwargs)
        return _http_response(default[0], default[1], url=url)
    return handler


class ResponseTruthinessPremiseTest(TestCase):

    def test_real_response_truthiness_follows_http_status(self):
        """Hatanın kaynağı: 'if not res' bir 401/403/404/429/500 yanıtını 'yanıt yok' sanır."""
        self.assertTrue(bool(_http_response(200)))
        for status in (401, 403, 404, 429, 500, 503):
            with self.subTest(status=status):
                self.assertFalse(bool(_http_response(status)))


class ErrorDisclosureResponseTruthinessTest(TestCase):

    def _scan(self, MockSession, handler):
        MockSession.return_value.get.side_effect = handler
        return ErrorDisclosureScanner().scan('https://example.com')

    def _endpoint(self, result, path):
        return [f for f in result.findings if f.affected_url == f'https://example.com{path}']

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_401_reaches_auth_required_branch(self, MockSession):
        result = self._scan(MockSession, _routes({'/actuator': (401, '{"error":"Unauthorized"}')}))
        finding = self._endpoint(result, '/actuator')
        self.assertEqual(len(finding), 1)
        self.assertEqual((finding[0].severity, finding[0].status), (Severity.INFO, FindingStatus.INFORMATIONAL))
        self.assertIn('HTTP 401 (auth gerekiyor)', finding[0].evidence)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_403_reaches_forbidden_branch(self, MockSession):
        result = self._scan(MockSession, _routes({'/phpmyadmin': (403, '<html>Forbidden</html>')}))
        finding = self._endpoint(result, '/phpmyadmin')
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0].status, FindingStatus.INFORMATIONAL)
        self.assertIn('HTTP 403 (yasaklı)', finding[0].evidence)

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_p0_3_catch_all_403_still_suppressed(self, MockSession):
        """Artık 403 yanıtları değerlendirildiği için soft-404 bastırması gerçekten çalışmalı."""
        result = self._scan(MockSession, _routes({}, default=(403, '<html>Forbidden</html>')))
        monitoring = [f for f in result.findings if f.title.startswith("İzleme endpoint'i bulundu")]
        self.assertEqual(monitoring, [])

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_404_error_page_with_stack_trace_is_analyzed(self, MockSession):
        page = 'Fatal error: Uncaught Exception in /var/www/html/index.php on line 7'
        result = self._scan(MockSession, _routes({}, default=(404, page)))
        self.assertIn('Application Stack Trace Disclosure', [f.title for f in result.findings])

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_200_behavior_unchanged(self, MockSession):
        body = '{"activeProfiles":[],"propertySources":[]}'
        result = self._scan(MockSession, _routes({'/actuator/env': (200, body)}))
        env = self._endpoint(result, '/actuator/env')
        self.assertEqual((env[0].severity, env[0].status), (Severity.CRITICAL, FindingStatus.CONFIRMED))

    @patch('Tarama.scanners.error_disclosure.requests.Session')
    def test_request_failure_is_still_no_response(self, MockSession):
        MockSession.return_value.get.side_effect = requests.ConnectionError('down')
        result = ErrorDisclosureScanner().scan('https://example.com')
        self.assertIsNone(result.error)
        self.assertEqual([f for f in result.findings if f.status != FindingStatus.INFORMATIONAL
                          and f.status != FindingStatus.SECURE], [])


class CmsResponseTruthinessTest(TestCase):

    def _scan(self, MockSession, handler):
        MockSession.return_value.get.side_effect = handler
        return CmsScanner().scan('https://example.com')

    def _admin(self, result):
        return {f.affected_url.rsplit('example.com', 1)[1]: f for f in result.findings
                if f.title.startswith('Admin paneli bulundu')}

    @patch('Tarama.scanners.cms.requests.Session')
    def test_401_and_403_admin_paths_reach_secure_branch(self, MockSession):
        result = self._scan(MockSession, _routes({
            'example.com': (200, '<html>home</html>'),
            '/wp-admin/': (401, '<html>Authorization Required</html>'),
            '/administrator/': (403, '<html>Forbidden</html>'),
        }))
        admin = self._admin(result)
        self.assertEqual(set(admin), {'/wp-admin/', '/administrator/'})
        self.assertEqual(admin['/wp-admin/'].status, FindingStatus.SECURE)
        self.assertIn('HTTP 401', admin['/wp-admin/'].evidence)
        self.assertEqual(admin['/administrator/'].status, FindingStatus.SECURE)
        self.assertIn('HTTP 403', admin['/administrator/'].evidence)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_p0_3_deny_all_403_does_not_create_admin_findings(self, MockSession):
        result = self._scan(MockSession, _routes({'example.com': (200, '<html>home</html>')},
                                                 default=(403, '<html>Forbidden</html>')))
        self.assertEqual(self._admin(result), {})

    @patch('Tarama.scanners.cms.requests.Session')
    def test_200_admin_unchanged_and_404_admin_not_reported(self, MockSession):
        result = self._scan(MockSession, _routes({
            'example.com': (200, '<html>home</html>'),
            '/admin/': (200, '<html><title>Admin</title>' + 'admin console ' * 30 + '</html>'),
        }))
        admin = self._admin(result)
        self.assertEqual(set(admin), {'/admin/'})
        self.assertEqual(admin['/admin/'].status, FindingStatus.INFORMATIONAL)

    @patch('Tarama.scanners.cms.requests.Session')
    def test_4xx_homepage_no_longer_aborts_scan(self, MockSession):
        result = self._scan(MockSession, _routes({'example.com': (403, '<html>Forbidden</html>')}))
        self.assertIsNone(result.error)
        self.assertIn('Bilinen CMS tespit edilmedi', [f.title for f in result.findings])

    @patch('Tarama.scanners.cms.requests.Session')
    def test_homepage_request_failure_still_reported_as_no_response(self, MockSession):
        MockSession.return_value.get.side_effect = requests.ConnectionError('down')
        result = CmsScanner().scan('https://example.com')
        self.assertEqual(result.error, 'Ana sayfa alınamadı')


class IntegrityResponseTruthinessTest(TestCase):

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_4xx_homepage_no_longer_aborts_scan(self, MockSession):
        page = '<html><head><script src="https://cdn.thirdparty.example/lib.js"></script></head></html>'
        MockSession.return_value.get.side_effect = _routes({'example.com': (404, page)})
        result = IntegrityScanner().scan('https://example.com')
        self.assertIsNone(result.error)
        self.assertTrue(any(f.title.startswith('SRI eksik') for f in result.findings))

    @patch('Tarama.scanners.integrity.requests.Session')
    def test_homepage_request_failure_still_reported_as_no_response(self, MockSession):
        MockSession.return_value.get.side_effect = requests.ConnectionError('down')
        self.assertEqual(IntegrityScanner().scan('https://example.com').error, 'Ana sayfa alınamadı')


class AccessControlResponseTruthinessTest(TestCase):

    def _session(self, MockSession, get_handler):
        instance = MockSession.return_value
        instance.get.side_effect = get_handler
        instance.options.return_value = _http_response(405)
        instance.request.return_value = _http_response(405)
        return instance

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_401_response_cors_headers_are_analyzed(self, MockSession):
        self._session(MockSession, _routes({'example.com': (
            401, '{"error":"auth"}', {'Access-Control-Allow-Origin': '*'})}))
        result = AccessControlScanner().scan('https://example.com')
        self.assertIn('CORS: Tüm kaynaklara izin verilmiş (wildcard)', [f.title for f in result.findings])

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_401_response_origin_reflection_is_analyzed(self, MockSession):
        def handler(url, headers=None, **kwargs):
            origin = (headers or {}).get('Origin')
            cors = {'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true'} if origin else {}
            return _http_response(401, '{"error":"auth"}', url=url, headers=cors)
        self._session(MockSession, handler)
        result = AccessControlScanner().scan('https://example.com')
        reflection = [f for f in result.findings if f.title == 'Potentially Insecure CORS Origin Reflection']
        self.assertEqual(len(reflection), 1)
        self.assertEqual((reflection[0].severity, reflection[0].status), (Severity.HIGH, FindingStatus.CONFIRMED))

    @patch('Tarama.scanners.access_control.requests.Session')
    def test_request_failure_is_still_no_response(self, MockSession):
        instance = self._session(MockSession, None)
        instance.get.side_effect = requests.ConnectionError('down')
        result = AccessControlScanner().scan('https://example.com')
        self.assertEqual([f for f in result.findings if 'CORS' in f.title], [])


class AuthRateLimitResponseTruthinessTest(TestCase):

    def _scan(self, MockSession, post_status, headers=None):
        instance = MockSession.return_value
        instance.get.side_effect = _routes({'example.com': (200, _HOME_WITH_LOGIN)})
        instance.post.side_effect = lambda url, **kw: _http_response(post_status, 'slow down', url=url,
                                                                    headers=headers)
        return AuthScanner().scan('https://example.com')

    @patch('Tarama.scanners.auth.requests.Session')
    def test_429_reaches_rate_limit_status_branch(self, MockSession):
        result = self._scan(MockSession, 429, headers={'Retry-After': '30'})
        titles = [f.title for f in result.findings]
        self.assertIn('Rate-limit koruması aktif (HTTP status)', titles)
        self.assertNotIn('Potential Lack of Authentication Rate Limiting', titles)
        secure = next(f for f in result.findings if f.title == 'Rate-limit koruması aktif (HTTP status)')
        self.assertEqual(secure.status, FindingStatus.SECURE)
        self.assertIn('HTTP 429', secure.evidence)

    @patch('Tarama.scanners.auth.requests.Session')
    def test_503_reaches_rate_limit_status_branch(self, MockSession):
        result = self._scan(MockSession, 503)
        self.assertIn('Rate-limit koruması aktif (HTTP status)', [f.title for f in result.findings])

    @patch('Tarama.scanners.auth.requests.Session')
    def test_request_failures_are_not_mistaken_for_rate_limiting(self, MockSession):
        instance = MockSession.return_value
        instance.get.side_effect = _routes({'example.com': (200, _HOME_WITH_LOGIN)})
        instance.post.side_effect = requests.ConnectionError('down')
        result = AuthScanner().scan('https://example.com')
        titles = [f.title for f in result.findings]
        self.assertNotIn('Rate-limit koruması aktif (HTTP status)', titles)
        self.assertIn('Potential Lack of Authentication Rate Limiting', titles)
