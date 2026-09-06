import logging
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..scanners.base import ScanResult
from ..scanners.headers import HeaderScanner
from ..scanners.ports import PortScanner
from ..scanners.sql import SqlInjectionScanner
from ..scanners.xss import XssScanner
from ..scanners.ssl_tls import SslScanner
from ..scanners.dns_scan import DnsScanner
from ..scanners.cms import CmsScanner
from ..scanners.access_control import AccessControlScanner
from ..scanners.auth import AuthScanner
from ..scanners.integrity import IntegrityScanner
from ..scanners.error_disclosure import ErrorDisclosureScanner
from ..scanners.cmd import CmdInjectionScanner
from ..scanners.nosql import NoSqlInjectionScanner

logger = logging.getLogger(__name__)


@dataclass
class ScanReport:
    target:           str
    headers:          ScanResult
    ports:            ScanResult
    sql:              ScanResult
    xss:              ScanResult
    ssl:              ScanResult
    dns:              ScanResult
    cms:              ScanResult
    access_control:   ScanResult
    auth:             ScanResult
    integrity:        ScanResult
    error_disclosure: ScanResult
    cmd:              ScanResult
    nosql:            ScanResult


def run_full_scan(target: str) -> ScanReport:
    """Tüm tarayıcıları paralel çalıştırır ve birleşik raporu döner."""
    scanners = {
        "headers":          HeaderScanner(),
        "ports":            PortScanner(),
        "sql":              SqlInjectionScanner(),
        "xss":              XssScanner(),
        "ssl":              SslScanner(),
        "dns":              DnsScanner(),
        "cms":              CmsScanner(),
        "access_control":   AccessControlScanner(),
        "auth":             AuthScanner(),
        "integrity":        IntegrityScanner(),
        "error_disclosure": ErrorDisclosureScanner(),
        "cmd":              CmdInjectionScanner(),
        "nosql":            NoSqlInjectionScanner(),
    }

    results: dict[str, ScanResult] = {}
    with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
        futures = {executor.submit(s.scan, target): name for name, s in scanners.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception:
                # Kasıtlı geniş sınır: bir scanner'ın beklenmeyen hatası tüm taramayı
                # düşürmemeli. Tam detay yalnızca sunucu loguna yazılır; API'ye sızan
                # mesaj sanitize edilir (stack trace / iç detay içermez).
                logger.exception("Scanner '%s' failed unexpectedly for target %r", name, target)
                results[name] = ScanResult(
                    scanner=name, target=target,
                    error=f"'{name}' tarayıcısı beklenmeyen bir hatayla karşılaştı.",
                )

    return ScanReport(
        target=target,
        headers=results["headers"],
        ports=results["ports"],
        sql=results["sql"],
        xss=results["xss"],
        ssl=results["ssl"],
        dns=results["dns"],
        cms=results["cms"],
        access_control=results["access_control"],
        auth=results["auth"],
        integrity=results["integrity"],
        error_disclosure=results["error_disclosure"],
        cmd=results["cmd"],
        nosql=results["nosql"],
    )
