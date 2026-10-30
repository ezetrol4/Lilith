import logging
import threading

from django.db import connection as db_connection
from django.utils import timezone

from .evidence_redaction import redact_sensitive_text, redact_sensitive_url
from .orchestrator import run_full_scan
from .safe_http import OUTBOUND_BLOCKED_MESSAGE
from ..models import ScanJob, ScanFinding

logger = logging.getLogger(__name__)


def _save_report(job: ScanJob, report) -> None:
    findings = []
    seen: set[tuple] = set()
    for scan_result in [report.headers, report.ports, report.sql, report.xss,
                        report.ssl, report.dns, report.cms,
                        report.access_control, report.auth,
                        report.integrity, report.error_disclosure,
                        report.cmd, report.nosql]:
        if scan_result.error:
            # SSRF politikasının engellediği istek, hedefe ait bir zafiyet değildir —
            # vulnerability sayısına katılan MEDIUM bir bulgu üretmemeli.
            blocked = scan_result.error == OUTBOUND_BLOCKED_MESSAGE
            findings.append(ScanFinding(
                job=job,
                scanner=scan_result.scanner,
                severity='INFO' if blocked else 'MEDIUM',
                title='Tarama hatası',
                # Hata metni istisna mesajından gelebilir (URL, yanıt parçası)
                evidence=redact_sensitive_text(scan_result.error),
                status='INFORMATIONAL' if blocked else '',
            ))
        for finding in scan_result.findings:
            # Kalıcılık sınırında defense-in-depth: Finding oluşturulduktan sonra
            # değiştirilmiş evidence de redakte edilmeden DB'ye yazılmaz.
            evidence = redact_sensitive_text(finding.evidence or '')
            affected_url = redact_sensitive_url(finding.affected_url or '')

            # Aynı scanner + başlık + evidence + affected_url + parameter kombinasyonu
            # tam olarak tekrarlanıyorsa (örn. farklı tekniklerin aynı sonucu üretmesi)
            # yalnızca birebir aynı kayıt bir kez saklanır — farklı evidence/parametre
            # taşıyan bulgular asla birleştirilmez (CLAUDE.md §4).
            identity = (
                scan_result.scanner, finding.title, evidence,
                affected_url, finding.parameter or '',
            )
            if identity in seen:
                continue
            seen.add(identity)

            findings.append(ScanFinding(
                job=job,
                scanner=scan_result.scanner,
                severity=finding.severity.value,
                title=finding.title,
                evidence=evidence,
                confidence=finding.confidence.value if finding.confidence else '',
                status=finding.status.value if finding.status else '',
                description=finding.description or '',
                affected_url=affected_url,
                parameter=finding.parameter or '',
                owasp=finding.owasp or '',
                cwe=finding.cwe or '',
                mitre=finding.mitre or '',
                recommendation=finding.recommendation or '',
            ))
    ScanFinding.objects.bulk_create(findings)


def _run_in_background(job_id: int, target: str) -> None:
    try:
        job = ScanJob.objects.get(id=job_id)
        job.status = 'RUNNING'
        job.save(update_fields=['status'])

        report = run_full_scan(target)
        _save_report(job, report)

        job.status = 'DONE'
        job.completed_at = timezone.now()
        job.save(update_fields=['status', 'completed_at'])
    except Exception:
        # Kasıtlı geniş sınır: orkestrasyon zaten tek tek scanner hatalarını izole eder
        # (bkz. orchestrator.py) — burası yalnızca TAMAMEN beklenmeyen bir hatayı
        # (örn. DB bağlantı kaybı) yakalar. Tam detay sunucu loguna yazılır.
        # Hedef URL kullanıcı girdisidir ve user:password@ içerebilir
        logger.exception("Scan job %s failed unexpectedly for target %r",
                         job_id, redact_sensitive_url(target))
        try:
            job = ScanJob.objects.get(id=job_id)
            job.status = 'FAILED'
            job.error = "Tarama beklenmeyen bir hatayla karşılaştı."
            job.save(update_fields=['status', 'error'])
        except Exception:
            # Son çare: durumu FAILED olarak işaretlemek bile başarısız olursa
            # (örn. DB tamamen erişilemez durumda) daha fazla yapılacak bir şey yok.
            pass
    finally:
        # Background thread'lerde DB bağlantısını manuel kapatmak gerekir
        db_connection.close()


def start_scan(target: str) -> ScanJob:
    """Creates a ScanJob, launches the scan in a background thread, returns the job.

    İki ayrı URL: DB'ye (ve dolayısıyla API/geçmişe) yalnızca güvenli görüntüleme
    URL'si yazılır; ham AĞ URL'si yalnızca bellekte, bu işin thread argümanı olarak
    scanner'lara ulaşır ve hiçbir yerde saklanmaz.
    """
    job = ScanJob.objects.create(target=redact_sensitive_url(target), status='PENDING')
    thread = threading.Thread(
        target=_run_in_background,
        args=(job.id, target),
        daemon=True,
        name=f"scan-{job.id}",
    )
    thread.start()
    return job
