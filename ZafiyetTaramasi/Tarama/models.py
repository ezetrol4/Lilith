from django.db import models

from .services.evidence_redaction import redact_sensitive_text, redact_sensitive_url

# CRITICAL -> INFO gerçek risk sırasını temsil eder. ScanFinding.severity düz bir
# CharField olduğundan alfabetik sıralama YANLIŞ sıra üretir (CRITICAL, HIGH, INFO,
# LOW, MEDIUM) — bu yüzden API çıktısı için ayrı bir rank kullanılır.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class ScanJob(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Bekliyor'),
        ('RUNNING', 'Çalışıyor'),
        ('DONE', 'Tamamlandı'),
        ('FAILED', 'Başarısız'),
    ]

    # Güvenli görüntüleme URL'si (redact_sensitive_url) — tarama için kullanılan ham ağ
    # URL'si burada SAKLANMAZ (bkz. services/scan_runner.start_scan).
    target = models.URLField(max_length=2048)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        # -id ikinci sıralama anahtarı olarak eklendi: created_at (auto_now_add) aynı
        # tick içinde oluşturulan işler için çakışabilir (özellikle SQLite/test ortamında),
        # bu durumda -id her zaman gerçek oluşturulma sırasını korur (CLAUDE.md §5/§11).
        ordering = ['-created_at', '-id']

    def __str__(self):
        return f"[{self.status}] {redact_sensitive_url(self.target)} ({self.created_at:%Y-%m-%d %H:%M})"

    @property
    def duration_seconds(self):
        if self.completed_at and self.created_at:
            return round((self.completed_at - self.created_at).total_seconds(), 1)
        return None


class ScanFinding(models.Model):
    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='findings')
    scanner = models.CharField(max_length=20)
    severity = models.CharField(max_length=10)
    title = models.CharField(max_length=255)
    evidence = models.TextField(blank=True)

    # V1 reporting refactor — hepsi opsiyonel, mevcut kayıtlar için default=''.
    confidence = models.CharField(max_length=10, blank=True, default='')
    status = models.CharField(max_length=20, blank=True, default='')
    description = models.TextField(blank=True, default='')
    affected_url = models.CharField(max_length=2048, blank=True, default='')
    parameter = models.CharField(max_length=255, blank=True, default='')
    owasp = models.CharField(max_length=100, blank=True, default='')
    cwe = models.CharField(max_length=50, blank=True, default='')
    mitre = models.CharField(max_length=100, blank=True, default='')
    recommendation = models.TextField(blank=True, default='')

    class Meta:
        ordering = ['scanner', 'severity']

    def __str__(self):
        return f"[{self.severity}] {self.scanner}: {self.title}"

    @property
    def severity_rank(self) -> int:
        """API çıktısı için gerçek risk sırasını döner (0=CRITICAL ... 4=INFO)."""
        return SEVERITY_RANK.get(self.severity, len(SEVERITY_RANK))

    def to_dict(self) -> dict:
        """Finding.to_dict() ile aynı alan seti — tek yetkili JSON temsili (CLAUDE.md §9)."""
        return {
            "scanner": self.scanner,
            "severity": self.severity,
            "title": self.title,
            # API sınırında defense-in-depth: P0-2 öncesinde ham olarak kaydedilmiş
            # tarihsel kayıtlar dahil hiçbir kanıt gizli değeri API'ye taşımaz.
            "evidence": redact_sensitive_text(self.evidence),
            "confidence": self.confidence or None,
            "status": self.status or None,
            "description": self.description or None,
            "affected_url": redact_sensitive_url(self.affected_url) or None,
            "parameter": self.parameter or None,
            "owasp": self.owasp or None,
            "cwe": self.cwe or None,
            "mitre": self.mitre or None,
            "recommendation": self.recommendation or None,
        }
