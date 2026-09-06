from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingStatus(Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"
    SECURE = "SECURE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass
class Finding:
    severity: Severity
    title: str
    evidence: Optional[str] = None

    # V1 reporting refactor — hepsi optional, mevcut scanner'ları kırmamak için.
    confidence: Optional[Confidence] = None
    status: Optional[FindingStatus] = None
    description: Optional[str] = None
    affected_url: Optional[str] = None
    parameter: Optional[str] = None
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    mitre: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "evidence": self.evidence or "",
            "confidence": self.confidence.value if self.confidence else None,
            "status": self.status.value if self.status else None,
            "description": self.description,
            "affected_url": self.affected_url,
            "parameter": self.parameter,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "mitre": self.mitre,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    scanner: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None


class Scanner(ABC):
    @abstractmethod
    def scan(self, target: str) -> ScanResult: ...


def _as_status(value) -> Optional["FindingStatus"]:
    """Hem Finding (enum) hem ScanFinding DB modeli (düz string, ''=yok) ile çalışır."""
    if isinstance(value, FindingStatus) or value is None:
        return value
    if not value:
        return None
    return FindingStatus(value)


def _as_severity(value) -> "Severity":
    return value if isinstance(value, Severity) else Severity(value)


def summarize_findings(findings) -> dict:
    """Bulgu listesini CLAUDE.md raporlama modeline göre tek, yetkili şekilde sayar.

    SECURE ve INFORMATIONAL bulgular vulnerability sayısına dahil edilmez.
    Status bilgisi olmayan (henüz migrate edilmemiş) bulgular severity'ye göre
    sayılır ancak ayrı bir 'unclassified' grubunda izlenir — sessizce yanlış
    sınıflandırılmazlar.
    """
    counts = {
        "total_findings": 0,
        "confirmed": 0,
        "potential": 0,
        "manual_review": 0,
        "informational": 0,
        "secure": 0,
        "unclassified": 0,
        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }

    _NON_VULNERABLE_STATUSES = {FindingStatus.SECURE, FindingStatus.INFORMATIONAL}
    _STATUS_KEY = {
        FindingStatus.CONFIRMED: "confirmed",
        FindingStatus.POTENTIAL: "potential",
        FindingStatus.MANUAL_REVIEW: "manual_review",
        FindingStatus.INFORMATIONAL: "informational",
        FindingStatus.SECURE: "secure",
    }

    for finding in findings:
        counts["total_findings"] += 1

        status = _as_status(finding.status)
        if status is None:
            counts["unclassified"] += 1
        else:
            counts[_STATUS_KEY[status]] += 1

        # SECURE/INFORMATIONAL bulgular vulnerability severity toplamlarına katılmaz.
        if status in _NON_VULNERABLE_STATUSES:
            continue
        counts["severity"][_as_severity(finding.severity).value.lower()] += 1

    return counts
