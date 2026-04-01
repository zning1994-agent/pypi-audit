"""Data models for pypi-audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """Represents a known vulnerability."""

    id: str
    package_name: str
    affected_versions: str
    fixed_version: str | None = None
    severity: Severity = Severity.UNKNOWN
    description: str = ""
    references: list[str] = field(default_factory=list)
    source: str = ""


@dataclass
class AuditResult:
    """Result of auditing dependencies."""

    package_name: str
    version: str | None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    is_ioc_match: bool = False
    ioc_type: str | None = None
    source_file: str | None = None

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def has_ioc_match(self) -> bool:
        return self.is_ioc_match

    @property
    def is_safe(self) -> bool:
        return not self.has_vulnerabilities and not self.has_ioc_match


@dataclass
class AuditReport:
    """Complete audit report."""

    results: list[AuditResult] = field(default_factory=list)
    total_scanned: int = 0
    total_vulnerable: int = 0
    total_ioc_matches: int = 0
    scan_time_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_findings(self) -> bool:
        return self.total_vulnerable > 0 or self.total_ioc_matches > 0
