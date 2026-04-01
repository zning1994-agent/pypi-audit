"""Data models for pypi-audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Source(Enum):
    """Vulnerability data source."""

    PYPI_SAFETY = "pypi_safety"
    OSV = "osv"
    IOC = "ioc"  # Indicator of Compromise (malicious package)


@dataclass
class Dependency:
    """Represents a Python package dependency."""

    name: str
    version: str
    source_file: str
    line_number: Optional[int] = None

    def __hash__(self) -> int:
        return hash((self.name, self.version))


@dataclass
class Vulnerability:
    """Represents a known vulnerability."""

    id: str
    package_name: str
    package_version: str
    severity: Severity
    source: Source
    title: str
    description: Optional[str] = None
    fixed_versions: list[str] = field(default_factory=list)
    advisory_url: Optional[str] = None
    aliases: list[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class VulnerabilityReport:
    """Report containing detected vulnerabilities."""

    dependency: Dependency
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        """Check if dependency has any vulnerabilities."""
        return len(self.vulnerabilities) > 0

    @property
    def max_severity(self) -> Severity:
        """Get the highest severity among all vulnerabilities."""
        if not self.vulnerabilities:
            return Severity.UNKNOWN
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.UNKNOWN,
        ]
        return min(
            self.vulnerabilities, key=lambda v: severity_order.index(v.severity)
        ).severity


@dataclass
class ScanResult:
    """Result of scanning dependencies."""

    scanned_at: str
    source_file: str
    total_dependencies: int = 0
    vulnerable_count: int = 0
    reports: list[VulnerabilityReport] = field(default_factory=list)
    ioc_matches: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Check if scan found no vulnerabilities."""
        return self.vulnerable_count == 0 and len(self.ioc_matches) == 0

    def add_report(self, report: VulnerabilityReport) -> None:
        """Add a vulnerability report."""
        self.reports.append(report)
        if report.is_vulnerable:
            self.vulnerable_count += 1


@dataclass
class IOCMatch:
    """Indicator of Compromise match result."""

    package_name: str
    package_version: str
    event_name: str
    event_date: str
    description: str
    severity: Severity = Severity.CRITICAL
