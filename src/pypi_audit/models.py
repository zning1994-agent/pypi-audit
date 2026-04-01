"""Data models for pypi-audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> "VulnerabilitySeverity":
        """Create severity from string value."""
        value = value.upper()
        if value in ("CRITICAL", "CRIT"):
            return cls.CRITICAL
        elif value == "HIGH":
            return cls.HIGH
        elif value in ("MEDIUM", "MODERATE"):
            return cls.MEDIUM
        elif value == "LOW":
            return cls.LOW
        return cls.UNKNOWN


class VulnerabilitySource(Enum):
    """Source of vulnerability data."""

    PYPI_SAFETY = "pypi_safety"
    OSV = "osv"
    IOC = "ioc"  # Indicator of Compromise (LiteLLM event)


@dataclass
class Vulnerability:
    """Represents a vulnerability found in a package."""

    id: str
    package_name: str
    package_version: str
    severity: VulnerabilitySeverity
    source: VulnerabilitySource
    title: str
    description: Optional[str] = None
    fixed_versions: list[str] = field(default_factory=list)
    advisory_url: Optional[str] = None
    cve_id: Optional[str] = None

    def get_severity_score(self) -> int:
        """Get numeric severity score for sorting."""
        scores = {
            VulnerabilitySeverity.CRITICAL: 4,
            VulnerabilitySeverity.HIGH: 3,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 1,
            VulnerabilitySeverity.UNKNOWN: 0,
        }
        return scores.get(self.severity, 0)


@dataclass
class Package:
    """Represents a Python package dependency."""

    name: str
    version: str
    source_file: str
    line_number: Optional[int] = None

    @property
    def package_id(self) -> str:
        """Unique identifier for this package."""
        return f"{self.name}=={self.version}"


@dataclass
class IocMatch:
    """Represents a match against known Indicators of Compromise."""

    package_name: str
    package_version: str
    source_file: str
    ioc_type: str
    description: str
    event_name: str
    event_date: str
    severity: VulnerabilitySeverity = VulnerabilitySeverity.CRITICAL


@dataclass
class ScanResult:
    """Result of scanning dependencies."""

    packages: list[Package] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    ioc_matches: list[IocMatch] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    files_scanned: list[str] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities found."""
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        """Count of critical vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH)

    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.vulnerabilities) > 0 or len(self.ioc_matches) > 0

    @property
    def sorted_vulnerabilities(self) -> list[Vulnerability]:
        """Get vulnerabilities sorted by severity (critical first)."""
        return sorted(self.vulnerabilities, key=lambda v: v.get_severity_score(), reverse=True)
