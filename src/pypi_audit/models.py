"""Data models for pypi-audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Vulnerability severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Source(Enum):
    """Vulnerability data source."""

    PYPI_SAFETY = "pypi_safety"
    OSV = "osv"
    IOC_LITELLM = "ioc_litellm"


@dataclass
class Package:
    """Represents a Python package dependency."""

    name: str
    version: Optional[str] = None
    extras: list[str] = field(default_factory=list)
    source_file: Optional[str] = None

    def __post_init__(self) -> None:
        """Normalize package name to lowercase."""
        self.name = self.name.lower()


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""

    package_name: str
    package_version: Optional[str]
    severity: Severity
    source: Source
    vulnerability_id: str
    title: str
    description: Optional[str] = None
    fixed_versions: list[str] = field(default_factory=list)
    advisory_url: Optional[str] = None
    cve_ids: list[str] = field(default_factory=list)

    def get_fix_suggestion(self) -> str:
        """Get upgrade recommendation."""
        if self.fixed_versions:
            return f"Upgrade to: {' or '.join(self.fixed_versions)}"
        return "Consider removing the package or finding an alternative"


@dataclass
class AuditResult:
    """Result of auditing a single package."""

    package: Package
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    is_vulnerable: bool = False

    @property
    def vulnerability_count(self) -> int:
        """Get total number of vulnerabilities."""
        return len(self.vulnerabilities)


@dataclass
class ScanResult:
    """Result of scanning a dependencies file."""

    file_path: str
    file_type: str
    packages: list[Package] = field(default_factory=list)
    audit_results: list[AuditResult] = field(default_factory=list)
    scan_duration: float = 0.0
    error_message: Optional[str] = None

    @property
    def total_packages(self) -> int:
        """Get total number of packages scanned."""
        return len(self.packages)

    @property
    def vulnerable_packages(self) -> int:
        """Get number of vulnerable packages found."""
        return sum(1 for result in self.audit_results if result.is_vulnerable)

    @property
    def total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities found."""
        return sum(result.vulnerability_count for result in self.audit_results)
