"""Data models for pypi-audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VulnerabilitySource(Enum):
    """Source of vulnerability information."""
    PYPI_SAFETY = "pypi_safety"
    OSV = "osv"
    IOC_DETECTOR = "ioc_detector"


@dataclass
class Dependency:
    """Represents a Python package dependency."""
    name: str
    version: str
    source_file: Optional[str] = None
    
    def __hash__(self) -> int:
        return hash((self.name.lower(), self.version))


@dataclass
class Vulnerability:
    """Represents a known vulnerability."""
    id: str
    package_name: str
    affected_versions: str
    severity: SeverityLevel
    source: VulnerabilitySource
    description: str = ""
    advisory_url: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    
    @property
    def is_critical(self) -> bool:
        """Check if vulnerability is critical severity."""
        return self.severity == SeverityLevel.CRITICAL
    
    @property
    def severity_score(self) -> int:
        """Get numeric severity score for sorting."""
        scores = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.UNKNOWN: 1,
        }
        return scores.get(self.severity, 0)


@dataclass
class VulnerabilityFinding:
    """A vulnerability finding for a specific dependency."""
    dependency: Dependency
    vulnerability: Vulnerability
    is_ioc_match: bool = False
    ioc_details: Optional[str] = None


@dataclass
class ScanResult:
    """Result of a dependency scan."""
    dependencies: list[Dependency] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    scan_time: float = 0.0
    files_scanned: list[str] = field(default_factory=list)
    
    @property
    def total_dependencies(self) -> int:
        """Total number of unique dependencies found."""
        return len(self.dependencies)
    
    @property
    def vulnerable_dependencies(self) -> int:
        """Number of dependencies with vulnerabilities."""
        return len(set(f.dependency for f in self.vulnerabilities))
    
    @property
    def critical_count(self) -> int:
        """Number of critical severity vulnerabilities."""
        return sum(1 for f in self.vulnerabilities if f.vulnerability.is_critical)
    
    @property
    def ioc_matches(self) -> int:
        """Number of IOC matches found."""
        return sum(1 for f in self.vulnerabilities if f.is_ioc_match)
    
    @property
    def has_findings(self) -> bool:
        """Check if scan found any vulnerabilities."""
        return len(self.vulnerabilities) > 0
