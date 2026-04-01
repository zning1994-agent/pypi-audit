"""
Base classes for API clients.

Provides common interfaces and data models for vulnerability API clients.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""
    
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Vulnerability:
    """
    Represents a security vulnerability in a package.
    
    Attributes:
        id: Unique identifier for the vulnerability.
        package: Name of the vulnerable package.
        version: Vulnerable version or version range.
        severity: Severity level of the vulnerability.
        advisory: Description or advisory text.
        cve_id: CVE identifier if available.
        source: API source (e.g., 'osv', 'pypi_safety').
        affected_versions: List of affected version ranges.
        fixed_versions: List of versions with fixes.
        published_date: When the vulnerability was published.
        modified_date: When the vulnerability was last modified.
        references: List of reference URLs.
    """
    
    id: str
    package: str
    version: str
    severity: VulnerabilitySeverity | None = None
    advisory: str | None = None
    cve_id: str | None = None
    source: str = "unknown"
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    published_date: str | None = None
    modified_date: str | None = None
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Post-initialization processing."""
        if self.severity is None:
            self.severity = VulnerabilitySeverity.UNKNOWN
    
    @property
    def severity_value(self) -> str:
        """Get severity as string value."""
        if self.severity:
            return self.severity.value
        return "unknown"
    
    @property
    def is_critical(self) -> bool:
        """Check if vulnerability is critical."""
        return self.severity == VulnerabilitySeverity.CRITICAL
    
    @property
    def has_cve(self) -> bool:
        """Check if vulnerability has a CVE ID."""
        return self.cve_id is not None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "package": self.package,
            "version": self.version,
            "severity": self.severity_value,
            "advisory": self.advisory,
            "cve_id": self.cve_id,
            "source": self.source,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "published_date": self.published_date,
            "modified_date": self.modified_date,
            "references": self.references,
            "metadata": self.metadata,
        }


class APIClient(ABC):
    """
    Abstract base class for vulnerability API clients.
    
    All API clients should inherit from this class and implement
    the required methods.
    """
    
    @abstractmethod
    def check_package(self, package_name: str, version: str) -> list[Vulnerability]:
        """
        Check a package version for vulnerabilities.
        
        Args:
            package_name: Name of the package.
            version: Version to check.
            
        Returns:
            List of vulnerabilities found.
        """
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close the client and release resources."""
        pass
    
    def __enter__(self) -> "APIClient":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()


@dataclass
class VulnerabilityReport:
    """
    Aggregated vulnerability report from multiple sources.
    
    Attributes:
        package: Package name.
        version: Package version checked.
        vulnerabilities: List of vulnerabilities found.
        sources: List of sources queried.
        scan_time: Time taken for the scan.
        timestamp: When the scan was performed.
    """
    
    package: str
    version: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    scan_time: float = 0.0
    timestamp: str | None = None
    
    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.vulnerabilities) > 0
    
    @property
    def critical_count(self) -> int:
        """Count of critical vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.is_critical)
    
    @property
    def high_count(self) -> int:
        """Count of high severity vulnerabilities."""
        return sum(
            1 for v in self.vulnerabilities 
            if v.severity == VulnerabilitySeverity.HIGH
        )
    
    def get_by_severity(
        self, 
        severity: VulnerabilitySeverity
    ) -> list[Vulnerability]:
        """Get vulnerabilities by severity level."""
        return [
            v for v in self.vulnerabilities 
            if v.severity == severity
        ]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "package": self.package,
            "version": self.version,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "sources": self.sources,
            "scan_time": self.scan_time,
            "timestamp": self.timestamp,
            "summary": {
                "total": len(self.vulnerabilities),
                "critical": self.critical_count,
                "high": self.high_count,
            },
        }
