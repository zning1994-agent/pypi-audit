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


class VulnerabilitySource(Enum):
    """Source of vulnerability information."""
    
    PYPI_SAFETY = "pypi_safety"
    OSV = "osv"
    IOC_LITELLM = "ioc_litellm"


@dataclass
class Package:
    """Represents a Python package dependency."""
    
    name: str
    version: str
    file_path: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Normalize package name to lowercase."""
        self.name = self.name.lower()
    
    @property
    def full_name(self) -> str:
        """Return package name with version."""
        return f"{self.name}=={self.version}"


@dataclass
class Vulnerability:
    """Represents a known vulnerability."""
    
    id: str
    package_name: str
    package_version: str
    severity: Severity
    title: str
    description: str
    source: VulnerabilitySource
    url: Optional[str] = None
    fixed_versions: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        """Normalize package name to lowercase."""
        self.package_name = self.package_name.lower()


@dataclass
class ScanResult:
    """Result of scanning a dependency file."""
    
    file_path: str
    file_type: str
    packages: list[Package] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    ioc_matches: list["IOCMatch"] = field(default_factory=list)
    scan_time: float = 0.0
    error: Optional[str] = None


@dataclass
class IOCMatch:
    """Match found by IOC detector."""
    
    package: Package
    ioc_data: "LiteLLMIOC"
    matched_on: str  # e.g., "package_name", "malicious_hash"
    details: str


@dataclass 
class LiteLLMIOC:
    """LiteLLM 2026-03-24 supply chain attack IOC data."""
    
    malicious_packages: list[str] = field(default_factory=list)
    malicious_versions: dict[str, list[str]] = field(default_factory=dict)
    compromised_hashes: dict[str, list[str]] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    event_date: str = "2026-03-24"
    description: str = ""
