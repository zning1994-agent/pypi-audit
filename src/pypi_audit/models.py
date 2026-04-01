"""Data models for pypi-audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SeverityLevel(Enum):
    """Vulnerability severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class Package:
    """Represents a Python package."""

    name: str
    version: str

    def __str__(self) -> str:
        return f"{self.name}=={self.version}"


@dataclass
class Vulnerability:
    """Represents a vulnerability."""

    id: str
    package_name: str
    package_version: str
    summary: str
    details: str
    severity: SeverityLevel
    aliases: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    ecosystem: str = "PyPI"

    def __str__(self) -> str:
        return f"{self.id}: {self.summary}"


@dataclass
class VulnerabilityReference:
    """Reference link for a vulnerability."""

    type: str
    url: str


@dataclass
class AffectedRange:
    """Affected version range for a vulnerability."""

    introduced: Optional[str] = None
    fixed: Optional[str] = None
    type: str = "semver"


@dataclass
class ScanResult:
    """Result of scanning a package for vulnerabilities."""

    package: Package
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    is_vulnerable: bool = False

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)
