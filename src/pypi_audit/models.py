"""Data models for pypi-audit."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Package:
    """Represents a Python package dependency."""

    name: str
    version: Optional[str] = None
    source: str = "pypi"
    file_path: Optional[str] = None

    @property
    def full_name(self) -> str:
        """Return package name with version if available."""
        if self.version:
            return f"{self.name}=={self.version}"
        return self.name


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""

    package_name: str
    version: Optional[str]
    vulnerability_id: str
    source: str  # e.g., "pypi_safety", "osv", "ioc"
    severity: str = "unknown"
    title: Optional[str] = None
    description: Optional[str] = None
    fixed_version: Optional[str] = None
    url: Optional[str] = None


@dataclass
class ScanResult:
    """Result of scanning a dependency file."""

    file_path: str
    file_type: str  # e.g., "requirements.txt", "pyproject.toml", "Pipfile.lock"
    packages: list[Package] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_time: float = 0.0

    @property
    def package_count(self) -> int:
        """Return the number of packages found."""
        return len(self.packages)

    @property
    def vulnerability_count(self) -> int:
        """Return the number of vulnerabilities found."""
        return len(self.vulnerabilities)
