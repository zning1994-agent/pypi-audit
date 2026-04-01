"""
pypi-audit data models.

This module contains all dataclasses and enums used throughout the project.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    """Vulnerability severity levels."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class DataSource(Enum):
    """Available security data sources."""
    
    PYPI_SAFETY = "pypi-safety"
    OSV = "osv"
    LITE_LLM = "litellm"


class OutputFormat(Enum):
    """Supported output formats."""
    
    TERMINAL = "terminal"
    JSON = "json"
    SIMPLE = "simple"


class DependencyFile(Enum):
    """Supported dependency file types."""
    
    REQUIREMENTS_TXT = "requirements.txt"
    PYPROJECT_TOML = "pyproject.toml"
    PIPFILE_LOCK = "Pipfile.lock"


@dataclass
class Package:
    """Represents a Python package with its metadata."""
    
    name: str
    version: str
    file_path: Optional[Path] = None
    
    def __str__(self) -> str:
        return f"{self.name}=={self.version}"
    
    def __hash__(self) -> int:
        return hash((self.name, self.version))


@dataclass
class Vulnerability:
    """Represents a security vulnerability found in a package."""
    
    package_name: str
    version: str
    severity: Severity
    source: DataSource
    vulnerability_id: str
    description: str = ""
    fix_version: Optional[str] = None
    advisory_url: Optional[str] = None
    cve_id: Optional[str] = None
    
    def __str__(self) -> str:
        return (
            f"{self.package_name}@{self.version} "
            f"[{self.severity.value}] {self.vulnerability_id}"
        )


@dataclass
class ScanResult:
    """Results from scanning a dependency file."""
    
    path: Path
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=datetime.now)
    total_packages: int = 0
    error_message: Optional[str] = None
    
    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.vulnerabilities) > 0
    
    @property
    def critical_count(self) -> int:
        """Count of critical vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Count of high severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        """Count of medium severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        """Count of low severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)


@dataclass
class ScanOptions:
    """Options for configuring a scan."""
    
    timeout: int = 30
    verbosity: int = 0
    sources: list[DataSource] = field(
        default_factory=lambda: [DataSource.PYPI_SAFETY, DataSource.OSV, DataSource.LITE_LLM]
    )
    severity_filter: Optional[Severity] = None
    check_litellm_ioc: bool = True
