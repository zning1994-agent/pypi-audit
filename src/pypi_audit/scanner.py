"""
pypi-audit Scanner Module.

Core scanning engine that orchestrates dependency parsing,
vulnerability checking, and result aggregation.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pypi_audit.models import ScanResult, ScanOptions, Package, Vulnerability
from pypi_audit.parsers import RequirementsParser, PyProjectParser, PipfileParser
from pypi_audit.api_clients import PyPISafetyClient, OSVClient
from pypi_audit.ioc import LiteLLMDetector

if TYPE_CHECKING:
    from pypi_audit.models import DataSource


class Scanner:
    """Main scanner class for vulnerability detection."""
    
    def __init__(
        self,
        timeout: int = 30,
        verbosity: int = 0,
        check_pypi_safety: bool = True,
        check_osv: bool = True,
        check_litellm: bool = True,
    ) -> None:
        """
        Initialize the scanner.
        
        Args:
            timeout: HTTP request timeout in seconds.
            verbosity: Verbosity level (0=silent, 1=normal, 2+=verbose).
            check_pypi_safety: Enable PyPI Safety API checks.
            check_osv: Enable OSV.dev API checks.
            check_litellm: Enable LiteLLM IOC checks.
        """
        self.timeout = timeout
        self.verbosity = verbosity
        self.check_pypi_safety = check_pypi_safety
        self.check_osv = check_osv
        self.check_litellm = check_litellm
        
        # Initialize API clients
        self._pypi_safety_client = PyPISafetyClient(timeout=timeout) if check_pypi_safety else None
        self._osv_client = OSVClient(timeout=timeout) if check_osv else None
        self._litellm_detector = LiteLLMDetector() if check_litellm else None
        
        # Initialize parsers
        self._parsers = [
            RequirementsParser(),
            PyProjectParser(),
            PipfileParser(),
        ]
    
    def scan(self, path: Path) -> ScanResult:
        """
        Scan a file or directory for vulnerabilities.
        
        Args:
            path: Path to a dependency file or directory.
            
        Returns:
            ScanResult containing all found vulnerabilities.
        """
        path = path.resolve()
        
        # Find dependency files
        dep_files = self._find_dependency_files(path)
        
        if not dep_files:
            return ScanResult(
                path=path,
                vulnerabilities=[],
                scanned_at=datetime.now(),
                total_packages=0,
                error_message="No supported dependency files found",
            )
        
        # Parse all dependency files
        all_packages: list[Package] = []
        for dep_file in dep_files:
            packages = self._parse_file(dep_file)
            all_packages.extend(packages)
        
        # Check for vulnerabilities
        vulnerabilities = self._check_vulnerabilities(all_packages)
        
        return ScanResult(
            path=path,
            vulnerabilities=vulnerabilities,
            scanned_at=datetime.now(),
            total_packages=len(all_packages),
        )
    
    def _find_dependency_files(self, path: Path) -> list[Path]:
        """Find all supported dependency files in the given path."""
        files = []
        
        if path.is_file():
            if self._is_supported_dep_file(path):
                files.append(path)
        else:
            for pattern in ["**/requirements*.txt", "**/pyproject.toml", "**/Pipfile.lock"]:
                files.extend(path.glob(pattern))
        
        return files
    
    def _is_supported_dep_file(self, path: Path) -> bool:
        """Check if the file is a supported dependency file."""
        name = path.name.lower()
        return (
            name.startswith("requirements") or
            name == "pyproject.toml" or
            name == "pipfile.lock"
        )
    
    def _parse_file(self, path: Path) -> list[Package]:
        """Parse a dependency file using the appropriate parser."""
        for parser in self._parsers:
            if parser.supports(path):
                return parser.parse(path)
        return []
    
    def _check_vulnerabilities(self, packages: list[Package]) -> list[Vulnerability]:
        """Check all packages against vulnerability databases."""
        vulnerabilities = []
        
        for package in packages:
            # Check PyPI Safety
            if self.check_pypi_safety and self._pypi_safety_client:
                vulns = self._pypi_safety_client.check_package(package.name, package.version)
                vulnerabilities.extend(vulns)
            
            # Check OSV
            if self.check_osv and self._osv_client:
                vulns = self._osv_client.check_package(package.name, package.version)
                vulnerabilities.extend(vulns)
            
            # Check LiteLLM IOC
            if self.check_litellm and self._litellm_detector:
                vulns = self._litellm_detector.check_package(package.name, package.version)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
