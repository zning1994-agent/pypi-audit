"""Core scanning engine for pypi-audit."""

import time
from pathlib import Path
from typing import Optional

from .models import (
    Dependency,
    ScanResult,
    SeverityLevel,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilitySource,
)
from .parsers import get_parser
from .api_clients import PyPISafetyClient, OSVClient
from .ioc.detector import IOCDetector


class Scanner:
    """Core scanning engine for Python dependencies."""
    
    def __init__(
        self,
        use_pypi_safety: bool = True,
        use_osv: bool = True,
        use_ioc: bool = True,
        api_timeout: int = 30,
    ):
        """
        Initialize the scanner.
        
        Args:
            use_pypi_safety: Enable PyPI Safety API checks
            use_osv: Enable OSV.dev API checks
            use_ioc: Enable IOC detector checks
            api_timeout: Timeout for API requests in seconds
        """
        self.use_pypi_safety = use_pypi_safety
        self.use_osv = use_osv
        self.use_ioc = use_ioc
        self.api_timeout = api_timeout
        
        self._pypi_client: Optional[PyPISafetyClient] = None
        self._osv_client: Optional[OSVClient] = None
        self._ioc_detector: Optional[IOCDetector] = None
    
    @property
    def pypi_client(self) -> PyPISafetyClient:
        """Get or create PyPI Safety API client."""
        if self._pypi_client is None:
            self._pypi_client = PyPISafetyClient(timeout=self.api_timeout)
        return self._pypi_client
    
    @property
    def osv_client(self) -> OSVClient:
        """Get or create OSV.dev API client."""
        if self._osv_client is None:
            self._osv_client = OSVClient(timeout=self.api_timeout)
        return self._osv_client
    
    @property
    def ioc_detector(self) -> IOCDetector:
        """Get or create IOC detector."""
        if self._ioc_detector is None:
            self._ioc_detector = IOCDetector()
        return self._ioc_detector
    
    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a single dependency file.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            ScanResult with found dependencies and vulnerabilities
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        parser_class = get_parser(file_path)
        if parser_class is None:
            raise ValueError(f"Unsupported file type: {file_path}")
        
        parser = parser_class()
        dependencies = parser.parse(file_path)
        
        return self._scan_dependencies(dependencies, [str(path)])
    
    def scan_directory(self, directory: str) -> ScanResult:
        """
        Scan all dependency files in a directory.
        
        Args:
            directory: Path to directory to scan
            
        Returns:
            Combined ScanResult for all found dependency files
        """
        dir_path = Path(directory)
        
        if not dir_path.exists():
            raise NotADirectoryError(f"Directory not found: {directory}")
        
        all_dependencies: list[Dependency] = []
        all_findings: list[VulnerabilityFinding] = []
        files_scanned: list[str] = []
        
        dependency_files = [
            ("requirements.txt", "requirements.txt"),
            ("pyproject.toml", "pyproject.toml"),
            ("Pipfile.lock", "Pipfile.lock"),
        ]
        
        for filename, file_id in dependency_files:
            file_path = dir_path / filename
            if file_path.exists():
                try:
                    parser_class = get_parser(str(file_path))
                    if parser_class:
                        parser = parser_class()
                        deps = parser.parse(str(file_path))
                        all_dependencies.extend(deps)
                        files_scanned.append(str(file_path))
                except Exception:
                    continue
        
        return self._scan_dependencies(all_dependencies, files_scanned)
    
    def _scan_dependencies(
        self,
        dependencies: list[Dependency],
        files_scanned: list[str],
    ) -> ScanResult:
        """
        Scan a list of dependencies for vulnerabilities.
        
        Args:
            dependencies: List of dependencies to scan
            files_scanned: List of source files scanned
            
        Returns:
            ScanResult with all findings
        """
        start_time = time.time()
        findings: list[VulnerabilityFinding] = []
        
        for dep in dependencies:
            dep_findings = self._check_dependency(dep)
            findings.extend(dep_findings)
        
        scan_time = time.time() - start_time
        
        return ScanResult(
            dependencies=dependencies,
            vulnerabilities=findings,
            scan_time=scan_time,
            files_scanned=files_scanned,
        )
    
    def _check_dependency(self, dep: Dependency) -> list[VulnerabilityFinding]:
        """
        Check a single dependency for vulnerabilities.
        
        Args:
            dep: Dependency to check
            
        Returns:
            List of vulnerability findings
        """
        findings: list[VulnerabilityFinding] = []
        
        # Check PyPI Safety API
        if self.use_pypi_safety:
            try:
                vulns = self.pypi_client.check_package(dep.name, dep.version)
                for vuln in vulns:
                    findings.append(VulnerabilityFinding(
                        dependency=dep,
                        vulnerability=vuln,
                    ))
            except Exception:
                pass
        
        # Check OSV.dev API
        if self.use_osv:
            try:
                vulns = self.osv_client.check_package(dep.name, dep.version)
                for vuln in vulns:
                    findings.append(VulnerabilityFinding(
                        dependency=dep,
                        vulnerability=vuln,
                    ))
            except Exception:
                pass
        
        # Check IOC detector
        if self.use_ioc:
            try:
                ioc_matches = self.ioc_detector.check_package(dep.name, dep.version)
                for ioc_match in ioc_matches:
                    findings.append(VulnerabilityFinding(
                        dependency=dep,
                        vulnerability=ioc_match,
                        is_ioc_match=True,
                        ioc_details=ioc_match.description,
                    ))
            except Exception:
                pass
        
        return findings
    
    def get_summary(self, result: ScanResult) -> dict:
        """
        Generate a summary of scan results.
        
        Args:
            result: ScanResult to summarize
            
        Returns:
            Dictionary with summary statistics
        """
        return {
            "total_dependencies": result.total_dependencies,
            "vulnerable_dependencies": result.vulnerable_dependencies,
            "total_vulnerabilities": len(result.vulnerabilities),
            "critical_count": result.critical_count,
            "ioc_matches": result.ioc_matches,
            "scan_time": f"{result.scan_time:.2f}s",
            "files_scanned": len(result.files_scanned),
        }
