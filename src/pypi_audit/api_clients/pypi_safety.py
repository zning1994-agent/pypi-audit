"""PyPI Safety API client."""

import httpx
from typing import Optional

from ..models import SeverityLevel, Vulnerability, VulnerabilitySource


class PyPISafetyClient:
    """Client for PyPI Safety API."""
    
    BASE_URL = "https://pypi.org/pypi"
    
    def __init__(self, timeout: int = 30):
        """
        Initialize PyPI Safety API client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self._client: Optional[httpx.Client] = None
    
    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client
    
    def check_package(self, package_name: str, version: str) -> list[Vulnerability]:
        """
        Check a package version against PyPI Safety database.
        
        Args:
            package_name: Name of the package
            version: Version to check
            
        Returns:
            List of vulnerabilities found
        """
        try:
            url = f"{self.BASE_URL}/{package_name}/{version}/json"
            response = self.client.get(url)
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            vulnerabilities: list[Vulnerability] = []
            
            # Extract vulnerabilities from JSON response
            if "vulnerabilities" in data:
                for vuln_data in data["vulnerabilities"]:
                    vulnerabilities.append(
                        Vulnerability(
                            id=vuln_data.get("id", f"PYPI-{package_name}-{version}"),
                            package_name=package_name,
                            affected_versions=version,
                            severity=self._parse_severity(vuln_data.get("severity")),
                            source=VulnerabilitySource.PYPI_SAFETY,
                            description=vuln_data.get("description", ""),
                            advisory_url=vuln_data.get("link", ""),
                            fixed_versions=vuln_data.get("fix_versions", []),
                        )
                    )
            
            return vulnerabilities
            
        except Exception:
            return []
    
    def _parse_severity(self, severity: Optional[str]) -> SeverityLevel:
        """Parse severity string to SeverityLevel enum."""
        if severity is None:
            return SeverityLevel.UNKNOWN
        
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
        }
        
        return severity_map.get(severity.lower(), SeverityLevel.UNKNOWN)
    
    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None
