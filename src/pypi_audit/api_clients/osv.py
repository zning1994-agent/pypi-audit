"""OSV.dev API client."""

import httpx
from typing import Optional

from ..models import SeverityLevel, Vulnerability, VulnerabilitySource


class OSVClient:
    """Client for OSV.dev API."""
    
    BASE_URL = "https://api.osv.dev/v1"
    
    def __init__(self, timeout: int = 30):
        """
        Initialize OSV.dev API client.
        
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
        Check a package version against OSV database.
        
        Args:
            package_name: Name of the package
            version: Version to check
            
        Returns:
            List of vulnerabilities found
        """
        try:
            # Query OSV for PyPI package vulnerabilities
            response = self.client.post(
                f"{self.BASE_URL}/query",
                json={
                    "package": {
                        "name": package_name,
                        "ecosystem": "PyPI",
                    },
                    "version": version,
                },
            )
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            vulnerabilities: list[Vulnerability] = []
            
            # Parse OSV response format
            for vulns in data.get("vulns", []):
                severity = self._extract_severity(vulns)
                
                vulnerabilities.append(
                    Vulnerability(
                        id=vulns.get("id", f"OSV-{package_name}-{version}"),
                        package_name=package_name,
                        affected_versions=self._extract_affected(vulns),
                        severity=severity,
                        source=VulnerabilitySource.OSV,
                        description=vulns.get("summary", ""),
                        advisory_url=vulns.get("external_links", [{}])[0].get("url", ""),
                    )
                )
            
            return vulnerabilities
            
        except Exception:
            return []
    
    def _extract_severity(self, vuln_data: dict) -> SeverityLevel:
        """Extract severity from OSV vulnerability data."""
        severity = SeverityLevel.UNKNOWN
        
        # Check for CVSS score
        severity_list = vuln_data.get("severity", [])
        for sev in severity_list:
            if "score" in sev:
                score = float(sev["score"])
                if score >= 9.0:
                    severity = SeverityLevel.CRITICAL
                elif score >= 7.0:
                    severity = SeverityLevel.HIGH
                elif score >= 4.0:
                    severity = SeverityLevel.MEDIUM
                else:
                    severity = SeverityLevel.LOW
                break
        
        return severity
    
    def _extract_affected(self, vuln_data: dict) -> str:
        """Extract affected versions string from OSV data."""
        affected = vuln_data.get("affected", [])
        if affected:
            ranges = affected[0].get("ranges", [{}])[0]
            events = ranges.get("events", [])
            if events:
                return " ".join(f"{e.get('introduced', e.get('fixed', '?'))}" for e in events)
        
        return "*"
    
    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None
