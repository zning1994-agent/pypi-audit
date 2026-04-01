"""PyPI Safety API client for vulnerability data."""

import httpx
from typing import Any

from .base import BaseAPIClient


class PyPISafetyClient(BaseAPIClient):
    """Client for PyPI Safety API."""

    BASE_URL = "https://pypi.python.org/pypi"

    def __init__(self, timeout: int = 30, api_key: str | None = None):
        """Initialize PyPI Safety client.
        
        Args:
            timeout: Request timeout in seconds.
            api_key: Optional PyPI Safety API key for premium features.
        """
        super().__init__(timeout)
        self.api_key = api_key

    def check_vulnerability(self, package_name: str, version: str) -> list[dict[str, Any]]:
        """Check vulnerabilities for a package version via PyPI JSON API.
        
        Args:
            package_name: Name of the package.
            version: Version string.
            
        Returns:
            List of vulnerability records.
        """
        vulnerabilities = []
        
        try:
            url = f"{self.BASE_URL}/{package_name}/{version}/json"
            response = httpx.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = self._extract_vulnerabilities(data)
                
        except httpx.RequestError:
            pass
        except Exception:
            pass
            
        return vulnerabilities

    def _extract_vulnerabilities(self, package_data: dict) -> list[dict[str, Any]]:
        """Extract vulnerability information from package data.
        
        Args:
            package_data: Raw package JSON data.
            
        Returns:
            List of vulnerability records.
        """
        vulnerabilities = []
        
        info = package_data.get("info", {})
        for advisory in info.get("vulnerabilities", []):
            vuln = {
                "id": advisory.get("id", ""),
                "package_name": advisory.get("package_name", ""),
                "advisory": advisory.get("advisory", ""),
                "漏洞等级": advisory.get(" severity", ""),
                "advisory_url": advisory.get("advisory_url", ""),
                "fix_version": advisory.get("fix_version", ""),
            }
            vulnerabilities.append(vuln)
            
        return vulnerabilities

    def get_vulnerability_details(self, vulnerability_id: str) -> dict[str, Any] | None:
        """Get details for a specific vulnerability.
        
        Args:
            vulnerability_id: The vulnerability identifier.
            
        Returns:
            Vulnerability details or None.
        """
        return None

    def check_bulk(self, packages: list[tuple[str, str]]) -> dict[str, list[dict[str, Any]]]:
        """Check multiple packages at once.
        
        Args:
            packages: List of (package_name, version) tuples.
            
        Returns:
            Dictionary mapping package identifiers to vulnerability lists.
        """
        results = {}
        for package_name, version in packages:
            vulns = self.check_vulnerability(package_name, version)
            if vulns:
                results[f"{package_name}=={version}"] = vulns
        return results
