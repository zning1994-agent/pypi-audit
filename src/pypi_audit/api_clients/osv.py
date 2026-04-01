"""OSV.dev API client for open source vulnerability data."""

import httpx
from typing import Any

from .base import BaseAPIClient


class OSVClient(BaseAPIClient):
    """Client for OSV.dev API."""

    BASE_URL = "https://api.osv.dev/v1"

    def check_vulnerability(self, package_name: str, version: str) -> list[dict[str, Any]]:
        """Query OSV for vulnerabilities affecting a package version.
        
        Args:
            package_name: Name of the package.
            version: Version string.
            
        Returns:
            List of vulnerability records from OSV.
        """
        vulnerabilities = []
        
        try:
            response = httpx.post(
                f"{self.BASE_URL}/query",
                json={
                    "package": {
                        "name": package_name,
                        "ecosystem": "PyPI"
                    },
                    "version": version
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = self._parse_osv_response(data, package_name, version)
                
        except httpx.RequestError:
            pass
        except Exception:
            pass
            
        return vulnerabilities

    def _parse_osv_response(self, data: dict, package_name: str, version: str) -> list[dict[str, Any]]:
        """Parse OSV API response into vulnerability records.
        
        Args:
            data: Raw OSV API response.
            package_name: Package name for context.
            version: Version for context.
            
        Returns:
            List of normalized vulnerability records.
        """
        vulnerabilities = []
        
        for vuln in data.get("vulns", []):
            record = {
                "id": vuln.get("id", ""),
                "summary": vuln.get("summary", ""),
                "details": vuln.get("details", ""),
                "severity": self._extract_severity(vuln),
                "references": [ref.get("url", "") for ref in vuln.get("references", [])],
                "affected": self._format_affected(vuln.get("affected", [])),
            }
            vulnerabilities.append(record)
            
        return vulnerabilities

    def _extract_severity(self, vuln: dict) -> str:
        """Extract severity information from vulnerability.
        
        Args:
            vuln: OSV vulnerability data.
            
        Returns:
            Severity string.
        """
        severity = "UNKNOWN"
        
        for severity_info in vuln.get("severity", []):
            if severity_info.get("type") == "CVSS_V3":
                score = severity_info.get("score", "N/A")
                severity = f"CVSS_V3:{score}"
                break
                
        return severity

    def _format_affected(self, affected: list) -> str:
        """Format affected versions information.
        
        Args:
            affected: List of affected package versions.
            
        Returns:
            Formatted string of affected versions.
        """
        if not affected:
            return "Unknown"
            
        ranges = []
        for entry in affected:
            package = entry.get("package", {}).get("name", "")
            if package:
                ranges.append(package)
                
        return ", ".join(ranges) if ranges else "Unknown"

    def get_vulnerability_details(self, vulnerability_id: str) -> dict[str, Any] | None:
        """Get detailed information about a specific vulnerability.
        
        Args:
            vulnerability_id: The OSV vulnerability ID.
            
        Returns:
            Full vulnerability details or None.
        """
        try:
            response = httpx.post(
                f"{self.BASE_URL}/vulns/{vulnerability_id}",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
                
        except httpx.RequestError:
            pass
        except Exception:
            pass
            
        return None

    def query_by_ecosystem(self, ecosystem: str, page: int = 1) -> list[dict[str, Any]]:
        """Query vulnerabilities by ecosystem.
        
        Args:
            ecosystem: Package ecosystem (e.g., "PyPI").
            page: Page number for pagination.
            
        Returns:
            List of vulnerability summaries.
        """
        try:
            response = httpx.post(
                f"{self.BASE_URL}/query",
                json={
                    "page": page,
                    "ecosystem": ecosystem
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("vulns", [])
                
        except httpx.RequestError:
            pass
        except Exception:
            pass
            
        return []
