"""OSV.dev API client for open source vulnerability data."""

from typing import Any

import httpx

from ..models import Dependency, Severity, Source, Vulnerability
from .base import BaseAPIClient


class OSVClient(BaseAPIClient):
    """Client for OSV.dev API (https://osv.dev)."""

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, http_client: httpx.Client | None = None) -> None:
        """Initialize the OSV.dev API client."""
        super().__init__(http_client)

    def is_available(self) -> bool:
        """Check if OSV API is available."""
        try:
            client = self._http_client or httpx.Client()
            try:
                response = client.get(f"{self.BASE_URL}/", timeout=5.0)
                return response.status_code in (200, 404)  # 404 means API is up
            finally:
                if self._owns_client:
                    client.close()
        except Exception:
            return False

    def get_vulnerabilities(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Get vulnerabilities for a dependency from OSV.

        Args:
            dependency: The dependency to check

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        try:
            client = self._http_client or httpx.Client()
            try:
                # Query OSV for PyPI package vulnerabilities
                payload = {
                    "package": {
                        "name": dependency.name,
                        "ecosystem": "PyPI",
                    },
                    "version": dependency.version,
                }

                response = client.post(
                    f"{self.BASE_URL}/query",
                    json=payload,
                    timeout=15.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = self._parse_vulnerabilities(
                        data, dependency
                    )
            finally:
                if self._owns_client:
                    client.close()
        except Exception:
            pass

        return vulnerabilities

    def query_package(self, package_name: str) -> list[str]:
        """
        Query all vulnerabilities for a package (without specific version).

        Args:
            package_name: Name of the package

        Returns:
            List of vulnerability IDs
        """
        try:
            client = self._http_client or httpx.Client()
            try:
                payload = {
                    "package": {
                        "name": package_name,
                        "ecosystem": "PyPI",
                    },
                }

                response = client.post(
                    f"{self.BASE_URL}/query",
                    json=payload,
                    timeout=15.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    return [
                        vuln.get("id") for vuln in data.get("vulns", [])
                        if vuln.get("id")
                    ]
            finally:
                if self._owns_client:
                    client.close()
        except Exception:
            pass

        return []

    def _parse_vulnerabilities(
        self, data: dict[str, Any], dependency: Dependency
    ) -> list[Vulnerability]:
        """Parse vulnerability data from OSV response."""
        vulnerabilities = []

        for vuln in data.get("vulns", []):
            vuln_id = vuln.get("id", "unknown")
            details = vuln.get("details", "")
            severity_data = vuln.get("severity", [])

            # Parse severity
            severity = Severity.UNKNOWN
            for sev in severity_data:
                if sev.get("type") == "CVSS_V3":
                    cvss_score = sev.get("score", "")
                    severity = self._parse_cvss_score(cvss_score)
                    break

            # Get fixed versions
            fixed_versions = []
            for affected in vuln.get("affected", []):
                for range_info in affected.get("ranges", []):
                    for event in range_info.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])

            vulnerability = Vulnerability(
                id=vuln_id,
                package_name=dependency.name,
                package_version=dependency.version,
                severity=severity,
                source=Source.OSV,
                title=vuln.get("summary", f"OSV-{vuln_id}"),
                description=details if len(details) < 1000 else details[:997] + "...",
                fixed_versions=list(set(fixed_versions)),
                aliases=vuln.get("aliases", []),
            )
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _parse_cvss_score(self, score: str | None) -> Severity:
        """Parse CVSS score string to Severity enum."""
        if not score:
            return Severity.UNKNOWN

        try:
            # CVSS scores are typically like "CVSS:3.1/AV:N/AC:L/..."
            # or just a numeric score like "7.5"
            if "/" in score:
                # Extract numeric part
                parts = score.split("/")
                for part in reversed(parts):
                    try:
                        numeric_score = float(part)
                        break
                    except ValueError:
                        continue
                else:
                    return Severity.UNKNOWN
            else:
                numeric_score = float(score)

            if numeric_score >= 9.0:
                return Severity.CRITICAL
            elif numeric_score >= 7.0:
                return Severity.HIGH
            elif numeric_score >= 4.0:
                return Severity.MEDIUM
            elif numeric_score > 0:
                return Severity.LOW
        except (ValueError, TypeError):
            pass

        return Severity.UNKNOWN
