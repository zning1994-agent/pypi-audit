"""PyPI Safety API client for vulnerability data."""

from typing import Any

import httpx

from ..models import Dependency, Severity, Source, Vulnerability
from .base import BaseAPIClient


class PyPISafetyClient(BaseAPIClient):
    """Client for PyPI Safety API."""

    BASE_URL = "https://pypi.org/pypi"

    def __init__(self, http_client: httpx.Client | None = None) -> None:
        """Initialize the PyPI Safety API client."""
        super().__init__(http_client)
        self._base_url = self.BASE_URL

    def is_available(self) -> bool:
        """Check if PyPI is available."""
        try:
            client = self._http_client or httpx.Client()
            try:
                response = client.get(f"{self._base_url}/json", timeout=5.0)
                return response.status_code == 200
            finally:
                if self._owns_client:
                    client.close()
        except Exception:
            return False

    def get_vulnerabilities(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Get vulnerabilities for a dependency from PyPI.

        Args:
            dependency: The dependency to check

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        try:
            client = self._http_client or httpx.Client()
            try:
                # Get package info from PyPI
                url = f"{self._base_url}/{dependency.name}/{dependency.version}/json"
                response = client.get(url, timeout=10.0)

                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = self._parse_vulnerabilities(data, dependency)
            finally:
                if self._owns_client:
                    client.close()
        except Exception:
            pass

        return vulnerabilities

    def _parse_vulnerabilities(
        self, data: dict[str, Any], dependency: Dependency
    ) -> list[Vulnerability]:
        """Parse vulnerability data from PyPI response."""
        vulnerabilities = []

        # Check for security advisories in package metadata
        info = data.get("info", {})
        releases = data.get("releases", {})
        current_release = releases.get(dependency.version, [{}])[0]

        # Parse vulnerability data from various sources
        vulns = info.get("vulnerabilities", [])

        for vuln in vulns:
            for alias in vuln.get("aliases", []):
                vulnerability = Vulnerability(
                    id=alias,
                    package_name=dependency.name,
                    package_version=dependency.version,
                    severity=self._parse_severity(vuln.get("severity")),
                    source=Source.PYPI_SAFETY,
                    title=vuln.get("title", "Unknown vulnerability"),
                    description=vuln.get("description"),
                    advisory_url=vuln.get("link"),
                    aliases=vuln.get("aliases", []),
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _parse_severity(self, severity: str | None) -> Severity:
        """Parse severity string to Severity enum."""
        if not severity:
            return Severity.UNKNOWN

        severity = severity.lower()
        if severity in ("critical", "10", "9"):
            return Severity.CRITICAL
        elif severity in ("high", "8", "7"):
            return Severity.HIGH
        elif severity in ("medium", "moderate", "5", "6"):
            return Severity.MEDIUM
        elif severity in ("low", "3", "4"):
            return Severity.LOW
        return Severity.UNKNOWN
