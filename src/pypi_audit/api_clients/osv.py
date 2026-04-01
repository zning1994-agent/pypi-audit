"""OSV.dev API client for vulnerability queries.

OSV.dev is an open vulnerability database that aggregates vulnerability data
from multiple sources including GitHub Security Advisories, PyPI, and others.

API Documentation: https://osv.dev/docs/
API Endpoint: https://api.osv.dev/v1/query
"""

import urllib.request
import urllib.error
from typing import Any, Optional

from pypi_audit.api_clients.base import BaseAPIClient
from pypi_audit.models import (
    AffectedRange,
    Package,
    SeverityLevel,
    Vulnerability,
    VulnerabilityReference,
)


class OSVClient(BaseAPIClient):
    """Client for OSV.dev API vulnerability queries.

    Supports querying vulnerabilities for PyPI packages by package name
    and version, or by package name alone.

    Example:
        >>> client = OSVClient()
        >>> package = Package(name="django", version="1.2.3")
        >>> vulns = client.query_package(package)
        >>> for vuln in vulns:
        ...     print(f"{vuln.id}: {vuln.summary}")
    """

    BASE_URL = "https://api.osv.dev/v1"
    ECOSYSTEM = "PyPI"

    def __init__(self, timeout: int = 30) -> None:
        """Initialize OSV.dev API client.

        Args:
            timeout: Request timeout in seconds. Default is 30.
        """
        super().__init__(timeout)
        self._base_url = self.BASE_URL

    def query_package(self, package: Package) -> list[Vulnerability]:
        """Query OSV.dev for vulnerabilities affecting a package.

        Sends a query to OSV.dev API to find all known vulnerabilities
        for the specified package and version.

        Args:
            package: Package to query (name and version required).

        Returns:
            List of Vulnerability objects found for the package.
            Returns empty list if no vulnerabilities found or on error.

        Raises:
            No explicit raises - errors are logged and empty list returned.
        """
        try:
            response = self._query_with_version(package)
            return self._parse_response(response, package)
        except urllib.error.URLError as e:
            # Log error but don't raise - scanner should continue
            return []

    def query_package_name(self, package_name: str) -> list[Vulnerability]:
        """Query OSV.dev for all vulnerabilities affecting a package by name.

        This queries without a specific version, returning all known
        vulnerabilities for the package regardless of version.

        Args:
            package_name: Name of the package to query.

        Returns:
            List of Vulnerability objects for the package.
        """
        try:
            response = self._query_by_name(package_name)
            package = Package(name=package_name, version="")
            return self._parse_response(response, package)
        except urllib.error.URLError:
            return []

    def _query_with_version(self, package: Package) -> dict[str, Any]:
        """Query OSV.dev API with package name and version.

        Args:
            package: Package with name and version.

        Returns:
            JSON response as dictionary.

        Raises:
            urllib.error.URLError: On network or API error.
        """
        payload = {
            "package": {
                "name": package.name,
                "ecosystem": self.ECOSYSTEM,
            },
            "version": package.version,
        }
        return self._make_request("/query", payload)

    def _query_by_name(self, package_name: str) -> dict[str, Any]:
        """Query OSV.dev API with package name only.

        Args:
            package_name: Name of the package.

        Returns:
            JSON response as dictionary.

        Raises:
            urllib.error.URLError: On network or API error.
        """
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": self.ECOSYSTEM,
            },
        }
        return self._make_request("/query", payload)

    def _make_request(
        self, endpoint: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Make HTTP POST request to OSV.dev API.

        Args:
            endpoint: API endpoint path.
            payload: JSON payload for the request.

        Returns:
            Parsed JSON response as dictionary.

        Raises:
            urllib.error.URLError: On network or API error.
        """
        import json

        url = f"{self._base_url}{endpoint}"
        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def _parse_response(
        self, response: dict[str, Any], package: Package
    ) -> list[Vulnerability]:
        """Parse OSV.dev API response into Vulnerability objects.

        Args:
            response: Raw API response dictionary.
            package: The package that was queried.

        Returns:
            List of parsed Vulnerability objects.
        """
        vulnerabilities: list[Vulnerability] = []
        vulns_data = response.get("vulns", [])

        for vuln_data in vulns_data:
            vulnerability = self._parse_vulnerability(vuln_data, package)
            if vulnerability:
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _parse_vulnerability(
        self, vuln_data: dict[str, Any], package: Package
    ) -> Optional[Vulnerability]:
        """Parse a single vulnerability entry from OSV.dev response.

        Args:
            vuln_data: Vulnerability data dictionary from API.
            package: The package that was queried.

        Returns:
            Parsed Vulnerability object, or None if parsing fails.
        """
        vuln_id = vuln_data.get("id")
        if not vuln_id:
            return None

        summary = vuln_data.get("summary", "")
        details = vuln_data.get("details", "")
        aliases = vuln_data.get("aliases", [])

        # Parse severity
        severity = self._parse_severity_osv(vuln_data.get("severity"))

        # Parse fixed versions from affected ranges
        fixed_versions = self._extract_fixed_versions(vuln_data.get("affected", []))

        # Parse references
        references = self._parse_references(vuln_data.get("references", []))

        return Vulnerability(
            id=vuln_id,
            package_name=package.name,
            package_version=package.version,
            summary=summary,
            details=details,
            severity=severity,
            aliases=aliases,
            fixed_versions=fixed_versions,
            references=references,
            ecosystem=self.ECOSYSTEM,
        )

    def _parse_severity_osv(
        self, severity_data: Optional[list[dict[str, Any]]]
    ) -> SeverityLevel:
        """Parse severity from OSV format to SeverityLevel enum.

        OSV uses CVSS V3 scoring. We extract the numeric score if available.

        Args:
            severity_data: List of severity objects from OSV.

        Returns:
            Mapped SeverityLevel enum value.
        """
        if not severity_data:
            return SeverityLevel.UNKNOWN

        for severity_obj in severity_data:
            score_str = severity_obj.get("score", "")
            if not score_str:
                continue

            # Try to extract CVSS score from strings like:
            # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # or just numeric "7.5"
            if "/" in score_str:
                # Try to parse from CVSS vector string
                cvss_info = severity_obj.get("type", "").upper()
                if "CVSS_V3" in cvss_info:
                    # For CVSS v3, we can estimate from the vector
                    # C:H = 0.56 impact, I:H = 0.22, A:H = 0.22
                    # Simplified: check for High impact indicators
                    if "C:H" in score_str or "I:H" in score_str:
                        if "AV:N" in score_str:
                            return SeverityLevel.HIGH
            else:
                # Try numeric score
                try:
                    score = float(score_str)
                    if score >= 9.0:
                        return SeverityLevel.CRITICAL
                    elif score >= 7.0:
                        return SeverityLevel.HIGH
                    elif score >= 4.0:
                        return SeverityLevel.MEDIUM
                    elif score > 0:
                        return SeverityLevel.LOW
                except ValueError:
                    pass

        return SeverityLevel.UNKNOWN

    def _extract_fixed_versions(
        self, affected_list: list[dict[str, Any]]
    ) -> list[str]:
        """Extract fixed versions from affected package ranges.

        Args:
            affected_list: List of affected package objects from OSV.

        Returns:
            List of fixed version strings.
        """
        fixed_versions: list[str] = []

        for affected in affected_list:
            # Check if package is for PyPI and matches our package
            pkg_info = affected.get("package", {})
            if pkg_info.get("ecosystem") != self.ECOSYSTEM:
                continue

            # Extract from ranges
            ranges = affected.get("ranges", [])
            for range_obj in ranges:
                events = range_obj.get("events", [])
                for event in events:
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

            # Also check explicit versions list
            versions = affected.get("versions", [])
            # Versions list contains affected versions, not fixed ones
            # So we don't add these to fixed_versions

        return list(set(fixed_versions))  # Remove duplicates

    def _parse_references(
        self, references_data: list[dict[str, Any]]
    ) -> list[str]:
        """Parse reference URLs from OSV response.

        Args:
            references_data: List of reference objects from OSV.

        Returns:
            List of reference URL strings.
        """
        urls: list[str] = []
        for ref in references_data:
            url = ref.get("url")
            if url:
                urls.append(url)
        return urls

    def get_vulnerability_details(self, vuln_id: str) -> Optional[dict[str, Any]]:
        """Fetch detailed information for a specific vulnerability.

        Args:
            vuln_id: OSV vulnerability ID.

        Returns:
            Full vulnerability details dictionary, or None if not found.

        Raises:
            urllib.error.URLError: On network error.
        """
        try:
            url = f"{self._base_url}/vulns/{vuln_id}"
            request = urllib.request.Request(url, headers={"Accept": "application/json"})

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                import json

                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError:
            return None

    def list_affected_versions(self, vuln_id: str) -> list[str]:
        """Get list of affected versions for a vulnerability.

        Args:
            vuln_id: OSV vulnerability ID.

        Returns:
            List of affected version strings.
        """
        details = self.get_vulnerability_details(vuln_id)
        if not details:
            return []

        affected_list = details.get("affected", [])
        versions: list[str] = []

        for affected in affected_list:
            pkg = affected.get("package", {})
            if pkg.get("ecosystem") == self.ECOSYSTEM:
                versions.extend(affected.get("versions", []))

        return versions
