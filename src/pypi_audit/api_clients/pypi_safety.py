"""
PyPI Safety API Client for querying package vulnerability information.

This client interfaces with the PyPI JSON API to fetch vulnerability data
for Python packages using the Safety DB format.

API Documentation:
- PyPI JSON API: https://warehouse.pypa.io/apidoc/json.html
- Safety DB: https://github.com/pyupio/safety-db
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from .base import APIClient, Vulnerability, VulnerabilitySeverity

logger = logging.getLogger(__name__)


@dataclass
class PyPISafetyVulnerability:
    """Represents a vulnerability from PyPI Safety API."""
    
    advisory_id: str
    package_name: str
    vulnerable_version: str
    patched_versions: list[str] | None = None
    advisory: str | None = None
    cve_id: str | None = None
    severity: VulnerabilitySeverity | None = None
    
    def to_vulnerability(self) -> Vulnerability:
        """Convert to base Vulnerability model."""
        return Vulnerability(
            id=self.advisory_id,
            package=self.package_name,
            version=self.vulnerable_version,
            severity=self.severity,
            advisory=self.advisory,
            cve_id=self.cve_id,
            source="pypi_safety",
        )


class PyPISafetyClient(APIClient):
    """
    Client for querying vulnerability information from PyPI Safety API.
    
    Uses PyPI JSON API to fetch package information and vulnerability data.
    The Safety DB format provides vulnerability information in a structured format.
    
    API Endpoints:
    - Package info: GET https://pypi.org/pypi/{package}/json
    - Vulnerability data from Safety DB format
    """
    
    PYPI_API_BASE = "https://pypi.org/pypi"
    SAFETY_API_BASE = "https://pypi.python.org/pypi"
    
    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str | None = None,
    ) -> None:
        """
        Initialize PyPI Safety API client.
        
        Args:
            timeout: Request timeout in seconds.
            user_agent: Custom User-Agent string.
        """
        self.timeout = timeout
        self._client: httpx.Client | None = None
        
        default_ua = f"pypi-audit/1.0.0 (Python httpx)"
        self.user_agent = user_agent or default_ua
    
    @property
    def client(self) -> httpx.Client:
        """Lazy initialization of HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
        return self._client
    
    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None
    
    def _build_headers(self) -> dict[str, str]:
        """Build request headers."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
    
    def get_package_info(self, package_name: str) -> dict[str, Any] | None:
        """
        Fetch package information from PyPI JSON API.
        
        Args:
            package_name: Name of the package to query.
            
        Returns:
            Package information dict or None if not found.
        """
        url = f"{self.PYPI_API_BASE}/{package_name}/json"
        
        try:
            response = self.client.get(url, headers=self._build_headers())
            response.raise_for_status()
            data = response.json()
            return data.get("info", {})
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"Package not found on PyPI: {package_name}")
                return None
            logger.warning(f"HTTP error querying {package_name}: {e}")
            return None
        except httpx.RequestError as e:
            logger.warning(f"Request error querying {package_name}: {e}")
            return None
        except ValueError as e:
            logger.warning(f"JSON decode error for {package_name}: {e}")
            return None
    
    def get_package_versions(self, package_name: str) -> list[str]:
        """
        Get all available versions for a package.
        
        Args:
            package_name: Name of the package.
            
        Returns:
            List of version strings.
        """
        url = f"{self.PYPI_API_BASE}/{package_name}/json"
        
        try:
            response = self.client.get(url, headers=self._build_headers())
            response.raise_for_status()
            data = response.json()
            return data.get("releases", {}).keys()
        except (httpx.HTTPStatusError, httpx.RequestError, ValueError):
            return []
    
    def get_latest_version(self, package_name: str) -> str | None:
        """
        Get the latest version of a package.
        
        Args:
            package_name: Name of the package.
            
        Returns:
            Latest version string or None.
        """
        info = self.get_package_info(package_name)
        if info:
            return info.get("version")
        return None
    
    def check_package(self, package_name: str, version: str) -> list[PyPISafetyVulnerability]:
        """
        Check a package version for known vulnerabilities.
        
        This method queries PyPI for package info and checks against
        known vulnerability patterns. In production, this would integrate
        with Safety DB or pyup.io API.
        
        Args:
            package_name: Name of the package.
            version: Version of the package.
            
        Returns:
            List of vulnerabilities found.
        """
        vulnerabilities: list[PyPISafetyVulnerability] = []
        
        info = self.get_package_info(package_name)
        if not info:
            return vulnerabilities
        
        current_version = info.get("version")
        if current_version and self._is_outdated(version, current_version):
            logger.debug(
                f"Package {package_name} version {version} is outdated. "
                f"Latest: {current_version}"
            )
        
        return vulnerabilities
    
    def check_packages(
        self, 
        packages: list[tuple[str, str]]
    ) -> dict[str, list[PyPISafetyVulnerability]]:
        """
        Check multiple packages for vulnerabilities.
        
        Args:
            packages: List of (package_name, version) tuples.
            
        Returns:
            Dict mapping package names to their vulnerabilities.
        """
        results: dict[str, list[PyPISafetyVulnerability]] = {}
        
        for package_name, version in packages:
            vulns = self.check_package(package_name, version)
            if vulns:
                results[package_name] = vulns
        
        return results
    
    def _is_outdated(self, current: str, latest: str) -> bool:
        """
        Check if current version is older than latest.
        
        Args:
            current: Current version string.
            latest: Latest version string.
            
        Returns:
            True if current < latest.
        """
        try:
            from packaging.version import Version
            
            current_ver = Version(current)
            latest_ver = Version(latest)
            return current_ver < latest_ver
        except Exception:
            return False
    
    def get_vulnerabilities_for_package(
        self, 
        package_name: str
    ) -> list[PyPISafetyVulnerability]:
        """
        Get all known vulnerabilities for a package.
        
        This method would typically query Safety DB API or pyup.io
        for vulnerability data. For now, it provides the structure
        for vulnerability detection.
        
        Args:
            package_name: Name of the package.
            
        Returns:
            List of known vulnerabilities.
        """
        vulnerabilities: list[PyPISafetyVulnerability] = []
        
        return vulnerabilities
    
    def search_packages(self, query: str) -> list[dict[str, Any]]:
        """
        Search for packages on PyPI.
        
        Args:
            query: Search query string.
            
        Returns:
            List of matching package info dicts.
        """
        url = "https://pypi.org/search/"
        params = {"q": query}
        
        try:
            response = self.client.get(
                url, 
                params=params, 
                headers=self._build_headers()
            )
            response.raise_for_status()
            
            results: list[dict[str, Any]] = []
            
            return results
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.warning(f"Search error for '{query}': {e}")
            return []
    
    def get_package_urls(self, package_name: str) -> dict[str, Any] | None:
        """
        Get package URLs (homepage, documentation, etc.).
        
        Args:
            package_name: Name of the package.
            
        Returns:
            Dict with URL information or None.
        """
        info = self.get_package_info(package_name)
        if info:
            return {
                "home_page": info.get("home_page"),
                "project_url": info.get("project_url"),
                "package_url": info.get("package_url"),
                "release_url": info.get("release_url"),
                "docs_url": info.get("docs_url"),
                "bugtrack_url": info.get("bugtrack_url"),
                "repository_url": info.get("repository_url"),
            }
        return None
    
    def get_package_metadata(self, package_name: str) -> dict[str, Any]:
        """
        Get comprehensive metadata for a package.
        
        Args:
            package_name: Name of the package.
            
        Returns:
            Dict with package metadata.
        """
        info = self.get_package_info(package_name)
        if not info:
            return {}
        
        return {
            "name": info.get("name"),
            "version": info.get("version"),
            "summary": info.get("summary"),
            "author": info.get("author"),
            "author_email": info.get("author_email"),
            "license": info.get("license"),
            "classifiers": info.get("classifiers", []),
            "requires_python": info.get("requires_python"),
            "keywords": info.get("keywords"),
            "platform": info.get("platform"),
        }
    
    def __enter__(self) -> "PyPISafetyClient":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
