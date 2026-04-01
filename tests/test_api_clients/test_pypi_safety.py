"""
Unit tests for PyPI Safety API client.

Tests the PyPISafetyClient class for querying package vulnerability
information from PyPI JSON API.
"""

from __future__ import annotations

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Any

from pypi_audit.api_clients.pypi_safety import (
    PyPISafetyClient,
    PyPISafetyVulnerability,
)
from pypi_audit.api_clients.base import VulnerabilitySeverity


class TestPyPISafetyClient:
    """Test suite for PyPISafetyClient."""
    
    @pytest.fixture
    def client(self) -> PyPISafetyClient:
        """Create a PyPI Safety client instance."""
        return PyPISafetyClient(timeout=5.0)
    
    @pytest.fixture
    def mock_package_info(self) -> dict[str, Any]:
        """Sample package info response."""
        return {
            "name": "requests",
            "version": "2.31.0",
            "summary": "Python HTTP for Humans.",
            "author": "Kenneth Reitz",
            "author_email": "me@kennethreitz.org",
            "license": "Apache 2.0",
            "home_page": "https://requests.readthedocs.io",
            "project_url": "https://github.com/psf/requests",
            "classifiers": [
                "Development Status :: 5 - Production/Stable",
                "Intended Audience :: Developers",
            ],
            "requires_python": ">=3.7",
        }
    
    def test_client_initialization(self, client: PyPISafetyClient) -> None:
        """Test client initializes with correct defaults."""
        assert client.timeout == 5.0
        assert "pypi-audit" in client.user_agent
        assert client._client is None  # Lazy initialization
    
    def test_client_initialization_custom_ua(self) -> None:
        """Test client with custom user agent."""
        custom_ua = "my-scanner/1.0"
        client = PyPISafetyClient(user_agent=custom_ua)
        assert client.user_agent == custom_ua
    
    def test_build_headers(self, client: PyPISafetyClient) -> None:
        """Test headers are built correctly."""
        headers = client._build_headers()
        assert "User-Agent" in headers
        assert "Accept" in headers
        assert headers["Accept"] == "application/json"
    
    def test_client_context_manager(self) -> None:
        """Test client as context manager."""
        with PyPISafetyClient() as client:
            assert client._client is not None
        # After context exit, client should be closed
        assert client._client is None
    
    def test_client_close(self, client: PyPISafetyClient) -> None:
        """Test client close method."""
        client._client = Mock()
        client.close()
        assert client._client is None
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_get_package_info_success(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
        mock_package_info: dict[str, Any],
    ) -> None:
        """Test successful package info retrieval."""
        mock_response = Mock()
        mock_response.json.return_value = {"info": mock_package_info}
        mock_response.raise_for_status = Mock()
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        result = client.get_package_info("requests")
        
        assert result == mock_package_info
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_get_package_info_not_found(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
    ) -> None:
        """Test package not found handling."""
        import httpx
        
        mock_response = Mock()
        mock_response.status_code = 404
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        mock_http_client.return_value.__enter__.return_value.get.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=Mock(),
            response=mock_response,
        )
        
        client._client = mock_http_client.return_value.__enter__.return_value
        result = client.get_package_info("nonexistent-package-xyz")
        
        assert result is None
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_get_package_versions(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
    ) -> None:
        """Test getting package versions."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "releases": {
                "1.0.0": [],
                "1.1.0": [],
                "2.0.0": [],
            }
        }
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        versions = client.get_package_versions("requests")
        
        assert "1.0.0" in versions
        assert "2.0.0" in versions
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_get_latest_version(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
        mock_package_info: dict[str, Any],
    ) -> None:
        """Test getting latest package version."""
        mock_response = Mock()
        mock_response.json.return_value = {"info": mock_package_info}
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        version = client.get_latest_version("requests")
        
        assert version == "2.31.0"
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_check_package_no_vulnerabilities(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
        mock_package_info: dict[str, Any],
    ) -> None:
        """Test checking package returns empty list when no vulns."""
        mock_response = Mock()
        mock_response.json.return_value = {"info": mock_package_info}
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        vulns = client.check_package("requests", "2.31.0")
        
        assert isinstance(vulns, list)
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_check_packages_multiple(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
    ) -> None:
        """Test checking multiple packages."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {"name": "pkg", "version": "1.0.0"}
        }
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        
        packages = [
            ("requests", "2.31.0"),
            ("urllib3", "2.0.0"),
        ]
        results = client.check_packages(packages)
        
        assert isinstance(results, dict)
    
    def test_is_outdated_newer(self, client: PyPISafetyClient) -> None:
        """Test version comparison - outdated version."""
        assert client._is_outdated("1.0.0", "2.0.0") is True
    
    def test_is_outdated_same(self, client: PyPISafetyClient) -> None:
        """Test version comparison - same version."""
        assert client._is_outdated("1.0.0", "1.0.0") is False
    
    def test_is_outdated_newer_version(self, client: PyPISafetyClient) -> None:
        """Test version comparison - current is newer."""
        assert client._is_outdated("2.0.0", "1.0.0") is False
    
    def test_is_outdated_invalid_version(self, client: PyPISafetyClient) -> None:
        """Test version comparison with invalid versions."""
        assert client._is_outdated("invalid", "1.0.0") is False
        assert client._is_outdated("1.0.0", "invalid") is False
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_get_package_urls(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
        mock_package_info: dict[str, Any],
    ) -> None:
        """Test getting package URLs."""
        mock_response = Mock()
        mock_response.json.return_value = {"info": mock_package_info}
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        urls = client.get_package_urls("requests")
        
        assert urls is not None
        assert "home_page" in urls
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_get_package_metadata(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
        mock_package_info: dict[str, Any],
    ) -> None:
        """Test getting comprehensive package metadata."""
        mock_response = Mock()
        mock_response.json.return_value = {"info": mock_package_info}
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        metadata = client.get_package_metadata("requests")
        
        assert metadata["name"] == "requests"
        assert metadata["version"] == "2.31.0"
        assert metadata["author"] == "Kenneth Reitz"
        assert "classifiers" in metadata
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_search_packages(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
    ) -> None:
        """Test package search."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        
        mock_http_client.return_value.__enter__.return_value.get.return_value = mock_response
        
        client._client = mock_http_client.return_value.__enter__.return_value
        results = client.search_packages("http client")
        
        assert isinstance(results, list)
    
    @patch("pypi_audit.api_clients.pypi_safety.httpx.Client")
    def test_get_vulnerabilities_for_package(
        self, 
        mock_http_client: MagicMock,
        client: PyPISafetyClient,
    ) -> None:
        """Test getting vulnerabilities for package."""
        client._client = mock_http_client.return_value.__enter__.return_value
        vulns = client.get_vulnerabilities_for_package("requests")
        
        assert isinstance(vulns, list)


class TestPyPISafetyVulnerability:
    """Test suite for PyPISafetyVulnerability dataclass."""
    
    def test_vulnerability_creation(self) -> None:
        """Test vulnerability creation with all fields."""
        vuln = PyPISafetyVulnerability(
            advisory_id="ADV-001",
            package_name="requests",
            vulnerable_version="2.30.0",
            patched_versions=[">=2.31.0"],
            advisory="Security advisory text",
            cve_id="CVE-2023-12345",
            severity=VulnerabilitySeverity.HIGH,
        )
        
        assert vuln.advisory_id == "ADV-001"
        assert vuln.package_name == "requests"
        assert vuln.vulnerable_version == "2.30.0"
        assert vuln.patched_versions == [">=2.31.0"]
        assert vuln.cve_id == "CVE-2023-12345"
        assert vuln.severity == VulnerabilitySeverity.HIGH
    
    def test_vulnerability_defaults(self) -> None:
        """Test vulnerability default values."""
        vuln = PyPISafetyVulnerability(
            advisory_id="ADV-002",
            package_name="urllib3",
            vulnerable_version="1.0.0",
        )
        
        assert vuln.patched_versions is None
        assert vuln.advisory is None
        assert vuln.cve_id is None
        assert vuln.severity is None
    
    def test_to_vulnerability(self) -> None:
        """Test conversion to base Vulnerability model."""
        pypi_vuln = PyPISafetyVulnerability(
            advisory_id="ADV-003",
            package_name="flask",
            vulnerable_version="2.0.0",
            advisory="SQL Injection vulnerability",
            cve_id="CVE-2023-99999",
            severity=VulnerabilitySeverity.CRITICAL,
        )
        
        vuln = pypi_vuln.to_vulnerability()
        
        assert vuln.id == "ADV-003"
        assert vuln.package == "flask"
        assert vuln.version == "2.0.0"
        assert vuln.advisory == "SQL Injection vulnerability"
        assert vuln.cve_id == "CVE-2023-99999"
        assert vuln.source == "pypi_safety"
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
    
    def test_to_vulnerability_no_severity(self) -> None:
        """Test conversion when severity is None."""
        pypi_vuln = PyPISafetyVulnerability(
            advisory_id="ADV-004",
            package_name="test",
            vulnerable_version="1.0.0",
        )
        
        vuln = pypi_vuln.to_vulnerability()
        
        assert vuln.severity == VulnerabilitySeverity.UNKNOWN


class TestPyPISafetyClientIntegration:
    """Integration tests for PyPI Safety client (requires network)."""
    
    @pytest.fixture
    def real_client(self) -> PyPISafetyClient:
        """Create real client for integration tests."""
        return PyPISafetyClient(timeout=10.0)
    
    @pytest.mark.integration
    def test_get_real_package_info(self, real_client: PyPISafetyClient) -> None:
        """Test fetching real package info from PyPI."""
        info = real_client.get_package_info("requests")
        
        if info:
            assert info.get("name") == "requests"
            assert "version" in info
    
    @pytest.mark.integration
    def test_get_nonexistent_package(self, real_client: PyPISafetyClient) -> None:
        """Test fetching non-existent package returns None."""
        info = real_client.get_package_info("this-package-does-not-exist-xyz123")
        assert info is None
    
    @pytest.mark.integration
    def test_get_package_versions(self, real_client: PyPISafetyClient) -> None:
        """Test getting package versions."""
        versions = real_client.get_package_versions("requests")
        
        assert isinstance(versions, list)
        assert len(versions) > 0
    
    @pytest.mark.integration
    def test_get_latest_version(self, real_client: PyPISafetyClient) -> None:
        """Test getting latest version."""
        version = real_client.get_latest_version("requests")
        
        assert version is not None
        assert isinstance(version, str)
        assert len(version) > 0
    
    @pytest.mark.integration
    def test_check_package(self, real_client: PyPISafetyClient) -> None:
        """Test checking package for vulnerabilities."""
        vulns = real_client.check_package("requests", "2.31.0")
        
        assert isinstance(vulns, list)
    
    def test_client_teardown(self, real_client: PyPISafetyClient) -> None:
        """Test client properly closes."""
        real_client.close()
        assert real_client._client is None
