"""Unit tests for PyPI Safety API client."""

import pytest
import httpx
from unittest.mock import patch, Mock
from typing import Any

from pypi_audit.api_clients.pypi_safety import PyPISafetyClient


class TestPyPISafetyClient:
    """Test suite for PyPISafetyClient."""

    def test_init_default_timeout(self):
        """Test client initialization with default timeout."""
        client = PyPISafetyClient()
        assert client.timeout == 30
        assert client.api_key is None

    def test_init_custom_timeout(self):
        """Test client initialization with custom timeout."""
        client = PyPISafetyClient(timeout=60)
        assert client.timeout == 60

    def test_init_with_api_key(self):
        """Test client initialization with API key."""
        client = PyPISafetyClient(api_key="test-key-123")
        assert client.api_key == "test-key-123"

    def test_base_url(self):
        """Test base URL is correctly set."""
        client = PyPISafetyClient()
        assert client.BASE_URL == "https://pypi.python.org/pypi"


class TestCheckVulnerability:
    """Test suite for check_vulnerability method."""

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_vulnerability_success(self, mock_get: Mock, sample_package_data: dict[str, Any]):
        """Test successful vulnerability check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_package_data
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        result = client.check_vulnerability("requests", "2.28.0")

        assert len(result) == 1
        assert result[0]["id"] == "VULN-001"
        assert result[0]["package_name"] == "requests"
        mock_get.assert_called_once()

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_vulnerability_no_vulnerabilities(self, mock_get: Mock):
        """Test check when no vulnerabilities exist."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"vulnerabilities": []}}
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        result = client.check_vulnerability("safe-package", "1.0.0")

        assert result == []

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_vulnerability_package_not_found(self, mock_get: Mock):
        """Test check when package is not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        result = client.check_vulnerability("nonexistent-package", "1.0.0")

        assert result == []

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_vulnerability_request_error(self, mock_get: Mock):
        """Test check handles request errors gracefully."""
        mock_get.side_effect = httpx.RequestError("Connection failed")

        client = PyPISafetyClient()
        result = client.check_vulnerability("requests", "2.28.0")

        assert result == []

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_vulnerability_timeout(self, mock_get: Mock):
        """Test check respects timeout setting."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"vulnerabilities": []}}
        mock_get.return_value = mock_response

        client = PyPISafetyClient(timeout=10)
        client.check_vulnerability("requests", "2.28.0")

        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["timeout"] == 10


class TestExtractVulnerabilities:
    """Test suite for _extract_vulnerabilities method."""

    def test_extract_single_vulnerability(self, sample_package_data: dict[str, Any]):
        """Test extracting single vulnerability."""
        client = PyPISafetyClient()
        result = client._extract_vulnerabilities(sample_package_data)

        assert len(result) == 1
        vuln = result[0]
        assert vuln["id"] == "VULN-001"
        assert vuln["package_name"] == "requests"
        assert vuln["advisory"] == "Test vulnerability"

    def test_extract_multiple_vulnerabilities(self):
        """Test extracting multiple vulnerabilities."""
        data = {
            "info": {
                "vulnerabilities": [
                    {"id": "VULN-001", "package_name": "test", "advisory": "First"},
                    {"id": "VULN-002", "package_name": "test", "advisory": "Second"},
                    {"id": "VULN-003", "package_name": "test", "advisory": "Third"},
                ]
            }
        }

        client = PyPISafetyClient()
        result = client._extract_vulnerabilities(data)

        assert len(result) == 3
        assert result[0]["id"] == "VULN-001"
        assert result[1]["id"] == "VULN-002"
        assert result[2]["id"] == "VULN-003"

    def test_extract_vulnerabilities_empty_list(self):
        """Test extracting from empty vulnerability list."""
        data = {"info": {"vulnerabilities": []}}

        client = PyPISafetyClient()
        result = client._extract_vulnerabilities(data)

        assert result == []

    def test_extract_vulnerabilities_missing_info(self):
        """Test extracting from data with missing info key."""
        data = {}

        client = PyPISafetyClient()
        result = client._extract_vulnerabilities(data)

        assert result == []

    def test_extract_vulnerabilities_missing_vulnerabilities_key(self):
        """Test extracting from data with missing vulnerabilities key."""
        data = {"info": {}}

        client = PyPISafetyClient()
        result = client._extract_vulnerabilities(data)

        assert result == []


class TestGetVulnerabilityDetails:
    """Test suite for get_vulnerability_details method."""

    def test_get_vulnerability_details_not_implemented(self):
        """Test that get_vulnerability_details returns None (not implemented)."""
        client = PyPISafetyClient()
        result = client.get_vulnerability_details("VULN-001")

        assert result is None


class TestCheckBulk:
    """Test suite for check_bulk method."""

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_bulk_all_safe(self, mock_get: Mock):
        """Test bulk check when all packages are safe."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"vulnerabilities": []}}
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        packages = [("pkg1", "1.0.0"), ("pkg2", "2.0.0")]
        result = client.check_bulk(packages)

        assert result == {}

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_bulk_mixed_results(self, mock_get: Mock, sample_package_data: dict[str, Any]):
        """Test bulk check with mixed results (some vulnerable, some safe)."""
        def side_effect(*args, **kwargs):
            mock_resp = Mock()
            url = args[0]
            if "requests" in url:
                mock_resp.status_code = 200
                mock_resp.json.return_value = sample_package_data
            else:
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"info": {"vulnerabilities": []}}
            return mock_resp

        mock_get.side_effect = side_effect

        client = PyPISafetyClient()
        packages = [("requests", "2.28.0"), ("safe-pkg", "1.0.0")]
        result = client.check_bulk(packages)

        assert "requests==2.28.0" in result
        assert len(result["requests==2.28.0"]) == 1
        assert "safe-pkg==1.0.0" not in result

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_bulk_all_vulnerable(self, mock_get: Mock, sample_package_data: dict[str, Any]):
        """Test bulk check when all packages are vulnerable."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_package_data
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        packages = [("pkg1", "1.0.0"), ("pkg2", "2.0.0")]
        result = client.check_bulk(packages)

        assert len(result) == 2
        assert "pkg1==1.0.0" in result
        assert "pkg2==2.0.0" in result

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_check_bulk_empty_list(self, mock_get: Mock):
        """Test bulk check with empty package list."""
        client = PyPISafetyClient()
        result = client.check_bulk([])

        assert result == {}
        mock_get.assert_not_called()


class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_empty_package_name(self, mock_get: Mock):
        """Test handling of empty package name."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"vulnerabilities": []}}
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        result = client.check_vulnerability("", "1.0.0")

        assert result == []
        mock_get.assert_called_once()

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_empty_version(self, mock_get: Mock):
        """Test handling of empty version string."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"vulnerabilities": []}}
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        result = client.check_vulnerability("requests", "")

        assert result == []

    @patch("pypi_audit.api_clients.pypi_safety.httpx.get")
    def test_special_characters_in_package_name(self, mock_get: Mock):
        """Test handling of special characters in package name."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = PyPISafetyClient()
        result = client.check_vulnerability("package-with-dashes", "1.0.0")

        assert result == []
