"""Unit tests for OSV.dev API client."""

import pytest
import httpx
from unittest.mock import patch, Mock
from typing import Any

from pypi_audit.api_clients.osv import OSVClient


class TestOSVClient:
    """Test suite for OSVClient."""

    def test_init_default_timeout(self):
        """Test client initialization with default timeout."""
        client = OSVClient()
        assert client.timeout == 30

    def test_init_custom_timeout(self):
        """Test client initialization with custom timeout."""
        client = OSVClient(timeout=60)
        assert client.timeout == 60

    def test_base_url(self):
        """Test base URL is correctly set."""
        client = OSVClient()
        assert client.BASE_URL == "https://api.osv.dev/v1"


class TestCheckVulnerability:
    """Test suite for check_vulnerability method."""

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_check_vulnerability_success(self, mock_post: Mock, sample_osv_response: dict[str, Any]):
        """Test successful vulnerability check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_osv_response
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("sample-package", "1.0.0")

        assert len(result) == 1
        assert result[0]["id"] == "OSV-2024-001"
        assert result[0]["summary"] == "Remote code execution vulnerability"
        mock_post.assert_called_once()

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_check_vulnerability_no_vulnerabilities(self, mock_post: Mock):
        """Test check when no vulnerabilities exist."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("safe-package", "1.0.0")

        assert result == []

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_check_vulnerability_request_error(self, mock_post: Mock):
        """Test check handles request errors gracefully."""
        mock_post.side_effect = httpx.RequestError("Connection failed")

        client = OSVClient()
        result = client.check_vulnerability("requests", "2.28.0")

        assert result == []

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_check_vulnerability_timeout(self, mock_post: Mock):
        """Test check respects timeout setting."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        client = OSVClient(timeout=15)
        client.check_vulnerability("requests", "2.28.0")

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["timeout"] == 15

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_check_vulnerability_api_returns_404(self, mock_post: Mock):
        """Test check handles 404 response."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("nonexistent", "1.0.0")

        assert result == []

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_check_vulnerability_pypi_ecosystem(self, mock_post: Mock, sample_osv_response: dict[str, Any]):
        """Test check uses PyPI ecosystem."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_osv_response
        mock_post.return_value = mock_response

        client = OSVClient()
        client.check_vulnerability("requests", "2.28.0")

        call_args = mock_post.call_args
        request_body = call_args[0][1]  # Second positional arg is json
        assert request_body["package"]["ecosystem"] == "PyPI"
        assert request_body["package"]["name"] == "requests"


class TestParseOSVResponse:
    """Test suite for _parse_osv_response method."""

    def test_parse_single_vulnerability(self, sample_osv_response: dict[str, Any]):
        """Test parsing single vulnerability."""
        client = OSVClient()
        result = client._parse_osv_response(sample_osv_response, "pkg", "1.0")

        assert len(result) == 1
        vuln = result[0]
        assert vuln["id"] == "OSV-2024-001"
        assert vuln["summary"] == "Remote code execution vulnerability"
        assert vuln["details"] == "Detailed description of the vulnerability"
        assert "CVSS_V3:9.8" in vuln["severity"]

    def test_parse_multiple_vulnerabilities(self):
        """Test parsing multiple vulnerabilities."""
        data = {
            "vulns": [
                {"id": "OSV-001", "summary": "First", "details": "", "severity": [], "references": [], "affected": []},
                {"id": "OSV-002", "summary": "Second", "details": "", "severity": [], "references": [], "affected": []},
                {"id": "OSV-003", "summary": "Third", "details": "", "severity": [], "references": [], "affected": []},
            ]
        }

        client = OSVClient()
        result = client._parse_osv_response(data, "pkg", "1.0")

        assert len(result) == 3

    def test_parse_empty_vulns(self):
        """Test parsing empty vulnerability list."""
        data = {"vulns": []}

        client = OSVClient()
        result = client._parse_osv_response(data, "pkg", "1.0")

        assert result == []

    def test_parse_missing_vulns_key(self):
        """Test parsing response without vulns key."""
        data = {}

        client = OSVClient()
        result = client._parse_osv_response(data, "pkg", "1.0")

        assert result == []


class TestExtractSeverity:
    """Test suite for _extract_severity method."""

    def test_extract_cvss_v3_severity(self):
        """Test extracting CVSS V3 severity."""
        vuln = {
            "severity": [
                {"type": "CVSS_V3", "score": "9.8"}
            ]
        }

        client = OSVClient()
        result = client._extract_severity(vuln)

        assert result == "CVSS_V3:9.8"

    def test_extract_cvss_v2_severity(self):
        """Test extracting CVSS V2 severity (falls back to unknown)."""
        vuln = {
            "severity": [
                {"type": "CVSS_V2", "score": "7.5"}
            ]
        }

        client = OSVClient()
        result = client._extract_severity(vuln)

        assert result == "UNKNOWN"

    def test_extract_no_severity(self):
        """Test extracting when no severity info exists."""
        vuln = {}

        client = OSVClient()
        result = client._extract_severity(vuln)

        assert result == "UNKNOWN"

    def test_extract_empty_severity_list(self):
        """Test extracting when severity list is empty."""
        vuln = {"severity": []}

        client = OSVClient()
        result = client._extract_severity(vuln)

        assert result == "UNKNOWN"

    def test_extract_cvss_v3_priority_over_other_types(self):
        """Test that CVSS_V3 is prioritized over other types."""
        vuln = {
            "severity": [
                {"type": "CVSS_V2", "score": "9.8"},
                {"type": "CVSS_V3", "score": "7.5"}
            ]
        }

        client = OSVClient()
        result = client._extract_severity(vuln)

        assert result == "CVSS_V3:7.5"


class TestFormatAffected:
    """Test suite for _format_affected method."""

    def test_format_affected_packages(self):
        """Test formatting affected packages."""
        affected = [
            {"package": {"name": "pkg1", "ecosystem": "PyPI"}},
            {"package": {"name": "pkg2", "ecosystem": "PyPI"}}
        ]

        client = OSVClient()
        result = client._format_affected(affected)

        assert "pkg1" in result
        assert "pkg2" in result

    def test_format_empty_affected(self):
        """Test formatting empty affected list."""
        client = OSVClient()
        result = client._format_affected([])

        assert result == "Unknown"

    def test_format_missing_package_name(self):
        """Test formatting when package name is missing."""
        affected = [{"package": {}}]

        client = OSVClient()
        result = client._format_affected(affected)

        assert result == "Unknown"


class TestGetVulnerabilityDetails:
    """Test suite for get_vulnerability_details method."""

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_get_details_success(self, mock_post: Mock):
        """Test successful retrieval of vulnerability details."""
        details = {
            "id": "OSV-2024-001",
            "summary": "Test vulnerability",
            "details": "Detailed description"
        }
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = details
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.get_vulnerability_details("OSV-2024-001")

        assert result == details

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_get_details_not_found(self, mock_post: Mock):
        """Test retrieval when vulnerability not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.get_vulnerability_details("NONEXISTENT")

        assert result is None

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_get_details_request_error(self, mock_post: Mock):
        """Test retrieval handles request errors."""
        mock_post.side_effect = httpx.RequestError("Connection failed")

        client = OSVClient()
        result = client.get_vulnerability_details("OSV-2024-001")

        assert result is None

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_get_details_timeout(self, mock_post: Mock):
        """Test retrieval respects timeout."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "test"}
        mock_post.return_value = mock_response

        client = OSVClient(timeout=20)
        client.get_vulnerability_details("OSV-2024-001")

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["timeout"] == 20


class TestQueryByEcosystem:
    """Test suite for query_by_ecosystem method."""

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_query_pypi_ecosystem(self, mock_post: Mock):
        """Test querying PyPI ecosystem."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": [{"id": "V1"}, {"id": "V2"}]}
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.query_by_ecosystem("PyPI")

        assert len(result) == 2
        call_args = mock_post.call_args[0][1]
        assert call_args["ecosystem"] == "PyPI"

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_query_with_pagination(self, mock_post: Mock):
        """Test querying with pagination."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        client = OSVClient()
        client.query_by_ecosystem("PyPI", page=3)

        call_args = mock_post.call_args[0][1]
        assert call_args["page"] == 3

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_query_request_error(self, mock_post: Mock):
        """Test query handles request errors."""
        mock_post.side_effect = httpx.RequestError("Connection failed")

        client = OSVClient()
        result = client.query_by_ecosystem("PyPI")

        assert result == []


class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_empty_package_name(self, mock_post: Mock):
        """Test handling of empty package name."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("", "1.0.0")

        assert result == []

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_empty_version(self, mock_post: Mock):
        """Test handling of empty version string."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("requests", "")

        assert result == []

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_special_characters_in_package_name(self, mock_post: Mock):
        """Test handling of special characters in package name."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("package_with_underscores", "1.0.0")

        assert result == []

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_parse_with_missing_optional_fields(self, mock_post: Mock):
        """Test parsing vulnerability with missing optional fields."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {"id": "OSV-001"}  # Minimal data
            ]
        }
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("pkg", "1.0")

        assert len(result) == 1
        assert result[0]["id"] == "OSV-001"
        assert result[0]["summary"] == ""
        assert result[0]["details"] == ""

    @patch("pypi_audit.api_clients.osv.httpx.post")
    def test_parse_references(self, mock_post: Mock):
        """Test parsing references from OSV response."""
        data = {
            "vulns": [
                {
                    "id": "OSV-001",
                    "summary": "Test",
                    "details": "",
                    "severity": [],
                    "references": [
                        {"url": "https://example.com/1"},
                        {"url": "https://example.com/2"},
                        {"url": "https://example.com/3"}
                    ],
                    "affected": []
                }
            ]
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = data
        mock_post.return_value = mock_response

        client = OSVClient()
        result = client.check_vulnerability("pkg", "1.0")

        assert len(result[0]["references"]) == 3
        assert "https://example.com/1" in result[0]["references"]
