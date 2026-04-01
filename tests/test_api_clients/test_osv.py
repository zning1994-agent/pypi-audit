"""Unit tests for OSV.dev API client."""

import json
from unittest.mock import MagicMock, patch

import pytest

from pypi_audit.api_clients.osv import OSVClient
from pypi_audit.models import Package, SeverityLevel, Vulnerability


class TestOSVClient:
    """Test suite for OSVClient."""

    @pytest.fixture
    def client(self) -> OSVClient:
        """Create an OSVClient instance for testing."""
        return OSVClient(timeout=10)

    @pytest.fixture
    def sample_package(self) -> Package:
        """Create a sample package for testing."""
        return Package(name="django", version="1.2.3")

    @pytest.fixture
    def mock_vuln_response(self) -> dict:
        """Create a mock OSV API response with vulnerabilities."""
        return {
            "vulns": [
                {
                    "id": "OSV-2021-1",
                    "summary": "Remote code execution in Django",
                    "details": "Django is vulnerable to remote code execution...",
                    "aliases": ["CVE-2021-12345", "GHSA-xxxx-xxxx"],
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "affected": [
                        {
                            "package": {
                                "name": "django",
                                "ecosystem": "PyPI",
                            },
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "3.2.1"},
                                    ],
                                }
                            ],
                            "versions": ["1.0.0", "1.1.0", "1.2.0", "1.2.1"],
                        }
                    ],
                    "references": [
                        {
                            "type": "ADVISORY",
                            "url": "https://example.com/advisory",
                        },
                        {
                            "type": "FIX",
                            "url": "https://github.com/django/django/pull/123",
                        },
                    ],
                },
                {
                    "id": "OSV-2021-2",
                    "summary": "SQL injection vulnerability",
                    "details": "SQL injection in Django ORM...",
                    "aliases": [],
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "7.5",
                        }
                    ],
                    "affected": [
                        {
                            "package": {
                                "name": "django",
                                "ecosystem": "PyPI",
                            },
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "1.0.0"},
                                        {"fixed": "2.0.0"},
                                    ],
                                }
                            ],
                            "versions": ["1.0.0", "1.1.0"],
                        }
                    ],
                    "references": [],
                },
            ]
        }

    def test_client_initialization(self, client: OSVClient) -> None:
        """Test client initializes with correct default values."""
        assert client.timeout == 10
        assert client.BASE_URL == "https://api.osv.dev/v1"
        assert client.ECOSYSTEM == "PyPI"

    def test_client_custom_timeout(self) -> None:
        """Test client can be initialized with custom timeout."""
        client = OSVClient(timeout=60)
        assert client.timeout == 60

    def test_query_package_builds_correct_payload(
        self, client: OSVClient, sample_package: Package
    ) -> None:
        """Test that query_package sends correct payload to API."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {"vulns": []}
            client.query_package(sample_package)

            mock_request.assert_called_once()
            call_args = mock_request.call_args
            assert call_args[0][0] == "/query"
            payload = call_args[0][1]
            assert payload["package"]["name"] == "django"
            assert payload["package"]["ecosystem"] == "PyPI"
            assert payload["version"] == "1.2.3"

    def test_query_package_returns_vulnerabilities(
        self,
        client: OSVClient,
        sample_package: Package,
        mock_vuln_response: dict,
    ) -> None:
        """Test that query_package correctly parses vulnerabilities."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = mock_vuln_response
            vulnerabilities = client.query_package(sample_package)

            assert len(vulnerabilities) == 2

            # Check first vulnerability
            vuln1 = vulnerabilities[0]
            assert vuln1.id == "OSV-2021-1"
            assert vuln1.package_name == "django"
            assert vuln1.package_version == "1.2.3"
            assert "Remote code execution" in vuln1.summary
            assert "CVE-2021-12345" in vuln1.aliases
            assert "GHSA-xxxx-xxxx" in vuln1.aliases
            assert "3.2.1" in vuln1.fixed_versions
            assert "https://example.com/advisory" in vuln1.references

            # Check second vulnerability
            vuln2 = vulnerabilities[1]
            assert vuln2.id == "OSV-2021-2"
            assert "SQL injection" in vuln2.summary
            assert "2.0.0" in vuln2.fixed_versions

    def test_query_package_empty_response(
        self, client: OSVClient, sample_package: Package
    ) -> None:
        """Test query_package handles empty response correctly."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {"vulns": []}
            vulnerabilities = client.query_package(sample_package)

            assert vulnerabilities == []

    def test_query_package_no_vulns_key(
        self, client: OSVClient, sample_package: Package
    ) -> None:
        """Test query_package handles response without vulns key."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {}
            vulnerabilities = client.query_package(sample_package)

            assert vulnerabilities == []

    def test_query_package_handles_network_error(
        self, client: OSVClient, sample_package: Package
    ) -> None:
        """Test query_package handles URLError gracefully."""
        import urllib.error

        with patch.object(client, "_make_request") as mock_request:
            mock_request.side_effect = urllib.error.URLError("Connection refused")
            vulnerabilities = client.query_package(sample_package)

            assert vulnerabilities == []

    def test_parse_severity_cvss_high(self, client: OSVClient) -> None:
        """Test severity parsing for high severity CVSS."""
        severity_data = [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.HIGH

    def test_parse_severity_numeric_critical(self, client: OSVClient) -> None:
        """Test severity parsing for numeric critical score."""
        severity_data = [{"type": "CVSS_V3", "score": "9.8"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.CRITICAL

    def test_parse_severity_numeric_high(self, client: OSVClient) -> None:
        """Test severity parsing for numeric high score."""
        severity_data = [{"type": "CVSS_V3", "score": "7.5"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.HIGH

    def test_parse_severity_numeric_medium(self, client: OSVClient) -> None:
        """Test severity parsing for numeric medium score."""
        severity_data = [{"type": "CVSS_V3", "score": "5.0"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.MEDIUM

    def test_parse_severity_numeric_low(self, client: OSVClient) -> None:
        """Test severity parsing for numeric low score."""
        severity_data = [{"type": "CVSS_V3", "score": "3.5"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.LOW

    def test_parse_severity_empty(self, client: OSVClient) -> None:
        """Test severity parsing for empty severity data."""
        severity = client._parse_severity_osv(None)
        assert severity == SeverityLevel.UNKNOWN

        severity = client._parse_severity_osv([])
        assert severity == SeverityLevel.UNKNOWN

    def test_parse_severity_no_score(self, client: OSVClient) -> None:
        """Test severity parsing when score is missing."""
        severity_data = [{"type": "CVSS_V3"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.UNKNOWN

    def test_extract_fixed_versions(
        self, client: OSVClient, mock_vuln_response: dict
    ) -> None:
        """Test extraction of fixed versions from affected ranges."""
        affected = mock_vuln_response["vulns"][0]["affected"]
        fixed_versions = client._extract_fixed_versions(affected)

        assert "3.2.1" in fixed_versions

    def test_extract_fixed_versions_empty(self, client: OSVClient) -> None:
        """Test extraction with no fixed versions."""
        fixed_versions = client._extract_fixed_versions([])
        assert fixed_versions == []

    def test_extract_fixed_versions_ignores_other_ecosystems(
        self, client: OSVClient
    ) -> None:
        """Test that non-PyPI packages are ignored."""
        affected = [
            {
                "package": {
                    "name": "django",
                    "ecosystem": "npm",  # Wrong ecosystem
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"fixed": "99.0.0"}],
                    }
                ],
            }
        ]
        fixed_versions = client._extract_fixed_versions(affected)
        assert "99.0.0" not in fixed_versions

    def test_parse_references(self, client: OSVClient) -> None:
        """Test parsing of reference URLs."""
        references = [
            {"type": "ADVISORY", "url": "https://example.com/1"},
            {"type": "FIX", "url": "https://example.com/2"},
            {"type": "WEB", "url": "https://example.com/3"},
        ]
        urls = client._parse_references(references)

        assert len(urls) == 3
        assert "https://example.com/1" in urls
        assert "https://example.com/2" in urls
        assert "https://example.com/3" in urls

    def test_parse_references_empty(self, client: OSVClient) -> None:
        """Test parsing empty references list."""
        urls = client._parse_references([])
        assert urls == []

    def test_parse_references_missing_url(self, client: OSVClient) -> None:
        """Test parsing references with missing URLs."""
        references = [
            {"type": "ADVISORY"},  # No URL
            {"type": "FIX", "url": "https://example.com/2"},
        ]
        urls = client._parse_references(references)
        assert len(urls) == 1
        assert "https://example.com/2" in urls

    def test_query_package_name(self, client: OSVClient) -> None:
        """Test querying by package name without version."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {"vulns": []}
            client.query_package_name("requests")

            mock_request.assert_called_once()
            call_args = mock_request.call_args
            payload = call_args[0][1]
            assert payload["package"]["name"] == "requests"
            assert payload["package"]["ecosystem"] == "PyPI"
            assert "version" not in payload

    def test_get_vulnerability_details_success(self, client: OSVClient) -> None:
        """Test fetching vulnerability details by ID."""
        mock_details = {
            "id": "OSV-2021-1",
            "summary": "Test vulnerability",
            "details": "Detailed description",
        }

        with patch.object(client, "_make_request") as mock_request:
            # Mock the direct URL request
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = MagicMock()
                mock_response.read.return_value = json.dumps(mock_details).encode()
                mock_urlopen.return_value.__enter__.return_value = mock_response

                result = client.get_vulnerability_details("OSV-2021-1")

                assert result == mock_details

    def test_get_vulnerability_details_not_found(self, client: OSVClient) -> None:
        """Test get_vulnerability_details handles 404."""
        import urllib.error

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                "", 404, "Not Found", {}, None
            )
            result = client.get_vulnerability_details("NONEXISTENT")
            assert result is None

    def test_list_affected_versions(self, client: OSVClient) -> None:
        """Test listing affected versions for a vulnerability."""
        mock_details = {
            "id": "OSV-2021-1",
            "affected": [
                {
                    "package": {"name": "django", "ecosystem": "PyPI"},
                    "versions": ["1.0.0", "1.1.0", "1.2.0"],
                },
                {
                    "package": {"name": "django", "ecosystem": "npm"},
                    "versions": ["2.0.0"],  # Should be ignored
                },
            ],
        }

        with patch.object(client, "get_vulnerability_details", return_value=mock_details):
            versions = client.list_affected_versions("OSV-2021-1")

            assert "1.0.0" in versions
            assert "1.1.0" in versions
            assert "1.2.0" in versions
            assert "2.0.0" not in versions  # npm ecosystem should be excluded

    def test_list_affected_versions_not_found(self, client: OSVClient) -> None:
        """Test list_affected_versions handles missing vulnerability."""
        with patch.object(client, "get_vulnerability_details", return_value=None):
            versions = client.list_affected_versions("NONEXISTENT")
            assert versions == []

    def test_vulnerability_with_multiple_fixed_versions(self, client: OSVClient) -> None:
        """Test handling of multiple fixed versions."""
        affected = [
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]},
                    {"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "3.2.1"}]},
                ],
            }
        ]
        fixed_versions = client._extract_fixed_versions(affected)

        assert "2.0.0" in fixed_versions
        assert "3.2.1" in fixed_versions

    def test_make_request_uses_correct_headers(self, client: OSVClient) -> None:
        """Test that _make_request sets correct HTTP headers."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"vulns": []}'
            mock_response.__enter__ = MagicMock(return_value=mock_response)

            client._make_request("/query", {"test": "data"})

            mock_urlopen.assert_called_once()
            call_args = mock_urlopen.call_args
            request = call_args[0][0]

            assert request.headers.get("Content-Type") == "application/json"
            assert request.headers.get("Accept") == "application/json"
            assert request.method == "POST"

    def test_severity_parsing_with_float_score(self, client: OSVClient) -> None:
        """Test severity parsing handles float scores."""
        # Test numeric as float
        severity_data = [{"type": "CVSS_V3", "score": 9.8}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.CRITICAL

    def test_severity_parsing_edge_cases(self, client: OSVClient) -> None:
        """Test severity parsing edge cases."""
        # Exactly at boundary values
        severity_data = [{"type": "CVSS_V3", "score": "9.0"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.CRITICAL

        severity_data = [{"type": "CVSS_V3", "score": "7.0"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.HIGH

        severity_data = [{"type": "CVSS_V3", "score": "4.0"}]
        severity = client._parse_severity_osv(severity_data)
        assert severity == SeverityLevel.MEDIUM


class TestOSVClientIntegration:
    """Integration tests for OSVClient (requires network)."""

    @pytest.fixture
    def client(self) -> OSVClient:
        """Create an OSVClient instance."""
        return OSVClient(timeout=30)

    def test_query_real_package(self, client: OSVClient) -> None:
        """Test querying a real package (Django)."""
        package = Package(name="django", version="1.0.0")
        vulnerabilities = client.query_package(package)

        # Django 1.0.0 is old and likely has vulnerabilities
        # At minimum, the request should succeed
        assert isinstance(vulnerabilities, list)
        for vuln in vulnerabilities:
            assert isinstance(vuln, Vulnerability)
            assert vuln.package_name == "django"
            assert vuln.id.startswith("OSV-")

    def test_query_nonexistent_package(self, client: OSVClient) -> None:
        """Test querying a package that doesn't exist."""
        package = Package(name="this-package-definitely-does-not-exist-xyz", version="1.0.0")
        vulnerabilities = client.query_package(package)

        assert vulnerabilities == []
