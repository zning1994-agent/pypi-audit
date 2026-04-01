"""Pytest configuration and shared fixtures for pypi-audit tests."""

import pytest

from pypi_audit.models import Package, SeverityLevel


@pytest.fixture
def sample_package() -> Package:
    """Create a sample Package for testing."""
    return Package(name="requests", version="2.28.0")


@pytest.fixture
def vulnerable_package() -> Package:
    """Create a package known to have vulnerabilities."""
    return Package(name="django", version="1.0.0")


@pytest.fixture
def severity_levels() -> list[SeverityLevel]:
    """Return all severity level enum values."""
    return list(SeverityLevel)


@pytest.fixture
def mock_vulnerability_data() -> dict:
    """Return mock vulnerability data for testing."""
    return {
        "id": "OSV-TEST-1",
        "summary": "Test vulnerability",
        "details": "This is a test vulnerability for unit testing.",
        "aliases": ["CVE-2021-12345"],
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [
            {
                "package": {"name": "test-package", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                    }
                ],
                "versions": ["0.1.0", "0.2.0", "0.9.0"],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.com/advisory"},
        ],
    }
