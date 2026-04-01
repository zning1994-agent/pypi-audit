"""Pytest configuration and fixtures for pypi-audit tests."""

import pytest
from unittest.mock import Mock, MagicMock
from typing import Any


@pytest.fixture
def mock_httpx_response() -> Mock:
    """Create a mock httpx response object.
    
    Returns:
        Mock httpx response.
    """
    response = Mock()
    response.status_code = 200
    response.json.return_value = {}
    response.raise_for_status = Mock()
    return response


@pytest.fixture
def sample_package_data() -> dict[str, Any]:
    """Sample PyPI package JSON data.
    
    Returns:
        Sample package data dictionary.
    """
    return {
        "info": {
            "name": "requests",
            "version": "2.28.0",
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "package_name": "requests",
                    "advisory": "Test vulnerability",
                    "severity": "HIGH",
                    "advisory_url": "https://example.com/advisory",
                    "fix_version": "2.28.1"
                }
            ]
        }
    }


@pytest.fixture
def sample_osv_response() -> dict[str, Any]:
    """Sample OSV API response.
    
    Returns:
        Sample OSV response dictionary.
    """
    return {
        "vulns": [
            {
                "id": "OSV-2024-001",
                "summary": "Remote code execution vulnerability",
                "details": "Detailed description of the vulnerability",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "9.8"
                    }
                ],
                "references": [
                    {"url": "https://osv.dev/vulnerability/OSV-2024-001"}
                ],
                "affected": [
                    {
                        "package": {
                            "name": "sample-package",
                            "ecosystem": "PyPI"
                        },
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "1.5.0"}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }


@pytest.fixture
def mock_httpx_client() -> MagicMock:
    """Create a mock httpx client.
    
    Returns:
        Mock httpx client.
    """
    client = MagicMock()
    return client


@pytest.fixture
def sample_vulnerability() -> dict[str, Any]:
    """Sample vulnerability record.
    
    Returns:
        Vulnerability dictionary.
    """
    return {
        "id": "VULN-001",
        "package_name": "test-package",
        "advisory": "Test advisory",
        "severity": "HIGH",
        "advisory_url": "https://example.com/advisory",
        "fix_version": "1.0.1"
    }


@pytest.fixture
def sample_package_list() -> list[tuple[str, str]]:
    """Sample package list for bulk checking.
    
    Returns:
        List of (name, version) tuples.
    """
    return [
        ("requests", "2.28.0"),
        ("flask", "2.0.0"),
        ("django", "4.0.0")
    ]
