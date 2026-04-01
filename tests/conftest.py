"""
Pytest configuration and shared fixtures.
"""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (may require network)"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests (no network required)"
    )


@pytest.fixture
def sample_package_info() -> dict:
    """Sample package info for testing."""
    return {
        "name": "test-package",
        "version": "1.0.0",
        "summary": "A test package",
        "author": "Test Author",
        "author_email": "test@example.com",
        "license": "MIT",
        "home_page": "https://example.com",
        "classifiers": [],
        "requires_python": ">=3.8",
    }


@pytest.fixture
def sample_vulnerability() -> dict:
    """Sample vulnerability data for testing."""
    return {
        "id": "VULN-001",
        "package": "test-package",
        "version": "1.0.0",
        "severity": "high",
        "advisory": "Test vulnerability advisory",
        "cve_id": "CVE-2023-12345",
        "source": "test",
    }
