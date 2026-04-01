"""Pytest configuration and fixtures for pypi-audit tests."""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def sample_package():
    """Fixture providing a sample Package object."""
    from pypi_audit.models import Package
    return Package(name="requests", version="2.28.0")


@pytest.fixture
def litellm_malicious_package():
    """Fixture providing a malicious LiteLLM package."""
    from pypi_audit.models import Package
    return Package(name="litellm", version="1.0.0")


@pytest.fixture
def litellm_safe_package():
    """Fixture providing a safe litellm package version."""
    from pypi_audit.models import Package
    return Package(name="litellm", version="0.5.0")


@pytest.fixture
def ioc_detector():
    """Fixture providing an IOCDetector instance."""
    from pypi_audit.ioc.detector import IOCDetector
    return IOCDetector()


@pytest.fixture
def sample_scan_result():
    """Fixture providing a sample ScanResult."""
    from pypi_audit.models import Package, ScanResult
    return ScanResult(
        file_path="requirements.txt",
        file_type="requirements",
        packages=[
            Package(name="requests", version="2.28.0"),
            Package(name="numpy", version="1.24.0"),
        ],
    )
