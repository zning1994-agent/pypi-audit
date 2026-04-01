"""Pytest fixtures for pypi-audit tests."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock

from src.pypi_audit.models import (
    Dependency,
    Vulnerability,
    VulnerabilityFinding,
    SeverityLevel,
    VulnerabilitySource,
)
from src.pypi_audit.scanner import Scanner
from src.pypi_audit.api_clients import PyPISafetyClient, OSVClient
from src.pypi_audit.ioc.detector import IOCDetector


@pytest.fixture
def sample_dependency() -> Dependency:
    """Create a sample dependency for testing."""
    return Dependency(
        name="requests",
        version="2.28.0",
        source_file="requirements.txt",
    )


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Create a sample vulnerability for testing."""
    return Vulnerability(
        id="VULN-001",
        package_name="requests",
        affected_versions="<2.28.1",
        severity=SeverityLevel.HIGH,
        source=VulnerabilitySource.PYPI_SAFETY,
        description="Remote code execution vulnerability",
        advisory_url="https://example.com/advisory",
        fixed_versions=["2.28.1"],
    )


@pytest.fixture
def sample_dependency_malicious() -> Dependency:
    """Create a sample malicious dependency for IOC testing."""
    return Dependency(
        name="litellm",
        version="1.0.0",
        source_file="requirements.txt",
    )


@pytest.fixture
def mock_pypi_client() -> MagicMock:
    """Create a mock PyPI Safety client."""
    mock = MagicMock(spec=PyPISafetyClient)
    mock.check_package.return_value = []
    return mock


@pytest.fixture
def mock_osv_client() -> MagicMock:
    """Create a mock OSV client."""
    mock = MagicMock(spec=OSVClient)
    mock.check_package.return_value = []
    return mock


@pytest.fixture
def mock_ioc_detector() -> MagicMock:
    """Create a mock IOC detector."""
    mock = MagicMock(spec=IOCDetector)
    mock.check_package.return_value = []
    return mock


@pytest.fixture
def scanner_with_mocks(mock_pypi_client, mock_osv_client, mock_ioc_detector) -> Scanner:
    """Create a scanner with mocked clients."""
    scanner = Scanner(use_pypi_safety=True, use_osv=True, use_ioc=True)
    scanner._pypi_client = mock_pypi_client
    scanner._osv_client = mock_osv_client
    scanner._ioc_detector = mock_ioc_detector
    return scanner


@pytest.fixture
def temp_requirements_file() -> Path:
    """Create a temporary requirements.txt file."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".txt",
        delete=False,
        prefix="requirements",
    ) as f:
        f.write("requests==2.28.0\n")
        f.write("flask>=2.0.0\n")
        f.write("# This is a comment\n")
        f.write("numpy>=1.21.0\n")
        temp_path = f.name
    
    yield Path(temp_path)
    os.unlink(temp_path)


@pytest.fixture
def temp_pyproject_file() -> Path:
    """Create a temporary pyproject.toml file."""
    content = '''
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
    "flask>=2.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black>=22.0.0",
]
'''
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".toml",
        delete=False,
        prefix="pyproject",
    ) as f:
        f.write(content)
        temp_path = f.name
    
    yield Path(temp_path)
    os.unlink(temp_path)


@pytest.fixture
def temp_pipfile_lock() -> Path:
    """Create a temporary Pipfile.lock file."""
    content = '''
{
    "_meta": {
        "hash": {"sha256": "abc123"},
        "pipfile-spec": 6
    },
    "default": {
        "requests": {
            "version": "==2.28.0",
            "hashes": ["sha256:abc123"]
        },
        "flask": {
            "version": "==2.0.0",
            "hashes": ["sha256:def456"]
        }
    }
}
'''
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".lock",
        delete=False,
        prefix="Pipfile",
    ) as f:
        f.write(content)
        temp_path = f.name
    
    yield Path(temp_path)
    os.unlink(temp_path)


@pytest.fixture
def temp_directory_with_deps(tmp_path) -> Path:
    """Create a temp directory with multiple dependency files."""
    # Create requirements.txt
    (tmp_path / "requirements.txt").write_text(
        "requests==2.28.0\nflask>=2.0.0\n"
    )
    
    # Create pyproject.toml
    (tmp_path / "pyproject.toml").write_text('''
[project]
dependencies = ["numpy>=1.21.0"]
''')
    
    # Create Pipfile.lock
    (tmp_path / "Pipfile.lock").write_text('''
{
    "default": {
        "django": {"version": "==4.0.0", "hashes": ["sha256:xyz789"]}
    }
}
''')
    
    return tmp_path


@pytest.fixture
def multiple_dependencies() -> list[Dependency]:
    """Create multiple sample dependencies."""
    return [
        Dependency(name="requests", version="2.28.0", source_file="requirements.txt"),
        Dependency(name="flask", version="2.0.0", source_file="requirements.txt"),
        Dependency(name="numpy", version="1.21.0", source_file="pyproject.toml"),
        Dependency(name="django", version="4.0.0", source_file="Pipfile.lock"),
    ]
