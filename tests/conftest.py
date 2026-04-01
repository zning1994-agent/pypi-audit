"""Tests conftest for pypi_audit."""

import pytest
from pathlib import Path


@pytest.fixture
def sample_requirements_content() -> str:
    """Sample requirements.txt content."""
    return """requests==2.28.0
flask>=2.0.0
django~=4.0
pytest>=7.0.0
"""


@pytest.fixture
def sample_pyproject_content() -> str:
    """Sample pyproject.toml content."""
    return """
[project]
name = "my-package"
version = "1.0.0"
dependencies = [
    "requests>=2.28.0",
    "flask>=2.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
"""


@pytest.fixture
def sample_pipfile_lock_content() -> str:
    """Sample Pipfile.lock content."""
    import json
    return json.dumps({
        "default": {
            "requests": {
                "version": "==2.28.0",
                "hashes": ["sha256:abc123"]
            },
            "flask": {
                "version": "==2.0.0",
                "hashes": ["sha256:def456"]
            }
        },
        "develop": {
            "pytest": {
                "version": "==7.0.0"
            }
        }
    })


@pytest.fixture
def temp_requirements_file(tmp_path: Path, sample_requirements_content: str) -> Path:
    """Create a temporary requirements.txt file."""
    file_path = tmp_path / "requirements.txt"
    file_path.write_text(sample_requirements_content)
    return file_path


@pytest.fixture
def temp_pyproject_file(tmp_path: Path, sample_pyproject_content: str) -> Path:
    """Create a temporary pyproject.toml file."""
    file_path = tmp_path / "pyproject.toml"
    file_path.write_text(sample_pyproject_content)
    return file_path


@pytest.fixture
def temp_pipfile_lock_file(tmp_path: Path, sample_pipfile_lock_content: str) -> Path:
    """Create a temporary Pipfile.lock file."""
    file_path = tmp_path / "Pipfile.lock"
    file_path.write_text(sample_pipfile_lock_content)
    return file_path
