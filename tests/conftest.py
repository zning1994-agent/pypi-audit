"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_requirements() -> str:
    """Return sample requirements.txt content."""
    return "requests==2.31.0\nflask==3.0.0\n"


@pytest.fixture
def sample_pyproject() -> dict:
    """Return sample pyproject.toml data."""
    return {
        "project": {
            "dependencies": ["requests==2.31.0", "flask>=3.0.0"],
        }
    }


@pytest.fixture
def sample_pipfile_lock() -> dict:
    """Return sample Pipfile.lock data."""
    return {
        "_meta": {
            "hash": {"sha256": "abc123"},
            "pipfile-spec": 6,
        },
        "default": {
            "requests": {"version": "==2.31.0", "hashes": ["sha256:abc"]},
            "flask": {"version": "==3.0.0", "hashes": ["sha256:def"]},
        },
        "develop": {
            "pytest": {"version": "==7.4.0", "hashes": ["sha256:ghi"]},
        },
    }
