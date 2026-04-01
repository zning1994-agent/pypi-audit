"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def sample_requirements_content() -> str:
    """Sample requirements.txt content for testing."""
    return """# This is a comment
requests==2.28.0
click>=8.0.0
rich[markdown]~=13.0
httpx<0.24.0
packaging
git+https://github.com/user/repo.git@v1.0.0
-e git+https://github.com/user/repo.git#egg=editable_pkg
pypi-audit@https://example.com/pypi-audit.tar.gz
pytest; python_version >= "3.8"
"""


@pytest.fixture
def sample_requirements_file(tmp_path: Path, sample_requirements_content: str) -> Path:
    """Create a temporary requirements.txt file."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(sample_requirements_content)
    return req_file


@pytest.fixture
def empty_requirements_file(tmp_path: Path) -> Path:
    """Create an empty requirements.txt file."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("")
    return req_file


@pytest.fixture
def malformed_requirements_file(tmp_path: Path) -> Path:
    """Create a requirements.txt with malformed lines."""
    return tmp_path / "requirements.txt"  # File doesn't exist


@pytest.fixture
def complex_requirements_content() -> str:
    """Complex requirements.txt with various formats."""
    return """
# Comment line
-r base.txt
--index-url https://pypi.org/simple
--extra-index-url https://custom.pypi.org/simple

requests[security]>=2.25.0,<3.0.0
click==8.1.0
flask[async]>=2.0
sqlalchemy>=1.4,<2.0
django~=4.0
aiohttp!=2.0.0
celery[redis]>=5.0
pydantic>=1.10,<2.0
uvicorn[standard]>=0.17
httpx[http2]>=0.23
python-dotenv==0.19.0
pydantic[email]>=2.0
"""


@pytest.fixture
def git_requirements_content() -> str:
    """Requirements with git dependencies."""
    return """
git+https://github.com/psf/requests.git@v2.28.0
git+ssh://git@github.com/user/repo.git@branch
-e git+https://github.com/user/editable.git#egg=my_package
urllib3 @ https://github.com/urllib3/urllib3/archive/refs/tags/1.26.0.tar.gz
"""
