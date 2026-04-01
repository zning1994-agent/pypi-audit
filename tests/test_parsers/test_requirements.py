"""Tests for requirements.txt parser."""

import pytest
from pathlib import Path

from pypi_audit.parsers.requirements import RequirementsParser
from pypi_audit.parsers.base import Dependency, ParseResult


class TestRequirementsParser:
    """Test cases for RequirementsParser."""

    @pytest.fixture
    def parser(self) -> RequirementsParser:
        """Create a parser instance."""
        return RequirementsParser()

    def test_supported_extensions(self, parser: RequirementsParser) -> None:
        """Test that parser reports correct supported extensions."""
        assert parser.supported_extensions == (".txt",)

    def test_parse_basic_requirements(
        self,
        parser: RequirementsParser,
        sample_requirements_content: str,
    ) -> None:
        """Test parsing basic requirements.txt format."""
        result = parser.parse("requirements.txt", sample_requirements_content)

        assert result.file_path == "requirements.txt"
        assert result.raw_content == sample_requirements_content
        assert not result.has_errors
        assert not result.is_empty

        # Check that dependencies were extracted
        names = [dep.name for dep in result.dependencies]
        assert "requests" in names
        assert "click" in names
        assert "rich" in names
        assert "httpx" in names
        assert "packaging" in names

    def test_parse_with_version_operator(self, parser: RequirementsParser) -> None:
        """Test parsing packages with various version operators."""
        content = """
requests==2.28.0
click>=8.0.0
flask~=4.0
aiohttp<0.24.0
urllib3>=1.0,!=1.1
"""
        result = parser.parse("requirements.txt", content)

        deps = {dep.name: dep for dep in result.dependencies}
        assert deps["requests"].version == "==2.28.0"
        assert deps["click"].version == ">=8.0.0"
        assert deps["flask"].version == "~=4.0"
        assert deps["aiohttp"].version == "<0.24.0"
        assert deps["urllib3"].version == ">=1.0,!=1.1"

    def test_parse_extras(self, parser: RequirementsParser) -> None:
        """Test parsing packages with extras."""
        content = """
requests[security]>=2.0
click[extra1,extra2]>=8.0
flask[async]>=2.0
"""
        result = parser.parse("requirements.txt", content)

        deps = {dep.name: dep for dep in result.dependencies}
        assert deps["requests"].extras == ["security"]
        assert deps["click"].extras == ["extra1", "extra2"]
        assert deps["flask"].extras == ["async"]

    def test_parse_environment_markers(self, parser: RequirementsParser) -> None:
        """Test parsing packages with environment markers."""
        content = """
pytest; python_version >= "3.8"
typing-extensions; python_version < "3.8"
win32api; sys_platform == "win32"
"""
        result = parser.parse("requirements.txt", content)

        deps = {dep.name: dep for dep in result.dependencies}
        assert deps["pytest"].markers == 'python_version >= "3.8"'
        assert deps["typing-extensions"].markers == 'python_version < "3.8"'
        assert deps["win32api"].markers == 'sys_platform == "win32"'

    def test_skip_comments(self, parser: RequirementsParser) -> None:
        """Test that comment lines are skipped."""
        content = """
# This is a comment
requests==2.28.0
  # Indented comment
click>=8.0.0
"""
        result = parser.parse("requirements.txt", content)

        names = [dep.name for dep in result.dependencies]
        assert len(names) == 2
        assert "requests" in names
        assert "click" in names

    def test_skip_options(self, parser: RequirementsParser) -> None:
        """Test that pip options are skipped."""
        content = """
--index-url https://pypi.org/simple
-r base.txt
--extra-index-url https://custom.pypi.com
-e .
--editable .
--find-links https://links.com
requests==2.28.0
"""
        result = parser.parse("requirements.txt", content)

        names = [dep.name for dep in result.dependencies]
        assert len(names) == 1
        assert "requests" in names

    def test_skip_empty_lines(self, parser: RequirementsParser) -> None:
        """Test that empty lines are skipped."""
        content = """

requests==2.28.0

click>=8.0.0

"""
        result = parser.parse("requirements.txt", content)

        assert len(result.dependencies) == 2

    def test_package_name_normalization(self, parser: RequirementsParser) -> None:
        """Test that package names are normalized to lowercase."""
        content = """
Requests==2.28.0
Click>=8.0.0
PACKAGING>=21.0
"""
        result = parser.parse("requirements.txt", content)

        names = [dep.name for dep in result.dependencies]
        assert "requests" in names
        assert "click" in names
        assert "packaging" in names
        assert "Requests" not in names
        assert "Click" not in names
        assert "PACKAGING" not in names

    def test_no_duplicates(self, parser: RequirementsParser) -> None:
        """Test that duplicate packages are not included."""
        content = """
requests==2.28.0
Requests>=2.0
REQUESTS<3.0
"""
        result = parser.parse("requirements.txt", content)

        requests_deps = [d for d in result.dependencies if d.name == "requests"]
        assert len(requests_deps) == 1

    def test_git_dependency(self, parser: RequirementsParser) -> None:
        """Test parsing git+https:// dependencies."""
        content = """
git+https://github.com/psf/requests.git@v2.28.0
git+ssh://git@github.com/user/repo.git@branch
"""
        result = parser.parse("requirements.txt", content)

        assert len(result.dependencies) == 2
        names = [dep.name for dep in result.dependencies]
        assert "requests" in names
        assert "repo" in names

    def test_editable_git_dependency(self, parser: RequirementsParser) -> None:
        """Test that editable git installs are skipped."""
        content = """
-e git+https://github.com/user/repo.git#egg=my_package
--editable git+https://github.com/user/repo2.git#egg=my_package2
requests==2.28.0
"""
        result = parser.parse("requirements.txt", content)

        names = [dep.name for dep in result.dependencies]
        assert "requests" in names
        assert len(names) == 1  # Only requests, not the git deps

    def test_url_dependency(self, parser: RequirementsParser) -> None:
        """Test parsing URL-based dependencies."""
        content = """
urllib3 @ https://github.com/urllib3/urllib3/archive/refs/tags/1.26.0.tar.gz
pypi-audit@https://example.com/pypi-audit.tar.gz
requests==2.28.0
"""
        result = parser.parse("requirements.txt", content)

        names = [dep.name for dep in result.dependencies]
        assert "urllib3" in names
        assert "pypi-audit" in names
        assert "requests" in names

    def test_parse_from_file(
        self,
        parser: RequirementsParser,
        sample_requirements_file: Path,
    ) -> None:
        """Test parsing from actual file."""
        result = parser.parse(str(sample_requirements_file))

        assert not result.has_errors
        assert len(result.dependencies) > 0
        assert all(dep.source_file == str(sample_requirements_file) for dep in result.dependencies)

    def test_parse_nonexistent_file(self, parser: RequirementsParser) -> None:
        """Test parsing a file that doesn't exist."""
        result = parser.parse("/nonexistent/requirements.txt")

        assert result.has_errors
        assert "File not found" in result.errors[0]

    def test_parse_iter(self, parser: RequirementsParser) -> None:
        """Test iterating over dependencies."""
        content = """
requests==2.28.0
click>=8.0.0
"""
        deps = list(parser.parse_iter("requirements.txt", content))

        assert len(deps) == 2
        assert all(isinstance(dep, Dependency) for dep in deps)

    def test_complex_requirements(
        self,
        parser: RequirementsParser,
        complex_requirements_content: str,
    ) -> None:
        """Test parsing complex requirements with various formats."""
        result = parser.parse("requirements.txt", complex_requirements_content)

        assert not result.has_errors
        names = [dep.name for dep in result.dependencies]
        assert len(names) > 0

        # Verify some expected packages
        expected = [
            "requests",
            "click",
            "flask",
            "sqlalchemy",
            "django",
            "aiohttp",
            "celery",
            "pydantic",
            "uvicorn",
            "httpx",
            "python-dotenv",
        ]
        for name in expected:
            assert name in names, f"Expected {name} in dependencies"


class TestDependencyModel:
    """Test cases for Dependency model."""

    def test_dependency_str_with_version(self) -> None:
        """Test string representation with version."""
        dep = Dependency(name="requests", version="==2.28.0")
        assert str(dep) == "requests==2.28.0"

    def test_dependency_str_without_version(self) -> None:
        """Test string representation without version."""
        dep = Dependency(name="requests")
        assert str(dep) == "requests"

    def test_dependency_defaults(self) -> None:
        """Test default values for Dependency."""
        dep = Dependency(name="requests")
        assert dep.version is None
        assert dep.extras == []
        assert dep.markers is None
        assert dep.source_file is None


class TestParseResultModel:
    """Test cases for ParseResult model."""

    def test_parse_result_has_errors(self) -> None:
        """Test has_errors property."""
        result = ParseResult(file_path="test.txt", errors=["Error 1"])
        assert result.has_errors

    def test_parse_result_no_errors(self) -> None:
        """Test has_errors property when no errors."""
        result = ParseResult(file_path="test.txt")
        assert not result.has_errors

    def test_parse_result_is_empty(self) -> None:
        """Test is_empty property."""
        result = ParseResult(file_path="test.txt")
        assert result.is_empty

    def test_parse_result_not_empty(self) -> None:
        """Test is_empty property when dependencies exist."""
        result = ParseResult(
            file_path="test.txt",
            dependencies=[Dependency(name="requests")],
        )
        assert not result.is_empty
