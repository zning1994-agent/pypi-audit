"""Tests for pyproject.toml parser."""

import pytest
import sys
from pathlib import Path

from pypi_audit.models import Package
from pypi_audit.parsers.pyproject import PyprojectParser


class TestPyprojectParser:
    """Test cases for PyprojectParser."""

    @pytest.fixture
    def parser(self) -> PyprojectParser:
        """Create a parser instance."""
        return PyprojectParser()

    @pytest.fixture
    def sample_pyproject_basic(self) -> str:
        """Basic pyproject.toml content."""
        return """
[project]
name = "my-package"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
    "numpy>=1.19.0,<2.0",
    "django>=4.0",
]

[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"
"""

    @pytest.fixture
    def sample_pyproject_with_optional(self) -> str:
        """pyproject.toml with optional dependencies."""
        return """
[project]
name = "my-package"
version = "1.0.0"
dependencies = [
    "requests>=2.28.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black>=23.0.0",
]
test = [
    "pytest-cov>=4.0.0",
]

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

    @pytest.fixture
    def sample_pyproject_with_extras(self) -> str:
        """pyproject.toml with package extras."""
        return """
[project]
name = "my-package"
dependencies = [
    "pip[mypy]>=21.0",
    "numpy[blas]>=1.19",
    "django[argon2,bcrypt]>=4.0",
]
"""

    @pytest.fixture
    def sample_pyproject_minimal(self) -> str:
        """Minimal pyproject.toml with no dependencies."""
        return """
[project]
name = "my-package"
version = "0.1.0"
"""

    @pytest.fixture
    def sample_pyproject_complex_versions(self) -> str:
        """pyproject.toml with various version specifiers."""
        return """
[project]
dependencies = [
    "package1~=1.4.2",
    "package2==2.0.0",
    "package3>=1.0.0,<2.0.0",
    "package4>1.0.0",
    "package5<=3.0.0",
]
"""

    # === Properties Tests ===

    def test_supported_extensions(self, parser: PyprojectParser) -> None:
        """Test supported file extensions."""
        assert parser.supported_extensions == (".toml",)
        assert parser.file_type == "pyproject"

    def test_can_parse(self, parser: PyprojectParser, tmp_path: Path) -> None:
        """Test can_parse method."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text("")
        assert parser.can_parse(pyproject_file) is True

        assert parser.can_parse(tmp_path / "requirements.txt") is False

    # === parse_content Tests ===

    def test_parse_basic_dependencies(
        self, parser: PyprojectParser, sample_pyproject_basic: str
    ) -> None:
        """Test parsing basic dependencies."""
        packages = parser.parse_content(sample_pyproject_basic)

        assert len(packages) >= 3

        names = [pkg.name for pkg in packages]
        assert "requests" in names
        assert "numpy" in names
        assert "django" in names

        # Check versions are extracted
        requests_pkg = next(pkg for pkg in packages if pkg.name == "requests")
        assert requests_pkg.version == "2.28"

    def test_parse_optional_dependencies(
        self, parser: PyprojectParser, sample_pyproject_with_optional: str
    ) -> None:
        """Test parsing optional dependencies."""
        packages = parser.parse_content(sample_pyproject_with_optional)

        # Should have main deps + optional deps
        names = [pkg.name for pkg in packages]
        assert "requests" in names
        assert "pytest" in names
        assert "black" in names
        assert "pytest-cov" in names

    def test_parse_extras(
        self, parser: PyprojectParser, sample_pyproject_with_extras: str
    ) -> None:
        """Test parsing package extras."""
        packages = parser.parse_content(sample_pyproject_with_extras)

        # Check pip with mypy extra
        pip_pkg = next(pkg for pkg in packages if pkg.name == "pip")
        assert "mypy" in pip_pkg.extras

        # Check numpy with blas extra
        numpy_pkg = next(pkg for pkg in packages if pkg.name == "numpy")
        assert "blas" in numpy_pkg.extras

        # Check django with multiple extras
        django_pkg = next(pkg for pkg in packages if pkg.name == "django")
        assert "argon2" in django_pkg.extras
        assert "bcrypt" in django_pkg.extras

    def test_parse_build_dependencies(
        self, parser: PyprojectParser, sample_pyproject_basic: str
    ) -> None:
        """Test parsing build system requirements."""
        packages = parser.parse_content(sample_pyproject_basic)

        names = [pkg.name for pkg in packages]
        assert "setuptools" in names
        assert "wheel" in names

    def test_parse_minimal_file(
        self, parser: PyprojectParser, sample_pyproject_minimal: str
    ) -> None:
        """Test parsing minimal pyproject.toml with no dependencies."""
        packages = parser.parse_content(sample_pyproject_minimal)
        assert packages == []

    def test_parse_complex_versions(
        self, parser: PyprojectParser, sample_pyproject_complex_versions: str
    ) -> None:
        """Test parsing various version specifiers."""
        packages = parser.parse_content(sample_pyproject_complex_versions)

        package_dict = {pkg.name: pkg for pkg in packages}

        # Check various version formats
        assert package_dict["package1"].version == "1.4"
        assert package_dict["package2"].version == "2.0"
        # package3 should get first version
        assert package_dict["package3"].version == "1.0"

    def test_parse_empty_dependencies_list(self, parser: PyprojectParser) -> None:
        """Test parsing with empty dependencies list."""
        content = """
[project]
name = "empty-deps"
dependencies = []
"""
        packages = parser.parse_content(content)
        assert packages == []

    def test_parse_with_comments(self, parser: PyprojectParser) -> None:
        """Test parsing with inline comments."""
        content = """
[project]
dependencies = [
    "requests>=2.28.0",  # HTTP library
    "numpy>=1.19.0,<2.0",  # NumPy with comment
]
"""
        packages = parser.parse_content(content)
        names = [pkg.name for pkg in packages]
        assert "requests" in names
        assert "numpy" in names

    def test_parse_invalid_toml(self, parser: PyprojectParser) -> None:
        """Test parsing invalid TOML content."""
        invalid_content = """
[project
name = "test"
"""
        with pytest.raises(ValueError, match="Failed to parse TOML"):
            parser.parse_content(invalid_content)

    def test_package_names_lowercase(self, parser: PyprojectParser) -> None:
        """Test that package names are normalized to lowercase."""
        content = """
[project]
dependencies = [
    "Requests>=2.28.0",
    "NUMPY>=1.19.0",
    "Django>=4.0",
]
"""
        packages = parser.parse_content(content)
        names = [pkg.name for pkg in packages]
        assert names == ["requests", "numpy", "django"]

    # === parse() File Tests ===

    def test_parse_file(self, parser: PyprojectParser, tmp_path: Path) -> None:
        """Test parsing from a file."""
        pyproject_file = tmp_path / "pyproject.toml"
        content = """
[project]
name = "test-package"
dependencies = [
    "click>=8.0.0",
]
"""
        pyproject_file.write_text(content)

        packages = parser.parse(pyproject_file)
        assert len(packages) == 1
        assert packages[0].name == "click"

    def test_parse_file_not_found(self, parser: PyprojectParser) -> None:
        """Test parsing non-existent file."""
        with pytest.raises(FileNotFoundError):
            parser.parse("/nonexistent/path/pyproject.toml")

    def test_parse_file_with_pathlib(self, parser: PyprojectParser, tmp_path: Path) -> None:
        """Test parsing with Path object."""
        pyproject_file = tmp_path / "pyproject.toml"
        content = """
[project]
dependencies = ["rich>=13.0.0"]
"""
        pyproject_file.write_text(content)

        packages = parser.parse(pyproject_file)
        assert len(packages) == 1
        assert packages[0].name == "rich"

    # === Source File Tracking ===

    def test_source_file_tracking(self, parser: PyprojectParser, tmp_path: Path) -> None:
        """Test that source file is tracked correctly."""
        pyproject_file = tmp_path / "subdir" / "pyproject.toml"
        pyproject_file.parent.mkdir(parents=True, exist_ok=True)
        pyproject_file.write_text("""
[project]
dependencies = ["packaging>=23.0"]
""")

        packages = parser.parse(pyproject_file)
        assert len(packages) == 1
        assert "packaging" in packages[0].name

    # === Edge Cases ===

    def test_parse_with_version_operators(self, parser: PyprojectParser) -> None:
        """Test various version operators."""
        content = """
[project]
dependencies = [
    "pkg1>=1.0.0",
    "pkg2>1.0.0",
    "pkg3<2.0.0",
    "pkg4<=2.0.0",
    "pkg5==1.5.0",
    "pkg6~=1.4.0",
]
"""
        packages = parser.parse_content(content)
        assert len(packages) == 6

    def test_parse_editable_dependency(self, parser: PyprojectParser) -> None:
        """Test that editable-style deps are skipped (not supported)."""
        content = """
[project]
dependencies = [
    "-e .",
    "-e git+https://github.com/user/repo.git",
    "normal-package>=1.0.0",
]
"""
        packages = parser.parse_content(content)
        names = [pkg.name for pkg in packages]
        assert "normal-package" in names
        # Editable deps should not be parsed as packages
        assert len(packages) == 1

    def test_parse_empty_string_in_list(self, parser: PyprojectParser) -> None:
        """Test handling of empty strings in dependency list."""
        content = """
[project]
dependencies = [
    "package1>=1.0.0",
    "",
    "package2>=2.0.0",
]
"""
        packages = parser.parse_content(content)
        names = [pkg.name for pkg in packages]
        assert "package1" in names
        assert "package2" in names
        assert len(packages) == 2

    def test_parse_whitespace_only(self, parser: PyprojectParser) -> None:
        """Test handling of whitespace-only strings."""
        content = """
[project]
dependencies = [
    "   ",
    "package>=1.0.0",
]
"""
        packages = parser.parse_content(content)
        assert len(packages) == 1
        assert packages[0].name == "package"

    def test_parse_without_version(self, parser: PyprojectParser) -> None:
        """Test parsing package without version specifier."""
        content = """
[project]
dependencies = [
    "some-package",
    "another-package>=1.0",
]
"""
        packages = parser.parse_content(content)
        pkg_dict = {pkg.name: pkg for pkg in packages}

        assert pkg_dict["some-package"].version is None
        assert pkg_dict["another-package"].version == "1.0"

    def test_source_file_for_all_packages(self, parser: PyprojectParser) -> None:
        """Test that source_file is set for all packages."""
        content = """
[project]
dependencies = ["pkg1>=1.0"]

[project.optional-dependencies]
dev = ["pkg2>=2.0"]

[build-system]
requires = ["setuptools"]
"""
        packages = parser.parse_content(content)
        for pkg in packages:
            assert pkg.source_file is not None

    # === Package Model Tests ===

    def test_package_model(self, parser: PyprojectParser) -> None:
        """Test that Package model is correctly populated."""
        content = """
[project]
dependencies = [
    "mypackage[extra1,extra2]>=1.2.3",
]
"""
        packages = parser.parse_content(content)
        pkg = packages[0]

        assert isinstance(pkg, Package)
        assert pkg.name == "mypackage"
        assert pkg.version == "1.2"
        assert pkg.extras == ["extra1", "extra2"]
