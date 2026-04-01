"""Unit tests for pyproject.toml parser."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch

from pypi_audit.parsers.pyproject import PyprojectParser
from pypi_audit.parsers.base import Dependency


class TestPyprojectParser:
    """Test cases for PyprojectParser."""
    
    @pytest.fixture
    def parser(self) -> PyprojectParser:
        """Create a parser instance."""
        return PyprojectParser()
    
    def test_supported_extensions(self, parser: PyprojectParser) -> None:
        """Test that parser supports .toml extension."""
        assert parser.supported_extensions == (".toml",)
    
    def test_parse_simple_dependencies(self, parser: PyprojectParser) -> None:
        """Test parsing simple dependencies list."""
        content = """
[project]
dependencies = [
    "requests>=2.28.0",
    "flask>=2.0.0",
]
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "requests" in names
        assert "flask" in names
    
    def test_parse_dependencies_with_version(self, parser: PyprojectParser) -> None:
        """Test parsing dependencies with version specifiers."""
        content = """
[project]
dependencies = [
    "requests==2.28.0",
    "django~=4.0.0",
]
"""
        deps = list(parser.parse_string(content))
        
        requests = next(d for d in deps if d.name == "requests")
        django = next(d for d in deps if d.name == "django")
        
        assert requests.version == "==2.28.0"
        assert django.version == "~=4.0.0"
    
    def test_parse_dependencies_with_extras(self, parser: PyprojectParser) -> None:
        """Test parsing dependencies with extras."""
        content = """
[project]
dependencies = [
    "requests[security]>=2.28.0",
]
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].extras == ["security"]
        assert deps[0].version == ">=2.28.0"
    
    def test_parse_dependencies_with_multiple_extras(self, parser: PyprojectParser) -> None:
        """Test parsing dependencies with multiple extras."""
        content = """
[project]
dependencies = [
    "requests[security,socks]>=2.28.0",
]
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].extras == ["security", "socks"]
    
    def test_parse_optional_dependencies(self, parser: PyprojectParser) -> None:
        """Test parsing optional dependencies (extras)."""
        content = """
[project]
dependencies = ["requests>=2.28.0"]

[project.optional-dependencies]
dev = ["pytest>=7.0.0", "black>=22.0.0"]
test = ["pytest-cov>=4.0.0"]
"""
        deps = list(parser.parse_string(content))
        
        # Should have 4 total: 1 default + 2 dev + 1 test
        assert len(deps) == 4
        
        # Check that optional deps have the extra name in their extras list
        optional_deps = [d for d in deps if d.extras]
        dev_deps = [d for d in optional_deps if "dev" in d.extras]
        test_deps = [d for d in optional_deps if "test" in d.extras]
        
        assert len(dev_deps) == 2
        assert len(test_deps) == 1
    
    def test_parse_complex_dependency_spec(self, parser: PyprojectParser) -> None:
        """Test parsing complex dictionary-style dependency spec."""
        content = """
[project]
dependencies = [
    {version = "^1.0", extras = ["aio"]},
    {name = "boto3", version = ">=1.20"},
]
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
        assert deps[0].name == "aio"
        assert deps[0].version == "^1.0"
        assert deps[1].name == "boto3"
        assert deps[1].version == ">=1.20"
    
    def test_parse_poetry_style_dependencies(self, parser: PyprojectParser) -> None:
        """Test parsing Poetry-style dependencies."""
        content = """
[tool.poetry.dependencies]
python = "^3.8"
requests = "^2.28.0"
flask = {version = "^2.0", python = "^3.8"}
"""
        deps = list(parser.parse_string(content))
        
        # Should skip python dependency
        non_python = [d for d in deps if d.name != "python"]
        assert len(non_python) == 2
        
        requests = next(d for d in non_python if d.name == "requests")
        flask = next(d for d in non_python if d.name == "flask")
        
        assert requests.version == "^2.28.0"
        assert flask.version == "^2.0"
    
    def test_parse_poetry_dependencies_with_extras(self, parser: PyprojectParser) -> None:
        """Test parsing Poetry dependencies with extras."""
        content = """
[tool.poetry.dependencies]
boto3 = {version = "^1.20", extras = ["s3transfer"]}
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "boto3"
        assert deps[0].extras == ["s3transfer"]
    
    def test_parse_poetry_group_dependencies(self, parser: PyprojectParser) -> None:
        """Test parsing Poetry optional group dependencies."""
        content = """
[tool.poetry.group.dev.dependencies]
pytest = "^7.0.0"
black = "^22.0.0"
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "pytest" in names
        assert "black" in names
    
    def test_parse_mixed_sources(self, parser: PyprojectParser) -> None:
        """Test parsing from both project and poetry formats."""
        content = """
[project]
dependencies = ["requests>=2.28.0"]

[tool.poetry.dependencies]
flask = "^2.0.0"
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "requests" in names
        assert "flask" in names
    
    def test_parse_empty_content(self, parser: PyprojectParser) -> None:
        """Test parsing empty content."""
        content = ""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_invalid_toml(self, parser: PyprojectParser) -> None:
        """Test parsing invalid TOML content."""
        content = "not valid toml [[["
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_no_dependencies_section(self, parser: PyprojectParser) -> None:
        """Test parsing TOML without dependencies section."""
        content = """
[project]
name = "my-package"
version = "1.0.0"
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_from_file(self, parser: PyprojectParser, tmp_path: Path) -> None:
        """Test parsing from an actual file."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text("""
[project]
dependencies = ["requests>=2.28.0", "flask>=2.0.0"]
""")
        
        deps = list(parser.parse(pyproject_file))
        
        assert len(deps) == 2
        assert all(dep.source_file == pyproject_file for dep in deps)
    
    def test_parse_version_v_prefix_normalized(self, parser: PyprojectParser) -> None:
        """Test that version 'v' prefix is normalized."""
        content = """
[project]
dependencies = [
    "requests==v2.28.0",
]
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].version == "==2.28.0"
    
    def test_parse_complex_version_constraints(self, parser: PyprojectParser) -> None:
        """Test parsing complex version constraints."""
        content = """
[project]
dependencies = [
    "requests>=2.0.0,<3.0.0",
    "django>=4.0,<5.0",
]
"""
        deps = list(parser.parse_string(content))
        
        requests = next(d for d in deps if d.name == "requests")
        django = next(d for d in deps if d.name == "django")
        
        assert requests.version == ">=2.0.0,<3.0.0"
        assert django.version == ">=4.0,<5.0"
    
    def test_parse_dependency_name_normalization(self, parser: PyprojectParser) -> None:
        """Test that dependency names are normalized."""
        content = """
[project]
dependencies = [
    "Requests",
    "Django_Core",
]
"""
        deps = list(parser.parse_string(content))
        
        names = {d.name for d in deps}
        assert "requests" in names
        assert "django-core" in names
    
    def test_parse_dependency_with_platform_marker(self, parser: PyprojectParser) -> None:
        """Test parsing dependencies with platform markers."""
        content = '''
[project]
dependencies = [
    "pywin32>=300 ; sys_platform == \'win32\'",
]
'''
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "pywin32"
    
    def test_parse_poetry_dev_dependencies(self, parser: PyprojectParser) -> None:
        """Test parsing Poetry dev dependencies."""
        content = """
[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
black = "^22.0.0"
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "pytest" in names
        assert "black" in names
    
    def test_parse_empty_dependencies_list(self, parser: PyprojectParser) -> None:
        """Test parsing with empty dependencies list."""
        content = """
[project]
dependencies = []
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_single_dependency(self, parser: PyprojectParser) -> None:
        """Test parsing single dependency."""
        content = """
[project]
dependencies = ["requests"]
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version is None
