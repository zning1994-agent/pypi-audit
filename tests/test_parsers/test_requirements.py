"""Unit tests for requirements.txt parser."""

import pytest
from pathlib import Path
from unittest.mock import mock_open, patch

from pypi_audit.parsers.requirements import RequirementsParser
from pypi_audit.parsers.base import Dependency


class TestRequirementsParser:
    """Test cases for RequirementsParser."""
    
    @pytest.fixture
    def parser(self) -> RequirementsParser:
        """Create a parser instance."""
        return RequirementsParser()
    
    def test_supported_extensions(self, parser: RequirementsParser) -> None:
        """Test that parser supports .txt extension."""
        assert parser.supported_extensions == (".txt",)
    
    def test_parse_simple_package(self, parser: RequirementsParser) -> None:
        """Test parsing a simple package without version."""
        content = "requests\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version is None
    
    def test_parse_package_with_version(self, parser: RequirementsParser) -> None:
        """Test parsing a package with version specifier."""
        content = "requests==2.28.0\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "==2.28.0"
    
    def test_parse_package_with_greater_than_version(self, parser: RequirementsParser) -> None:
        """Test parsing a package with >= version specifier."""
        content = "requests>=2.28.0\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == ">=2.28.0"
    
    def test_parse_package_with_extras(self, parser: RequirementsParser) -> None:
        """Test parsing a package with extras."""
        content = "requests[security]\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].extras == ["security"]
    
    def test_parse_package_with_multiple_extras(self, parser: RequirementsParser) -> None:
        """Test parsing a package with multiple extras."""
        content = "requests[security,socks]\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].extras == ["security", "socks"]
    
    def test_parse_package_with_version_and_extras(self, parser: RequirementsParser) -> None:
        """Test parsing a package with both version and extras."""
        content = "requests[security]==2.28.0\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "==2.28.0"
        assert deps[0].extras == ["security"]
    
    def test_parse_package_with_marker(self, parser: RequirementsParser) -> None:
        """Test parsing a package with environment marker."""
        content = "requests ; python_version >= '3.8'\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].marker == "python_version >= '3.8'"
    
    def test_parse_package_with_marker_and_version(self, parser: RequirementsParser) -> None:
        """Test parsing a package with marker and version."""
        content = "PyJWT[crypto]>=2.0.0 ; python_version >= '3.8'\n"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "PyJWT"
        assert deps[0].version == ">=2.0.0"
        assert deps[0].extras == ["crypto"]
        assert deps[0].marker == "python_version >= '3.8'"
    
    def test_parse_multiple_packages(self, parser: RequirementsParser) -> None:
        """Test parsing multiple packages."""
        content = """requests==2.28.0
flask>=2.0.0
django
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 3
        assert deps[0].name == "requests"
        assert deps[0].version == "==2.28.0"
        assert deps[1].name == "flask"
        assert deps[1].version == ">=2.0.0"
        assert deps[2].name == "django"
        assert deps[2].version is None
    
    def test_parse_with_comments(self, parser: RequirementsParser) -> None:
        """Test parsing with inline and full-line comments."""
        content = """# This is a comment
requests==2.28.0  # inline comment
# Another comment
flask>=2.0.0
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "flask"
    
    def test_parse_empty_lines(self, parser: RequirementsParser) -> None:
        """Test parsing with empty lines."""
        content = """requests==2.28.0

flask>=2.0.0

"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
    
    def test_parse_skip_requirement_directives(self, parser: RequirementsParser) -> None:
        """Test that -r and --requirement directives are skipped."""
        content = """-r other_requirements.txt
--requirement=base.txt
requests==2.28.0
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
    
    def test_parse_skip_editable_installs(self, parser: RequirementsParser) -> None:
        """Test that -e and --editable directives are skipped."""
        content = """-e git+https://github.com/user/repo.git
--editable=.
requests==2.28.0
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
    
    def test_parse_skip_options(self, parser: RequirementsParser) -> None:
        """Test that pip options are skipped."""
        content = """--index-url https://pypi.org/simple
--extra-index-url https://custom.pypi.org/simple
-f https://files.pythonhosted.org
requests==2.28.0
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
    
    def test_parse_package_name_normalization(self, parser: RequirementsParser) -> None:
        """Test that package names are normalized."""
        content = """Requests
Django_Core
Some_Package==1.0.0
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].name == "requests"
        assert deps[1].name == "django-core"
        assert deps[2].name == "some-package"
    
    def test_parse_version_v_prefix_normalized(self, parser: RequirementsParser) -> None:
        """Test that version 'v' prefix is normalized."""
        content = """requests==v2.28.0
flask>=v1.0.0
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].version == "==2.28.0"
        assert deps[1].version == ">=1.0.0"
    
    def test_parse_complex_version_specs(self, parser: RequirementsParser) -> None:
        """Test various version specifiers."""
        content = """requests~=2.28.0
flask>=2.0.0,<3.0.0
django!=1.0.0
celery[redis]>=5.0.0
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].version == "~=2.28.0"
        assert deps[1].version == ">=2.0.0,<3.0.0"
        assert deps[2].version == "!=1.0.0"
        assert deps[3].version == ">=5.0.0"
        assert deps[3].extras == ["redis"]
    
    def test_parse_from_file(self, parser: RequirementsParser, tmp_path: Path) -> None:
        """Test parsing from an actual file."""
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text("requests==2.28.0\nflask>=2.0.0\n")
        
        deps = list(parser.parse(requirements_file))
        
        assert len(deps) == 2
        assert all(dep.source_file == requirements_file for dep in deps)
    
    def test_parse_package_with_hyphen_in_name(self, parser: RequirementsParser) -> None:
        """Test parsing packages with hyphens in names."""
        content = """boto3
PyYAML
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].name == "boto3"
        assert deps[1].name == "pyyaml"
    
    def test_parse_package_with_underscore_in_name(self, parser: RequirementsParser) -> None:
        """Test parsing packages with underscores in names."""
        content = """my_package
another_pkg
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].name == "my-package"
        assert deps[1].name == "another-pkg"
    
    def test_parse_empty_content(self, parser: RequirementsParser) -> None:
        """Test parsing empty content."""
        content = ""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_only_comments(self, parser: RequirementsParser) -> None:
        """Test parsing content with only comments."""
        content = """# Comment 1
# Comment 2
# Comment 3
"""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_package_with_operators(self, parser: RequirementsParser) -> None:
        """Test parsing with various version operators."""
        content = """pkg1===1.0.0
pkg2>=1.0.0,<2.0.0
pkg3!=1.0.0
pkg4<=2.0.0
"""
        deps = list(parser.parse_string(content))
        
        assert deps[0].version == "===1.0.0"
        assert deps[1].version == ">=1.0.0,<2.0.0"
        assert deps[2].version == "!=1.0.0"
        assert deps[3].version == "<=2.0.0"
