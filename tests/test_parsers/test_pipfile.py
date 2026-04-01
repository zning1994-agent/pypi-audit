"""Unit tests for Pipfile.lock parser."""

import pytest
import json
from pathlib import Path

from pypi_audit.parsers.pipfile import PipfileParser
from pypi_audit.parsers.base import Dependency


class TestPipfileParser:
    """Test cases for PipfileParser."""
    
    @pytest.fixture
    def parser(self) -> PipfileParser:
        """Create a parser instance."""
        return PipfileParser()
    
    def test_supported_extensions(self, parser: PipfileParser) -> None:
        """Test that parser supports .lock and .json extensions."""
        assert parser.supported_extensions == (".lock", ".json")
    
    def test_parse_simple_package(self, parser: PipfileParser) -> None:
        """Test parsing a simple package."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "==2.28.0"
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "==2.28.0"
    
    def test_parse_multiple_packages(self, parser: PipfileParser) -> None:
        """Test parsing multiple packages."""
        content = json.dumps({
            "default": {
                "requests": {"version": "==2.28.0"},
                "flask": {"version": "==2.0.0"},
                "django": {"version": "==4.0.0"}
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 3
        names = {d.name for d in deps}
        assert "requests" in names
        assert "flask" in names
        assert "django" in names
    
    def test_parse_package_with_hashes(self, parser: PipfileParser) -> None:
        """Test parsing a package with hashes (pinned)."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "==2.28.0",
                    "hashes": [
                        "sha256:abc123",
                        "sha256:def456"
                    ]
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "==2.28.0"
    
    def test_parse_package_with_extras(self, parser: PipfileParser) -> None:
        """Test parsing a package with extras."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "==2.28.0",
                    "extras": ["security"]
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].extras == ["security"]
    
    def test_parse_package_with_multiple_extras(self, parser: PipfileParser) -> None:
        """Test parsing a package with multiple extras."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "==2.28.0",
                    "extras": ["security", "socks"]
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert deps[0].extras == ["security", "socks"]
    
    def test_parse_develop_dependencies(self, parser: PipfileParser) -> None:
        """Test parsing develop dependencies."""
        content = json.dumps({
            "default": {},
            "develop": {
                "pytest": {"version": "==7.0.0"},
                "black": {"version": "==22.0.0"}
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "pytest" in names
        assert "black" in names
    
    def test_parse_both_default_and_develop(self, parser: PipfileParser) -> None:
        """Test parsing both default and develop dependencies."""
        content = json.dumps({
            "default": {
                "requests": {"version": "==2.28.0"}
            },
            "develop": {
                "pytest": {"version": "==7.0.0"}
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 2
    
    def test_parse_package_with_v_prefix_version(self, parser: PipfileParser) -> None:
        """Test parsing package with 'v' prefix in version."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "v2.28.0"
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert deps[0].version == "2.28.0"
    
    def test_parse_package_without_version(self, parser: PipfileParser) -> None:
        """Test parsing package without explicit version."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "*"
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
    
    def test_parse_package_pinned_with_hashes_only(self, parser: PipfileParser) -> None:
        """Test parsing package pinned only by hashes (no version)."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "*",
                    "hashes": ["sha256:abc123"]
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        # Should mark as pinned since it has hashes
        assert deps[0].version == "pinned"
    
    def test_parse_empty_sections(self, parser: PipfileParser) -> None:
        """Test parsing with empty default and develop sections."""
        content = json.dumps({
            "default": {},
            "develop": {}
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_invalid_json(self, parser: PipfileParser) -> None:
        """Test parsing invalid JSON content."""
        content = "not valid json"
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_from_file(self, parser: PipfileParser, tmp_path: Path) -> None:
        """Test parsing from an actual file."""
        lock_file = tmp_path / "Pipfile.lock"
        lock_file.write_text(json.dumps({
            "default": {
                "requests": {"version": "==2.28.0"},
                "flask": {"version": "==2.0.0"}
            }
        }))
        
        deps = list(parser.parse(lock_file))
        
        assert len(deps) == 2
        assert all(dep.source_file == lock_file for dep in deps)
    
    def test_parse_package_name_normalization(self, parser: PipfileParser) -> None:
        """Test that package names are normalized."""
        content = json.dumps({
            "default": {
                "Requests": {"version": "==2.28.0"},
                "Django_Core": {"version": "==4.0.0"}
            }
        })
        deps = list(parser.parse_string(content))
        
        assert deps[0].name == "requests"
        assert deps[1].name == "django-core"
    
    def test_parse_package_with_version_equals_prefix(self, parser: PipfileParser) -> None:
        """Test parsing package with == prefix in version field."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "==2.28.0"
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        # Version should have == prefix stripped
        assert deps[0].version == "==2.28.0"
    
    def test_parse_package_without_spec_dict(self, parser: PipfileParser) -> None:
        """Test that non-dict specs are skipped."""
        content = json.dumps({
            "default": {
                "requests": "==2.28.0",
                "flask": {"version": "==2.0.0"}
            }
        })
        deps = list(parser.parse_string(content))
        
        # Should only get flask, requests has string spec
        assert len(deps) == 1
        assert deps[0].name == "flask"
    
    def test_parse_complex_package_spec(self, parser: PipfileParser) -> None:
        """Test parsing package with full spec."""
        content = json.dumps({
            "default": {
                "requests": {
                    "version": "==2.28.0",
                    "hashes": ["sha256:abc123", "sha256:def456"],
                    "extras": ["security"],
                    "markers": "python_version >= '3.6'"
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "==2.28.0"
        assert deps[0].extras == ["security"]
    
    def test_parse_empty_content(self, parser: PipfileParser) -> None:
        """Test parsing empty content."""
        content = ""
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 0
    
    def test_parse_only_markers_no_version(self, parser: PipfileParser) -> None:
        """Test parsing package with only markers."""
        content = json.dumps({
            "default": {
                "pywin32": {
                    "version": "*",
                    "markers": "sys_platform == 'win32'"
                }
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 1
        assert deps[0].name == "pywin32"
    
    def test_parse_multiple_packages_with_mixed_versions(self, parser: PipfileParser) -> None:
        """Test parsing multiple packages with different version formats."""
        content = json.dumps({
            "default": {
                "pkg1": {"version": "==1.0.0"},
                "pkg2": {"version": "v2.0.0"},
                "pkg3": {"version": "*"},
                "pkg4": {"version": "==3.0.0", "hashes": ["sha256:abc"]}
            }
        })
        deps = list(parser.parse_string(content))
        
        assert len(deps) == 4
        versions = {d.name: d.version for d in deps}
        assert versions["pkg1"] == "==1.0.0"
        assert versions["pkg2"] == "2.0.0"  # v prefix stripped
        assert versions["pkg3"] is None
        assert versions["pkg4"] == "==3.0.0"
