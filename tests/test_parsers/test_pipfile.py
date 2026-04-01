"""Unit tests for Pipfile.lock parser."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent
from typing import TYPE_CHECKING

import pytest

from pypi_audit.models import Package
from pypi_audit.parsers.pipfile import PipfileLockParser, parse_pipfile_lock

if TYPE_CHECKING:
    from pytest import TempPathFactory


class TestPipfileLockParser:
    """Test cases for PipfileLockParser class."""

    @pytest.fixture
    def parser(self) -> PipfileLockParser:
        """Create a PipfileLockParser instance."""
        return PipfileLockParser()

    @pytest.fixture
    def sample_pipfile_lock(self, tmp_path: Path) -> Path:
        """Create a sample Pipfile.lock file."""
        lock_content = {
            "_meta": {
                "hash": {"sha256": "abc123"},
                "pipfile-spec": 6,
            },
            "default": {
                "requests": {
                    "version": "==2.31.0",
                    "hashes": ["sha256:abc123..."],
                },
                "flask": {
                    "version": "==3.0.0",
                    "hashes": ["sha256:def456..."],
                },
            },
            "develop": {
                "pytest": {
                    "version": "==7.4.0",
                    "hashes": ["sha256:ghi789..."],
                },
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content, indent=4))
        return file_path

    def test_supported_extensions(self, parser: PipfileLockParser) -> None:
        """Test that parser supports .lock extension."""
        assert ".lock" in parser.supported_extensions

    def test_file_type(self, parser: PipfileLockParser) -> None:
        """Test file type identifier."""
        assert parser.file_type == "Pipfile.lock"

    def test_can_parse(self, parser: PipfileLockParser, sample_pipfile_lock: Path) -> None:
        """Test can_parse returns True for Pipfile.lock files."""
        assert parser.can_parse(sample_pipfile_lock) is True

    def test_cannot_parse_other_files(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test can_parse returns False for non-lock files."""
        other_file = tmp_path / "requirements.txt"
        other_file.write_text("requests==2.31.0")
        assert parser.can_parse(other_file) is False

    def test_parse_returns_packages(self, parser: PipfileLockParser, sample_pipfile_lock: Path) -> None:
        """Test that parse yields Package objects."""
        packages = list(parser.parse(sample_pipfile_lock))
        assert len(packages) == 3

        names = {pkg.name for pkg in packages}
        assert names == {"requests", "flask", "pytest"}

    def test_parse_extracts_versions(self, parser: PipfileLockParser, sample_pipfile_lock: Path) -> None:
        """Test that versions are correctly extracted."""
        packages = {pkg.name: pkg for pkg in parser.parse(sample_pipfile_lock)}

        assert packages["requests"].version == "2.31.0"
        assert packages["flask"].version == "3.0.0"
        assert packages["pytest"].version == "7.4.0"

    def test_parse_source_attribute(self, parser: PipfileLockParser, sample_pipfile_lock: Path) -> None:
        """Test that source attribute indicates default vs develop."""
        packages = {pkg.name: pkg for pkg in parser.parse(sample_pipfile_lock)}

        assert packages["requests"].source == "pipfile.default"
        assert packages["flask"].source == "pipfile.default"
        assert packages["pytest"].source == "pipfile.develop"

    def test_parse_file_path(self, parser: PipfileLockParser, sample_pipfile_lock: Path) -> None:
        """Test that file_path is set correctly."""
        packages = list(parser.parse(sample_pipfile_lock))

        for pkg in packages:
            assert pkg.file_path == str(sample_pipfile_lock)

    def test_parse_empty_lock_file(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test parsing an empty Pipfile.lock."""
        lock_content = {"_meta": {"hash": {"sha256": "empty"}, "pipfile-spec": 6}}
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parser.parse(file_path))
        assert len(packages) == 0

    def test_parse_only_default_deps(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test parsing with only default dependencies."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {
                "django": {"version": "==4.2.0"},
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parser.parse(file_path))
        assert len(packages) == 1
        assert packages[0].name == "django"
        assert packages[0].source == "pipfile.default"

    def test_parse_version_with_operator(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test parsing version strings with various operators."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {
                "pkg1": {"version": "==1.0.0"},
                "pkg2": {"version": ">=2.0"},
                "pkg3": {"version": "~=3.5"},
                "pkg4": {"version": "!=4.0"},
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = {pkg.name: pkg for pkg in parser.parse(file_path)}

        assert packages["pkg1"].version == "1.0.0"
        assert packages["pkg2"].version == "2.0"
        assert packages["pkg3"].version == "3.5"
        assert packages["pkg4"].version == "4.0"

    def test_parse_invalid_json(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test that invalid JSON raises ValueError."""
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text("not valid json {{{")

        with pytest.raises(ValueError, match="Failed to parse Pipfile.lock"):
            list(parser.parse(file_path))

    def test_parse_missing_file(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test that missing file raises ValueError."""
        missing_file = tmp_path / "nonexistent.lock"

        with pytest.raises(ValueError, match="Failed to parse Pipfile.lock"):
            list(parser.parse(missing_file))

    def test_parse_malformed_entry(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test that malformed entries are skipped."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {
                "valid-package": {"version": "==1.0.0"},
                "invalid-entry": "just a string, not a dict",
                "another-valid": {"version": "==2.0.0"},
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parser.parse(file_path))
        names = {pkg.name for pkg in packages}

        assert "valid-package" in names
        assert "another-valid" in names
        assert "invalid-entry" not in names

    def test_parse_version_dict_format(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test parsing version in dict format (edge case)."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {
                "pkg": {"version": {"version": "==1.0.0"}},
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parser.parse(file_path))
        # Should handle this gracefully
        assert len(packages) <= 1

    def test_parse_packages_are_package_instances(self, parser: PipfileLockParser, sample_pipfile_lock: Path) -> None:
        """Test that all yielded objects are Package instances."""
        packages = list(parser.parse(sample_pipfile_lock))

        for pkg in packages:
            assert isinstance(pkg, Package)
            assert isinstance(pkg.name, str)
            assert pkg.source.startswith("pipfile.")

    def test_package_full_name(self, parser: PipfileLockParser, sample_pipfile_lock: Path) -> None:
        """Test Package.full_name property."""
        packages = list(parser.parse(sample_pipfile_lock))
        requests_pkg = next(p for p in packages if p.name == "requests")

        assert requests_pkg.full_name == "requests==2.31.0"


class TestParsePipfileLockFunction:
    """Test cases for the parse_pipfile_lock convenience function."""

    def test_convenience_function(self, tmp_path: Path) -> None:
        """Test parse_pipfile_lock function returns packages."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {"click": {"version": "==8.1.0"}},
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parse_pipfile_lock(file_path))

        assert len(packages) == 1
        assert packages[0].name == "click"
        assert packages[0].version == "8.1.0"


class TestPipfileLockEdgeCases:
    """Edge case tests for Pipfile.lock parsing."""

    def test_case_sensitive_package_names(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test that package names preserve case."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {
                "Django": {"version": "==4.2.0"},
                "requests": {"version": "==2.31.0"},
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parser.parse(file_path))
        names = {pkg.name for pkg in packages}

        assert "Django" in names
        assert "requests" in names

    def test_empty_version_field(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test handling of empty version field."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {
                "no-version-pkg": {"version": ""},
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parser.parse(file_path))
        assert len(packages) == 1
        assert packages[0].version is None

    def test_package_with_editable(self, parser: PipfileLockParser, tmp_path: Path) -> None:
        """Test handling of editable packages."""
        lock_content = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
            "default": {
                "local-package": {
                    "version": "==0.1.0",
                    "editable": True,
                    "path": ".",
                },
            },
        }
        file_path = tmp_path / "Pipfile.lock"
        file_path.write_text(json.dumps(lock_content))

        packages = list(parser.parse(file_path))
        assert len(packages) == 1
        assert packages[0].name == "local-package"
        assert packages[0].version == "0.1.0"
