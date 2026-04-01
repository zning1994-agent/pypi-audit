"""Pipfile.lock parser using pipfile library."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterator

import tomli

from ..models import Package
from .base import BaseParser

if TYPE_CHECKING:
    from pipfile.requirements import Requirement


class PipfileLockParser(BaseParser):
    """Parser for Pipfile.lock files."""

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported file extensions."""
        return (".lock",)

    @property
    def file_type(self) -> str:
        """Return the type identifier for this parser."""
        return "Pipfile.lock"

    def parse(self, file_path: Path) -> Iterator[Package]:
        """
        Parse a Pipfile.lock file and yield Package objects.

        Args:
            file_path: Path to the Pipfile.lock file

        Yields:
            Package objects representing each locked dependency
        """
        try:
            with open(file_path, "rb") as f:
                lock_data = tomli.load(f)
        except (OSError, tomli.TOMLDecodeError) as e:
            raise ValueError(f"Failed to parse Pipfile.lock: {e}") from e

        # Pipfile.lock contains default, develop, and other sections
        # We focus on default (production) dependencies
        default_deps = lock_data.get("default", {})
        develop_deps = lock_data.get("develop", {})

        # Yield production dependencies first
        yield from self._parse_dependencies(default_deps, file_path, source="default")

        # Then yield development dependencies
        yield from self._parse_dependencies(develop_deps, file_path, source="develop")

    def _parse_dependencies(
        self, deps: dict, file_path: Path, source: str = "default"
    ) -> Iterator[Package]:
        """
        Parse dependencies from a section of Pipfile.lock.

        Args:
            deps: Dictionary of dependencies from Pipfile.lock
            file_path: Original file path for reference
            source: Source section (default/develop)

        Yields:
            Package objects for each dependency
        """
        for name, info in deps.items():
            try:
                package = self._parse_single_dependency(name, info, file_path, source)
                if package:
                    yield package
            except Exception:
                # Skip malformed entries but continue parsing
                continue

    def _parse_single_dependency(
        self, name: str, info: dict, file_path: Path, source: str
    ) -> Package | None:
        """
        Parse a single dependency entry from Pipfile.lock.

        Args:
            name: Package name
            info: Package info dictionary
            file_path: Original file path
            source: Source section

        Returns:
            Package object or None if invalid
        """
        if not isinstance(info, dict):
            return None

        # Extract version from Pipfile.lock format
        # Pipfile.lock stores: {"version": "==1.2.3", "hashes": [...], ...}
        version_info = info.get("version", "")

        # Handle various version formats
        version = self._extract_version(version_info)

        return Package(
            name=name,
            version=version,
            source=f"pipfile.{source}",
            file_path=str(file_path),
        )

    def _extract_version(self, version_info: str | dict) -> str | None:
        """
        Extract version string from Pipfile.lock version field.

        Args:
            version_info: Version field from Pipfile.lock

        Returns:
            Cleaned version string or None
        """
        if not version_info:
            return None

        # Handle dict format: {"version": "==1.2.3"}
        if isinstance(version_info, dict):
            version_info = version_info.get("version", "")

        # Version should be in format "==1.2.3" or similar
        version_str = str(version_info)

        # Strip operators and get clean version
        # Common formats: "==1.2.3", ">=1.0", "~=1.5"
        for op in ("==", ">=", "<=", "~=", "!=", "==="):
            if version_str.startswith(op):
                return version_str[len(op) :].strip()

        # If no operator found, return as-is
        return version_str if version_str else None


def parse_pipfile_lock(file_path: Path) -> Iterator[Package]:
    """
    Convenience function to parse a Pipfile.lock file.

    Args:
        file_path: Path to Pipfile.lock

    Returns:
        Iterator of Package objects
    """
    parser = PipfileLockParser()
    return parser.parse(file_path)
