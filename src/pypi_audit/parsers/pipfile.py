"""Parser for Pipfile.lock files."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterator

from ..models import Dependency
from .base import BaseParser

# Try to import tomli for Python < 3.11, fall back to tomllib
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore


class PipfileParser(BaseParser):
    """Parser for Pipfile.lock dependency files."""

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".lock",)

    def can_parse(self, file_path: Path) -> bool:
        """Check if the file is a Pipfile.lock file."""
        return file_path.name == "Pipfile.lock"

    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """
        Parse a Pipfile.lock file for dependencies.

        Args:
            file_path: Path to Pipfile.lock

        Yields:
            Dependency objects from the lock file
        """
        if not file_path.exists():
            return

        try:
            data = self._load_lock_file(file_path)
        except Exception:
            return

        if not data:
            return

        # Parse default dependencies
        default_deps = data.get("default", {})
        yield from self._parse_dep_dict(default_deps, file_path)

        # Parse develop dependencies
        develop_deps = data.get("develop", {})
        yield from self._parse_dep_dict(develop_deps, file_path)

    def _load_lock_file(self, file_path: Path) -> dict[str, Any]:
        """Load Pipfile.lock content."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Pipfile.lock can also be TOML format in some cases
        # But typically it's JSON
        return data

    def _parse_dep_dict(
        self, dependencies: dict[str, Any], source_file: Path
    ) -> Iterator[Dependency]:
        """Parse a dictionary of dependencies from Pipfile.lock."""
        for name, spec in dependencies.items():
            if not isinstance(spec, dict):
                continue

            # Get version from the lock file spec
            version = spec.get("version", "*")

            # Handle different version formats
            if isinstance(version, str):
                # Remove prefixes like "==", ">=", etc.
                version = version.lstrip("=<>!~")

            yield Dependency(
                name=name,
                version=version or "*",
                source_file=str(source_file),
                line_number=None,
            )
