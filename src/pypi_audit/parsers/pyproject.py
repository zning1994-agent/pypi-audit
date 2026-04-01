"""Parser for pyproject.toml files."""

from __future__ import annotations

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


class PyprojectParser(BaseParser):
    """Parser for pyproject.toml dependency files."""

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".toml",)

    def can_parse(self, file_path: Path) -> bool:
        """Check if the file is a pyproject.toml file."""
        return file_path.name == "pyproject.toml"

    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """
        Parse a pyproject.toml file for dependencies.

        Args:
            file_path: Path to pyproject.toml

        Yields:
            Dependency objects from [project.dependencies] and [project.optional-dependencies]
        """
        if not file_path.exists():
            return

        if tomllib is None:
            # Cannot parse TOML without tomli on Python < 3.11
            return

        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            return

        # Parse main dependencies
        dependencies = data.get("project", {}).get("dependencies", [])
        yield from self._parse_dependency_list(dependencies, file_path)

        # Parse optional dependencies
        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        for extra_name, deps in optional_deps.items():
            yield from self._parse_dependency_list(deps, file_path, extra=extra_name)

        # Parse PEP 621 build dependencies
        build_deps = data.get("project", {}).get("optional-dependencies", {}).get(
            "test", []
        )
        yield from self._parse_dependency_list(build_deps, file_path, extra="build")

        # Also check legacy poetry-style dependencies
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        yield from self._parse_poetry_dependencies(poetry_deps, file_path)

    def _parse_dependency_list(
        self, dependencies: list[str], source_file: Path, extra: str | None = None
    ) -> Iterator[Dependency]:
        """Parse a list of dependency strings."""
        for dep in dependencies:
            dep_obj = self._parse_dependency_string(dep, source_file, extra)
            if dep_obj:
                yield dep_obj

    def _parse_dependency_string(
        self, dep: str, source_file: Path, extra: str | None = None
    ) -> Dependency | None:
        """Parse a single dependency string like 'requests>=2.0'."""
        import re

        # Match package name and version specifier
        pattern = re.compile(
            r'^([a-zA-Z0-9][-a-zA-Z0-9._]*)'  # Package name
            r'((?:[=<>!~]+|>=?|<=?)(?:[\d.]+(?:[a-zA-Z0-9._-]+)?)?)?'  # Version
            r'(?:\[.*?\])?'  # Extras (strip them)
        )
        match = pattern.match(dep.strip())
        if match:
            name = match.group(1)
            version = match.group(2) or "*"
            return Dependency(
                name=name,
                version=version,
                source_file=str(source_file),
                line_number=None,
            )
        return None

    def _parse_poetry_dependencies(
        self, dependencies: dict[str, Any], source_file: Path
    ) -> Iterator[Dependency]:
        """Parse Poetry-style dependencies."""
        for name, spec in dependencies.items():
            # Skip Python itself
            if name == "python":
                continue

            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = spec.get("version", "*")
            else:
                version = "*"

            yield Dependency(
                name=name,
                version=version,
                source_file=str(source_file),
                line_number=None,
            )
