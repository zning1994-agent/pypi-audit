"""Parser for pyproject.toml files.

Supports extracting dependencies from:
- project.dependencies
- project.optional-dependencies
- build-system.requires (PEP 508 build dependencies)
"""

import sys
from pathlib import Path
from typing import Optional

from ..models import Package
from .base import BaseParser

# Compatibility: tomllib (Python 3.11+) or tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment]


class PyprojectParser(BaseParser):
    """Parser for pyproject.toml files."""

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Get supported file extensions."""
        return (".toml",)

    @property
    def file_type(self) -> str:
        """Get the type identifier for this parser."""
        return "pyproject"

    def parse(self, file_path: str | Path) -> list[Package]:
        """
        Parse a pyproject.toml file and extract packages.

        Args:
            file_path: Path to the pyproject.toml file.

        Returns:
            List of Package objects.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the TOML format is invalid or no dependencies found.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if tomllib is None:
            raise ImportError(
                "tomli is required for Python < 3.11. "
                "Install it with: pip install tomli"
            )

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            raise ValueError(f"Failed to parse TOML: {e}") from e

        return self._extract_packages(data, str(path))

    def parse_content(self, content: str) -> list[Package]:
        """
        Parse pyproject.toml content from a string.

        Args:
            content: Raw TOML content.

        Returns:
            List of Package objects.

        Raises:
            ValueError: If the TOML format is invalid.
        """
        if tomllib is None:
            raise ImportError(
                "tomli is required for Python < 3.11. "
                "Install it with: pip install tomli"
            )

        try:
            data = tomllib.loads(content)
        except Exception as e:
            raise ValueError(f"Failed to parse TOML content: {e}") from e

        return self._extract_packages(data, "<string>")

    def _extract_packages(
        self, data: dict, source_file: str
    ) -> list[Package]:
        """
        Extract packages from parsed TOML data.

        Args:
            data: Parsed TOML data as dictionary.
            source_file: Source file path for Package.source_file.

        Returns:
            List of Package objects.
        """
        packages: list[Package] = []

        # Extract from [project] section
        project_deps = self._extract_project_dependencies(data)
        packages.extend(project_deps)

        # Extract from [project.optional-dependencies] section
        optional_deps = self._extract_optional_dependencies(data)
        packages.extend(optional_deps)

        # Extract from [build-system] section
        build_deps = self._extract_build_dependencies(data)
        packages.extend(build_deps)

        # Set source_file for all packages
        for pkg in packages:
            if pkg.source_file is None:
                pkg.source_file = source_file

        return packages

    def _extract_project_dependencies(self, data: dict) -> list[Package]:
        """Extract dependencies from [project] section."""
        packages: list[Package] = []
        project = data.get("project", {})

        # Main dependencies
        deps = project.get("dependencies", [])
        packages.extend(self._parse_dependency_list(deps, "project.dependencies"))

        # Optional dependencies (already flattened)
        optional_deps = project.get("optional-dependencies", {})
        for extra_name, extras_list in optional_deps.items():
            packages.extend(
                self._parse_dependency_list(extras_list, f"project.optional-dependencies.{extra_name}")
            )

        return packages

    def _extract_optional_dependencies(self, data: dict) -> list[Package]:
        """Extract optional dependencies from [project.optional-dependencies]."""
        # This is handled in _extract_project_dependencies
        return []

    def _extract_build_dependencies(self, data: dict) -> list[Package]:
        """Extract build dependencies from [build-system] section."""
        packages: list[Package] = []
        build_system = data.get("build-system", {})

        requires = build_system.get("requires", [])
        packages.extend(self._parse_dependency_list(requires, "build-system.requires"))

        return packages

    def _parse_dependency_list(
        self, deps: list[str], section: str
    ) -> list[Package]:
        """
        Parse a list of dependency specifications.

        Args:
            deps: List of PEP 508 dependency strings.
            section: Section name for debugging.

        Returns:
            List of Package objects.
        """
        packages: list[Package] = []

        for dep in deps:
            pkg = self._parse_single_dependency(dep, section)
            if pkg is not None:
                packages.append(pkg)

        return packages

    def _parse_single_dependency(
        self, dep_string: str, section: str
    ) -> Optional[Package]:
        """
        Parse a single PEP 508 dependency string.

        Examples:
            "requests>=2.28.0"
            "numpy>=1.19.0,<2.0"
            "pip[mypy]>=21.0"
            "django[argon2]>=4.0"

        Args:
            dep_string: PEP 508 dependency specification.
            section: Section name for debugging.

        Returns:
            Package object or None if parsing fails.
        """
        if not dep_string or not isinstance(dep_string, str):
            return None

        # Remove comments
        dep_string = dep_string.split("#")[0].strip()
        if not dep_string:
            return None

        # Find package name and version/specifier
        # PEP 508 format: package-name[extras](version_specifier)
        # Examples: "requests>=2.28", "numpy>=1.19,<2.0", "pip[mypy]>=21.0"

        # Split by first occurrence of version operator
        import re

        # Match package name with optional extras
        # Package name: alphanumeric, underscore, dash
        # Extras: comma-separated identifiers in brackets
        match = re.match(
            r"^\s*([a-zA-Z0-9][-a-zA-Z0-9._]*)"  # Package name
            r"(?:\[([^\]]+)\])?"  # Optional extras
            r"\s*(.*)$",  # Rest (version specifiers)
            dep_string,
            re.IGNORECASE,
        )

        if not match:
            return None

        name = match.group(1)
        extras_str = match.group(2)
        version_spec = match.group(3) if match.group(3) else None

        # Parse extras
        extras: list[str] = []
        if extras_str:
            extras = [e.strip() for e in extras_str.split(",") if e.strip()]

        # Extract version from version specifiers if present
        version: Optional[str] = None
        if version_spec:
            version = self._extract_version_from_spec(version_spec)

        return Package(
            name=name,
            version=version,
            extras=extras,
            source_file=section,
        )

    def _extract_version_from_spec(self, spec: str) -> Optional[str]:
        """
        Extract the first version from a version specifier string.

        Args:
            spec: Version specifier like ">=2.28" or ">=1.19,<2.0"

        Returns:
            Version string or None.
        """
        import re

        # Match common version specifiers: >=, ==, >, <, ~=
        version_patterns = [
            r">=\s*(\d+(?:\.\d+)*(?:\.\d+)?)",  # >= version
            r"==\s*(\d+(?:\.\d+)*(?:\.\d+)?)",  # == version
            r"~\s*=\s*(\d+(?:\.\d+)*(?:\.\d+)?)",  # ~= version
        ]

        for pattern in version_patterns:
            match = re.search(pattern, spec)
            if match:
                return match.group(1)

        return None
