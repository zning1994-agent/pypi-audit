"""Parser for requirements.txt files."""

from pathlib import Path
from typing import Iterator
import re

from ..models import Dependency
from .base import BaseParser


class RequirementsParser(BaseParser):
    """Parser for requirements.txt dependency files."""

    # Pattern to match package==version or package>=version etc.
    PACKAGE_PATTERN = re.compile(
        r'^([a-zA-Z0-9][-a-zA-Z0-9._]*)'  # Package name
        r'((?:[=<>!~]+|>=?|<=?)(?:[\d.]+(?:[a-zA-Z0-9._-]+)?)?)'  # Version specifier
        r'(?:\s*#.*)?$'  # Optional comment
    )

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".txt",)

    def can_parse(self, file_path: Path) -> bool:
        """Check if the file is a requirements.txt file."""
        return file_path.name.startswith("requirements") and file_path.suffix == ".txt"

    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """
        Parse a requirements.txt file.

        Args:
            file_path: Path to requirements.txt

        Yields:
            Dependency objects
        """
        if not file_path.exists():
            return

        with open(file_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Handle -r include directives
                if line.startswith("-r ") or line.startswith("--requirement "):
                    continue

                # Handle -e editable installs
                if line.startswith("-e ") or line.startswith("--editable "):
                    continue

                dependency = self._parse_line(line, file_path, line_no)
                if dependency:
                    yield dependency

    def _parse_line(
        self, line: str, source_file: Path, line_no: int
    ) -> Dependency | None:
        """Parse a single line from requirements.txt."""
        match = self.PACKAGE_PATTERN.match(line)
        if match:
            name = match.group(1)
            version_spec = match.group(2)

            # Extract version from specifier (e.g., ">=1.0.0" -> "1.0.0")
            version = self._extract_version(version_spec)

            return Dependency(
                name=name,
                version=version,
                source_file=str(source_file),
                line_number=line_no,
            )
        return None

    def _extract_version(self, version_spec: str) -> str:
        """Extract version number from version specifier."""
        # Remove comparison operators
        version = version_spec.lstrip("><=!~")
        # Handle trailing comma for multiple constraints
        version = version.rstrip(",")
        return version or "*"
