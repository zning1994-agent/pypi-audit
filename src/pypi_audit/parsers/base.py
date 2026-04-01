"""Base parser for dependency files."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..models import Package


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""

    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """Get supported file extensions."""
        ...

    @property
    @abstractmethod
    def file_type(self) -> str:
        """Get the type identifier for this parser."""
        ...

    @abstractmethod
    def parse(self, file_path: str | Path) -> list[Package]:
        """
        Parse a dependency file and extract packages.

        Args:
            file_path: Path to the dependency file.

        Returns:
            List of Package objects.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file format is invalid.
        """
        ...

    @abstractmethod
    def parse_content(self, content: str) -> list[Package]:
        """
        Parse dependency content from a string.

        Args:
            content: Raw content of the dependency file.

        Returns:
            List of Package objects.

        Raises:
            ValueError: If the content format is invalid.
        """
        ...

    def can_parse(self, file_path: str | Path) -> bool:
        """
        Check if this parser can handle the given file.

        Args:
            file_path: Path to check.

        Returns:
            True if the file extension is supported.
        """
        path = Path(file_path)
        return path.suffix in self.supported_extensions
