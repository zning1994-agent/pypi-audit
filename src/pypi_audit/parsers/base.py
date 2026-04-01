"""Base parser interface for dependency files."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from ..models import Package


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""

    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """Return tuple of supported file extensions."""
        pass

    @property
    @abstractmethod
    def file_type(self) -> str:
        """Return the type identifier for this parser."""
        pass

    @abstractmethod
    def parse(self, file_path: Path) -> Iterator[Package]:
        """
        Parse a dependency file and yield Package objects.

        Args:
            file_path: Path to the dependency file

        Yields:
            Package objects representing each dependency
        """
        pass

    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file."""
        return file_path.suffix in self.supported_extensions
