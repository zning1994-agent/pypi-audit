"""Base parser for dependency files."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from ..models import Dependency


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""

    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported file extensions."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """
        Parse a dependency file and yield Dependency objects.

        Args:
            file_path: Path to the dependency file

        Yields:
            Dependency objects found in the file
        """
        raise NotImplementedError

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.

        Args:
            file_path: Path to the file to check

        Returns:
            True if this parser can handle the file, False otherwise
        """
        raise NotImplementedError
