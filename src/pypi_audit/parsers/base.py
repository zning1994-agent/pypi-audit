"""Base class for dependency file parsers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class Dependency:
    """Represents a single dependency package."""
    
    name: str
    version: str | None = None
    extras: list[str] | None = None
    marker: str | None = None
    source_file: Path | None = None
    
    def __post_init__(self) -> None:
        """Normalize package name to lowercase."""
        self.name = self.name.lower().replace("_", "-")


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""
    
    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported file extensions."""
        pass
    
    @abstractmethod
    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """Parse a dependency file and yield Dependency objects."""
        pass
    
    @abstractmethod
    def parse_string(self, content: str) -> Iterator[Dependency]:
        """Parse dependency content from a string."""
        pass
    
    @staticmethod
    def _normalize_version(version: str) -> str:
        """Normalize version string by removing leading 'v'."""
        if version.startswith("v"):
            return version[1:]
        return version
