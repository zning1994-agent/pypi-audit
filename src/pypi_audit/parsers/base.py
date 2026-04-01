"""Base parser for dependency files."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class Dependency:
    """Represents a single dependency package."""

    name: str
    version: str | None = None
    extras: list[str] = field(default_factory=list)
    markers: str | None = None
    source_file: str | None = None

    def __str__(self) -> str:
        if self.version:
            return f"{self.name}=={self.version}"
        return self.name


@dataclass
class ParseResult:
    """Result of parsing a dependency file."""

    file_path: str
    dependencies: list[Dependency] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_content: str = ""

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def is_empty(self) -> bool:
        return len(self.dependencies) == 0


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""

    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported file extensions."""
        pass

    @abstractmethod
    def parse(self, file_path: str, content: str | None = None) -> ParseResult:
        """
        Parse a dependency file.

        Args:
            file_path: Path to the dependency file
            content: Optional file content (if None, read from file_path)

        Returns:
            ParseResult containing extracted dependencies
        """
        pass

    def _read_file(self, file_path: str) -> str:
        """Read file content from disk."""
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

    def parse_iter(self, file_path: str, content: str | None = None) -> Iterator[Dependency]:
        """Iterate over dependencies one by one."""
        result = self.parse(file_path, content)
        yield from result.dependencies
