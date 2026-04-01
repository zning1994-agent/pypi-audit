"""
Base parser class for dependency files.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import Package


@dataclass
class ParseResult:
    """Result of parsing a dependency file."""
    
    file_path: str
    file_type: str
    packages: list["Package"] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parse_time: float = 0.0
    
    @property
    def has_errors(self) -> bool:
        """Check if there were parsing errors."""
        return len(self.errors) > 0
    
    @property
    def has_warnings(self) -> bool:
        """Check if there were warnings."""
        return len(self.warnings) > 0
    
    @property
    def package_count(self) -> int:
        """Number of packages parsed."""
        return len(self.packages)


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Parser name."""
        pass
    
    @property
    @abstractmethod
    def file_type(self) -> str:
        """Type of file this parser handles."""
        pass
    
    @abstractmethod
    def parse(self, file_path: str) -> ParseResult:
        """
        Parse a dependency file.
        
        Args:
            file_path: Path to the dependency file.
            
        Returns:
            ParseResult with parsed packages and any errors/warnings.
        """
        pass
    
    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to check.
            
        Returns:
            True if this parser can handle the file.
        """
        pass
