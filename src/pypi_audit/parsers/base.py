"""Base parser class for dependency files."""

from abc import ABC, abstractmethod
from pathlib import Path

from ..models import Dependency


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""
    
    @abstractmethod
    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse a dependency file and return list of dependencies.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            List of Dependency objects
        """
        pass
    
    def _read_file(self, file_path: str) -> str:
        """Read file content safely."""
        path = Path(file_path)
        return path.read_text(encoding="utf-8")
    
    def _create_dependency(
        self,
        name: str,
        version: str,
        source_file: str | None = None,
    ) -> Dependency:
        """Create a Dependency object with normalization."""
        return Dependency(
            name=name.strip().lower(),
            version=version.strip(),
            source_file=source_file,
        )
