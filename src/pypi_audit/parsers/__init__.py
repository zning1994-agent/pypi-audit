"""Dependency file parsers."""

from .base import BaseParser
from .requirements import RequirementsParser
from .pyproject import PyprojectParser
from .pipfile import PipfileParser


def get_parser(file_path: str) -> type[BaseParser] | None:
    """
    Get the appropriate parser for a dependency file.
    
    Args:
        file_path: Path to the dependency file
        
    Returns:
        Parser class or None if unsupported
    """
    path_lower = file_path.lower()
    
    if path_lower.endswith("requirements.txt"):
        return RequirementsParser
    elif path_lower.endswith("pyproject.toml"):
        return PyprojectParser
    elif path_lower.endswith("pipfile.lock"):
        return PipfileParser
    
    return None


__all__ = [
    "BaseParser",
    "RequirementsParser",
    "PyprojectParser",
    "PipfileParser",
    "get_parser",
]
