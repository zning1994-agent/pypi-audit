"""Pipfile.lock parser."""

import sys
from typing import Any

from .base import BaseParser
from ..models import Dependency

# Handle Python version for tomllib
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class PipfileParser(BaseParser):
    """Parser for Pipfile.lock files."""
    
    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse Pipfile.lock file.
        
        Args:
            file_path: Path to Pipfile.lock
            
        Returns:
            List of Dependency objects
        """
        content = self._read_file(file_path)
        dependencies: list[Dependency] = []
        
        try:
            data = tomllib.loads(content)
        except Exception:
            return []
        
        # Get the default dependencies section
        default_deps = data.get("default", {})
        
        for name, dep_data in default_deps.items():
            if not isinstance(dep_data, dict):
                continue
            
            version = self._extract_version(dep_data)
            if version:
                dependencies.append(
                    self._create_dependency(name, version, file_path)
                )
        
        return dependencies
    
    def _extract_version(self, dep_data: dict[str, Any]) -> str:
        """Extract version from Pipfile.lock dependency data."""
        # Check for version key
        if "version" in dep_data:
            version = dep_data["version"]
            # Remove leading '==' or other operators
            if isinstance(version, str):
                version = version.lstrip("=<>~!")
                return version
        
        # Check for hashes (sometimes version is implicit)
        if "version" not in dep_data and "hashes" in dep_data:
            return "*"
        
        return "*"
