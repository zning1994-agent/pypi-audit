"""
Parser for Pipfile.lock files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from .base import BaseParser, ParseResult
from ..models import Package


class PipfileParser(BaseParser):
    """Parser for Pipfile.lock files."""
    
    @property
    def name(self) -> str:
        return "Pipfile.lock"
    
    @property
    def file_type(self) -> str:
        return "pipfile"
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Pipfile.lock file."""
        return Path(file_path).name == "Pipfile.lock"
    
    def parse(self, file_path: str) -> ParseResult:
        """Parse Pipfile.lock file."""
        result = ParseResult(file_path=file_path, file_type=self.file_type)
        
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            
            packages: list[Package] = []
            
            # Parse default dependencies
            if "default" in data:
                packages.extend(self._parse_lock_section(data["default"]))
            
            # Parse develop dependencies
            if "develop" in data:
                packages.extend(self._parse_lock_section(data["develop"]))
            
            result.packages = packages
            
        except FileNotFoundError:
            result.errors.append(f"File not found: {file_path}")
        except PermissionError:
            result.errors.append(f"Permission denied: {file_path}")
        except Exception as e:
            result.errors.append(f"Error parsing Pipfile.lock: {e}")
        
        return result
    
    def _parse_lock_section(self, section: dict[str, Any]) -> list[Package]:
        """Parse a lock file section (default or develop)."""
        packages: list[Package] = []
        
        for name, info in section.items():
            if isinstance(info, dict):
                version = info.get("version", "*")
                if version.startswith("=="):
                    version = version[2:]
                
                pkg = Package(name=name, version=version)
                pkg.file_type = self.file_type
                pkg.file_path = "Pipfile.lock"
                packages.append(pkg)
        
        return packages
