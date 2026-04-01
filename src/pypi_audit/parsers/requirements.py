"""
Parser for requirements.txt files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .base import BaseParser, ParseResult
from ..models import Package


class RequirementsParser(BaseParser):
    """Parser for requirements.txt format files."""
    
    @property
    def name(self) -> str:
        return "requirements.txt"
    
    @property
    def file_type(self) -> str:
        return "requirements"
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a requirements.txt file."""
        path = Path(file_path)
        return path.name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt")
    
    def parse(self, file_path: str) -> ParseResult:
        """Parse requirements.txt file."""
        result = ParseResult(file_path=file_path, file_type=self.file_type)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            packages = self._parse_content(content, file_path)
            result.packages = packages
            
        except FileNotFoundError:
            result.errors.append(f"File not found: {file_path}")
        except PermissionError:
            result.errors.append(f"Permission denied: {file_path}")
        except Exception as e:
            result.errors.append(f"Error reading file: {e}")
        
        return result
    
    def _parse_content(self, content: str, file_path: str) -> list[Package]:
        """Parse requirements content string."""
        packages: list[Package] = []
        lines = content.strip().split("\n")
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            
            # Skip options lines
            if line.startswith("-"):
                continue
            
            package = self._parse_line(line)
            if package:
                package.file_path = file_path
                package.file_type = self.file_type
                packages.append(package)
        
        return packages
    
    def _parse_line(self, line: str) -> Package | None:
        """Parse a single requirement line."""
        # Match package==version or package>=version pattern
        patterns = [
            r"^([a-zA-Z0-9._-]+)==([a-zA-Z0-9._*+-]+)$",
            r"^([a-zA-Z0-9._-]+)>=([a-zA-Z0-9._*+-]+)$",
            r"^([a-zA-Z0-9._-]+)<=([a-zA-Z0-9._*+-]+)$",
            r"^([a-zA-Z0-9._-]+)!=([a-zA-Z0-9._*+-]+)$",
            r"^([a-zA-Z0-9._-]+)$",  # Package name only
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                groups = match.groups()
                name = groups[0]
                version = groups[1] if len(groups) > 1 else "*"
                return Package(name=name, version=version)
        
        return None
