"""Requirements.txt parser."""

import re
from typing import Optional

from .base import BaseParser
from ..models import Dependency


class RequirementsParser(BaseParser):
    """Parser for requirements.txt files."""
    
    # Regex patterns for requirements.txt formats
    PATTERN_STANDARD = re.compile(
        r'^([a-zA-Z0-9][-a-zA-Z0-9._]*)'  # Package name
        r'(?:\[([^\]]+)\])?'               # Optional extras
        r'(?:(==|>=|<=|~=|!=|>|<)([^;,\s]+))?'  # Version specifier
    )
    
    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse requirements.txt file.
        
        Args:
            file_path: Path to requirements.txt
            
        Returns:
            List of Dependency objects
        """
        content = self._read_file(file_path)
        dependencies: list[Dependency] = []
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            
            # Skip options like -r, -e, --index-url, etc.
            if line.startswith("-"):
                continue
            
            # Parse the requirement
            dep = self._parse_line(line)
            if dep:
                dependencies.append(dep)
        
        return dependencies
    
    def _parse_line(self, line: str) -> Optional[Dependency]:
        """Parse a single requirement line."""
        # Handle comments after requirement
        if "#" in line:
            line = line.split("#")[0].strip()
        
        match = self.PATTERN_STANDARD.match(line)
        if match:
            name = match.group(1)
            version_op = match.group(3)
            version = match.group(4) or "*"
            
            return self._create_dependency(name, version)
        
        # Try to parse as simple package==version format
        if "==" in line:
            parts = line.split("==")
            if len(parts) == 2:
                return self._create_dependency(parts[0].strip(), parts[1].strip())
        
        return None
