"""Parser for requirements.txt files."""

import re
from pathlib import Path
from typing import Iterator

from .base import BaseParser, Dependency


class RequirementsParser(BaseParser):
    """Parser for requirements.txt dependency files."""
    
    # Pattern to match package specifications
    # Supports: package, package==version, package>=version, package[extra], etc.
    PACKAGE_PATTERN = re.compile(
        r"^(?P<name>[a-zA-Z0-9][-a-zA-Z0-9._]*)"
        r"(?:\[(?P<extras>[^\]]+)\])?"
        r"(?P<version_spec>[^;#\s]*)"
        r"(?:\s*#.*)?$"
    )
    
    # Pattern to match environment markers
    MARKER_PATTERN = re.compile(r";\s*(?P<marker>.+)$")
    
    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".txt",)
    
    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """Parse a requirements.txt file."""
        content = file_path.read_text(encoding="utf-8")
        for dep in self.parse_string(content):
            dep.source_file = file_path
            yield dep
    
    def parse_string(self, content: str) -> Iterator[Dependency]:
        """Parse requirements from string content."""
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            
            # Handle -r include directives
            if line.startswith("-r ") or line.startswith("--requirement="):
                continue
            
            # Handle -e editable installs
            if line.startswith("-e ") or line.startswith("--editable "):
                continue
            
            # Handle options like --index-url, -f, etc.
            if line.startswith("-"):
                continue
            
            # Parse the package line
            dep = self._parse_line(line)
            if dep:
                yield dep
    
    def _parse_line(self, line: str) -> Dependency | None:
        """Parse a single requirements line."""
        # Remove inline comments
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            return None
        
        # Extract marker if present
        marker = None
        marker_match = self.MARKER_PATTERN.search(line)
        if marker_match:
            marker = marker_match.group("marker").strip()
            line = self.MARKER_PATTERN.sub("", line).strip()
        
        # Parse package specification
        match = self.PACKAGE_PATTERN.match(line)
        if not match:
            return None
        
        name = match.group("name")
        extras = None
        if match.group("extras"):
            extras = [e.strip() for e in match.group("extras").split(",")]
        
        version_spec = match.group("version_spec") or None
        
        # Normalize version spec (remove leading 'v' if present)
        if version_spec:
            version_spec = self._normalize_version(version_spec)
        
        return Dependency(
            name=name,
            version=version_spec,
            extras=extras,
            marker=marker,
        )
