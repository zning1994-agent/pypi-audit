"""Parser for Pipfile.lock files."""

import sys
from pathlib import Path
from typing import Any, Iterator

from .base import BaseParser, Dependency


class PipfileParser(BaseParser):
    """Parser for Pipfile.lock dependency files."""
    
    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".lock", ".json")
    
    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """Parse a Pipfile.lock file."""
        content = file_path.read_text(encoding="utf-8")
        for dep in self.parse_string(content):
            dep.source_file = file_path
            yield dep
    
    def parse_string(self, content: str) -> Iterator[Dependency]:
        """Parse dependencies from Pipfile.lock content."""
        import json
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return
        
        # Parse default dependencies
        default_deps = data.get("default", {})
        yield from self._parse_pipfile_deps(default_deps)
        
        # Parse develop dependencies
        develop_deps = data.get("develop", {})
        yield from self._parse_pipfile_deps(develop_deps)
    
    def _parse_pipfile_deps(self, deps: dict[str, Any]) -> Iterator[Dependency]:
        """Parse Pipfile dependency dictionary."""
        for name, spec in deps.items():
            if not isinstance(spec, dict):
                continue
            
            # Get version from the spec
            version = spec.get("version", "")
            
            # Normalize version (remove leading 'v' and extract version number)
            if isinstance(version, str):
                if version.startswith("=="):
                    version = version[2:]
                elif version.startswith("v"):
                    version = version[1:]
                else:
                    # Try to extract version from markers like {"version": "*", "markers": "..."}
                    version = None
            
            # Get hash for verification
            hashes = spec.get("hashes", [])
            if hashes and not version:
                # If no version but has hashes, mark as pinned
                version = "pinned"
            
            # Get optional/extras
            extras = spec.get("extras", [])
            
            yield Dependency(
                name=name,
                version=self._normalize_version(version) if version else None,
                extras=extras if extras else None,
            )
