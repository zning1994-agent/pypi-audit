"""Pyproject.toml parser."""

import sys
from typing import Any

from .base import BaseParser
from ..models import Dependency

# Handle Python version for tomllib
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class PyprojectParser(BaseParser):
    """Parser for pyproject.toml files."""
    
    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse pyproject.toml file.
        
        Args:
            file_path: Path to pyproject.toml
            
        Returns:
            List of Dependency objects
        """
        content = self._read_file(file_path)
        dependencies: list[Dependency] = []
        
        try:
            data = tomllib.loads(content)
        except Exception:
            return []
        
        # Parse project.dependencies
        project_deps = data.get("project", {}).get("dependencies", [])
        if isinstance(project_deps, list):
            for dep_str in project_deps:
                dep = self._parse_dependency_string(dep_str, file_path)
                if dep:
                    dependencies.append(dep)
        elif isinstance(project_deps, dict):
            # PEP 639 format: {package: version}
            for name, version in project_deps.items():
                dependencies.append(
                    self._create_dependency(name, version, file_path)
                )
        
        # Parse project.optional-dependencies (extras)
        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        for extra_name, extra_list in optional_deps.items():
            if isinstance(extra_list, list):
                for dep_str in extra_list:
                    dep = self._parse_dependency_string(dep_str, file_path)
                    if dep:
                        dependencies.append(dep)
        
        # Parse tool.poetry.dependencies (Poetry format)
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, version_spec in poetry_deps.items():
            if name == "python":
                continue
            version = self._parse_poetry_version(version_spec)
            if version:
                dependencies.append(self._create_dependency(name, version, file_path))
        
        return dependencies
    
    def _parse_dependency_string(self, dep_str: str, source_file: str) -> Dependency | None:
        """Parse a dependency string like 'requests>=2.28.0'."""
        import re
        
        # Simple pattern for common formats
        pattern = re.compile(
            r'^([a-zA-Z0-9][-a-zA-Z0-9._]*)'  # Package name
            r'(?:\[([^\]]+)\])?'               # Optional extras
            r'(?:(==|>=|<=|~=|!=|>|<)(.+))?$'  # Version specifier
        )
        
        match = pattern.match(dep_str.strip())
        if match:
            name = match.group(1)
            version = match.group(4) or "*"
            return self._create_dependency(name, version, source_file)
        
        return None
    
    def _parse_poetry_version(self, version_spec: Any) -> str:
        """Parse Poetry version specification."""
        if isinstance(version_spec, str):
            return version_spec
        elif isinstance(version_spec, dict):
            # Poetry uses {version = "^1.0.0", ...} format
            if "version" in version_spec:
                return str(version_spec["version"])
            # Handle python version constraint
            if "python" in version_spec:
                return "*"
        elif isinstance(version_spec, list):
            return " ".join(str(v) for v in version_spec)
        return "*"
