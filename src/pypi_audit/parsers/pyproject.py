"""Parser for pyproject.toml files."""

import sys
from pathlib import Path
from typing import Any, Iterator

from .base import BaseParser, Dependency


class PyprojectParser(BaseParser):
    """Parser for pyproject.toml dependency files."""
    
    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".toml",)
    
    def parse(self, file_path: Path) -> Iterator[Dependency]:
        """Parse a pyproject.toml file."""
        content = file_path.read_text(encoding="utf-8")
        for dep in self.parse_string(content):
            dep.source_file = file_path
            yield dep
    
    def parse_string(self, content: str) -> Iterator[Dependency]:
        """Parse dependencies from pyproject.toml content."""
        # Import tomllib/tomli based on Python version
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib
        
        try:
            data = tomllib.loads(content)
        except Exception:
            return
        
        # Parse project dependencies
        project_deps = data.get("project", {}).get("dependencies", [])
        yield from self._parse_dependencies_list(project_deps)
        
        # Parse project optional dependencies (extras)
        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        for extra_name, deps in optional_deps.items():
            for dep in self._parse_dependencies_list(deps):
                if dep.extras is None:
                    dep.extras = []
                dep.extras.append(extra_name)
                yield dep
        
        # Parse poetry-style dependencies (tool.poetry.dependencies)
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        yield from self._parse_poetry_dependencies(poetry_deps)
        
        # Parse poetry optional dependencies
        poetry_optional = data.get("tool", {}).get("poetry", {}).get("group", {})
        for group_name, group_data in poetry_optional.items():
            group_deps = group_data.get("dependencies", {})
            yield from self._parse_poetry_dependencies(group_deps)
    
    def _parse_dependencies_list(self, deps: list[str] | dict[str, Any]) -> Iterator[Dependency]:
        """Parse a list of dependency specifications."""
        for dep in deps:
            if isinstance(dep, str):
                yield from self._parse_string_dep(dep)
            elif isinstance(dep, dict):
                # Handle complex dependency specs like {version = "^1.0", extras = ["aio"]}
                for name, spec in dep.items():
                    dep_obj = self._parse_complex_spec(name, spec)
                    if dep_obj:
                        yield dep_obj
    
    def _parse_string_dep(self, dep_str: str) -> Iterator[Dependency]:
        """Parse a single dependency string."""
        dep_str = dep_str.strip()
        if not dep_str or dep_str.startswith("#"):
            return
        
        # Simple format: package or package==version
        if "[" in dep_str:
            # Has extras
            name, rest = dep_str.split("[", 1)
            extras_str, rest = rest.split("]", 1)
            extras = [e.strip() for e in extras_str.split(",")]
        else:
            name = dep_str.split("=")[0].split("<")[0].split(">")[0].split("!")[0].split(" ")[0]
            extras = None
            rest = ""
        
        # Extract version
        version = None
        for sep in ["==", ">=", "<=", ">", "<", "!=", "~=", "^=", "==="]:
            if sep in name:
                parts = name.split(sep)
                name = parts[0]
                version = self._normalize_version(sep + parts[1])
                break
        
        if version is None and rest:
            for sep in ["==", ">=", "<=", ">", "<", "!=", "~=", "^=", "==="]:
                if sep in rest:
                    version = self._normalize_version(rest.split(sep)[1].strip())
                    break
        
        yield Dependency(name=name.strip(), version=version, extras=extras)
    
    def _parse_complex_spec(self, name: str, spec: str | dict[str, Any]) -> Dependency | None:
        """Parse a complex dependency specification (dict format)."""
        if isinstance(spec, str):
            return next(self._parse_string_dep(f"{name}{spec}"), None)
        
        if isinstance(spec, dict):
            version = spec.get("version")
            if version:
                version = self._normalize_version(version)
            
            extras = spec.get("extras")
            if extras:
                extras = [extras] if isinstance(extras, str) else list(extras)
            
            return Dependency(name=name, version=version, extras=extras)
        
        return None
    
    def _parse_poetry_dependencies(self, deps: dict[str, Any]) -> Iterator[Dependency]:
        """Parse Poetry-style dependency dictionary."""
        for name, spec in deps.items():
            # Skip Python version constraints
            if name == "python":
                continue
            
            if isinstance(spec, str):
                version = self._normalize_version(spec) if spec else None
                yield Dependency(name=name, version=version)
            elif isinstance(spec, dict):
                version = spec.get("version")
                if version:
                    version = self._normalize_version(version)
                
                extras = spec.get("extras")
                if extras:
                    extras = [extras] if isinstance(extras, str) else list(extras)
                
                yield Dependency(name=name, version=version, extras=extras)
            else:
                yield Dependency(name=name)
