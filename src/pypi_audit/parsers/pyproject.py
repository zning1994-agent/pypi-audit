"""
Parser for pyproject.toml files.
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


class PyprojectParser(BaseParser):
    """Parser for pyproject.toml dependency specifications."""
    
    @property
    def name(self) -> str:
        return "pyproject.toml"
    
    @property
    def file_type(self) -> str:
        return "pyproject"
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a pyproject.toml file."""
        return Path(file_path).name == "pyproject.toml"
    
    def parse(self, file_path: str) -> ParseResult:
        """Parse pyproject.toml file."""
        result = ParseResult(file_path=file_path, file_type=self.file_type)
        
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            
            packages: list[Package] = []
            
            # Parse project.dependencies
            if "project" in data:
                deps = data["project"].get("dependencies", [])
                packages.extend(self._parse_dependency_list(deps))
                
                # Parse optional-dependencies
                opt_deps = data["project"].get("optional-dependencies", {})
                for group_name, group_deps in opt_deps.items():
                    packages.extend(
                        self._parse_dependency_list(group_deps, group=group_name)
                    )
            
            # Parse poetry dependencies (legacy)
            if "tool" in data and "poetry" in data["tool"]:
                poetry_deps = data["tool"]["poetry"].get("dependencies", {})
                packages.extend(self._parse_dict_dependencies(poetry_deps))
                
                dev_deps = data["tool"]["poetry"].get("dev-dependencies", {})
                packages.extend(
                    self._parse_dict_dependencies(dev_deps, group="dev")
                )
            
            result.packages = packages
            
        except FileNotFoundError:
            result.errors.append(f"File not found: {file_path}")
        except PermissionError:
            result.errors.append(f"Permission denied: {file_path}")
        except Exception as e:
            result.errors.append(f"Error parsing pyproject.toml: {e}")
        
        return result
    
    def _parse_dependency_list(
        self, 
        deps: list[str], 
        group: str | None = None
    ) -> list[Package]:
        """Parse list of dependency strings."""
        packages: list[Package] = []
        
        for dep in deps:
            pkg = self._parse_requirement_string(dep)
            if pkg:
                pkg.file_type = self.file_type
                if group:
                    pkg.file_path = f"pyproject.toml:{group}"
                else:
                    pkg.file_path = "pyproject.toml"
                packages.append(pkg)
        
        return packages
    
    def _parse_dict_dependencies(
        self, 
        deps: dict[str, Any],
        group: str | None = None
    ) -> list[Package]:
        """Parse dict-style dependency specifications."""
        packages: list[Package] = []
        
        for name, spec in deps.items():
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = spec.get("version", "*")
            else:
                version = "*"
            
            pkg = Package(name=name, version=version)
            pkg.file_type = self.file_type
            if group:
                pkg.file_path = f"pyproject.toml:poetry:{group}"
            else:
                pkg.file_path = "pyproject.toml:poetry"
            
            packages.append(pkg)
        
        return packages
    
    def _parse_requirement_string(self, requirement: str) -> Package | None:
        """Parse a single requirement string."""
        import re
        
        # Simple version specifier parsing
        patterns = [
            r"^([a-zA-Z0-9._-]+)\s*([<>=!~]+)\s*([a-zA-Z0-9._*+-]+)",
            r"^([a-zA-Z0-9._-]+)\s*\[.*?\]\s*([<>=!~]+)?.*",
            r"^([a-zA-Z0-9._-]+)",
        ]
        
        for pattern in patterns:
            match = re.match(pattern, requirement)
            if match:
                name = match.group(1)
                version = match.group(3) if match.lastindex >= 3 else "*"
                return Package(name=name, version=version)
        
        return None
