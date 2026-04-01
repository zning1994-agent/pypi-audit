"""pyproject.toml parser stub."""

from pypi_audit.parsers.base import BaseParser, ParseResult


class PyprojectParser(BaseParser):
    """Parser for pyproject.toml dependency sections."""

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".toml",)

    def parse(self, file_path: str, content: str | None = None) -> ParseResult:
        """Parse pyproject.toml file."""
        raise NotImplementedError("pyproject.toml parsing not yet implemented")
