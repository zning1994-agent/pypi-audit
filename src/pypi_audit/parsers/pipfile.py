"""Pipfile.lock parser stub."""

from pypi_audit.parsers.base import BaseParser, ParseResult


class PipfileParser(BaseParser):
    """Parser for Pipfile.lock files."""

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".lock",)

    def parse(self, file_path: str, content: str | None = None) -> ParseResult:
        """Parse Pipfile.lock file."""
        raise NotImplementedError("Pipfile.lock parsing not yet implemented")
