"""Requirements.txt file parser."""

import re
from typing import Iterator

from pypi_audit.parsers.base import BaseParser, Dependency, ParseResult


class RequirementsParser(BaseParser):
    """Parser for requirements.txt format files.

    Supports standard requirements.txt syntax including:
    - Basic: package==1.0.0
    - Comparison: package>=1.0.0
    - Extras: package[extra1,extra2]>=1.0.0
    - Git: git+https://github.com/user/repo.git@tag
    - URL: package@http://example.com/package.tar.gz
    - Comments: # comment
    - Options: --index-url, -r, etc.
    - Environment markers: package; python_version >= "3.8"
    """

    # Regex patterns for parsing requirements.txt
    # Matches: package==1.0.0, package>=1.0.0,<2.0.0, package[extras]>=1.0.0
    PACKAGE_PATTERN = re.compile(
        r"""
        ^                   # Start of line
       \s*                  # Leading whitespace (optional)
        (?:
            # Options lines (--index-url, -r, etc.) - skip
            --?\w+
            |
            # Package lines
            (?P<package>
                [a-zA-Z0-9][-a-zA-Z0-9._]*
            )
            (?P<extras>\[.*?\])?          # Optional extras like [dev,test]
            \s*
            (?:
                (?P<op>[=<>!~]+)\s*       # Version operator
                (?P<version>[^;#\s]+)     # Version string
            )?
        )
        \s*
        (?:
            ;\s*                          # Environment marker separator
            (?P<markers>.+?)              # Environment markers
        )?
        \s*
        (?:#.*)?                          # Optional comment
        $                                 # End of line
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    # Pattern for git+https:// style dependencies
    GIT_PATTERN = re.compile(
        r"""
        ^\s*
        (?P<package>[a-zA-Z0-9][-a-zA-Z0-9._]*)?
        \s*@\s*
        git\+https?://
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    # Pattern for URL-based dependencies (package@url)
    URL_PATTERN = re.compile(
        r"""
        ^\s*
        (?P<package>[a-zA-Z0-9][-a-zA-Z0-9._]*)
        \s*@\s*
        https?://
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Supported file extensions."""
        return (".txt",)

    def parse(self, file_path: str, content: str | None = None) -> ParseResult:
        """Parse a requirements.txt file.

        Args:
            file_path: Path to the requirements.txt file
            content: Optional file content (if None, read from file_path)

        Returns:
            ParseResult containing extracted dependencies
        """
        if content is None:
            try:
                content = self._read_file(file_path)
            except FileNotFoundError:
                return ParseResult(
                    file_path=file_path,
                    errors=[f"File not found: {file_path}"],
                )
            except Exception as e:
                return ParseResult(
                    file_path=file_path,
                    errors=[f"Error reading file: {e}"],
                )

        result = ParseResult(file_path=file_path, raw_content=content)
        dependencies = list(self._parse_lines(content, file_path))
        result.dependencies = dependencies

        return result

    def _parse_lines(self, content: str, file_path: str) -> Iterator[Dependency]:
        """Parse each line of requirements content.

        Args:
            content: Raw file content
            file_path: Source file path (for reference in Dependency)

        Yields:
            Dependency objects found in the file
        """
        seen: set[str] = set()  # Track seen packages to avoid duplicates

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Skip options (--index-url, -r, -e, --extra-index-url, etc.)
            if line.startswith("-"):
                continue

            # Try to parse as a standard requirement
            match = self.PACKAGE_PATTERN.match(line)
            if match and match.group("package"):
                package_name = match.group("package").lower()
                version = match.group("version")
                extras_str = match.group("extras")
                markers = match.group("markers")

                # Parse extras
                extras: list[str] = []
                if extras_str:
                    # Extract extras from brackets: [dev,test] -> ['dev', 'test']
                    extras_content = extras_str.strip("[]")
                    if extras_content:
                        extras = [e.strip() for e in extras_content.split(",") if e.strip()]

                # Normalize version operator
                op = match.group("op")
                if version and op:
                    version = f"{op}{version}"

                # Avoid duplicates
                if package_name not in seen:
                    seen.add(package_name)
                    yield Dependency(
                        name=package_name,
                        version=version,
                        extras=extras,
                        markers=markers,
                        source_file=file_path,
                    )
                continue

            # Handle git+https:// style dependencies
            git_match = self.GIT_PATTERN.match(line)
            if git_match:
                package_name = git_match.group("package")
                if package_name:
                    package_name = package_name.lower()
                    if package_name not in seen:
                        seen.add(package_name)
                        yield Dependency(
                            name=package_name,
                            version=None,
                            source_file=file_path,
                        )
                continue

            # Handle URL-based dependencies (package@url)
            url_match = self.URL_PATTERN.match(line)
            if url_match:
                package_name = url_match.group("package").lower()
                if package_name not in seen:
                    seen.add(package_name)
                    yield Dependency(
                        name=package_name,
                        version=None,
                        source_file=file_path,
                    )
                continue

            # Handle editable installs: -e git+https://... or -e .
            if line.startswith("-e ") or line.startswith("--editable "):
                continue

    def parse_iter(self, file_path: str, content: str | None = None) -> Iterator[Dependency]:
        """Parse and yield dependencies one by one.

        Args:
            file_path: Path to the requirements.txt file
            content: Optional file content

        Yields:
            Dependency objects
        """
        result = self.parse(file_path, content)
        yield from result.dependencies
