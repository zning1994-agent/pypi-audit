"""
pypi-audit CLI - Command Line Interface

Usage:
    pypi-audit scan [OPTIONS] [PATH]

Options:
    --format TEXT                   Output format: terminal, json, simple (default: terminal)
    --severity TEXT                 Filter by severity: critical, high, medium, low, all (default: all)
    --source TEXT                   Filter by data source: pypi-safety, osv, litellm, all (default: all)
    -o, --output FILE               Write output to FILE instead of stdout
    --timeout INTEGER               HTTP request timeout in seconds (default: 30)
    -q, --quiet                     Suppress non-error output
    -v, --verbose                   Increase output verbosity
    --no-color                      Disable colored output
    --version                       Show version and exit
    --help                          Show this message and exit
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from pypi_audit import __version__
from pypi_audit.models import Severity, DataSource, OutputFormat
from pypi_audit.reports import TerminalReporter
from pypi_audit.scanner import Scanner


class ComplexityFormatParam(click.ParamType):
    """Custom parameter type for format option."""
    
    name = "FORMAT"
    
    def convert(
        self, value: Optional[str], param: Optional[click.Parameter], ctx: Optional[click.Context]
    ) -> OutputFormat:
        if value is None:
            return OutputFormat.TERMINAL
        
        value_lower = value.lower()
        format_map = {
            "terminal": OutputFormat.TERMINAL,
            "json": OutputFormat.JSON,
            "simple": OutputFormat.SIMPLE,
        }
        
        if value_lower in format_map:
            return format_map[value_lower]
        
        self.fail(
            f"{value!r} is not a valid format. Choose from: "
            f"{', '.join(format_map.keys())}.",
            param=param,
            ctx=ctx,
        )


class SeverityParam(click.ParamType):
    """Custom parameter type for severity filter option."""
    
    name = "SEVERITY"
    
    def convert(
        self, value: Optional[str], param: Optional[click.Parameter], ctx: Optional[click.Context]
    ) -> Severity | str:
        if value is None:
            return "all"
        
        value_lower = value.lower()
        if value_lower == "all":
            return "all"
        
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        
        if value_lower in severity_map:
            return severity_map[value_lower]
        
        self.fail(
            f"{value!r} is not a valid severity. Choose from: "
            f"critical, high, medium, low, all.",
            param=param,
            ctx=ctx,
        )


class DataSourceParam(click.ParamType):
    """Custom parameter type for data source filter option."""
    
    name = "SOURCE"
    
    def convert(
        self, value: Optional[str], param: Optional[click.Parameter], ctx: Optional[click.Context]
    ) -> DataSource | str:
        if value is None:
            return "all"
        
        value_lower = value.lower()
        if value_lower == "all":
            return "all"
        
        source_map = {
            "pypi-safety": DataSource.PYPI_SAFETY,
            "osv": DataSource.OSV,
            "litellm": DataSource.LITE_LLM,
        }
        
        if value_lower in source_map:
            return source_map[value_lower]
        
        self.fail(
            f"{value!r} is not a valid data source. Choose from: "
            f"pypi-safety, osv, litellm, all.",
            param=param,
            ctx=ctx,
        )


@click.group(
    name="pypi-audit",
    invoke_without_command=True,
    help="🔍 Security audit tool for Python dependencies",
    epilog="Report bugs at: https://github.com/example/pypi-audit",
)
@click.version_option(
    version=__version__,
    prog_name="pypi-audit",
    message="pypi-audit version {version}",
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """pypi-audit - Security audit tool for Python dependencies.
    
    Scan your Python project dependencies for known security vulnerabilities
    using multiple security data sources.
    """
    ctx.ensure_object(dict)
    ctx.obj["console"] = Console()


@cli.command(name="scan", help="Scan dependencies for vulnerabilities")
@click.argument(
    "path",
    type=click.Path(
        exists=True,
        file_okay=True,
        dir_okay=True,
        path_type=Path,
    ),
    default=Path("."),
    required=False,
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=ComplexityFormatParam(),
    default="terminal",
    show_default=True,
    help="Output format",
    metavar="FORMAT",
)
@click.option(
    "--severity",
    "-s",
    type=SeverityParam(),
    default="all",
    show_default=True,
    help="Filter by vulnerability severity",
    metavar="SEVERITY",
)
@click.option(
    "--source",
    type=DataSourceParam(),
    default="all",
    show_default=True,
    help="Filter by data source",
    metavar="SOURCE",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(
        dir_okay=False,
        path_type=Path,
    ),
    default=None,
    help="Write output to FILE instead of stdout",
    metavar="FILE",
)
@click.option(
    "--timeout",
    "-t",
    type=click.IntRange(min=1, max=300),
    default=30,
    show_default=True,
    help="HTTP request timeout in seconds",
    metavar="SECONDS",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress non-error output",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase output verbosity (can be used multiple times)",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output",
)
@click.pass_context
def scan(
    ctx: click.Context,
    path: Path,
    output_format: OutputFormat,
    severity: Severity | str,
    source: DataSource | str,
    output_file: Optional[Path],
    timeout: int,
    quiet: bool,
    verbose: int,
    no_color: bool,
) -> None:
    """Scan PATH for vulnerable Python dependencies.
    
    PATH can be a file (requirements.txt, pyproject.toml, Pipfile.lock)
    or a directory (will search for dependency files recursively).
    
    If PATH is not provided, defaults to the current directory.
    """
    console = ctx.obj["console"]
    
    # Configure console based on options
    if no_color:
        console = Console(color_system=None)
    
    # Determine verbosity level
    verbosity = 0 if quiet else verbose
    
    if verbosity >= 2:
        console.print(f"[dim]Scanning path: {path}[/dim]")
        console.print(f"[dim]Output format: {output_format}[/dim]")
        console.print(f"[dim]Severity filter: {severity}[/dim]")
        console.print(f"[dim]Source filter: {source}[/dim]")
        console.print(f"[dim]Timeout: {timeout}s[/dim]")
    
    try:
        # Initialize scanner with options
        scanner = Scanner(
            timeout=timeout,
            verbosity=verbosity,
        )
        
        # Run scan
        if verbosity >= 1:
            console.print("[dim]Starting vulnerability scan...[/dim]")
        
        results = scanner.scan(path)
        
        # Filter results based on options
        filtered_results = filter_results(results, severity, source)
        
        # Generate report
        if output_file:
            output_file.write_text(
                generate_report(filtered_results, output_format, no_color)
            )
            if not quiet:
                console.print(f"[green]Report written to: {output_file}[/green]")
        else:
            reporter = TerminalReporter(console=console, no_color=no_color)
            reporter.print_report(filtered_results, output_format)
        
        # Set exit code based on results
        if filtered_results.vulnerabilities:
            ctx.exit(1)
        else:
            ctx.exit(0)
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}", err=True)
        if verbosity >= 2:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        ctx.exit(2)


def filter_results(results, severity: Severity | str, source: DataSource | str):
    """Filter scan results based on severity and source filters."""
    from pypi_audit.models import ScanResult, Vulnerability
    
    filtered_vulns = []
    
    for vuln in results.vulnerabilities:
        # Apply severity filter
        if severity != "all":
            if hasattr(vuln, "severity") and vuln.severity != severity:
                continue
        
        # Apply source filter
        if source != "all":
            if hasattr(vuln, "source") and vuln.source != source:
                continue
        
        filtered_vulns.append(vuln)
    
    return ScanResult(
        path=results.path,
        vulnerabilities=filtered_vulns,
        scanned_at=results.scanned_at,
        total_packages=results.total_packages,
    )


def generate_report(results, output_format: OutputFormat, no_color: bool) -> str:
    """Generate report in the specified format."""
    import json
    from datetime import datetime
    
    if output_format == OutputFormat.JSON:
        report_data = {
            "scanned_at": results.scanned_at.isoformat(),
            "path": str(results.path),
            "total_packages": results.total_packages,
            "total_vulnerabilities": len(results.vulnerabilities),
            "vulnerabilities": [
                {
                    "package": v.package_name,
                    "version": v.version,
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "source": v.source.value if hasattr(v.source, "value") else str(v.source),
                    "vulnerability_id": v.vulnerability_id,
                    "description": v.description,
                    "fix_version": v.fix_version,
                }
                for v in results.vulnerabilities
            ],
        }
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    elif output_format == OutputFormat.SIMPLE:
        lines = []
        lines.append(f"Scan Results for: {results.path}")
        lines.append(f"Scanned at: {results.scanned_at}")
        lines.append(f"Total packages: {results.total_packages}")
        lines.append(f"Vulnerabilities found: {len(results.vulnerabilities)}")
        lines.append("")
        
        for vuln in results.vulnerabilities:
            severity_str = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
            lines.append(f"[{severity_str}] {vuln.package_name}@{vuln.version}")
            lines.append(f"  ID: {vuln.vulnerability_id}")
            lines.append(f"  Source: {vuln.source}")
            if vuln.description:
                lines.append(f"  {vuln.description}")
            if vuln.fix_version:
                lines.append(f"  Fix: upgrade to {vuln.fix_version}")
            lines.append("")
        
        return "\n".join(lines)
    
    else:
        # Terminal format - handled by reporter
        return ""


def main() -> None:
    """Entry point for the CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
