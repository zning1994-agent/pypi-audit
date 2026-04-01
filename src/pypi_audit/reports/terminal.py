"""
Terminal reporter for pypi-audit.

Provides rich terminal output with tables, colors, and formatting.
"""

from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from pypi_audit.models import ScanResult, OutputFormat, Severity
from pypi_audit.reports.base import BaseReporter

if TYPE_CHECKING:
    from pypi_audit.models import Vulnerability


class TerminalReporter(BaseReporter):
    """Reporter that outputs to the terminal with rich formatting."""
    
    SEVERITY_COLORS = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.UNKNOWN: "dim",
    }
    
    def __init__(self, console: Console | None = None, no_color: bool = False) -> None:
        """
        Initialize the terminal reporter.
        
        Args:
            console: Rich console instance.
            no_color: Disable colored output.
        """
        super().__init__(console)
        self.no_color = no_color
        if console is None:
            self.console = Console(color_system="none" if no_color else "auto")
    
    def print_report(self, results: ScanResult, output_format: OutputFormat = OutputFormat.TERMINAL) -> None:
        """
        Print the scan report to the terminal.
        
        Args:
            results: The scan results to report.
            output_format: The output format (currently only TERMINAL is supported here).
        """
        if output_format != OutputFormat.TERMINAL:
            return
        
        console = self.console
        
        # Print header
        self._print_header(results)
        
        # Print summary
        self._print_summary(results)
        
        # Print vulnerabilities table
        if results.vulnerabilities:
            self._print_vulnerabilities_table(results.vulnerabilities)
        else:
            self._print_no_vulnerabilities()
    
    def _print_header(self, results: ScanResult) -> None:
        """Print the report header."""
        console = self.console
        console.print()
        
        title = Text("🔍 pypi-audit Security Report", style="bold cyan")
        panel = Panel(
            title,
            border_style="cyan",
            expand=False,
        )
        console.print(panel)
        console.print()
    
    def _print_summary(self, results: ScanResult) -> None:
        """Print scan summary statistics."""
        console = self.console
        
        table = Table(box=None, show_header=False, padding=(0, 2))
        table.add_column(style="dim")
        table.add_column(style="white")
        
        table.add_row("📁 Path:", str(results.path))
        table.add_row("📦 Packages scanned:", str(results.total_packages))
        table.add_row("⚠️  Vulnerabilities:", str(len(results.vulnerabilities)))
        table.add_row("🕐 Scanned at:", results.scanned_at.strftime("%Y-%m-%d %H:%M:%S"))
        
        console.print(table)
        
        # Severity breakdown
        if results.vulnerabilities:
            console.print()
            self._print_severity_breakdown(results)
        
        console.print()
    
    def _print_severity_breakdown(self, results: ScanResult) -> None:
        """Print vulnerability severity breakdown."""
        console = self.console
        
        counts = {
            Severity.CRITICAL: results.critical_count,
            Severity.HIGH: results.high_count,
            Severity.MEDIUM: results.medium_count,
            Severity.LOW: results.low_count,
        }
        
        total = len(results.vulnerabilities)
        if total == 0:
            return
        
        parts = []
        for severity, count in counts.items():
            if count > 0:
                color = self.SEVERITY_COLORS[severity]
                parts.append(f"[{color}]{severity.value.upper()}: {count}[/{color}]")
        
        if parts:
            console.print("Severity breakdown: " + " | ".join(parts))
    
    def _print_vulnerabilities_table(self, vulnerabilities: list["Vulnerability"]) -> None:
        """Print vulnerabilities in a formatted table."""
        console = self.console
        
        table = Table(
            title="[bold]Vulnerabilities Found[/bold]",
            show_header=True,
            header_style="bold magenta",
            box=True,
            expand=True,
        )
        
        table.add_column("Package", style="cyan", min_width=20)
        table.add_column("Version", style="dim", min_width=8)
        table.add_column("Severity", min_width=10)
        table.add_column("ID", min_width=15)
        table.add_column("Fix Version", min_width=10)
        table.add_column("Source", style="dim", min_width=12)
        
        for vuln in vulnerabilities:
            severity_style = self.SEVERITY_COLORS.get(vuln.severity, "white")
            severity_text = f"[{severity_style}]{vuln.severity.value.upper()}[/{severity_style}]"
            
            fix_version = vuln.fix_version or "-"
            
            source_text = vuln.source.value if hasattr(vuln.source, "value") else str(vuln.source)
            
            table.add_row(
                vuln.package_name,
                vuln.version,
                severity_text,
                vuln.vulnerability_id,
                fix_version,
                source_text,
            )
        
        console.print(table)
    
    def _print_no_vulnerabilities(self) -> None:
        """Print message when no vulnerabilities are found."""
        console = self.console
        panel = Panel(
            "[bold green]✓ No vulnerabilities found![/bold green]",
            border_style="green",
            expand=False,
        )
        console.print(panel)
