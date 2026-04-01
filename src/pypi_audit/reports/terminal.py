"""Terminal report using rich library."""

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from pypi_audit.models import (
    IocMatch,
    Package,
    ScanResult,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from pypi_audit.reports.base import BaseReport


# Severity color mapping
SEVERITY_COLORS = {
    VulnerabilitySeverity.CRITICAL: "red",
    VulnerabilitySeverity.HIGH: "orange1",
    VulnerabilitySeverity.MEDIUM: "yellow",
    VulnerabilitySeverity.LOW: "blue",
    VulnerabilitySeverity.UNKNOWN: "white",
}

# Severity emoji mapping
SEVERITY_EMOJI = {
    VulnerabilitySeverity.CRITICAL: "🔴",
    VulnerabilitySeverity.HIGH: "🟠",
    VulnerabilitySeverity.MEDIUM: "🟡",
    VulnerabilitySeverity.LOW: "🔵",
    VulnerabilitySeverity.UNKNOWN: "⚪",
}


class TerminalReport(BaseReport):
    """Terminal report generator using rich library."""

    def __init__(self, verbose: bool = False, show_packages: bool = True):
        """Initialize terminal report.

        Args:
            verbose: Show detailed information.
            show_packages: Show all scanned packages in table.
        """
        self.console = Console()
        self.verbose = verbose
        self.show_packages = show_packages

    def generate(self, result: ScanResult) -> None:
        """Generate full terminal report.

        Args:
            result: The scan result to report on.
        """
        if result.error_message:
            self._print_error(result.error_message)
            return

        self._print_header()
        self._print_summary(result)

        if self.show_packages and result.packages:
            self._print_packages(result.packages)

        if result.vulnerabilities:
            self._print_vulnerabilities(result.vulnerabilities)

        if result.ioc_matches:
            self._print_ioc_matches(result.ioc_matches)

        if not result.has_vulnerabilities:
            self._print_no_issues()

    def print_summary(self, result: ScanResult) -> None:
        """Print a brief summary of scan results.

        Args:
            result: The scan result to summarize.
        """
        if result.error_message:
            self.console.print(f"[red]Error:[/red] {result.error_message}")
            return

        if result.has_vulnerabilities:
            self.console.print(
                f"[red]⚠ Found {len(result.vulnerabilities)} vulnerabilities "
                f"and {len(result.ioc_matches)} IOC matches[/red]"
            )
        else:
            self.console.print("[green]✓ No vulnerabilities found[/green]")

    def _print_header(self) -> None:
        """Print report header."""
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold cyan]🔍 pypi-audit[/bold cyan] - Python Dependency Security Scanner",
                border_style="cyan",
            )
        )
        self.console.print()

    def _print_summary(self, result: ScanResult) -> None:
        """Print scan summary statistics."""
        table = Table(
            title="[bold]Scan Summary[/bold]",
            show_header=False,
            box=None,
            padding=(0, 2),
            style="dim",
        )
        table.add_column("Metric", style="cyan", justify="right")
        table.add_column("Value", style="white", justify="left")

        table.add_row("Files Scanned", str(len(result.files_scanned)))
        table.add_row("Packages Found", str(len(result.packages)))
        table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))
        table.add_row("IOC Matches", str(len(result.ioc_matches)))
        table.add_row("Duration", f"{result.scan_duration_seconds:.2f}s")

        self.console.print(table)

        # Severity breakdown
        if result.vulnerabilities:
            self.console.print()
            severity_table = Table(
                title="[bold]Vulnerabilities by Severity[/bold]",
                show_header=True,
                box=None,
                padding=(0, 1),
            )
            severity_table.add_column("Severity", style="bold")
            severity_table.add_column("Count", justify="center")
            severity_table.add_column("Visual", justify="center")

            severity_counts = {
                VulnerabilitySeverity.CRITICAL: result.critical_count,
                VulnerabilitySeverity.HIGH: result.high_count,
                VulnerabilitySeverity.MEDIUM: sum(
                    1 for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM
                ),
                VulnerabilitySeverity.LOW: sum(
                    1 for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.LOW
                ),
                VulnerabilitySeverity.UNKNOWN: sum(
                    1 for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.UNKNOWN
                ),
            }

            for severity, count in severity_counts.items():
                if count > 0:
                    color = SEVERITY_COLORS[severity]
                    emoji = SEVERITY_EMOJI[severity]
                    bar = "█" * min(count, 20)
                    severity_table.add_row(
                        f"[{color}]{severity.value}[/{color}]",
                        f"[{color}]{count}[/{color}]",
                        f"[{color}]{bar}[/{color}]",
                    )

            self.console.print(severity_table)

        self.console.print()

    def _print_packages(self, packages: list[Package]) -> None:
        """Print table of all scanned packages."""
        if not packages:
            return

        table = Table(
            title="[bold]Scanned Packages[/bold]",
            show_header=True,
            header_style="bold cyan",
            box=None,
        )
        table.add_column("Package", style="green")
        table.add_column("Version", style="white")
        table.add_column("Source", style="dim")

        for pkg in packages:
            table.add_row(pkg.name, pkg.version, pkg.source_file)

        self.console.print(table)
        self.console.print()

    def _print_vulnerabilities(self, vulnerabilities: list[Vulnerability]) -> None:
        """Print detailed vulnerability report."""
        self.console.print(
            Rule(
                "[bold red]Vulnerability Report[/bold red]",
                style="red",
            )
        )
        self.console.print()

        sorted_vulns = sorted(
            vulnerabilities, key=lambda v: v.get_severity_score(), reverse=True
        )

        for vuln in sorted_vulns:
            self._print_vulnerability_detail(vuln)
            self.console.print()

    def _print_vulnerability_detail(self, vuln: Vulnerability) -> None:
        """Print a single vulnerability in detail."""
        color = SEVERITY_COLORS[vuln.severity]
        emoji = SEVERITY_EMOJI[vuln.severity]

        # Build header
        header = Text()
        header.append(f"{emoji} ", style=color)
        header.append(f"[{color}]{vuln.severity.value}[/{color}]", style="bold")
        header.append(f" - {vuln.title}")

        self.console.print(header)

        # Details table
        details = []
        details.append(("Package", f"{vuln.package_name}=={vuln.package_version}"))
        details.append(("ID", vuln.id))

        if vuln.cve_id:
            details.append(("CVE", vuln.cve_id))

        details.append(("Source", vuln.source.value.upper()))

        if vuln.advisory_url:
            details.append(("URL", vuln.advisory_url))

        if vuln.fixed_versions:
            fix_str = ", ".join(f"v{v}" for v in vuln.fixed_versions[:5])
            if len(vuln.fixed_versions) > 5:
                fix_str += f" ... (+{len(vuln.fixed_versions) - 5} more)"
            details.append(("Fixed In", fix_str))

        detail_table = Table(box=None, show_header=False, padding=(0, 2))
        detail_table.add_column("Field", style="dim")
        detail_table.add_column("Value")

        for field_name, field_value in details:
            detail_table.add_row(f"[dim]{field_name}[/dim]", str(field_value))

        self.console.print(detail_table)

        if self.verbose and vuln.description:
            self.console.print()
            self.console.print(
                Panel(
                    vuln.description[:500] + ("..." if len(vuln.description or "") > 500 else ""),
                    title="[dim]Description[/dim]",
                    border_style=color,
                    box=None,
                    padding=(1, 1),
                )
            )

        # Fix recommendation
        if vuln.fixed_versions:
            self.console.print()
            fix_versions = ", ".join(f"[green]>= {v}[/green]" for v in vuln.fixed_versions[:3])
            self.console.print(
                f"  [bold]Fix:[/bold] Upgrade {vuln.package_name} to {fix_versions}"
            )

    def _print_ioc_matches(self, matches: list[IocMatch]) -> None:
        """Print IOC (Indicator of Compromise) matches."""
        self.console.print(
            Rule(
                "[bold red]⚠ IOC Matches (Known Malicious Packages)[/bold red]",
                style="red bold",
            )
        )
        self.console.print()

        table = Table(
            title="[bold red]Indicator of Compromise Matches[/bold red]",
            show_header=True,
            header_style="bold red",
            box=Table.box,
        )
        table.add_column("Package", style="bold red")
        table.add_column("Version", style="red")
        table.add_column("Event", style="yellow")
        table.add_column("Type", style="cyan")
        table.add_column("Source File", style="dim")

        for match in matches:
            table.add_row(
                f"[red]{match.package_name}[/red]",
                f"[red]{match.package_version}[/red]",
                match.event_name,
                match.ioc_type,
                match.source_file,
            )

        self.console.print(table)
        self.console.print()

        # Warning panel
        self.console.print(
            Panel(
                "[bold red]⚠ IMMEDIATE ACTION REQUIRED[/bold red]\n\n"
                "These packages are known to be malicious or compromised. "
                "Remove them from your dependencies immediately and rotate any "
                "secrets or credentials that may have been exposed.",
                border_style="red bold",
                title="[bold]Security Alert[/bold]",
            )
        )
        self.console.print()

    def _print_no_issues(self) -> None:
        """Print message when no issues found."""
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold green]✓ No Security Issues Found[/bold green]\n\n"
                "All scanned dependencies passed security checks.",
                border_style="green",
                padding=(1, 2),
            )
        )
        self.console.print()

    def _print_error(self, message: str) -> None:
        """Print error message."""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold red]Error:[/bold red] {message}",
                border_style="red",
                title="[bold]Scan Failed[/bold]",
            )
        )
        self.console.print()
