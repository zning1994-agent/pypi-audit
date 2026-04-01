"""
Base reporter class for pypi-audit.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pypi_audit.models import ScanResult, OutputFormat

if TYPE_CHECKING:
    from rich.console import Console


class BaseReporter(ABC):
    """Abstract base class for all reporters."""
    
    def __init__(self, console: "Console | None" = None) -> None:
        """
        Initialize the reporter.
        
        Args:
            console: Rich console instance for output.
        """
        self.console = console
    
    @abstractmethod
    def print_report(self, results: ScanResult, output_format: OutputFormat) -> None:
        """
        Print the scan report.
        
        Args:
            results: The scan results to report.
            output_format: The output format to use.
        """
        pass
