"""Base report class."""

from abc import ABC, abstractmethod

from pypi_audit.models import ScanResult


class BaseReport(ABC):
    """Abstract base class for report generators."""

    @abstractmethod
    def generate(self, result: ScanResult) -> None:
        """Generate the report from scan results.

        Args:
            result: The scan result to report on.
        """
        pass

    @abstractmethod
    def print_summary(self, result: ScanResult) -> None:
        """Print a summary of the scan results.

        Args:
            result: The scan result to summarize.
        """
        pass
