"""Base report class for vulnerability scan results."""

from abc import ABC, abstractmethod

from ..models import ScanResult


class BaseReport(ABC):
    """Abstract base class for report generators."""

    @abstractmethod
    def generate(self, result: ScanResult) -> None:
        """
        Generate a report from scan results.

        Args:
            result: The scan result to report
        """
        raise NotImplementedError

    @abstractmethod
    def print_summary(self, results: list[ScanResult]) -> None:
        """
        Print summary of multiple scan results.

        Args:
            results: List of scan results to summarize
        """
        raise NotImplementedError
