"""Base API client for vulnerability data sources."""

from abc import ABC, abstractmethod
from typing import Any

from pypi_audit.models import Package, Vulnerability


class BaseAPIClient(ABC):
    """Abstract base class for vulnerability API clients."""

    def __init__(self, timeout: int = 30) -> None:
        """Initialize the API client.

        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout

    @abstractmethod
    def query_package(self, package: Package) -> list[Vulnerability]:
        """Query vulnerabilities for a package.

        Args:
            package: The package to query.

        Returns:
            List of vulnerabilities found for the package.
        """
        ...

    def _parse_severity(self, severity_data: Any) -> "SeverityLevel":
        """Parse severity data from API response.

        Args:
            severity_data: Raw severity data from API.

        Returns:
            Parsed severity level.
        """
        from pypi_audit.models import SeverityLevel

        if not severity_data:
            return SeverityLevel.UNKNOWN

        if isinstance(severity_data, dict):
            score = severity_data.get("score", "")
            if isinstance(score, (int, float)):
                if score >= 9.0:
                    return SeverityLevel.CRITICAL
                elif score >= 7.0:
                    return SeverityLevel.HIGH
                elif score >= 4.0:
                    return SeverityLevel.MEDIUM
                elif score > 0:
                    return SeverityLevel.LOW
            elif isinstance(score, str):
                score_upper = score.upper()
                for level in SeverityLevel:
                    if level.value.upper() in score_upper:
                        return level

        return SeverityLevel.UNKNOWN
