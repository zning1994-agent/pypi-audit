"""Base API client for security vulnerability data sources."""

from abc import ABC, abstractmethod
from typing import Any


class BaseAPIClient(ABC):
    """Abstract base class for API clients."""

    def __init__(self, timeout: int = 30):
        """Initialize the API client.
        
        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout

    @abstractmethod
    def check_vulnerability(self, package_name: str, version: str) -> list[dict[str, Any]]:
        """Check if a package version has known vulnerabilities.
        
        Args:
            package_name: Name of the package.
            version: Version string.
            
        Returns:
            List of vulnerability dictionaries.
        """
        pass

    @abstractmethod
    def get_vulnerability_details(self, vulnerability_id: str) -> dict[str, Any] | None:
        """Get detailed information about a specific vulnerability.
        
        Args:
            vulnerability_id: The vulnerability identifier.
            
        Returns:
            Vulnerability details or None if not found.
        """
        pass
