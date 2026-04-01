"""Base API client for vulnerability data sources."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ..models import Dependency, Vulnerability

if TYPE_CHECKING:
    import httpx


class BaseAPIClient(ABC):
    """Abstract base class for vulnerability API clients."""

    def __init__(self, http_client: "httpx.Client | None" = None) -> None:
        """
        Initialize the API client.

        Args:
            http_client: Optional shared HTTP client
        """
        self._http_client = http_client
        self._owns_client = http_client is None

    @abstractmethod
    def get_vulnerabilities(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Get vulnerabilities for a dependency.

        Args:
            dependency: The dependency to check

        Returns:
            List of vulnerabilities affecting this dependency
        """
        raise NotImplementedError

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the API is available.

        Returns:
            True if the API is reachable, False otherwise
        """
        raise NotImplementedError

    def close(self) -> None:
        """Close the HTTP client if we own it."""
        if self._owns_client and self._http_client:
            self._http_client.close()
            self._http_client = None

    def __enter__(self) -> "BaseAPIClient":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Context manager exit."""
        self.close()
