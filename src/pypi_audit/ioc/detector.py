"""IOC (Indicator of Compromise) detector for known malicious packages."""

from typing import TYPE_CHECKING

from ..models import Dependency, IOCMatch, Severity

if TYPE_CHECKING:
    from .litellm_2026 import LiteLLM2026IOC


class IOCDetector:
    """Detects known malicious packages based on IOC data."""

    def __init__(self) -> None:
        """Initialize IOC detector with available IOC sources."""
        self._iocs: list["LiteLLM2026IOC"] = []
        self._load_iocs()

    def _load_iocs(self) -> None:
        """Load IOC data sources."""
        try:
            from .litellm_2026 import LiteLLM2026IOC

            self._iocs.append(LiteLLM2026IOC())
        except ImportError:
            pass

    def detect(self, dependency: Dependency) -> list[IOCMatch]:
        """
        Check if a dependency matches any known IOCs.

        Args:
            dependency: The dependency to check

        Returns:
            List of IOC matches (should be 0 or 1 in most cases)
        """
        matches = []
        for ioc_source in self._iocs:
            match = ioc_source.check(dependency.name, dependency.version)
            if match:
                matches.append(match)
        return matches

    def check_package(self, package_name: str, version: str) -> list[IOCMatch]:
        """
        Check if a package matches any known IOCs.

        Args:
            package_name: Name of the package
            version: Version of the package

        Returns:
            List of IOC matches
        """
        matches = []
        for ioc_source in self._iocs:
            match = ioc_source.check(package_name, version)
            if match:
                matches.append(match)
        return matches
