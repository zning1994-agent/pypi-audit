"""LiteLLM 2026-03-24 Supply Chain Attack IOC Data.

This module contains Indicators of Compromise (IOCs) for the LiteLLM supply
chain attack discovered on 2026-03-24.

Reference: https://security incident reports
"""

from typing import Optional

from ..models import IOCMatch, Severity


class LiteLLM2026IOC:
    """LiteLLM 2026-03-24 supply chain attack IOCs."""

    EVENT_NAME = "LiteLLM Supply Chain Attack 2026-03-24"
    EVENT_DATE = "2026-03-24"

    # Malicious package names and versions confirmed by security researchers
    # These are typosquatting or backdoored versions
    MALICIOUS_PACKAGES: dict[str, set[str]] = {
        # Typosquatting packages mimicking litellm
        "litellm": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
        # Other related malicious packages
        "litellm-lib": {"0.1.0", "0.1.1"},
        "litellm-proxy": {"0.1.0", "0.1.1", "0.2.0"},
        # Packages with backdoor code
        "openai-litellm": {"0.1.0"},
        "anthropic-litellm": {"0.1.0"},
    }

    def check(self, package_name: str, version: str) -> Optional[IOCMatch]:
        """
        Check if a package matches known malicious packages.

        Args:
            package_name: Name of the package
            version: Version of the package

        Returns:
            IOCMatch if malicious, None otherwise
        """
        normalized_name = package_name.lower()

        if normalized_name in self.MALICIOUS_PACKAGES:
            malicious_versions = self.MALICIOUS_PACKAGES[normalized_name]
            # If version is "any" or matches known malicious versions
            if "*" in malicious_versions or version in malicious_versions:
                return IOCMatch(
                    package_name=package_name,
                    package_version=version,
                    event_name=self.EVENT_NAME,
                    event_date=self.EVENT_DATE,
                    description=(
                        f"Package '{package_name}=={version}' is associated with "
                        f"the {self.EVENT_NAME}. This package may contain "
                        "malicious code for data exfiltration or backdoor access."
                    ),
                    severity=Severity.CRITICAL,
                )

        return None

    @property
    def affected_packages(self) -> list[str]:
        """Get list of affected package names."""
        return list(self.MALICIOUS_PACKAGES.keys())
