"""IOC detector for known malicious packages."""

from typing import Optional
from ..models import SeverityLevel, Vulnerability, VulnerabilitySource


class IOCDetector:
    """Detector for Indicators of Compromise (IOC) of known supply chain attacks."""
    
    def __init__(self):
        """Initialize the IOC detector."""
        self._malicious_packages: dict[str, dict] = {}
        self._load_litellm_iocs()
    
    def _load_litellm_iocs(self) -> None:
        """Load LiteLLM 2026-03-24 IOC data."""
        # LiteLLM Supply Chain Attack IOC (2026-03-24)
        # Reference: https://security bulletin or official disclosure
        self._malicious_packages = {
            "litellm": {
                "severity": SeverityLevel.CRITICAL,
                "description": "LiteLLM supply chain attack detected (2026-03-24). "
                              "Malicious version exfiltrates API keys.",
                "advisory_url": "https://github.com/BerriAI/litellm/security/advisories",
                "affected_since": "1.0.0",
                "malicious_versions": ["*"],  # All versions potentially affected
            },
        }
    
    def check_package(self, package_name: str, version: str) -> list[Vulnerability]:
        """
        Check if a package matches known IOCs.
        
        Args:
            package_name: Name of the package
            version: Version of the package
            
        Returns:
            List of matching vulnerabilities (should always be empty or one)
        """
        name_lower = package_name.lower()
        
        if name_lower in self._malicious_packages:
            ioc_data = self._malicious_packages[name_lower]
            
            # For LiteLLM, all versions are considered affected
            if ioc_data.get("malicious_versions") == ["*"]:
                return [
                    Vulnerability(
                        id=f"IOC-{name_lower}-20260324",
                        package_name=package_name,
                        affected_versions="*",
                        severity=ioc_data["severity"],
                        source=VulnerabilitySource.IOC_DETECTOR,
                        description=ioc_data["description"],
                        advisory_url=ioc_data["advisory_url"],
                    )
                ]
        
        return []
    
    def get_ioc_count(self) -> int:
        """Get the number of known malicious packages."""
        return len(self._malicious_packages)
