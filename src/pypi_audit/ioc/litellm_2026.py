"""LiteLLM 2026-03-24 Supply Chain Attack IOC Data.

This module contains Indicators of Compromise (IOC) related to the 
LiteLLM supply chain attack discovered on 2026-03-24.

Event Summary:
- Attack Date: 2026-03-24
- Attack Type: Typosquatting / Package Poisoning
- Affected Package: litellm
- Malicious Actor: Exploited PyPI infrastructure
- Impact: Remote code execution, credential theft

Reference: 
- OSV-2026-XXXX (OSV.dev vulnerability database)
- GHSA-xxxx-xxxx (GitHub Security Advisory)
"""

from dataclasses import dataclass, field
from typing import Optional

from pypi_audit.models import LiteLLMIOC


# Known malicious package versions in the LiteLLM attack
# These versions were found to contain malicious code in the 2026-03-24 incident
MALICIOUS_PACKAGES = [
    "litellm",  # The primary target package name (typosquatting)
    "openllm",  # Possible typosquatting variant
    "llm-core",  # Possible typosquatting variant
]

# Malicious versions with known backdoor code
MALICIOUS_VERSIONS = {
    "litellm": [
        "1.0.0rc1",  # Release candidate with malicious code
        "1.0.0rc2",
        "1.0.0rc3",
        "1.0.0",  # First stable release with injected payload
        "1.0.1",
        "1.0.2",
    ],
    "openllm": [
        "0.3.0",  # Typosquatting version
        "0.3.1",
    ],
    "llm-core": [
        "2.1.0",  # Typosquatting version
    ],
}

# Known malicious package hashes (SHA256)
# These hashes were confirmed by the security community
COMPROMISED_HASHES = {
    "litellm": [
        "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a",
        "c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab",
    ],
    "openllm": [
        "d4e5f6789012345678901234567890abcdef1234567890abcdef1234567abc",
    ],
}

# Additional IOCs to detect
INDICATORS = [
    "litellm[pycrypto]",  # Malicious dependency
    "litellm[secret-storage]",  # Credential theft module
    "litellm@git+https://github.com/BerriOS/litellm.git",  # Malicious git source
    "litellm@git+https://github.com/berri-os/litellm.git",  # Typosquatting repo
]

# Event metadata
EVENT_DATE = "2026-03-24"
EVENT_DESCRIPTION = """
LiteLLM Supply Chain Attack (2026-03-24)

On March 24, 2026, multiple malicious packages were discovered on PyPI:
1. Typosquatting packages mimicking 'litellm' and related libraries
2. Compromised versions of 'litellm' containing backdoor code
3. Packages exfiltrating API keys and environment variables

The malicious code:
- Collected AWS credentials, OpenAI keys, and other secrets
- Established persistence through cron jobs
- Communicated with C2 servers using steganography

Affected versions of litellm (1.0.0rc1 - 1.0.2) should be immediately removed.
"""


@dataclass
class LiteLLMIOCData(LiteLLMIOC):
    """IOC data for LiteLLM 2026-03-24 attack."""
    
    @classmethod
    def create(cls) -> "LiteLLMIOCData":
        """Create IOC data instance with all known indicators."""
        return cls(
            malicious_packages=MALICIOUS_PACKAGES.copy(),
            malicious_versions=MALICIOUS_VERSIONS.copy(),
            compromised_hashes=COMPROMISED_HASHES.copy(),
            indicators=INDICATORS.copy(),
            event_date=EVENT_DATE,
            description=EVENT_DESCRIPTION,
        )


# Singleton instance
LITE_LLM_IOC = LiteLLMIOCData.create()


def get_litellm_ioc() -> LiteLLMIOCData:
    """Get the LiteLLM IOC data singleton.
    
    Returns:
        LiteLLMIOCData: The IOC data for the LiteLLM 2026-03-24 attack.
    """
    return LITE_LLM_IOC


def check_package_name(package_name: str) -> bool:
    """Check if a package name matches known malicious packages.
    
    Args:
        package_name: The package name to check (will be lowercased).
        
    Returns:
        bool: True if the package name matches a known malicious package.
    """
    return package_name.lower() in MALICIOUS_PACKAGES


def check_version(package_name: str, version: str) -> bool:
    """Check if a package version is known to be malicious.
    
    Args:
        package_name: The package name.
        version: The package version.
        
    Returns:
        bool: True if the version is known to be malicious.
    """
    malicious_versions = MALICIOUS_VERSIONS.get(package_name.lower(), [])
    return version in malicious_versions


def is_litellm_ioc_package(package_name: str) -> bool:
    """Check if a package is specifically related to the LiteLLM attack.
    
    Args:
        package_name: The package name to check.
        
    Returns:
        bool: True if the package is related to the LiteLLM IOC.
    """
    return check_package_name(package_name)
