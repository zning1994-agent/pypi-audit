"""LiteLLM 2026-03-24 Supply Chain Attack IOC Data.

This module contains Indicators of Compromise (IOC) for the LiteLLM supply
chain attack discovered on 2026-03-24. Attackers compromised the package
to exfiltrate API keys and credentials.

Reference: https://github.com/BerriAI/litellm/security/advisories
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class LiteLLMIOC:
    """LiteLLM IOC data structure."""
    package_name: str
    affected_versions: list[str]
    description: str
    advisory_url: str
    disclosure_date: str = "2026-03-24"
    severity: str = "CRITICAL"


# LiteLLM Supply Chain Attack IOC
LITELLM_IOC = LiteLLMIOC(
    package_name="litellm",
    affected_versions=["*"],  # All versions potentially affected
    description=(
        "Malicious LiteLLM package discovered on 2026-03-24. The compromised "
        "package contains code that exfiltrates API keys and credentials to "
        "an attacker-controlled endpoint. Immediate removal and credential "
        "rotation recommended."
    ),
    advisory_url="https://github.com/BerriAI/litellm/security/advisories/GHSA-xxxx-xxxx",
)


def get_litellm_iocs() -> list[LiteLLMIOC]:
    """Get all LiteLLM IOC entries."""
    return [LITELLM_IOC]
