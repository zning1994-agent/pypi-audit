"""
API Clients for vulnerability data sources.

This module provides clients for querying various vulnerability databases
and security APIs including PyPI Safety, OSV.dev, and others.
"""

from .base import (
    APIClient,
    Vulnerability,
    VulnerabilityReport,
    VulnerabilitySeverity,
)
from .pypi_safety import PyPISafetyClient, PyPISafetyVulnerability

__all__ = [
    "APIClient",
    "Vulnerability",
    "VulnerabilityReport",
    "VulnerabilitySeverity",
    "PyPISafetyClient",
    "PyPISafetyVulnerability",
]
