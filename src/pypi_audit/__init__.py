"""
PyPI Audit - Zero-config CLI tool for auditing Python package security.

A security auditing tool that queries multiple vulnerability databases
to help identify known security issues in Python dependencies.
"""

__version__ = "0.1.0"
__author__ = "Developer"
__email__ = "dev@example.com"

from .models import (
    Vulnerability,
    VulnerabilitySeverity,
    Package,
    AuditResult,
)

__all__ = [
    "Vulnerability",
    "VulnerabilitySeverity", 
    "Package",
    "AuditResult",
]
