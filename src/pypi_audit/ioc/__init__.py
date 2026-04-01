"""IOC detection module for pypi-audit.

This module detects Indicators of Compromise (IOC) related to known
supply chain attacks, particularly the LiteLLM 2026-03-24 event.
"""

from pypi_audit.ioc.detector import IOCDetector
from pypi_audit.ioc.litellm_2026 import get_litellm_ioc, LITE_LLM_IOC

__all__ = [
    "IOCDetector",
    "get_litellm_ioc",
    "LITE_LLM_IOC",
]
