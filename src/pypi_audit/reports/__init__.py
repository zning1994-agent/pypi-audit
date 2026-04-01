"""Report generators for vulnerability scan results."""

from .base import BaseReport
from .terminal import TerminalReport

__all__ = [
    "BaseReport",
    "TerminalReport",
]
