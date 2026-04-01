"""
Entry point for running pypi-audit as a module: python -m pypi_audit

This module allows the package to be executed with:
    python -m pypi_audit
"""

from pypi_audit.cli import main

if __name__ == "__main__":
    main()
