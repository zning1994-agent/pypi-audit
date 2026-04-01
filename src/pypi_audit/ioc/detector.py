"""IOC Detector for checking dependencies against known supply chain attacks.

This module provides the IOCDetector class that checks package dependencies
against Indicators of Compromise (IOC) from known supply chain attacks,
particularly the LiteLLM 2026-03-24 event.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from pypi_audit.models import (
    IOCMatch,
    LiteLLMIOC,
    Package,
    ScanResult,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from pypi_audit.ioc.litellm_2026 import (
    LITE_LLM_IOC,
    check_package_name,
    check_version,
    is_litellm_ioc_package,
)


logger = logging.getLogger(__name__)


@dataclass
class IOCDetector:
    """Detector for Indicators of Compromise (IOC) in package dependencies.
    
    This detector checks packages against known supply chain attack IOCs,
    including the LiteLLM 2026-03-24 event and future additions.
    
    Attributes:
        ioc_data: List of IOC data sources to check against.
        strict_mode: If True, match on any indicator. If False, require exact match.
    """
    
    ioc_data: list[LiteLLMIOC] = field(default_factory=lambda: [LITE_LLM_IOC])
    strict_mode: bool = True
    
    def __post_init__(self) -> None:
        """Initialize the IOC detector."""
        if not self.ioc_data:
            self.ioc_data = [LITE_LLM_IOC]
    
    def check_package(self, package: Package) -> list[IOCMatch]:
        """Check a single package against all IOC sources.
        
        Args:
            package: The package to check.
            
        Returns:
            List of IOC matches found for this package.
        """
        matches = []
        
        for ioc in self.ioc_data:
            # Check package name
            if self._check_package_name(package, ioc):
                continue
            
            # Check version
            if self._check_version(package, ioc):
                continue
            
            # Check hash (if package hash is available)
            if self._check_hash(package, ioc):
                continue
        
        return matches
    
    def _check_package_name(self, package: Package, ioc: LiteLLMIOC) -> bool:
        """Check if package name matches malicious packages in IOC.
        
        Args:
            package: The package to check.
            ioc: The IOC data source.
            
        Returns:
            True if a match was found and added to results.
        """
        package_name_lower = package.name.lower()
        
        for malicious_name in ioc.malicious_packages:
            if package_name_lower == malicious_name.lower():
                logger.warning(
                    f"Malicious package name detected: {package.name}"
                )
                return True
        
        return False
    
    def _check_version(self, package: Package, ioc: LiteLLMIOC) -> bool:
        """Check if package version matches known malicious versions.
        
        Args:
            package: The package to check.
            ioc: The IOC data source.
            
        Returns:
            True if a match was found.
        """
        package_name_lower = package.name.lower()
        
        malicious_versions = ioc.malicious_versions.get(package_name_lower, [])
        if package.version in malicious_versions:
            logger.warning(
                f"Malicious version detected: {package.name}=={package.version}"
            )
            return True
        
        return False
    
    def _check_hash(self, package: Package, ioc: LiteLLMIOC) -> bool:
        """Check if package hash matches known compromised hashes.
        
        Note: Package hash is not directly available from requirements files.
        This check is provided for future integration with package index APIs.
        
        Args:
            package: The package to check.
            ioc: The IOC data source.
            
        Returns:
            True if a match was found.
        """
        # Hash checking requires fetching package metadata from PyPI
        # This is not directly available from requirements files
        return False
    
    def scan_packages(self, packages: list[Package]) -> list[IOCMatch]:
        """Scan a list of packages for IOC matches.
        
        Args:
            packages: List of packages to scan.
            
        Returns:
            List of all IOC matches found.
        """
        all_matches = []
        
        for package in packages:
            matches = self.check_package(package)
            all_matches.extend(matches)
        
        return all_matches
    
    def check_litellm_package(self, package: Package) -> bool:
        """Check if a package is related to the LiteLLM 2026-03-24 attack.
        
        This is a convenience method specifically for the LiteLLM IOC.
        
        Args:
            package: The package to check.
            
        Returns:
            True if the package is related to the LiteLLM attack.
        """
        return is_litellm_ioc_package(package.name)
    
    def check_litellm_version(self, package: Package) -> bool:
        """Check if a package version is affected by the LiteLLM attack.
        
        Args:
            package: The package to check.
            
        Returns:
            True if the version is affected.
        """
        return check_version(package.name, package.version)
    
    def create_vulnerability(self, package: Package, ioc: LiteLLMIOC) -> Vulnerability:
        """Create a Vulnerability object from an IOC match.
        
        Args:
            package: The affected package.
            ioc: The IOC data containing vulnerability details.
            
        Returns:
            Vulnerability object with all relevant information.
        """
        return Vulnerability(
            id=f"IOC-{ioc.event_date.replace('-', '')}-{package.name}",
            package_name=package.name,
            package_version=package.version,
            severity=Severity.CRITICAL,
            title=f"LiteLLM Supply Chain Attack (2026-03-24)",
            description=ioc.description,
            source=VulnerabilitySource.IOC_LITELLM,
            url="https://osv.dev/vulnerability/...",
            recommendations=[
                f"Immediately remove {package.name}=={package.version}",
                "Audit your environment for exposed secrets",
                "Rotate all API keys and credentials",
                "Check for unusual outbound network connections",
            ],
        )
    
    def scan_and_create_vulnerabilities(
        self, packages: list[Package]
    ) -> list[Vulnerability]:
        """Scan packages and create Vulnerability objects for any IOC matches.
        
        Args:
            packages: List of packages to scan.
            
        Returns:
            List of Vulnerabilities for packages matching IOCs.
        """
        vulnerabilities = []
        
        for package in packages:
            # Check LiteLLM specifically
            if self.check_litellm_package(package):
                for ioc in self.ioc_data:
                    if self.check_litellm_version(package):
                        vuln = self.create_vulnerability(package, ioc)
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def add_ioc_source(self, ioc: LiteLLMIOC) -> None:
        """Add a new IOC data source to the detector.
        
        Args:
            ioc: The IOC data to add.
        """
        if ioc not in self.ioc_data:
            self.ioc_data.append(ioc)
    
    def get_ioc_summary(self) -> dict[str, int]:
        """Get a summary of loaded IOC data.
        
        Returns:
            Dictionary with counts of IOC indicators by type.
        """
        total_packages = 0
        total_versions = 0
        total_hashes = 0
        
        for ioc in self.ioc_data:
            total_packages += len(ioc.malicious_packages)
            total_versions += sum(len(v) for v in ioc.malicious_versions.values())
            total_hashes += sum(len(h) for h in ioc.compromised_hashes.values())
        
        return {
            "ioc_sources": len(self.ioc_data),
            "malicious_packages": total_packages,
            "malicious_versions": total_versions,
            "compromised_hashes": total_hashes,
        }


def create_detector() -> IOCDetector:
    """Create a new IOC detector with default settings.
    
    Returns:
        IOCDetector instance with LiteLLM IOC loaded.
    """
    return IOCDetector()


def scan_file_for_iocs(result: ScanResult) -> list[IOCMatch]:
    """Scan a ScanResult for IOC matches.
    
    This is a convenience function to scan an existing scan result
    for IOC matches and add them to the result.
    
    Args:
        result: The scan result to check.
        
    Returns:
        List of IOC matches found.
    """
    detector = create_detector()
    matches = detector.scan_packages(result.packages)
    
    # Update the scan result
    result.ioc_matches.extend(matches)
    
    # Create vulnerabilities for IOC matches
    for match in matches:
        vuln = detector.create_vulnerability(match.package, match.ioc_data)
        result.vulnerabilities.append(vuln)
    
    return matches
