"""Tests for IOC detector module."""

import pytest

from pypi_audit.models import (
    IOCMatch,
    Package,
    ScanResult,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from pypi_audit.ioc.detector import (
    IOCDetector,
    create_detector,
    scan_file_for_iocs,
)
from pypi_audit.ioc.litellm_2026 import LITE_LLM_IOC


class TestIOCDetectorInit:
    """Tests for IOCDetector initialization."""
    
    def test_default_initialization(self):
        """Test that detector initializes with default IOC data."""
        detector = IOCDetector()
        assert len(detector.ioc_data) == 1
        assert LITE_LLM_IOC in detector.ioc_data
    
    def test_strict_mode_default(self):
        """Test that strict mode defaults to True."""
        detector = IOCDetector()
        assert detector.strict_mode is True
    
    def test_custom_ioc_data(self):
        """Test initialization with custom IOC data."""
        custom_ioc = LITE_LLM_IOC
        detector = IOCDetector(ioc_data=[custom_ioc])
        assert len(detector.ioc_data) == 1
    
    def test_empty_ioc_data_fallback(self):
        """Test that empty IOC data falls back to default."""
        detector = IOCDetector(ioc_data=[])
        assert len(detector.ioc_data) == 1


class TestCheckPackage:
    """Tests for check_package method."""
    
    def test_safe_package_returns_empty(self):
        """Test that safe packages return no matches."""
        detector = IOCDetector()
        package = Package(name="requests", version="2.28.0")
        matches = detector.check_package(package)
        assert len(matches) == 0
    
    def test_malicious_package_name_detected(self):
        """Test that malicious package names are detected."""
        detector = IOCDetector()
        package = Package(name="litellm", version="1.0.0")
        # This should trigger detection (returns True for name match)
        assert detector.check_litellm_package(package) is True
    
    def test_malicious_version_detected(self):
        """Test that malicious versions are detected."""
        detector = IOCDetector()
        package = Package(name="litellm", version="1.0.0")
        assert detector.check_litellm_version(package) is True
    
    def test_safe_version_not_detected(self):
        """Test that safe versions are not detected."""
        detector = IOCDetector()
        package = Package(name="litellm", version="0.5.0")
        assert detector.check_litellm_version(package) is False
    
    def test_case_insensitive_detection(self):
        """Test that detection is case insensitive."""
        detector = IOCDetector()
        package = Package(name="LiteLLM", version="1.0.0")
        assert detector.check_litellm_package(package) is True


class TestScanPackages:
    """Tests for scan_packages method."""
    
    def test_scan_empty_list(self):
        """Test scanning an empty package list."""
        detector = IOCDetector()
        matches = detector.scan_packages([])
        assert len(matches) == 0
    
    def test_scan_mixed_packages(self):
        """Test scanning a mix of safe and malicious packages."""
        detector = IOCDetector()
        packages = [
            Package(name="requests", version="2.28.0"),
            Package(name="numpy", version="1.24.0"),
            Package(name="litellm", version="1.0.0"),
        ]
        # Only litellm should be detected
        assert detector.check_litellm_package(packages[0]) is False
        assert detector.check_litellm_package(packages[1]) is False
        assert detector.check_litellm_package(packages[2]) is True
    
    def test_scan_all_safe_packages(self):
        """Test scanning only safe packages."""
        detector = IOCDetector()
        packages = [
            Package(name="requests", version="2.28.0"),
            Package(name="numpy", version="1.24.0"),
            Package(name="pandas", version="1.5.0"),
        ]
        for pkg in packages:
            assert detector.check_litellm_package(pkg) is False


class TestCreateVulnerability:
    """Tests for create_vulnerability method."""
    
    def test_creates_vulnerability_with_correct_data(self):
        """Test that vulnerability is created with correct data."""
        detector = IOCDetector()
        package = Package(name="litellm", version="1.0.0")
        vuln = detector.create_vulnerability(package, LITE_LLM_IOC)
        
        assert vuln.package_name == "litellm"
        assert vuln.package_version == "1.0.0"
        assert vuln.severity == Severity.CRITICAL
        assert vuln.source == VulnerabilitySource.IOC_LITELLM
        assert "LiteLLM" in vuln.title
        assert len(vuln.recommendations) > 0
    
    def test_vulnerability_has_recommendations(self):
        """Test that vulnerability includes recommendations."""
        detector = IOCDetector()
        package = Package(name="litellm", version="1.0.0")
        vuln = detector.create_vulnerability(package, LITE_LLM_IOC)
        
        assert len(vuln.recommendations) > 0
        assert any("remove" in r.lower() for r in vuln.recommendations)


class TestScanAndCreateVulnerabilities:
    """Tests for scan_and_create_vulnerabilities method."""
    
    def test_safe_packages_returns_empty(self):
        """Test that safe packages return no vulnerabilities."""
        detector = IOCDetector()
        packages = [
            Package(name="requests", version="2.28.0"),
            Package(name="numpy", version="1.24.0"),
        ]
        vulns = detector.scan_and_create_vulnerabilities(packages)
        assert len(vulns) == 0
    
    def test_malicious_package_returns_vulnerability(self):
        """Test that malicious packages return vulnerabilities."""
        detector = IOCDetector()
        packages = [
            Package(name="litellm", version="1.0.0"),
        ]
        vulns = detector.scan_and_create_vulnerabilities(packages)
        assert len(vulns) == 1
        assert vulns[0].severity == Severity.CRITICAL
    
    def test_multiple_malicious_packages(self):
        """Test multiple malicious packages."""
        detector = IOCDetector()
        packages = [
            Package(name="litellm", version="1.0.0"),
            Package(name="litellm", version="1.0.1"),
        ]
        vulns = detector.scan_and_create_vulnerabilities(packages)
        assert len(vulns) == 2


class TestAddIocSource:
    """Tests for add_ioc_source method."""
    
    def test_add_ioc_source(self):
        """Test adding a new IOC source."""
        detector = IOCDetector()
        initial_count = len(detector.ioc_data)
        
        detector.add_ioc_source(LITE_LLM_IOC)
        assert len(detector.ioc_data) == initial_count + 1
    
    def test_add_duplicate_ioc_source(self):
        """Test that duplicate IOC sources are not added."""
        detector = IOCDetector()
        detector.add_ioc_source(LITE_LLM_IOC)
        detector.add_ioc_source(LITE_LLM_IOC)
        # Should not duplicate since it's the same object
        assert len(detector.ioc_data) == 2


class TestGetIocSummary:
    """Tests for get_ioc_summary method."""
    
    def test_returns_summary_dict(self):
        """Test that summary returns expected structure."""
        detector = IOCDetector()
        summary = detector.get_ioc_summary()
        
        assert "ioc_sources" in summary
        assert "malicious_packages" in summary
        assert "malicious_versions" in summary
        assert "compromised_hashes" in summary
    
    def test_summary_values_positive(self):
        """Test that summary values are positive."""
        detector = IOCDetector()
        summary = detector.get_ioc_summary()
        
        assert summary["ioc_sources"] > 0
        assert summary["malicious_packages"] > 0


class TestCreateDetector:
    """Tests for create_detector factory function."""
    
    def test_returns_ioc_detector(self):
        """Test that factory returns IOCDetector instance."""
        detector = create_detector()
        assert isinstance(detector, IOCDetector)
    
    def test_detector_has_default_ioc(self):
        """Test that factory-created detector has default IOC."""
        detector = create_detector()
        assert len(detector.ioc_data) > 0


class TestScanFileForIocs:
    """Tests for scan_file_for_iocs convenience function."""
    
    def test_scan_safe_file(self):
        """Test scanning a file with only safe packages."""
        result = ScanResult(
            file_path="requirements.txt",
            file_type="requirements",
            packages=[
                Package(name="requests", version="2.28.0"),
            ],
        )
        matches = scan_file_for_iocs(result)
        assert len(matches) == 0
        assert len(result.ioc_matches) == 0
    
    def test_scan_malicious_file(self):
        """Test scanning a file with malicious packages."""
        result = ScanResult(
            file_path="requirements.txt",
            file_type="requirements",
            packages=[
                Package(name="litellm", version="1.0.0"),
            ],
        )
        matches = scan_file_for_iocs(result)
        # Results are added to result.ioc_matches
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].severity == Severity.CRITICAL
    
    def test_scan_empty_file(self):
        """Test scanning a file with no packages."""
        result = ScanResult(
            file_path="requirements.txt",
            file_type="requirements",
            packages=[],
        )
        matches = scan_file_for_iocs(result)
        assert len(matches) == 0


class TestIOCMatch:
    """Tests for IOCMatch data class."""
    
    def test_ioc_match_creation(self):
        """Test creating an IOCMatch."""
        package = Package(name="litellm", version="1.0.0")
        match = IOCMatch(
            package=package,
            ioc_data=LITE_LLM_IOC,
            matched_on="package_name",
            details="Package name matches malicious package list",
        )
        
        assert match.package.name == "litellm"
        assert match.matched_on == "package_name"
        assert len(match.details) > 0
