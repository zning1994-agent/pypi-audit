"""Unit tests for the scanner engine core functionality."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

from src.pypi_audit.scanner import Scanner
from src.pypi_audit.models import (
    Dependency,
    Vulnerability,
    VulnerabilityFinding,
    ScanResult,
    SeverityLevel,
    VulnerabilitySource,
)


class TestScannerInitialization:
    """Tests for Scanner initialization and configuration."""

    def test_scanner_default_initialization(self):
        """Test scanner initializes with default settings."""
        scanner = Scanner()
        
        assert scanner.use_pypi_safety is True
        assert scanner.use_osv is True
        assert scanner.use_ioc is True
        assert scanner.api_timeout == 30

    def test_scanner_custom_initialization(self):
        """Test scanner initializes with custom settings."""
        scanner = Scanner(
            use_pypi_safety=False,
            use_osv=False,
            use_ioc=True,
            api_timeout=60,
        )
        
        assert scanner.use_pypi_safety is False
        assert scanner.use_osv is False
        assert scanner.use_ioc is True
        assert scanner.api_timeout == 60

    def test_scanner_lazy_client_creation(self):
        """Test that API clients are created lazily."""
        scanner = Scanner()
        
        # Clients should be None initially
        assert scanner._pypi_client is None
        assert scanner._osv_client is None
        assert scanner._ioc_detector is None
        
        # Accessing properties should create clients
        _ = scanner.pypi_client
        _ = scanner.osv_client
        _ = scanner.ioc_detector
        
        # Now they should be created
        assert scanner._pypi_client is not None
        assert scanner._osv_client is not None
        assert scanner._ioc_detector is not None


class TestScanFile:
    """Tests for Scanner.scan_file method."""

    def test_scan_file_success(self, temp_requirements_file, scanner_with_mocks):
        """Test successful scan of a requirements.txt file."""
        # Setup mock to return vulnerabilities
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_file(str(temp_requirements_file))
        
        assert isinstance(result, ScanResult)
        assert result.total_dependencies == 3  # 2 normal + 1 with extras comment
        assert len(result.files_scanned) == 1
        assert str(temp_requirements_file) in result.files_scanned

    def test_scan_file_nonexistent_raises_error(self, scanner_with_mocks):
        """Test that scanning non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            scanner_with_mocks.scan_file("/nonexistent/path/requirements.txt")

    def test_scan_file_unsupported_type(self, scanner_with_mocks):
        """Test that scanning unsupported file type raises ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".unknown", delete=False) as f:
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Unsupported file type"):
                scanner_with_mocks.scan_file(temp_path)
        finally:
            os.unlink(temp_path)

    def test_scan_file_with_vulnerabilities(
        self,
        temp_requirements_file,
        scanner_with_mocks,
        sample_vulnerability,
    ):
        """Test scan detects vulnerabilities correctly."""
        # Setup mock to return a vulnerability
        scanner_with_mocks._pypi_client.check_package.return_value = [sample_vulnerability]
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_file(str(temp_requirements_file))
        
        assert result.has_findings is True
        assert len(result.vulnerabilities) >= 1

    def test_scan_pyproject_file(self, temp_pyproject_file, scanner_with_mocks):
        """Test scanning pyproject.toml file."""
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_file(str(temp_pyproject_file))
        
        assert isinstance(result, ScanResult)
        assert result.total_dependencies >= 2  # main + dev dependencies

    def test_scan_pipfile_lock(self, temp_pipfile_lock, scanner_with_mocks):
        """Test scanning Pipfile.lock file."""
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_file(str(temp_pipfile_lock))
        
        assert isinstance(result, ScanResult)
        assert result.total_dependencies >= 2


class TestScanDirectory:
    """Tests for Scanner.scan_directory method."""

    def test_scan_directory_success(self, temp_directory_with_deps, scanner_with_mocks):
        """Test successful scan of directory with multiple dependency files."""
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_directory(str(temp_directory_with_deps))
        
        assert isinstance(result, ScanResult)
        assert result.total_dependencies >= 4  # All deps from all files
        assert len(result.files_scanned) == 3  # All three files

    def test_scan_directory_nonexistent_raises_error(self, scanner_with_mocks):
        """Test that scanning non-existent directory raises error."""
        with pytest.raises(NotADirectoryError):
            scanner_with_mocks.scan_directory("/nonexistent/path")

    def test_scan_directory_partial_files(self, tmp_path, scanner_with_mocks):
        """Test directory scan with only some dependency files present."""
        # Create only requirements.txt
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_directory(str(tmp_path))
        
        assert result.total_dependencies == 1
        assert len(result.files_scanned) == 1

    def test_scan_directory_empty(self, tmp_path, scanner_with_mocks):
        """Test directory scan with no dependency files."""
        result = scanner_with_mocks.scan_directory(str(tmp_path))
        
        assert result.total_dependencies == 0
        assert len(result.files_scanned) == 0


class TestCheckDependency:
    """Tests for Scanner._check_dependency method."""

    def test_check_dependency_with_pypi_safety(
        self,
        scanner_with_mocks,
        sample_dependency,
        sample_vulnerability,
    ):
        """Test dependency check with PyPI Safety API."""
        scanner_with_mocks._pypi_client.check_package.return_value = [sample_vulnerability]
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        findings = scanner_with_mocks._check_dependency(sample_dependency)
        
        assert len(findings) == 1
        assert findings[0].dependency == sample_dependency
        assert findings[0].vulnerability == sample_vulnerability
        assert findings[0].is_ioc_match is False

    def test_check_dependency_with_osv(
        self,
        scanner_with_mocks,
        sample_dependency,
    ):
        """Test dependency check with OSV API."""
        osv_vuln = Vulnerability(
            id="OSV-123",
            package_name="requests",
            affected_versions="<2.28.1",
            severity=SeverityLevel.MEDIUM,
            source=VulnerabilitySource.OSV,
            description="OSV vulnerability",
        )
        
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = [osv_vuln]
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        findings = scanner_with_mocks._check_dependency(sample_dependency)
        
        assert len(findings) == 1
        assert findings[0].vulnerability.source == VulnerabilitySource.OSV

    def test_check_dependency_with_ioc(
        self,
        scanner_with_mocks,
        sample_dependency_malicious,
    ):
        """Test dependency check with IOC detector."""
        ioc_vuln = Vulnerability(
            id="IOC-litellm-20260324",
            package_name="litellm",
            affected_versions="*",
            severity=SeverityLevel.CRITICAL,
            source=VulnerabilitySource.IOC_DETECTOR,
            description="LiteLLM supply chain attack",
        )
        
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = [ioc_vuln]
        
        findings = scanner_with_mocks._check_dependency(sample_dependency_malicious)
        
        assert len(findings) == 1
        assert findings[0].is_ioc_match is True
        assert findings[0].ioc_details is not None

    def test_check_dependency_multiple_sources(
        self,
        scanner_with_mocks,
        sample_dependency,
        sample_vulnerability,
    ):
        """Test dependency check from multiple vulnerability sources."""
        osv_vuln = Vulnerability(
            id="OSV-456",
            package_name="requests",
            affected_versions="<2.29.0",
            severity=SeverityLevel.HIGH,
            source=VulnerabilitySource.OSV,
            description="OSV vulnerability",
        )
        
        scanner_with_mocks._pypi_client.check_package.return_value = [sample_vulnerability]
        scanner_with_mocks._osv_client.check_package.return_value = [osv_vuln]
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        findings = scanner_with_mocks._check_dependency(sample_dependency)
        
        assert len(findings) == 2

    def test_check_dependency_no_vulnerabilities(
        self,
        scanner_with_mocks,
        sample_dependency,
    ):
        """Test dependency check with no vulnerabilities found."""
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        findings = scanner_with_mocks._check_dependency(sample_dependency)
        
        assert len(findings) == 0

    def test_check_dependency_pypi_disabled(
        self,
        sample_dependency,
        sample_vulnerability,
    ):
        """Test dependency check when PyPI Safety is disabled."""
        scanner = Scanner(use_pypi_safety=False, use_osv=True, use_ioc=True)
        scanner._pypi_client = MagicMock()
        scanner._osv_client = MagicMock()
        scanner._ioc_detector = MagicMock()
        
        scanner._pypi_client.check_package.return_value = [sample_vulnerability]
        scanner._osv_client.check_package.return_value = []
        scanner._ioc_detector.check_package.return_value = []
        
        findings = scanner._check_dependency(sample_dependency)
        
        # Should not call PyPI client when disabled
        assert scanner._pypi_client.check_package.call_count == 0
        assert len(findings) == 0

    def test_check_dependency_osv_disabled(self, sample_dependency):
        """Test dependency check when OSV is disabled."""
        scanner = Scanner(use_pypi_safety=True, use_osv=False, use_ioc=True)
        scanner._pypi_client = MagicMock()
        scanner._osv_client = MagicMock()
        scanner._ioc_detector = MagicMock()
        
        scanner._pypi_client.check_package.return_value = []
        scanner._osv_client.check_package.return_value = [MagicMock()]
        scanner._ioc_detector.check_package.return_value = []
        
        findings = scanner._check_dependency(sample_dependency)
        
        assert scanner._osv_client.check_package.call_count == 0
        assert len(findings) == 0

    def test_check_dependency_ioc_disabled(self, sample_dependency_malicious):
        """Test dependency check when IOC is disabled."""
        scanner = Scanner(use_pypi_safety=True, use_osv=True, use_ioc=False)
        scanner._pypi_client = MagicMock()
        scanner._osv_client = MagicMock()
        scanner._ioc_detector = MagicMock()
        
        scanner._pypi_client.check_package.return_value = []
        scanner._osv_client.check_package.return_value = []
        scanner._ioc_detector.check_package.return_value = [MagicMock()]
        
        findings = scanner._check_dependency(sample_dependency_malicious)
        
        assert scanner._ioc_detector.check_package.call_count == 0
        assert len(findings) == 0

    def test_check_dependency_api_error_handling(self, scanner_with_mocks, sample_dependency):
        """Test that API errors are handled gracefully."""
        scanner_with_mocks._pypi_client.check_package.side_effect = Exception("API Error")
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        # Should not raise, should return empty list
        findings = scanner_with_mocks._check_dependency(sample_dependency)
        assert len(findings) == 0


class TestGetSummary:
    """Tests for Scanner.get_summary method."""

    def test_get_summary_with_findings(self, scanner_with_mocks, multiple_dependencies):
        """Test summary generation with vulnerabilities."""
        # Create some findings
        findings = [
            VulnerabilityFinding(
                dependency=multiple_dependencies[0],
                vulnerability=Vulnerability(
                    id="VULN-001",
                    package_name="requests",
                    affected_versions="<2.28.1",
                    severity=SeverityLevel.CRITICAL,
                    source=VulnerabilitySource.PYPI_SAFETY,
                ),
            ),
            VulnerabilityFinding(
                dependency=multiple_dependencies[1],
                vulnerability=Vulnerability(
                    id="VULN-002",
                    package_name="flask",
                    affected_versions="<2.1.0",
                    severity=SeverityLevel.HIGH,
                    source=VulnerabilitySource.OSV,
                ),
            ),
        ]
        
        result = ScanResult(
            dependencies=multiple_dependencies,
            vulnerabilities=findings,
            scan_time=1.5,
            files_scanned=["requirements.txt"],
        )
        
        summary = scanner_with_mocks.get_summary(result)
        
        assert summary["total_dependencies"] == 4
        assert summary["vulnerable_dependencies"] == 2
        assert summary["total_vulnerabilities"] == 2
        assert summary["critical_count"] == 1
        assert summary["ioc_matches"] == 0
        assert "1.50s" in summary["scan_time"]
        assert summary["files_scanned"] == 1

    def test_get_summary_no_findings(self, scanner_with_mocks, multiple_dependencies):
        """Test summary generation with no vulnerabilities."""
        result = ScanResult(
            dependencies=multiple_dependencies,
            vulnerabilities=[],
            scan_time=0.5,
            files_scanned=["requirements.txt", "pyproject.toml"],
        )
        
        summary = scanner_with_mocks.get_summary(result)
        
        assert summary["total_dependencies"] == 4
        assert summary["vulnerable_dependencies"] == 0
        assert summary["total_vulnerabilities"] == 0
        assert summary["critical_count"] == 0
        assert summary["ioc_matches"] == 0

    def test_get_summary_with_ioc_matches(self, scanner_with_mocks):
        """Test summary generation with IOC matches."""
        malicious_dep = Dependency(
            name="litellm",
            version="1.0.0",
            source_file="requirements.txt",
        )
        
        findings = [
            VulnerabilityFinding(
                dependency=malicious_dep,
                vulnerability=Vulnerability(
                    id="IOC-litellm-20260324",
                    package_name="litellm",
                    affected_versions="*",
                    severity=SeverityLevel.CRITICAL,
                    source=VulnerabilitySource.IOC_DETECTOR,
                ),
                is_ioc_match=True,
                ioc_details="LiteLLM supply chain attack",
            ),
        ]
        
        result = ScanResult(
            dependencies=[malicious_dep],
            vulnerabilities=findings,
            scan_time=0.3,
            files_scanned=["requirements.txt"],
        )
        
        summary = scanner_with_mocks.get_summary(result)
        
        assert summary["ioc_matches"] == 1
        assert summary["critical_count"] == 1


class TestScanResult:
    """Tests for ScanResult model properties."""

    def test_total_dependencies(self):
        """Test total_dependencies property."""
        deps = [
            Dependency(name="a", version="1.0"),
            Dependency(name="b", version="2.0"),
            Dependency(name="c", version="3.0"),
        ]
        result = ScanResult(dependencies=deps)
        
        assert result.total_dependencies == 3

    def test_vulnerable_dependencies(self):
        """Test vulnerable_dependencies property."""
        deps = [
            Dependency(name="a", version="1.0"),
            Dependency(name="b", version="2.0"),
        ]
        findings = [
            VulnerabilityFinding(
                dependency=deps[0],
                vulnerability=MagicMock(),
            ),
            VulnerabilityFinding(
                dependency=deps[0],
                vulnerability=MagicMock(),
            ),
            VulnerabilityFinding(
                dependency=deps[1],
                vulnerability=MagicMock(),
            ),
        ]
        result = ScanResult(dependencies=deps, vulnerabilities=findings)
        
        assert result.vulnerable_dependencies == 2

    def test_critical_count(self):
        """Test critical_count property."""
        deps = [Dependency(name="a", version="1.0")]
        
        critical_vuln = Vulnerability(
            id="1",
            package_name="a",
            affected_versions="*",
            severity=SeverityLevel.CRITICAL,
            source=VulnerabilitySource.PYPI_SAFETY,
        )
        high_vuln = Vulnerability(
            id="2",
            package_name="a",
            affected_versions="*",
            severity=SeverityLevel.HIGH,
            source=VulnerabilitySource.PYPI_SAFETY,
        )
        
        findings = [
            VulnerabilityFinding(dependency=deps[0], vulnerability=critical_vuln),
            VulnerabilityFinding(dependency=deps[0], vulnerability=critical_vuln),
            VulnerabilityFinding(dependency=deps[0], vulnerability=high_vuln),
        ]
        
        result = ScanResult(dependencies=deps, vulnerabilities=findings)
        
        assert result.critical_count == 2

    def test_has_findings(self):
        """Test has_findings property."""
        result_empty = ScanResult(dependencies=[], vulnerabilities=[])
        assert result_empty.has_findings is False
        
        result_with = ScanResult(
            dependencies=[Dependency(name="a", version="1.0")],
            vulnerabilities=[
                VulnerabilityFinding(
                    dependency=Dependency(name="a", version="1.0"),
                    vulnerability=MagicMock(),
                ),
            ],
        )
        assert result_with.has_findings is True


class TestScanTime:
    """Tests for scan timing functionality."""

    def test_scan_file_calculates_time(self, temp_requirements_file, scanner_with_mocks):
        """Test that scan_file calculates scan time."""
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_file(str(temp_requirements_file))
        
        assert result.scan_time >= 0

    def test_scan_directory_calculates_time(
        self,
        temp_directory_with_deps,
        scanner_with_mocks,
    ):
        """Test that scan_directory calculates scan time."""
        scanner_with_mocks._pypi_client.check_package.return_value = []
        scanner_with_mocks._osv_client.check_package.return_value = []
        scanner_with_mocks._ioc_detector.check_package.return_value = []
        
        result = scanner_with_mocks.scan_directory(str(temp_directory_with_deps))
        
        assert result.scan_time >= 0


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_requirements_file(self, scanner_with_mocks):
        """Test scanning empty requirements file."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            prefix="requirements",
        ) as f:
            f.write("# Just a comment\n")
            f.write("  \n")
            temp_path = f.name
        
        try:
            scanner_with_mocks._pypi_client.check_package.return_value = []
            scanner_with_mocks._osv_client.check_package.return_value = []
            scanner_with_mocks._ioc_detector.check_package.return_value = []
            
            result = scanner_with_mocks.scan_file(temp_path)
            
            assert result.total_dependencies == 0
        finally:
            os.unlink(temp_path)

    def test_malformed_requirements_lines(self, scanner_with_mocks):
        """Test scanning requirements with malformed lines."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            prefix="requirements",
        ) as f:
            f.write("valid-package==1.0.0\n")
            f.write("--index-url https://pypi.org/simple\n")
            f.write("-r other-requirements.txt\n")
            f.write("-e git+https://github.com/user/repo.git\n")
            f.write("another-valid>=2.0.0\n")
            temp_path = f.name
        
        try:
            scanner_with_mocks._pypi_client.check_package.return_value = []
            scanner_with_mocks._osv_client.check_package.return_value = []
            scanner_with_mocks._ioc_detector.check_package.return_value = []
            
            result = scanner_with_mocks.scan_file(temp_path)
            
            assert result.total_dependencies == 2
        finally:
            os.unlink(temp_path)

    def test_case_sensitivity_in_dependencies(self, scanner_with_mocks):
        """Test that dependency names are normalized."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            prefix="requirements",
        ) as f:
            f.write("Requests==2.28.0\n")
            f.write("FLASK>=2.0.0\n")
            temp_path = f.name
        
        try:
            scanner_with_mocks._pypi_client.check_package.return_value = []
            scanner_with_mocks._osv_client.check_package.return_value = []
            scanner_with_mocks._ioc_detector.check_package.return_value = []
            
            result = scanner_with_mocks.scan_file(temp_path)
            
            names = [dep.name for dep in result.dependencies]
            assert all(name == name.lower() for name in names)
        finally:
            os.unlink(temp_path)

    def test_special_characters_in_version(self, scanner_with_mocks):
        """Test parsing versions with special characters."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            prefix="requirements",
        ) as f:
            f.write("package1==1.0.0+local\n")
            f.write("package2==2.0.0rc1\n")
            f.write("package3>=3.0.0,<4.0.0\n")
            temp_path = f.name
        
        try:
            scanner_with_mocks._pypi_client.check_package.return_value = []
            scanner_with_mocks._osv_client.check_package.return_value = []
            scanner_with_mocks._ioc_detector.check_package.return_value = []
            
            result = scanner_with_mocks.scan_file(temp_path)
            
            assert result.total_dependencies == 3
        finally:
            os.unlink(temp_path)
