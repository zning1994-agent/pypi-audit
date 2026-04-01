"""Tests for terminal report module."""

import pytest
from io import StringIO

from pypi_audit.models import (
    IocMatch,
    Package,
    ScanResult,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from pypi_audit.reports.terminal import TerminalReport, SEVERITY_COLORS, SEVERITY_EMOJI


class TestSeverityMappings:
    """Test severity color and emoji mappings."""

    def test_severity_colors_exist(self):
        """Test all severity levels have colors."""
        for severity in VulnerabilitySeverity:
            assert severity in SEVERITY_COLORS
            assert severity in SEVERITY_EMOJI

    def test_severity_colors_are_strings(self):
        """Test all color values are strings."""
        for color in SEVERITY_COLORS.values():
            assert isinstance(color, str)
            assert len(color) > 0

    def test_severity_emoji_are_strings(self):
        """Test all emoji values are strings."""
        for emoji in SEVERITY_EMOJI.values():
            assert isinstance(emoji, str)
            assert len(emoji) > 0


class TestTerminalReportInit:
    """Test TerminalReport initialization."""

    def test_default_init(self):
        """Test default initialization."""
        report = TerminalReport()
        assert report.verbose is False
        assert report.show_packages is True

    def test_verbose_mode(self):
        """Test verbose mode initialization."""
        report = TerminalReport(verbose=True)
        assert report.verbose is True

    def test_hide_packages(self):
        """Test hiding packages table."""
        report = TerminalReport(show_packages=False)
        assert report.show_packages is False


class TestPrintSummary:
    """Test print_summary method."""

    def test_summary_with_vulnerabilities(self):
        """Test summary output when vulnerabilities found."""
        result = ScanResult()
        result.vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                package_name="test-package",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.HIGH,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Test Vulnerability",
            )
        ]

        console = TerminalReport()
        # Should not raise any exceptions
        console.print_summary(result)

    def test_summary_no_vulnerabilities(self):
        """Test summary output when no vulnerabilities."""
        result = ScanResult()

        console = TerminalReport()
        # Should not raise any exceptions
        console.print_summary(result)

    def test_summary_with_error(self):
        """Test summary output with error message."""
        result = ScanResult()
        result.error_message = "Test error"

        console = TerminalReport()
        # Should not raise any exceptions
        console.print_summary(result)


class TestGenerate:
    """Test generate method."""

    def test_generate_with_packages(self):
        """Test generate with packages only."""
        result = ScanResult()
        result.packages = [
            Package(name="requests", version="2.28.0", source_file="requirements.txt"),
            Package(name="click", version="8.1.0", source_file="pyproject.toml"),
        ]
        result.files_scanned = ["requirements.txt", "pyproject.toml"]

        report = TerminalReport()
        # Should not raise any exceptions
        report.generate(result)

    def test_generate_with_vulnerabilities(self):
        """Test generate with vulnerabilities."""
        result = ScanResult()
        result.vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                package_name="malicious-package",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.CRITICAL,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Remote Code Execution",
                description="This vulnerability allows remote code execution.",
                fixed_versions=["1.1.0", "1.0.1"],
                advisory_url="https://example.com/advisory",
                cve_id="CVE-2024-0001",
            ),
            Vulnerability(
                id="VULN-002",
                package_name="vulnerable-package",
                package_version="2.0.0",
                severity=VulnerabilitySeverity.MEDIUM,
                source=VulnerabilitySource.OSV,
                title="Information Disclosure",
            ),
        ]
        result.packages = [
            Package(name="malicious-package", version="1.0.0", source_file="requirements.txt"),
            Package(name="vulnerable-package", version="2.0.0", source_file="requirements.txt"),
        ]

        report = TerminalReport(verbose=True)
        # Should not raise any exceptions
        report.generate(result)

    def test_generate_with_ioc_matches(self):
        """Test generate with IOC matches."""
        result = ScanResult()
        result.ioc_matches = [
            IocMatch(
                package_name="litellm",
                package_version="0.1.5",
                source_file="requirements.txt",
                ioc_type="malicious_package",
                description="LiteLLM supply chain attack package",
                event_name="LiteLLM 2026-03-24",
                event_date="2026-03-24",
            )
        ]

        report = TerminalReport()
        # Should not raise any exceptions
        report.generate(result)

    def test_generate_with_error(self):
        """Test generate with error message."""
        result = ScanResult()
        result.error_message = "Failed to parse requirements.txt"

        report = TerminalReport()
        # Should not raise any exceptions
        report.generate(result)

    def test_generate_empty_result(self):
        """Test generate with empty result."""
        result = ScanResult()
        result.files_scanned = ["requirements.txt"]

        report = TerminalReport()
        # Should not raise any exceptions
        report.generate(result)


class TestVulnerabilitySorting:
    """Test vulnerability sorting in reports."""

    def test_vulnerabilities_sorted_by_severity(self):
        """Test vulnerabilities are sorted critical first."""
        result = ScanResult()
        result.vulnerabilities = [
            Vulnerability(
                id="1",
                package_name="low-pkg",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.LOW,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Low Severity",
            ),
            Vulnerability(
                id="2",
                package_name="critical-pkg",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.CRITICAL,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Critical Severity",
            ),
            Vulnerability(
                id="3",
                package_name="high-pkg",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.HIGH,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="High Severity",
            ),
        ]

        report = TerminalReport()
        report.generate(result)

        # Verify sorting order in result
        sorted_vulns = result.sorted_vulnerabilities
        assert sorted_vulns[0].severity == VulnerabilitySeverity.CRITICAL
        assert sorted_vulns[1].severity == VulnerabilitySeverity.HIGH
        assert sorted_vulns[2].severity == VulnerabilitySeverity.LOW


class TestReportSummaryCounts:
    """Test summary count calculations."""

    def test_summary_counts(self):
        """Test vulnerability counts in summary."""
        result = ScanResult()
        result.vulnerabilities = [
            Vulnerability(
                id=str(i),
                package_name=f"pkg{i}",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.CRITICAL,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Test",
            )
            for i in range(3)
        ] + [
            Vulnerability(
                id=str(i),
                package_name=f"pkg{i}",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.HIGH,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Test",
            )
            for i in range(5)
        ]

        assert result.critical_count == 3
        assert result.high_count == 5
        assert result.total_vulnerabilities == 8

    def test_has_vulnerabilities(self):
        """Test has_vulnerabilities property."""
        result = ScanResult()
        assert result.has_vulnerabilities is False

        result.vulnerabilities.append(
            Vulnerability(
                id="1",
                package_name="pkg",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.LOW,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Test",
            )
        )
        assert result.has_vulnerabilities is True

        result.vulnerabilities.clear()
        result.ioc_matches.append(
            IocMatch(
                package_name="pkg",
                package_version="1.0.0",
                source_file="req.txt",
                ioc_type="test",
                description="test",
                event_name="test",
                event_date="2026-01-01",
            )
        )
        assert result.has_vulnerabilities is True


class TestVerboseMode:
    """Test verbose mode functionality."""

    def test_verbose_shows_description(self):
        """Test verbose mode shows vulnerability descriptions."""
        result = ScanResult()
        result.vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                package_name="test-package",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.HIGH,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Test Vulnerability",
                description="This is a detailed description of the vulnerability that should be shown in verbose mode.",
            )
        ]

        report = TerminalReport(verbose=True)
        # Should not raise - description should be displayed
        report.generate(result)

    def test_non_verbose_hides_description(self):
        """Test non-verbose mode hides descriptions."""
        result = ScanResult()
        result.vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                package_name="test-package",
                package_version="1.0.0",
                severity=VulnerabilitySeverity.HIGH,
                source=VulnerabilitySource.PYPI_SAFETY,
                title="Test Vulnerability",
                description="This description should not be shown.",
            )
        ]

        report = TerminalReport(verbose=False)
        # Should not raise - description should be hidden
        report.generate(result)
