"""Tests for LiteLLM 2026-03-24 IOC data module."""

import pytest

from pypi_audit.ioc.litellm_2026 import (
    LITE_LLM_IOC,
    MALICIOUS_PACKAGES,
    MALICIOUS_VERSIONS,
    COMPROMISED_HASHES,
    INDICATORS,
    EVENT_DATE,
    check_package_name,
    check_version,
    is_litellm_ioc_package,
    get_litellm_ioc,
    LiteLLMIOCData,
)


class TestLiteLLMIOCData:
    """Tests for LiteLLMIOCData class."""
    
    def test_singleton_instance(self):
        """Test that LITE_LLM_IOC is a singleton."""
        ioc1 = get_litellm_ioc()
        ioc2 = get_litellm_ioc()
        assert ioc1 is ioc2
    
    def test_ioc_has_malicious_packages(self):
        """Test that IOC data contains malicious packages."""
        assert len(LITE_LLM_IOC.malicious_packages) > 0
        assert "litellm" in LITE_LLM_IOC.malicious_packages
    
    def test_ioc_has_malicious_versions(self):
        """Test that IOC data contains malicious versions."""
        assert len(LITE_LLM_IOC.malicious_versions) > 0
        assert "litellm" in LITE_LLM_IOC.malicious_versions
        assert len(LITE_LLM_IOC.malicious_versions["litellm"]) > 0
    
    def test_ioc_has_compromised_hashes(self):
        """Test that IOC data contains compromised hashes."""
        assert len(LITE_LLM_IOC.compromised_hashes) > 0
    
    def test_ioc_has_event_date(self):
        """Test that IOC data contains event date."""
        assert LITE_LLM_IOC.event_date == EVENT_DATE
        assert LITE_LLM_IOC.event_date == "2026-03-24"
    
    def test_ioc_has_description(self):
        """Test that IOC data contains description."""
        assert len(LITE_LLM_IOC.description) > 0
        assert "Supply Chain Attack" in LITE_LLM_IOC.description
    
    def test_ioc_has_indicators(self):
        """Test that IOC data contains additional indicators."""
        assert len(LITE_LLM_IOC.indicators) > 0
    
    def test_create_returns_filled_instance(self):
        """Test that create() returns a properly filled instance."""
        ioc = LiteLLMIOCData.create()
        assert ioc.malicious_packages == MALICIOUS_PACKAGES
        assert ioc.malicious_versions == MALICIOUS_VERSIONS
        assert ioc.compromised_hashes == COMPROMISED_HASHES
        assert ioc.indicators == INDICATORS


class TestCheckPackageName:
    """Tests for check_package_name function."""
    
    def test_detects_litellm_exact_match(self):
        """Test detection of exact litellm package name."""
        assert check_package_name("litellm") is True
    
    def test_detects_litellm_case_insensitive(self):
        """Test that package name matching is case insensitive."""
        assert check_package_name("LiteLLM") is True
        assert check_package_name("LITELLM") is True
        assert check_package_name("Litellm") is True
    
    def test_detects_openllm_typosquat(self):
        """Test detection of typosquatting variant."""
        assert check_package_name("openllm") is True
    
    def test_detects_llm_core_typosquat(self):
        """Test detection of llm-core typosquatting variant."""
        assert check_package_name("llm-core") is True
    
    def test_rejects_safe_package(self):
        """Test that safe packages are not flagged."""
        assert check_package_name("requests") is False
        assert check_package_name("numpy") is False
        assert check_package_name("pandas") is False
    
    def test_rejects_similar_names(self):
        """Test that similar but different names are not flagged."""
        assert check_package_name("litellm-extras") is False
        assert check_package_name("litellmproxy") is False
        assert check_package_name("litellm-api") is False


class TestCheckVersion:
    """Tests for check_version function."""
    
    def test_detects_malicious_version(self):
        """Test detection of known malicious version."""
        assert check_version("litellm", "1.0.0") is True
        assert check_version("litellm", "1.0.1") is True
        assert check_version("litellm", "1.0.2") is True
    
    def test_detects_malicious_rc_version(self):
        """Test detection of malicious release candidate versions."""
        assert check_version("litellm", "1.0.0rc1") is True
        assert check_version("litellm", "1.0.0rc2") is True
        assert check_version("litellm", "1.0.0rc3") is True
    
    def test_rejects_safe_version(self):
        """Test that safe versions are not flagged."""
        assert check_version("litellm", "0.5.0") is False
        assert check_version("litellm", "1.1.0") is False
    
    def test_rejects_other_package_versions(self):
        """Test that versions for other packages are not flagged."""
        assert check_version("requests", "1.0.0") is False
        assert check_version("numpy", "1.0.0") is False
    
    def test_case_insensitive_package_name(self):
        """Test that package name matching is case insensitive."""
        assert check_version("LiteLLM", "1.0.0") is True
        assert check_version("LITELLM", "1.0.0") is True


class TestIsLitellmIocPackage:
    """Tests for is_litellm_ioc_package function."""
    
    def test_returns_true_for_litellm(self):
        """Test that litellm is identified as IOC package."""
        assert is_litellm_ioc_package("litellm") is True
    
    def test_returns_true_for_typosquat_variants(self):
        """Test that typosquat variants are identified."""
        assert is_litellm_ioc_package("openllm") is True
        assert is_litellm_ioc_package("llm-core") is True
    
    def test_returns_false_for_safe_packages(self):
        """Test that safe packages are not identified."""
        assert is_litellm_ioc_package("boto3") is False
        assert is_litellm_ioc_package("openai") is False


class TestLiteLLMIOCConsistency:
    """Tests for consistency between IOC data structures."""
    
    def test_all_malicious_packages_have_versions(self):
        """Test that all malicious packages have associated versions."""
        for package in MALICIOUS_PACKAGES:
            assert package in MALICIOUS_VERSIONS
            assert len(MALICIOUS_VERSIONS[package]) > 0
    
    def test_all_packages_in_versions_have_entries(self):
        """Test that packages in versions dict are in malicious packages."""
        for package in MALICIOUS_VERSIONS:
            assert package in MALICIOUS_PACKAGES
    
    def test_event_date_format(self):
        """Test that event date follows expected format."""
        import re
        pattern = r"^\d{4}-\d{2}-\d{2}$"
        assert re.match(pattern, EVENT_DATE) is not None
    
    def test_hashes_are_valid_format(self):
        """Test that hashes look like valid SHA256 hashes."""
        import re
        pattern = r"^[a-f0-9]{64}$"
        for hashes in COMPROMISED_HASHES.values():
            for hash_value in hashes:
                assert re.match(pattern, hash_value) is not None
