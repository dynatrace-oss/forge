# Copyright (c) 2025 Dynatrace LLC. All rights reserved.
#
# This software and associated documentation files (the "Software") are being
# made available by Dynatrace LLC for the sole purpose of illustrating the
# implementation of certain algorithms which are published. Permission is
# hereby granted, free of charge, to any person obtaining a copy of the
# Software, to view and use the Software for internal, non-production,
# non-commercial purposes only. Without limiting the foregoing, the Software
# may not (i) be used to process live data or train, fine-tune, enrich or
# improve any machine learning or foundation model or other artificial
# intelligence model or system or (ii) distributed, sublicensed, modified, used
# to provide a service, or sold either alone or as part of or in combination
# with any other software. The Software shall at all times be considered the
# proprietary property of Dynatrace LLC.
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import pytest

from forge.intel.cache import RawCache, SourceType
from forge.intel.compiler import (
    IntelReport,
    ReportCompiler,
    VulnerableFunction,
    _infer_tech_from_description,
)


@pytest.fixture()
def cache(tmp_path):
    return RawCache(cache_dir=tmp_path / "raw")


@pytest.fixture()
def compiler(cache, tmp_path):
    return ReportCompiler(cache, compiled_dir=tmp_path / "compiled")


class TestReportCompiler:
    def test_compile_with_nvd(self, cache, compiler):
        cache.put(
            SourceType.NVD,
            "CVE-2024-1234",
            {
                "description": "SQL injection in login",
                "cwe_ids": ["CWE-89"],
                "severity": "critical",
                "cvss_score": 9.8,
                "affected_versions": ["<1.2.3"],
                "fix_versions": ["1.2.3"],
                "references": ["https://example.com/advisory"],
            },
        )
        report = compiler.compile("CVE-2024-1234")
        assert report.description == "SQL injection in login"
        assert report.cwe_ids == ["CWE-89"]
        assert report.cvss_score == pytest.approx(9.8)
        assert "nvd" in report.sources_used
        assert report.confidence > 0.0

    def test_compile_all_sources(self, cache, compiler):
        cache.put(SourceType.NVD, "CVE-2024-1234", {"description": "test"})
        cache.put(SourceType.GITHUB_ADVISORY, "CVE-2024-1234", {"description": "test2"})
        cache.put(SourceType.PATCH_DIFF, "CVE-2024-1234", {"changed_files": []})
        cache.put(SourceType.EXPLOIT_DB, "CVE-2024-1234", {"exploits": []})
        cache.put(SourceType.CONTAINER_INFO, "CVE-2024-1234", {"endpoints": []})
        cache.put(SourceType.TECH_STACK, "CVE-2024-1234", {"language": "python"})
        report = compiler.compile("CVE-2024-1234")
        assert len(report.sources_used) == 6
        assert report.confidence == pytest.approx(1.0)

    def test_save_and_load(self, compiler):
        report = IntelReport(
            cve_id="CVE-2024-5678",
            description="Test vulnerability",
            confidence=0.75,
            sources_used=["nvd", "patch-diff"],
        )
        compiler.save(report)
        loaded = compiler.load("CVE-2024-5678")
        assert loaded is not None
        assert loaded.cve_id == "CVE-2024-5678"
        assert loaded.confidence == pytest.approx(0.75)


class TestVulnerableFunctionModel:
    """Tests for the VulnerableFunction and updated PatchAnalysis models."""

    def test_vulnerable_function_defaults(self) -> None:
        vf = VulnerableFunction()
        assert vf.file_path == ""
        assert vf.function_name == ""
        assert vf.code == ""


class TestInferTechFromDescription:
    """Bug 6 regression: Ruby/Rack/Sinatra must be detected from free-text descriptions."""

    @pytest.mark.parametrize(
        ("text", "expected_lang", "expected_fw"),
        [
            ("Rack middleware vulnerability", "ruby", "rack"),
            ("Sinatra web application", "ruby", "sinatra"),
            ("Ruby on Rails controller", "ruby", "rails"),
            ("A vulnerability in a Ruby gem", "ruby", None),
            ("Flask web application", "python", "flask"),
            ("Spring Boot endpoint", "java", "spring-boot"),
            ("Express.js API server", "javascript", "express"),
        ],
        ids=["rack", "sinatra", "rails", "bare-ruby", "flask", "spring-boot", "express"],
    )
    def test_infer_tech(self, text: str, expected_lang: str, expected_fw: str | None) -> None:
        result = _infer_tech_from_description(text)
        assert result.get("language") == expected_lang, f"Expected {expected_lang}, got {result}"
        if expected_fw:
            assert result.get("framework") == expected_fw, (
                f"Expected fw={expected_fw}, got {result}"
            )

    def test_no_match_returns_empty(self) -> None:
        result = _infer_tech_from_description("completely unknown tech XYZ123")
        assert result == {}
