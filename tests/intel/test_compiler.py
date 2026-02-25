# Copyright 2025 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
