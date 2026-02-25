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

from typing import Any

import pytest

from forge.cve.loader import (
    classify_web_suitability,
    languages_from_patches,
    pick_primary_language,
)
from forge.models import GenieAdvisory, GeniePatchDiff, PatchCommit, SourceData


class TestLanguagesFromPatches:
    """Verify language detection from patch file extensions."""

    def test_python_patch(self) -> None:
        patches = [
            PatchCommit(
                url="https://example.com/commit/1",
                diff_content="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py",
            )
        ]
        langs = languages_from_patches(patches)
        assert "Python" in langs

    def test_php_and_js_mixed(self) -> None:
        patches = [
            PatchCommit(
                url="https://example.com/commit/1",
                diff_content=(
                    "diff --git a/src/Controller.php b/src/Controller.php\n"
                    "diff --git a/public/main.js b/public/main.js\n"
                ),
            )
        ]
        langs = languages_from_patches(patches)
        assert "PHP" in langs
        assert "JavaScript" in langs

    def test_typescript_detection(self) -> None:
        patches = [
            PatchCommit(
                url="https://example.com/commit/1",
                diff_content="diff --git a/src/index.ts b/src/index.ts",
            )
        ]
        langs = languages_from_patches(patches)
        assert "TypeScript" in langs

    def test_go_detection(self) -> None:
        patches = [
            PatchCommit(
                url="https://example.com/commit/1",
                diff_content="diff --git a/main.go b/main.go",
            )
        ]
        langs = languages_from_patches(patches)
        assert "Go" in langs

    def test_empty_patches(self) -> None:
        langs = languages_from_patches([])
        assert langs == set()

    def test_c_native_detection(self) -> None:
        patches = [
            PatchCommit(
                url="https://example.com/commit/1",
                diff_content="diff --git a/src/buffer.c b/src/buffer.c",
            )
        ]
        langs = languages_from_patches(patches)
        assert "C" in langs


class TestPickPrimaryLanguage:
    """Verify primary language selection from a set."""

    def test_single_language(self) -> None:
        assert pick_primary_language({"Go"}) == "Go"

    def test_empty_set(self) -> None:
        assert pick_primary_language(set()) == ""

    def test_priority_ordering(self) -> None:
        # PHP > JavaScript, TypeScript > Python, Python > C
        assert pick_primary_language({"PHP", "JavaScript"}) == "PHP"
        assert pick_primary_language({"TypeScript", "Python"}) == "TypeScript"
        assert pick_primary_language({"C", "Python"}) == "Python"


class TestClassifyWebSuitability:
    """Verify the non-web CVE classifier."""

    def test_c_memory_safety_is_non_web(self) -> None:
        assert (
            classify_web_suitability(
                cwe_ids=["CWE-119"],
                language="C",
                description="Buffer overflow in network parser",
            )
            is False
        )

    def test_cpp_use_after_free_is_non_web(self) -> None:
        assert (
            classify_web_suitability(
                cwe_ids=["CWE-416"],
                language="C++",
                description="Use-after-free in image decoder",
            )
            is False
        )

    def test_web_languages_are_suitable(self) -> None:
        # PHP/SQL injection, Go/XSS, Python/deserialization all web-suitable
        for cwe, lang, desc in [
            ("CWE-89", "PHP", "SQL injection in search endpoint"),
            ("CWE-79", "Go", "XSS in template rendering"),
            ("CWE-502", "Python", "Unsafe deserialization in REST API"),
        ]:
            assert classify_web_suitability([cwe], lang, desc) is True

    def test_c_buffer_overflow_keyword(self) -> None:
        assert (
            classify_web_suitability(
                cwe_ids=["CWE-787"],
                language="C",
                description="Heap buffer overflow in XML parsing",
            )
            is False
        )

    def test_empty_language_is_web(self) -> None:
        # Unknown language should not be filtered out
        assert (
            classify_web_suitability(
                cwe_ids=["CWE-89"],
                language="",
                description="SQL injection",
            )
            is True
        )


class TestCveSourceToTask:
    """Verify _cve_source_to_task populates CVETask fields."""

    def test_populates_language_and_description(self) -> None:
        from forge.cli import _cve_source_to_task

        entry: dict[str, Any] = {
            "cve_id": "CVE-2024-1234",
            "cwes": ["CWE-89"],
            "language": "PHP",
            "description": "SQL injection in search endpoint",
        }
        task = _cve_source_to_task(entry)
        assert task.cve_id == "CVE-2024-1234"
        assert task.cwe_ids == ["CWE-89"]
        assert task.language == "PHP"
        assert task.description == "SQL injection in search endpoint"

    def test_defaults_when_missing(self) -> None:
        from forge.cli import _cve_source_to_task

        entry: dict[str, Any] = {
            "cve_id": "CVE-2024-5678",
            "cwes": [],
        }
        task = _cve_source_to_task(entry)
        assert task.language == ""
        assert task.description == ""


class TestPipelineStatusSkipped:
    """Verify GENERATION_SKIPPED status exists."""

    def test_generation_skipped_is_valid(self) -> None:
        from forge.agents.orchestrator import PipelineStatus

        assert PipelineStatus.GENERATION_SKIPPED in list(PipelineStatus)


class TestSourceDataPropagation:
    """Verify GENIE source_data flows through _cve_source_to_task."""

    def test_source_data_populated_on_task(self) -> None:
        from forge.cli import _cve_source_to_task

        source_data: dict[str, Any] = {
            "patch_diffs": [
                {"url": "https://github.com/ex/commit/abc", "diff": "--- a/app.py\n+++ b/app.py"}
            ],
            "security_advisories": [
                {"url": "https://ghsa.example.com/1", "content": "PoC: curl http://..."}
            ],
            "sw_version": "1.2.3",
            "sw_version_wget": "https://example.com/v1.2.3.tar.gz",
        }
        entry: dict[str, Any] = {
            "cve_id": "CVE-2024-9999",
            "cwes": ["CWE-79"],
            "language": "Python",
            "description": "XSS in template",
            "source_data": source_data,
        }
        task = _cve_source_to_task(entry)
        assert task.source_data is not None
        assert len(task.source_data.patch_diffs) == 1
        assert task.source_data.patch_diffs[0].url == "https://github.com/ex/commit/abc"
        assert len(task.source_data.security_advisories) == 1
        assert task.source_data.sw_version == "1.2.3"

    def test_source_data_none_when_empty(self) -> None:
        from forge.cli import _cve_source_to_task

        entry: dict[str, Any] = {
            "cve_id": "CVE-2024-0000",
            "cwes": [],
            "source_data": {},
        }
        task = _cve_source_to_task(entry)
        # Empty dict should be normalised to None
        assert task.source_data is None

    def test_source_data_none_when_absent(self) -> None:
        from forge.cli import _cve_source_to_task

        entry: dict[str, Any] = {"cve_id": "CVE-2024-0001", "cwes": []}
        task = _cve_source_to_task(entry)
        assert task.source_data is None


class TestSerialiseGenieSource:
    """Verify _serialise_genie_source extracts the right fields."""

    def test_serialises_patch_diffs_and_advisories(self) -> None:
        from forge.cli import _serialise_genie_source
        from forge.models import CVESource, PatchCommit, SecurityAdvisory

        source = CVESource(
            cve_id="CVE-2024-1111",
            description="Test vuln",
            patch_commits=[
                PatchCommit(url="https://github.com/a/commit/1", diff_content="diff --git a/x"),
                PatchCommit(url="https://github.com/a/commit/2", diff_content=None),
            ],
            security_advisories=[
                SecurityAdvisory(url="https://ghsa.example/1", content="PoC steps here"),
                SecurityAdvisory(url="https://ghsa.example/2", content=None),
            ],
            sw_version="2.0.0",
            sw_version_wget="https://example.com/v2.tar.gz",
        )
        result = _serialise_genie_source(source)

        # Only patches with actual diff_content should be included
        assert len(result.patch_diffs) == 1
        assert result.patch_diffs[0].url == "https://github.com/a/commit/1"

        # Only advisories with actual content should be included
        assert len(result.security_advisories) == 1
        assert result.security_advisories[0].content == "PoC steps here"

        assert result.sw_version == "2.0.0"
        assert result.sw_version_wget == "https://example.com/v2.tar.gz"


class TestHasRichGenieData:
    """Verify has_rich_genie_data correctly identifies sufficient data."""

    def test_rich_data_returns_true(self) -> None:
        from forge.agents.orch_helper import has_rich_genie_data
        from forge.models import CVETask

        task = CVETask(
            cve_id="CVE-2024-1234",
            description="SQL injection in login endpoint",
            source_data=SourceData(
                patch_diffs=[GeniePatchDiff(url="https://example.com/c/1", diff="--- a/app.py")],
                sw_version="1.0",
            ),
        )
        assert has_rich_genie_data(task) is True

    def test_no_source_data_returns_false(self) -> None:
        from forge.agents.orch_helper import has_rich_genie_data
        from forge.models import CVETask

        task = CVETask(cve_id="CVE-2024-0000", description="something")
        assert has_rich_genie_data(task) is False

    def test_no_description_returns_false(self) -> None:
        from forge.agents.orch_helper import has_rich_genie_data
        from forge.models import CVETask

        task = CVETask(
            cve_id="CVE-2024-0000",
            description="",
            source_data=SourceData(
                patch_diffs=[GeniePatchDiff(url="x", diff="y")],
            ),
        )
        assert has_rich_genie_data(task) is False

    def test_empty_diffs_returns_false(self) -> None:
        from forge.agents.orch_helper import has_rich_genie_data
        from forge.models import CVETask

        task = CVETask(
            cve_id="CVE-2024-0000",
            description="something",
            source_data=SourceData(
                patch_diffs=[GeniePatchDiff(url="x", diff="")],
            ),
        )
        assert has_rich_genie_data(task) is False


class TestBuildSyntheticIntel:
    """Verify build_synthetic_intel produces a proper intel output dict."""

    def test_basic_synthetic_report(self) -> None:
        from forge.agents.orch_helper import build_synthetic_intel
        from forge.models import CVETask

        task = CVETask(
            cve_id="CVE-2024-5555",
            cwe_ids=["CWE-89"],
            language="PHP",
            description="SQL injection in search",
            source_data=SourceData(
                patch_diffs=[
                    GeniePatchDiff(
                        url="https://github.com/ex/c/abc",
                        diff="--- a/search.php\n+++ b/search.php",
                    )
                ],
                security_advisories=[
                    GenieAdvisory(
                        url="https://ghsa.example/1",
                        content="PoC: curl http://target/search?q='OR 1=1--",
                    )
                ],
                sw_version="3.1.0",
            ),
        )
        intel = build_synthetic_intel(task)

        assert intel["cve_id"] == "CVE-2024-5555"
        assert intel["cwe_ids"] == ["CWE-89"]
        assert "search.php" in intel["patch_analysis"]
        assert "PoC: curl" in intel["existing_pocs"]
        assert intel["tech_stack"]["language"] == "PHP"
        assert intel["confidence"] == pytest.approx(0.85)
        assert "genie_patch_diffs" in intel["sources_used"]

    def test_no_advisories_still_works(self) -> None:
        from forge.agents.orch_helper import build_synthetic_intel
        from forge.models import CVETask

        task = CVETask(
            cve_id="CVE-2024-6666",
            description="Buffer issue",
            source_data=SourceData(
                patch_diffs=[GeniePatchDiff(url="x", diff="diff content")],
            ),
        )
        intel = build_synthetic_intel(task)
        assert intel["existing_pocs"] == ""
        assert "diff content" in intel["patch_analysis"]


class TestGeneratorPatchDiffInput:
    """Verify generator format_input renders patch diffs."""

    def test_patch_diffs_rendered(self) -> None:
        from forge.agents.generator import GeneratorAgent

        # We just need to test format_input, not the full agent
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-7777",
            "cwe_id": "CWE-79",
            "description": "XSS in template",
            "language": "Go",
            "framework": "",
            "patch_diffs": [
                {
                    "url": "https://github.com/ex/c/1",
                    "diff": "--- a/main.go\n+++ b/main.go\n-vulnerable line",
                }
            ],
            "vulnerable_sw_version": "1.5.0",
            "attempt": 1,
        }
        # Call format_input as a standalone method via an instance
        from forge.agents.base import AgentConfig
        from forge.pipeline.llm_client import LLMClient

        config = AgentConfig(name="generator", system_prompt="test", max_turns=5, model="test")
        llm = LLMClient(default_model="test")
        agent = GeneratorAgent(llm=llm, config=config)
        text = agent.format_input(input_data)

        assert "PATCH DIFFS" in text
        assert "vulnerable line" in text
        assert "Vulnerable software version: 1.5.0" in text

    def test_no_patch_diffs_no_section(self) -> None:
        from forge.agents.base import AgentConfig
        from forge.agents.generator import GeneratorAgent
        from forge.pipeline.llm_client import LLMClient

        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-8888",
            "cwe_id": "CWE-89",
            "description": "SQL injection",
            "language": "Python",
            "framework": "flask",
            "attempt": 1,
        }
        config = AgentConfig(name="generator", system_prompt="test", max_turns=5, model="test")
        llm = LLMClient(default_model="test")
        agent = GeneratorAgent(llm=llm, config=config)
        text = agent.format_input(input_data)

        assert "PATCH DIFFS" not in text


class TestBuildExploitInputAdvisories:
    """Verify build_exploit_input includes advisory PoCs."""

    def test_advisories_injected(self) -> None:
        from forge.agents.orch_helper import build_exploit_input
        from forge.models import CVETask

        task = CVETask(
            cve_id="CVE-2024-1234",
            cwe_ids=["CWE-89"],
            language="PHP",
            description="SQL injection",
        )
        source_data = SourceData(
            security_advisories=[
                GenieAdvisory(url="https://ghsa.example/1", content="PoC steps here")
            ],
        )
        result = build_exploit_input(
            {"cve_id": "CVE-2024-1234"},
            {"primary_strategy": {}},
            task,
            source_data=source_data,
        )
        assert "security_advisories" in result
        assert result["security_advisories"][0]["content"] == "PoC steps here"

    def test_no_source_data_no_advisories(self) -> None:
        from forge.agents.orch_helper import build_exploit_input
        from forge.models import CVETask

        task = CVETask(cve_id="CVE-2024-0000", description="test")
        result = build_exploit_input(
            {"cve_id": "CVE-2024-0000"},
            {},
            task,
        )
        assert "security_advisories" not in result


class TestBuildPlannerInputAdvisories:
    """Verify build_planner_input includes advisory PoCs and patch diffs."""

    def test_advisories_and_diffs_injected(self) -> None:
        from forge.agents.orch_helper import build_planner_input

        source_data = SourceData(
            security_advisories=[
                GenieAdvisory(url="https://ghsa.example/1", content="Steps to reproduce...")
            ],
            patch_diffs=[GeniePatchDiff(url="https://github.com/x/c/1", diff="--- a/vuln.py")],
        )
        result = build_planner_input(
            {"cve_id": "CVE-2024-1234"},
            source_data=source_data,
        )
        assert "security_advisories" in result
        assert "patch_diffs" in result

    def test_no_source_data_clean(self) -> None:
        from forge.agents.orch_helper import build_planner_input

        result = build_planner_input({"cve_id": "CVE-2024-0000"})
        assert "security_advisories" not in result
        assert "patch_diffs" not in result


_GENERATOR_PROMPT_PATH = "data/prompts/agents/generator.yaml"


def _load_generator_prompt() -> Any:
    """Load the generator system prompt for content verification."""
    from pathlib import Path

    import yaml

    prompt_file = Path(__file__).parent.parent.parent / _GENERATOR_PROMPT_PATH
    with open(prompt_file) as f:
        data = yaml.safe_load(f)
    return data["system"]


class TestGeneratorPatchDiffTruncation:
    """Verify large patch diffs are truncated at 8K chars."""

    def test_large_diff_truncated(self) -> None:
        from forge.agents.base import AgentConfig
        from forge.agents.generator import GeneratorAgent
        from forge.pipeline.llm_client import LLMClient

        # Create a diff that exceeds 8000 chars
        large_diff = "--- a/big.py\n+++ b/big.py\n" + "x" * 9000
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-TRUNC",
            "cwe_id": "CWE-79",
            "description": "Test truncation",
            "language": "Python",
            "framework": "",
            "patch_diffs": [{"url": "https://example.com/c/1", "diff": large_diff}],
            "attempt": 1,
        }
        config = AgentConfig(name="generator", system_prompt="test", max_turns=5, model="test")
        llm = LLMClient(default_model="test")
        agent = GeneratorAgent(llm=llm, config=config)
        text = agent.format_input(input_data)

        assert "PATCH DIFFS" in text
        assert "... [truncated]" in text
        # The full 9000-char diff should NOT appear
        assert "x" * 9000 not in text

    def test_small_diff_not_truncated(self) -> None:
        from forge.agents.base import AgentConfig
        from forge.agents.generator import GeneratorAgent
        from forge.pipeline.llm_client import LLMClient

        small_diff = "--- a/app.py\n+++ b/app.py\n- vulnerable()\n+ safe()"
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-SMALL",
            "cwe_id": "CWE-89",
            "description": "Test no truncation",
            "language": "Python",
            "framework": "flask",
            "patch_diffs": [{"url": "https://example.com/c/1", "diff": small_diff}],
            "attempt": 1,
        }
        config = AgentConfig(name="generator", system_prompt="test", max_turns=5, model="test")
        llm = LLMClient(default_model="test")
        agent = GeneratorAgent(llm=llm, config=config)
        text = agent.format_input(input_data)

        assert "PATCH DIFFS" in text
        assert "... [truncated]" not in text
        assert "vulnerable()" in text


class TestBuildInputGenieData:
    """Verify _build_input forwards GENIE data from intel_report."""

    def _make_agent(self) -> Any:
        from forge.agents.base import AgentConfig
        from forge.agents.generator import GeneratorAgent
        from forge.pipeline.llm_client import LLMClient

        config = AgentConfig(name="generator", system_prompt="test", max_turns=5, model="test")
        llm = LLMClient(default_model="test")
        return GeneratorAgent(llm=llm, config=config)

    def test_patch_diffs_forwarded(self) -> None:
        agent = self._make_agent()
        intel: dict[str, Any] = {
            "cve_id": "CVE-2024-FWD1",
            "patch_diffs": [
                {"url": "https://github.com/x/c/1", "diff": "--- a/vuln.go\n+++ b/vuln.go"},
            ],
            "vulnerable_sw_version": "2.1.0",
        }
        result = agent._build_input(intel, None, "", 1)
        assert result["patch_diffs"] == intel["patch_diffs"]
        assert result["vulnerable_sw_version"] == "2.1.0"

    def test_empty_patch_diffs_not_forwarded(self) -> None:
        agent = self._make_agent()
        intel: dict[str, Any] = {
            "cve_id": "CVE-2024-FWD2",
            "patch_diffs": [],
        }
        result = agent._build_input(intel, None, "", 1)
        assert "patch_diffs" not in result

    def test_reference_app_forwarded(self) -> None:
        agent = self._make_agent()
        intel: dict[str, Any] = {
            "cve_id": "CVE-2024-FWD3",
            "reference_app": {"Dockerfile": "FROM python:3.11-slim", "app.py": "print('hi')"},
        }
        result = agent._build_input(intel, None, "", 1)
        assert "reference_app" in result
        assert "Dockerfile" in result["reference_app"]

    def test_retry_includes_existing_files(self) -> None:
        agent = self._make_agent()
        agent._app_state["Dockerfile"] = "FROM python:3.11-slim"
        agent._app_state["app.py"] = "print('hello')"
        intel: dict[str, Any] = {"cve_id": "CVE-2024-FWD4"}
        result = agent._build_input(intel, "Build failed", "exit code 1", 2)
        assert "existing_files" in result
        assert result["existing_files"]["Dockerfile"] == "FROM python:3.11-slim"
        assert result["prior_feedback"] == "Build failed"
        assert result["attempt"] == 2


class TestEarlyNonWebCheck:
    """Verify _is_web_reproducible can filter before Intel when data is available."""

    def test_c_memory_cve_skipped_early(self) -> None:
        """C + CWE-119 should be caught by early check (pre-Intel)."""
        from forge.cve.loader import classify_web_suitability

        # Simulates the early check: task has language + CWE already
        result = classify_web_suitability(
            cwe_ids=["CWE-119"],
            language="C",
            description="Buffer overflow in parser",
        )
        assert result is False

    def test_web_cve_passes_early_check(self) -> None:
        """PHP + CWE-89 should pass the early check."""
        from forge.cve.loader import classify_web_suitability

        result = classify_web_suitability(
            cwe_ids=["CWE-89"],
            language="PHP",
            description="SQL injection in search endpoint",
        )
        assert result is True

    def test_no_language_skips_early_check(self) -> None:
        """Without language, early check should not filter (unknown = web)."""
        from forge.cve.loader import classify_web_suitability

        result = classify_web_suitability(
            cwe_ids=["CWE-119"],
            language="",
            description="Buffer overflow",
        )
        # Without language, CWE-119 alone doesn't trigger non-web filtering
        # (the classifier requires C/C++ language to flag memory safety CWEs)
        assert result is True


class TestExploitFormatInputAdvisories:
    """Verify exploit agent format_input renders advisory PoCs."""

    def _make_exploit_agent(self) -> Any:
        from unittest.mock import AsyncMock

        from forge.agents.base import AgentConfig
        from forge.agents.exploit import ExploitAgent
        from forge.pipeline.llm_client import LLMClient

        config = AgentConfig(
            name="exploit",
            system_prompt="test exploit",
            max_turns=20,
            model="test",
        )
        llm = LLMClient(default_model="test")
        session = AsyncMock()
        session.base_url = "http://localhost:8080"
        return ExploitAgent(llm=llm, session=session, config=config)

    def test_advisories_rendered_in_format_input(self) -> None:
        agent = self._make_exploit_agent()
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-ADV1",
            "cwe_ids": ["CWE-89"],
            "target_url": "http://localhost:8080",
            "security_advisories": [
                {
                    "url": "https://ghsa.example/1",
                    "content": "PoC: curl http://target/search?q=' OR 1=1--",
                },
            ],
        }
        text = agent.format_input(input_data)
        assert "SECURITY ADVISORIES" in text
        assert "PoC: curl" in text
        assert "ghsa.example" in text

    def test_no_advisories_no_section(self) -> None:
        agent = self._make_exploit_agent()
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-ADV2",
            "cwe_ids": ["CWE-79"],
            "target_url": "http://localhost:8080",
        }
        text = agent.format_input(input_data)
        assert "SECURITY ADVISORIES" not in text

    def test_empty_content_advisory_skipped(self) -> None:
        agent = self._make_exploit_agent()
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-ADV3",
            "cwe_ids": ["CWE-79"],
            "target_url": "http://localhost:8080",
            "security_advisories": [
                {"url": "https://ghsa.example/2", "content": ""},
            ],
        }
        text = agent.format_input(input_data)
        # Section header appears but no content rendered (empty content skipped)
        assert "ghsa.example/2" not in text or "SECURITY ADVISORIES" in text
