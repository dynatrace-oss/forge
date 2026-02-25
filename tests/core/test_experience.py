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

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from forge.experience import (
    PackageExperienceStore,
    _dedupe_bounded,
    _parse_distilled_notes,
    _safe_filename,
)


class TestSafeFilename:
    """Tests for _safe_filename helper."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("flask", "flask"),
            ("@angular/core", "_at_angular__core"),
            ("my-package", "my-package"),
            ("some/scoped", "some__scoped"),
            ("UPPER Case", "upper_case"),
        ],
    )
    def test_safe_filename(self, name: str, expected: str) -> None:
        assert _safe_filename(name) == expected


class TestDedupeBounded:
    """Tests for _dedupe_bounded helper."""

    def test_deduplicates(self) -> None:
        assert _dedupe_bounded(["a", "b", "a", "c", "b"], 10) == ["a", "b", "c"]

    def test_bounded(self) -> None:
        result = _dedupe_bounded(["a", "b", "c", "d", "e"], 3)
        assert len(result) == 3
        assert result == ["c", "d", "e"]

    def test_empty(self) -> None:
        assert _dedupe_bounded([], 10) == []


class TestParseDistilledNotes:
    """Tests for _parse_distilled_notes."""

    def test_parse_json_array(self) -> None:
        raw = '["note 1", "note 2"]'
        assert _parse_distilled_notes(raw) == ["note 1", "note 2"]

    def test_parse_markdown_wrapped(self) -> None:
        raw = '```json\n["tip A", "tip B"]\n```'
        assert _parse_distilled_notes(raw) == ["tip A", "tip B"]

    def test_invalid_json(self) -> None:
        assert _parse_distilled_notes("not json at all") == []

    def test_empty_array(self) -> None:
        assert _parse_distilled_notes("[]") == []


class TestPackageExperienceStore:
    """Core PackageExperienceStore tests."""

    def test_get_returns_none_when_empty(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        assert store.get("lunary", "npm") is None

    def test_record_build_creates_file(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_build(
            "lunary",
            "npm",
            "CVE-2024-0001",
            success=True,
            attempts=2,
            base_image="node:18-slim",
            deps=["express", "lunary"],
        )

        exp = store.get("lunary", "npm")
        assert exp is not None
        assert exp.package == "lunary"
        assert exp.ecosystem == "npm"
        assert exp.cve_count == 1
        assert exp.build.working_base_image == "node:18-slim"
        assert "express" in exp.build.working_deps
        assert exp.cve_history[0].cve_id == "CVE-2024-0001"
        assert exp.cve_history[0].build_success is True

    def test_record_build_failure_records_errors(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_build(
            "flask",
            "pypi",
            "CVE-2024-0002",
            success=False,
            attempts=3,
            build_errors=["ETARGET: no matching version", "pip install failed"],
        )

        exp = store.get("flask", "pypi")
        assert exp is not None
        assert len(exp.build.failed_approaches) == 2
        assert exp.cve_history[0].build_success is False

    def test_record_exploit_updates_techniques(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_exploit(
            "lunary",
            "npm",
            "CVE-2024-0001",
            level=3,
            techniques=["sql_injection", "auth_bypass"],
            endpoints=["/api/v1/login", "/api/v1/users"],
            auth_mechanism="JWT",
        )

        exp = store.get("lunary", "npm")
        assert exp is not None
        assert "sql_injection" in exp.exploit.effective_techniques
        assert "auth_bypass" in exp.exploit.effective_techniques
        assert exp.exploit.auth_mechanism == "JWT"
        assert "/api/v1/login" in exp.exploit.known_endpoints

    def test_record_exploit_failed_techniques_tracked(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_exploit(
            "lunary",
            "npm",
            "CVE-2024-0001",
            level=0,
            techniques=["xss_reflected"],
        )

        exp = store.get("lunary", "npm")
        assert exp is not None
        assert "xss_reflected" in exp.exploit.failed_techniques

    def test_failed_technique_removed_on_later_success(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        # First attempt fails
        store.record_exploit("lunary", "npm", "CVE-2024-0001", level=0, techniques=["sqli"])
        # Later success with same technique
        store.record_exploit("lunary", "npm", "CVE-2024-0002", level=3, techniques=["sqli"])

        exp = store.get("lunary", "npm")
        assert exp is not None
        assert "sqli" in exp.exploit.effective_techniques
        assert "sqli" not in exp.exploit.failed_techniques

    def test_record_detection(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_detection(
            "lunary",
            "npm",
            "CVE-2024-0001",
            rule_patterns=["sigma rule for auth bypass"],
            indicator_types=["sigma", "snort"],
        )

        exp = store.get("lunary", "npm")
        assert exp is not None
        assert "sigma" in exp.detection.indicator_types
        assert len(exp.detection.effective_rule_patterns) == 1

    def test_format_build_context_empty_when_no_experience(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        assert store.format_build_context("unknown", "npm") == ""

    def test_format_build_context_includes_key_info(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_build(
            "lunary",
            "npm",
            "CVE-2024-0001",
            success=True,
            base_image="node:18-slim",
            deps=["express", "lunary"],
        )

        ctx = store.format_build_context("lunary", "npm")
        assert "PACKAGE BUILD EXPERIENCE" in ctx
        assert "node:18-slim" in ctx
        assert "express" in ctx

    def test_format_exploit_context_empty_when_no_experience(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        assert store.format_exploit_context("unknown", "npm") == ""

    def test_format_exploit_context_includes_techniques(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_exploit(
            "lunary",
            "npm",
            "CVE-2024-0001",
            level=3,
            techniques=["idor"],
            auth_mechanism="JWT",
        )

        ctx = store.format_exploit_context("lunary", "npm")
        assert "PACKAGE EXPLOIT EXPERIENCE" in ctx
        assert "JWT" in ctx
        assert "idor" in ctx

    def test_persistence_across_instances(self, tmp_path: Path) -> None:
        """Experience survives store re-instantiation (disk persistence)."""
        store1 = PackageExperienceStore(experience_dir=tmp_path)
        store1.record_build("lunary", "npm", "CVE-2024-0001", success=True)

        store2 = PackageExperienceStore(experience_dir=tmp_path)
        exp = store2.get("lunary", "npm")
        assert exp is not None
        assert exp.cve_count == 1

    def test_multiple_cves_same_package(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_build("lunary", "npm", "CVE-2024-0001", success=True)
        store.record_build("lunary", "npm", "CVE-2024-0002", success=True)

        exp = store.get("lunary", "npm")
        assert exp is not None
        assert exp.cve_count == 2
        assert len(exp.cve_history) == 2

    def test_duplicate_cve_not_added_twice(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_build("lunary", "npm", "CVE-2024-0001", success=True)
        store.record_build("lunary", "npm", "CVE-2024-0001", success=True)

        exp = store.get("lunary", "npm")
        assert exp is not None
        assert exp.cve_count == 1

    def test_package_count(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        assert store.package_count() == 0

        store.record_build("lunary", "npm", "CVE-2024-0001", success=True)
        store.record_build("flask", "pypi", "CVE-2024-0002", success=True)
        assert store.package_count() == 2

    def test_distill_enabled_requires_llm_and_model(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        assert store.distill_enabled is False

        store_with_llm = PackageExperienceStore(
            experience_dir=tmp_path,
            llm=MagicMock(),
            distill_model="some-model",
        )
        assert store_with_llm.distill_enabled is True

    def test_scoped_npm_package_filename(self, tmp_path: Path) -> None:
        """Scoped npm packages like @angular/core are safely stored."""
        store = PackageExperienceStore(experience_dir=tmp_path)
        store.record_build("@angular/core", "npm", "CVE-2024-0001", success=True)

        exp = store.get("@angular/core", "npm")
        assert exp is not None
        assert exp.package == "@angular/core"

        # Verify the file on disk has safe name
        yaml_path = tmp_path / "npm" / "_at_angular__core.yaml"
        assert yaml_path.exists()


class TestDistillBuild:
    """Tests for distill_build (LLM-powered distillation)."""

    @pytest.mark.asyncio
    async def test_distill_build_adds_notes(self, tmp_path: Path) -> None:
        mock_llm = AsyncMock()
        mock_llm.chat.return_value = ('["Use node:18-slim for smaller images"]', MagicMock())

        store = PackageExperienceStore(
            experience_dir=tmp_path,
            llm=mock_llm,
            distill_model="test-model",
        )
        # Seed with a build record
        store.record_build("lunary", "npm", "CVE-2024-0001", success=True)

        added = await store.distill_build(
            "lunary",
            "npm",
            build_errors=["npm ERR! ETARGET"],
            dockerfile_content="FROM node:18\nRUN npm install",
            success=True,
        )
        assert added == 1
        exp = store.get("lunary", "npm")
        assert exp is not None
        assert "Use node:18-slim for smaller images" in exp.build.dockerfile_notes

    @pytest.mark.asyncio
    async def test_distill_build_skips_without_llm(self, tmp_path: Path) -> None:
        store = PackageExperienceStore(experience_dir=tmp_path)
        added = await store.distill_build(
            "lunary",
            "npm",
            build_errors=["some error"],
        )
        assert added == 0

    @pytest.mark.asyncio
    async def test_distill_exploit_adds_hints(self, tmp_path: Path) -> None:
        mock_llm = AsyncMock()
        mock_llm.chat.return_value = ('["Check /api/v1/auth for IDOR"]', MagicMock())

        store = PackageExperienceStore(
            experience_dir=tmp_path,
            llm=mock_llm,
            distill_model="test-model",
        )

        added = await store.distill_exploit(
            "lunary",
            "npm",
            level=3,
            techniques=["idor"],
            tool_call_summary="GET /api/v1/auth → 200",
        )
        assert added == 1
        exp = store.get("lunary", "npm")
        assert exp is not None
        assert "Check /api/v1/auth for IDOR" in exp.exploit.payload_hints


class TestOrchestratorHelpers:
    """Tests for extraction helpers in orchestrator module."""

    def test_extract_base_image(self) -> None:
        from forge.agents.orchestrator import _extract_base_image

        assert _extract_base_image("FROM node:18-slim\nRUN npm install") == "node:18-slim"
        assert _extract_base_image("FROM python:3.12\nCOPY . .") == "python:3.12"
        assert _extract_base_image("") == ""
        assert _extract_base_image("RUN echo hello") == ""

    def test_extract_deps_list_npm(self) -> None:
        from forge.agents.orchestrator import _extract_deps_list

        pkg_json = json.dumps(
            {
                "dependencies": {"express": "^4.18", "lunary": "^1.0"},
                "devDependencies": {"jest": "^29"},
            }
        )
        deps = _extract_deps_list({"package.json": pkg_json}, "javascript")
        assert "express" in deps
        assert "lunary" in deps

    def test_extract_deps_list_python(self) -> None:
        from forge.agents.orchestrator import _extract_deps_list

        reqs = "flask==2.0\nrequests>=1.0\n# comment\n-r base.txt"
        deps = _extract_deps_list({"requirements.txt": reqs}, "python")
        assert "flask" in deps
        assert "requests" in deps
        assert len(deps) == 2  # comment and -r skipped

    def test_extract_endpoints_from_tool_calls(self) -> None:
        from forge.agents.base import AgentResult
        from forge.agents.orchestrator import _extract_endpoints_from_tool_calls
        from forge.tools.base import ToolCall

        result = AgentResult(
            output={},
            tool_calls=[
                ToolCall(name="http_request", arguments={"url": "http://localhost:8080/api/users"}),
                ToolCall(name="http_request", arguments={"url": "http://localhost:8080/api/login"}),
                ToolCall(
                    name="http_request", arguments={"url": "http://localhost:8080/api/users"}
                ),  # dup
                ToolCall(name="exec_command", arguments={"command": "ls"}),
            ],
        )
        endpoints = _extract_endpoints_from_tool_calls(result)
        assert "/api/users" in endpoints
        assert "/api/login" in endpoints
        assert len(endpoints) == 2  # deduped
