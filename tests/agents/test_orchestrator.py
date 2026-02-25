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
from typing import Any

import pytest

from forge.agents.base import AgentConfig, AgentResult, BaseAgent
from forge.agents.orch_helper import (
    build_exploit_input,
    build_planner_input,
    extract_level,
    task_to_intel_input,
)
from forge.agents.orchestrator import (
    AgentRole,
    Orchestrator,
    PipelineStatus,
)
from forge.models import AppManifest, CVETask, TokenUsage
from forge.pipeline.llm_client import LLMClient


class FixedAgent(BaseAgent):
    """Agent that returns a fixed output without calling the LLM."""

    def __init__(self, fixed_output: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._fixed_output = fixed_output

    def format_input(self, input_data: dict[str, Any]) -> str:
        return json.dumps(input_data)

    def parse_output(self, content: str) -> dict[str, Any]:
        return self._fixed_output

    async def run(self, input_data: dict[str, Any]) -> AgentResult:
        return AgentResult(
            output=self._fixed_output,
            turns_used=1,
            tokens=TokenUsage(total_tokens=100, llm_calls=1),
        )


def _make_agent(name: str, output: dict[str, Any]) -> FixedAgent:
    """Create a FixedAgent with the given output."""
    llm = LLMClient(enable_otel=False)
    config = AgentConfig(name=name, system_prompt=f"{name} prompt", max_turns=5)
    return FixedAgent(fixed_output=output, config=config, llm=llm)


def _make_task(cve_id: str = "CVE-2024-0001") -> CVETask:
    return CVETask(
        cve_id=cve_id,
        cwe_ids=["CWE-79"],
        description="Test XSS vulnerability",
        severity="high",
        language="python",
        vulnerable_package="flask",
        vulnerable_version="2.0.0",
    )


class TestTaskToIntelInput:
    def test_extracts_fields(self) -> None:
        task = _make_task()
        result = task_to_intel_input(task)
        assert result["cve_id"] == "CVE-2024-0001"
        assert result["cwe_ids"] == ["CWE-79"]
        assert result["language"] == "python"
        assert result["vulnerable_package"] == "flask"
        assert "task_dir" not in result
        assert "container_image" not in result


class TestBuildPlannerInput:
    @pytest.mark.parametrize(
        ("manifest", "expect_manifest"),
        [
            (None, False),
        ],
        ids=["without_manifest"],
    )
    def testbuild_planner_input(self, manifest: AppManifest | None, expect_manifest: bool) -> None:
        intel = {"root_cause": "XSS"}
        result = build_planner_input(intel, manifest) if manifest else build_planner_input(intel)
        assert result["intel_report"] == intel
        if expect_manifest:
            assert result["app_manifest"]["framework"] == "flask"
            assert result["app_manifest"]["vulnerable_endpoint"] == "/search"
        else:
            assert "app_manifest" not in result

    def testbuild_planner_input_passes_prior_knowledge(self) -> None:
        """Bug 1 regression: build_planner_input must thread prior_knowledge into the dict."""
        intel = {"root_cause": "SQLi"}
        kb_text = "CWE-89: UNION-based extraction succeeds 80% of the time."
        result = build_planner_input(intel, prior_knowledge=kb_text)
        assert result["prior_knowledge"] == kb_text

    def testbuild_planner_input_omits_empty_prior_knowledge(self) -> None:
        """Empty prior_knowledge should NOT produce a key in the dict."""
        result = build_planner_input({"root_cause": "XSS"}, prior_knowledge="")
        assert "prior_knowledge" not in result


class TestBuildExploitInput:
    def test_with_manifest_and_target_url(self) -> None:
        task = _make_task()
        manifest = AppManifest(
            cve_id="CVE-2024-0001",
            cwe="CWE-79",
            language="python",
            framework="flask",
            vulnerable_endpoint="/search",
        )
        result = build_exploit_input(
            {"root_cause": "XSS"},
            {"strategy": "inject"},
            task,
            manifest=manifest,
            target_url="http://localhost:9090",
        )
        assert result["target_url"] == "http://localhost:9090"
        assert result["framework"] == "flask"
        assert result["language"] == "python"
        assert result["vulnerable_endpoint"] == "/search"


class TestOrchestratorFullPipeline:
    @pytest.mark.asyncio
    async def test_full_pipeline_with_detector(self) -> None:
        """4-agent pipeline still works without generator."""
        intel = _make_agent("intel", {"root_cause": "XSS", "confidence": 0.9})
        planner = _make_agent("planner", {"primary_strategy": "inject script"})
        exploit = _make_agent(
            "exploit",
            {"running_max_level": 3, "exploitation_level": 3, "evidence": ["alert(1)"]},
        )
        detector = _make_agent("detector", {"rules": ["rule_sigma_1", "rule_snort_1"]})

        orch = Orchestrator(intel=intel, planner=planner, exploit=exploit, detector=detector)
        result = await orch.run(_make_task())

        assert result.cve_id == "CVE-2024-0001"
        assert result.status == PipelineStatus.COMPLETED
        assert result.exploitation_level == 3
        assert result.intel_report == {"root_cause": "XSS", "confidence": 0.9}
        assert result.attack_plan == {"primary_strategy": "inject script"}
        assert result.detection_rules == ["rule_sigma_1", "rule_snort_1"]
        assert AgentRole.INTEL in result.agent_results
        assert AgentRole.PLANNER in result.agent_results
        assert AgentRole.EXPLOIT in result.agent_results
        assert AgentRole.DETECTOR in result.agent_results
        assert result.tokens.total_tokens == 400  # 4 agents x 100 each

    @pytest.mark.asyncio
    async def test_skips_detector_at_l0(self) -> None:
        intel = _make_agent("intel", {"report": "data"})
        planner = _make_agent("planner", {"plan": "try stuff"})
        exploit = _make_agent("exploit", {"exploitation_level": 0})
        detector = _make_agent("detector", {"rules": ["should_not_run"]})

        orch = Orchestrator(intel=intel, planner=planner, exploit=exploit, detector=detector)
        result = await orch.run(_make_task())

        assert result.exploitation_level == 0
        assert result.status == PipelineStatus.COMPLETED
        assert result.detection_rules == []
        assert AgentRole.DETECTOR not in result.agent_results
        assert result.tokens.total_tokens == 300  # Only 3 agents


class TestExtractLevel:
    """Tests for extract_level() safe extraction."""

    @pytest.mark.parametrize(
        ("output_dict", "expected_level"),
        [
            ({"running_max_level": 3}, 3),
            ({"running_max_level": "not_a_number"}, 0),
        ],
        ids=["valid", "invalid_value"],
    )
    def testextract_level(self, output_dict: dict[str, Any], expected_level: int) -> None:
        result = AgentResult(output=output_dict)
        assert extract_level(result) == expected_level


class TestTokenTracking:
    """Tests for token accumulation across agents."""

    @pytest.mark.asyncio
    async def test_tokens_on_pipeline_error(self) -> None:
        """Error during pipeline should still report accumulated tokens."""
        intel = _make_agent("intel", {"report": "data"})
        planner = _make_agent("planner", {"plan": "test"})

        class FailingAgent(BaseAgent):
            def format_input(self, input_data: dict[str, Any]) -> str:
                return ""

            def parse_output(self, content: str) -> dict[str, Any]:
                return {}

            async def run(self, input_data: dict[str, Any]) -> AgentResult:
                raise RuntimeError("Exploit agent crashed")

        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="exploit", system_prompt="test", max_turns=5)
        exploit = FailingAgent(config=config, llm=llm)

        orch = Orchestrator(intel=intel, planner=planner, exploit=exploit)
        result = await orch.run(_make_task())

        assert result.status == PipelineStatus.ERROR
        # Intel + planner ran before crash: 200 tokens
        assert result.tokens.total_tokens == 200

    @pytest.mark.asyncio
    async def test_partial_tokens_captured_from_crashed_agent(self) -> None:
        """Bug 5 regression: error handler must capture _partial_tokens from agents
        that started but never finished (not in agent_results)."""
        intel = _make_agent("intel", {"report": "data"})
        planner = _make_agent("planner", {"plan": "test"})

        class PartialCrashAgent(BaseAgent):
            """Agent that sets _partial_tokens then crashes."""

            def format_input(self, input_data: dict[str, Any]) -> str:
                return ""

            def parse_output(self, content: str) -> dict[str, Any]:
                return {}

            async def run(self, input_data: dict[str, Any]) -> AgentResult:
                # Simulate having completed 2 turns before crashing
                self._partial_tokens = TokenUsage(
                    total_tokens=500,
                    prompt_tokens=300,
                    completion_tokens=200,
                    llm_calls=2,
                )
                raise RuntimeError("Mid-turn crash after 2 LLM calls")

        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="exploit", system_prompt="test", max_turns=5)
        exploit = PartialCrashAgent(config=config, llm=llm)

        orch = Orchestrator(intel=intel, planner=planner, exploit=exploit)
        result = await orch.run(_make_task())

        assert result.status == PipelineStatus.ERROR
        # Intel(100) + Planner(100) + Exploit partial(500) = 700
        assert result.tokens.total_tokens == 700, (
            f"Expected 700 (200 completed + 500 partial), got {result.tokens.total_tokens}"
        )


class TestCWEModuleThreading:
    """Tests for CWEModule being threaded into ExploitAgent."""

    @pytest.mark.asyncio
    async def test_cwe_module_threaded_to_exploit_agent(self) -> None:
        """ExploitAgent receives CWEModule when task has CWE IDs."""
        from unittest.mock import AsyncMock, patch

        from forge.agents.exploit import ExploitAgent
        from forge.models import CWEModule
        from forge.sandbox.models import SandboxSnapshot

        intel = _make_agent("intel", {"report": "data"})
        planner = _make_agent("planner", {"plan": "test"})

        # Create a real ExploitAgent with a mock session
        session = AsyncMock()
        session.base_url = "http://localhost:8080"
        session.snapshot = AsyncMock(return_value=SandboxSnapshot())
        exploit_llm = LLMClient(enable_otel=False)
        exploit_config = AgentConfig(
            name="exploit",
            system_prompt="exploit prompt",
            max_turns=1,
        )
        exploit = ExploitAgent(
            llm=exploit_llm,
            session=session,
            config=exploit_config,
        )

        # Mock the run method to avoid actual LLM calls
        with patch.object(
            exploit,
            "run",
            new_callable=AsyncMock,
            return_value=AgentResult(
                output={"running_max_level": 2},
                turns_used=1,
                tokens=TokenUsage(total_tokens=50, llm_calls=1),
            ),
        ):
            task = CVETask(
                cve_id="CVE-2024-0001",
                cwe_ids=["CWE-89"],
                description="SQL injection",
                severity="high",
            )
            orch = Orchestrator(intel=intel, planner=planner, exploit=exploit)
            result = await orch.run(task)

        assert result.status == PipelineStatus.COMPLETED
        # Verify CWEModule was injected
        assert exploit._cwe_module is not None
        assert exploit._cwe_module.cwe_id == "CWE-89"
        assert isinstance(exploit._cwe_module, CWEModule)


class CostlyAgent(BaseAgent):
    """Agent that returns a fixed output with configurable cost."""

    def __init__(self, fixed_output: dict[str, Any], cost_usd: float = 0.0, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._fixed_output = fixed_output
        self._cost_usd = cost_usd

    def format_input(self, input_data: dict[str, Any]) -> str:
        return json.dumps(input_data)

    def parse_output(self, content: str) -> dict[str, Any]:
        return self._fixed_output

    async def run(self, input_data: dict[str, Any]) -> AgentResult:
        tokens = TokenUsage(
            total_tokens=1000,
            llm_calls=1,
            estimated_cost_usd=self._cost_usd,
        )
        # Record to shared tracker when wired (bypasses turn loop)
        if self._budget_tracker is not None:
            self._budget_tracker.record(tokens)
        return AgentResult(
            output=self._fixed_output,
            turns_used=1,
            tokens=tokens,
        )


def _make_costly_agent(name: str, output: dict[str, Any], cost_usd: float) -> CostlyAgent:
    llm = LLMClient(enable_otel=False)
    config = AgentConfig(name=name, system_prompt=f"{name} prompt", max_turns=5)
    return CostlyAgent(fixed_output=output, cost_usd=cost_usd, config=config, llm=llm)


class TestOrchestratorPreservesRunningMax:
    """Bug 7d: orchestrator must preserve running_max from a crashed ExploitAgent."""

    @pytest.mark.asyncio
    async def test_error_handler_preserves_running_max(self) -> None:
        """When ExploitAgent crashes after reaching L3, PipelineResult keeps L3."""
        from unittest.mock import AsyncMock, patch

        from forge.agents.exploit import ExploitAgent
        from forge.oracle.models import OracleEvidence
        from forge.sandbox.models import SandboxSnapshot

        intel = _make_agent("intel", {"root_cause": "SSTI"})
        planner = _make_agent("planner", {"strategy": "inject"})

        # Create a real ExploitAgent with a mock session
        session = AsyncMock()
        session.base_url = "http://localhost:8080"
        session.snapshot = AsyncMock(return_value=SandboxSnapshot())
        exploit_llm = LLMClient(enable_otel=False)
        exploit_config = AgentConfig(
            name="exploit",
            system_prompt="exploit prompt",
            max_turns=5,
        )
        exploit = ExploitAgent(
            llm=exploit_llm,
            session=session,
            config=exploit_config,
        )

        # Simulate that the agent reached L3 before crashing
        exploit._state.running_max = 3
        exploit._state.accumulated_evidence = [
            OracleEvidence(
                source="filesystem",
                description="passwd file read",
                level_match=3,
                confidence=0.95,
            ),
        ]

        async def _crash(input_data: dict[str, Any]) -> AgentResult:
            raise RuntimeError("LLM returned empty choices")

        with patch.object(exploit, "run", side_effect=_crash):
            orch = Orchestrator(
                intel=intel,
                planner=planner,
                exploit=exploit,
            )
            result = await orch.run(_make_task())

        assert result.status == PipelineStatus.ERROR
        assert result.exploitation_level == 3, (
            f"Expected preserved L3, got L{result.exploitation_level}"
        )
        assert result.oracle_confidence > 0.0
        assert "empty choices" in (result.error_message or "")

    @pytest.mark.asyncio
    async def test_error_handler_zero_when_no_progress(self) -> None:
        """When ExploitAgent crashes with no progress, level stays 0."""
        from unittest.mock import AsyncMock, patch

        from forge.agents.exploit import ExploitAgent
        from forge.sandbox.models import SandboxSnapshot

        intel = _make_agent("intel", {"root_cause": "XSS"})
        planner = _make_agent("planner", {"strategy": "inject"})

        session = AsyncMock()
        session.base_url = "http://localhost:8080"
        session.snapshot = AsyncMock(return_value=SandboxSnapshot())
        exploit_llm = LLMClient(enable_otel=False)
        exploit_config = AgentConfig(
            name="exploit",
            system_prompt="exploit prompt",
            max_turns=5,
        )
        exploit = ExploitAgent(
            llm=exploit_llm,
            session=session,
            config=exploit_config,
        )
        # running_max stays at default 0

        async def _crash(input_data: dict[str, Any]) -> AgentResult:
            raise RuntimeError("Network timeout")

        with patch.object(exploit, "run", side_effect=_crash):
            orch = Orchestrator(intel=intel, planner=planner, exploit=exploit)
            result = await orch.run(_make_task())

        assert result.status == PipelineStatus.ERROR
        assert result.exploitation_level == 0
        assert result.oracle_confidence == pytest.approx(0.0)


class TestOrchestratorCostCap:
    """Verify orchestrator-level cost cap stops the pipeline between agent phases."""

    @pytest.mark.asyncio
    async def test_cost_cap_after_intel(self) -> None:
        """Pipeline stops after intel when cost already exceeds budget."""
        intel = _make_costly_agent("intel", {"root_cause": "XSS"}, cost_usd=6.0)
        planner = _make_costly_agent("planner", {"strategy": "inject"}, cost_usd=1.0)
        exploit = _make_costly_agent("exploit", {"running_max_level": 0}, cost_usd=1.0)

        orch = Orchestrator(
            intel=intel,
            planner=planner,
            exploit=exploit,
            cost_budget=5.0,
        )
        result = await orch.run(_make_task())
        assert result.status == PipelineStatus.COST_CAP_REACHED
        assert "after intel phase" in (result.error_message or "")
        # Planner should never have run
        assert AgentRole.PLANNER not in result.agent_results


class TestClassifyGenerationError:
    """Unit tests for _classify_generation_error helper."""

    def test_dockerfile_build_error(self) -> None:
        from forge.agents.orch_recording import classify_generation_error
        from forge.learnings import ErrorCategory

        assert classify_generation_error("Build failed: COPY go.sum not found") == (
            ErrorCategory.DOCKERFILE_BUILD_ERROR
        )

    def test_package_not_found(self) -> None:
        from forge.agents.orch_recording import classify_generation_error
        from forge.learnings import ErrorCategory

        assert classify_generation_error("package not found: express@99.0.0") == (
            ErrorCategory.PACKAGE_NOT_FOUND
        )

    def test_port_mismatch(self) -> None:
        from forge.agents.orch_recording import classify_generation_error
        from forge.learnings import ErrorCategory

        assert classify_generation_error("Port mismatch: expected 8080 got 3000") == (
            ErrorCategory.PORT_MISMATCH
        )

    def test_fallback_health_check(self) -> None:
        from forge.agents.orch_recording import classify_generation_error
        from forge.learnings import ErrorCategory

        assert classify_generation_error("Verification failed") == (
            ErrorCategory.HEALTH_CHECK_FAILURE
        )
