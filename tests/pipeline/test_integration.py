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
from unittest.mock import AsyncMock, MagicMock

import pytest

from forge.agents.base import AgentConfig, AgentResult, BaseAgent
from forge.agents.generator import GenerationOutcome, GeneratorAgent
from forge.agents.orchestrator import (
    AgentRole,
    Orchestrator,
    PipelineStatus,
)
from forge.generator.exceptions import GenerationFailedError
from forge.models import AppManifest, CVETask, GeneratedApp, TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.sandbox.models import DeployResult
from forge.signals.query import SpanQuery


def _make_task() -> CVETask:
    return CVETask(
        cve_id="CVE-2024-9999",
        cwe_ids=["CWE-89"],
        description="SQL injection in login endpoint",
        severity="critical",
        language="python",
        framework="flask",
        vulnerable_package="flask-app",
        vulnerable_version="1.0.0",
    )


def _llm_text_response(content: str) -> MagicMock:
    """LLM response with text content, no tool calls."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = None
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    return resp


def _llm_tool_response(tool_calls: list[dict[str, Any]]) -> MagicMock:
    """LLM response with tool calls."""
    msg = MagicMock()
    msg.content = None
    tcs = []
    for i, tc in enumerate(tool_calls):
        m = MagicMock()
        m.id = f"call_{i}"
        m.function.name = tc["name"]
        m.function.arguments = json.dumps(tc.get("arguments", {}))
        tcs.append(m)
    msg.tool_calls = tcs
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    return resp


class FixedAgent(BaseAgent):
    """Agent that returns a fixed output without calling the LLM."""

    def __init__(self, name: str, fixed_output: dict[str, Any]) -> None:
        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name=name, system_prompt=f"{name} prompt", max_turns=5)
        super().__init__(config, llm)
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


def _session() -> AsyncMock:
    """Create a mock sandbox session."""
    from forge.sandbox.models import SandboxSnapshot

    s = AsyncMock()
    for attr in ("exec_exploit", "exec", "read_file", "write_exploit_file", "http_request"):
        setattr(s, attr, AsyncMock())
    s.snapshot = AsyncMock(return_value=SandboxSnapshot())
    s.base_url = "http://localhost:8080"
    s.exploit_url = "http://localhost:8080"
    return s


class TestOrchestratorWithFixedAgents:
    """Tests with FixedAgent (no real LLM, no real tools)."""

    @pytest.mark.asyncio
    async def test_detector_factory_creates_detector(self) -> None:
        """Verify detector_factory is called with SpanQuery when L1+."""
        intel = FixedAgent("intel", {"root_cause": "SQLi"})
        planner = FixedAgent("planner", {"primary_strategy": "inject"})
        exploit = FixedAgent("exploit", {"exploitation_level": 2, "running_max_level": 2})

        factory_called_with: list[SpanQuery] = []

        def detector_factory(query: SpanQuery) -> BaseAgent:
            factory_called_with.append(query)
            return FixedAgent("detector", {"rules": ["sigma_1"]})

        orch = Orchestrator(
            intel=intel,
            planner=planner,
            exploit=exploit,
            detector_factory=detector_factory,
        )
        result = await orch.run(_make_task())

        assert result.exploitation_level == 2
        assert result.detection_rules == ["sigma_1"]
        assert len(factory_called_with) == 1
        assert factory_called_with[0].cve_id == "CVE-2024-9999"


class TestFiveAgentPipeline:
    """Integration tests for the 5-agent pipeline with Generator + Sandbox."""

    @pytest.mark.asyncio
    async def test_full_5_agent_pipeline(self) -> None:
        """Intel -> Generator -> Planner -> Exploit -> Detector."""
        intel = FixedAgent("intel", {"root_cause": "XSS", "confidence": 0.9})
        planner = FixedAgent("planner", {"primary_strategy": "inject script"})
        exploit = FixedAgent(
            "exploit",
            {"running_max_level": 3, "exploitation_level": 3, "evidence": ["alert(1)"]},
        )
        detector = FixedAgent("detector", {"rules": ["rule_sigma_1"]})

        # Mock Generator Agent
        mock_app = GeneratedApp(
            cve_id="CVE-2024-9999",
            project_files={"app.py": "from flask import Flask", "Dockerfile": "FROM python:3.12"},
            manifest=AppManifest(
                cve_id="CVE-2024-9999",
                cwe="CWE-89",
                language="python",
                framework="flask",
                vulnerable_endpoint="/search",
            ),
        )
        generator = AsyncMock(spec=GeneratorAgent)
        generator.generate = AsyncMock(
            return_value=GenerationOutcome(app=mock_app, tokens=TokenUsage())
        )

        # Mock Sandbox Manager
        mock_session = AsyncMock()
        mock_session.base_url = "http://localhost:9090"
        mock_session.deploy = AsyncMock(
            return_value=DeployResult(success=True, health_check_passed=True),
        )
        mock_session.destroy = AsyncMock()

        sandbox_manager = AsyncMock()
        sandbox_manager.create = AsyncMock(return_value=mock_session)

        orch = Orchestrator(
            intel=intel,
            planner=planner,
            exploit=exploit,
            detector=detector,
            generator=generator,
            sandbox_manager=sandbox_manager,
        )
        result = await orch.run(_make_task())

        assert result.status == PipelineStatus.COMPLETED
        assert result.exploitation_level == 3
        assert "app.py" in result.generated_app.get("files", [])
        assert result.manifest["framework"] == "flask"
        assert result.manifest["vulnerable_endpoint"] == "/search"
        assert result.detection_rules == ["rule_sigma_1"]
        assert AgentRole.GENERATOR in result.agent_results
        assert AgentRole.INTEL in result.agent_results
        assert AgentRole.PLANNER in result.agent_results
        assert AgentRole.EXPLOIT in result.agent_results
        assert AgentRole.DETECTOR in result.agent_results

        # Verify sandbox lifecycle: 2 creates (verification + deploy)
        assert sandbox_manager.create.await_count == 2
        mock_session.deploy.assert_awaited_once()
        # destroy called twice: once for verification sandbox, once for deploy sandbox
        assert mock_session.destroy.await_count == 2

    @pytest.mark.asyncio
    async def test_generation_failed_returns_status(self) -> None:
        """GenerationFailedError results in generation_failed status."""
        intel = FixedAgent("intel", {"root_cause": "SQLi"})
        planner = FixedAgent("planner", {"plan": "inject"})
        exploit = FixedAgent("exploit", {"running_max_level": 0})

        generator = AsyncMock(spec=GeneratorAgent)
        generator.generate = AsyncMock(
            side_effect=GenerationFailedError(
                cve_id="CVE-2024-9999",
                attempts=3,
                last_error="Dockerfile missing",
            ),
        )

        orch = Orchestrator(
            intel=intel,
            planner=planner,
            exploit=exploit,
            generator=generator,
        )
        result = await orch.run(_make_task())

        assert result.status == PipelineStatus.GENERATION_FAILED
        assert result.generation_attempts == 3
        assert "Dockerfile missing" in (result.error_message or "")
        # Planner/Exploit/Detector should NOT have run
        assert AgentRole.PLANNER not in result.agent_results
        assert AgentRole.EXPLOIT not in result.agent_results
