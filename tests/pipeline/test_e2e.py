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

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from forge.agents.base import AgentConfig, AgentResult, BaseAgent
from forge.agents.exploit import ExploitAgent
from forge.agents.generator import GenerationOutcome, GeneratorAgent
from forge.agents.orchestrator import (
    AgentRole,
    Orchestrator,
    OrchestratorStores,
    PipelineResult,
    PipelineStatus,
)
from forge.config import ForgeConfig, PathsConfig
from forge.generator.exceptions import GenerationFailedError
from forge.models import AppManifest, CVETask, GeneratedApp, TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.sandbox.models import CommandResult, DeployResult
from forge.storage import StorageManager

# --- Helpers ---


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


class FixedAgent(BaseAgent):
    """Agent stub that returns a fixed output without calling the LLM."""

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


def _llm_text(content: str) -> MagicMock:
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = None
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    return resp


def _llm_tools(tool_calls: list[dict[str, Any]]) -> MagicMock:
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


def _tok(total: int = 100) -> TokenUsage:
    return TokenUsage(total_tokens=total, llm_calls=1)


def _mock_session() -> AsyncMock:
    from forge.sandbox.models import SandboxSnapshot

    s = AsyncMock()
    for attr in ("exec_exploit", "exec", "read_file", "write_exploit_file", "http_request"):
        setattr(s, attr, AsyncMock())
    s.snapshot = AsyncMock(return_value=SandboxSnapshot())
    s.base_url = "http://localhost:9090"
    s.exploit_url = "http://localhost:9090"
    return s


def _mock_generated_app() -> GeneratedApp:
    return GeneratedApp(
        cve_id="CVE-2024-9999",
        project_files={
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "Dockerfile": "FROM python:3.12\nCOPY . .\nCMD python app.py\n",
            "docker-compose.yml": "services:\n  app:\n    build: .\n",
        },
        manifest=AppManifest(
            cve_id="CVE-2024-9999",
            cwe="CWE-89",
            language="python",
            framework="flask",
            vulnerable_endpoint="/search",
        ),
    )


# --- Fixtures ---


@pytest.fixture()
def config(tmp_path: Path) -> ForgeConfig:
    """ForgeConfig with tmp_path-based directories."""
    return ForgeConfig(
        paths=PathsConfig(
            results=str(tmp_path / "results"),
            generated_apps=str(tmp_path / "generated-apps"),
            knowledge=str(tmp_path / "knowledge"),
            cache=str(tmp_path / "cache"),
            prompts=str(tmp_path / "prompts"),
        ),
    )


@pytest.fixture()
def storage(config: ForgeConfig) -> StorageManager:
    """StorageManager from ForgeConfig."""
    return StorageManager.from_config(config.paths)


# --- Tests ---


class TestFullPipelineE2E:
    """End-to-end pipeline: CVE -> Intel -> Generate -> Deploy -> Exploit -> Detect.

    All LLM calls mocked. Sandbox mocked.
    Tests verify the full Orchestrator wiring and PipelineResult completeness.
    """

    @pytest.mark.asyncio
    async def test_full_pipeline_single_cve(
        self,
        config: ForgeConfig,
        tmp_path: Path,
    ) -> None:
        """Full 5-agent pipeline produces a complete PipelineResult.

        - Intel produces report
        - Generator produces GeneratedApp
        - Deploy succeeds
        - Planner produces plan
        - Exploit reaches L3 (via mocked LLM + real tool dispatch)
        - Detector produces rules
        - PipelineResult has all fields populated
        """
        task = _make_task()

        # Intel + Planner + Detector: FixedAgent stubs
        intel = FixedAgent(
            "intel",
            {
                "root_cause": "SQL injection via unsanitised user input in login query",
                "confidence": 0.9,
                "sources_used": ["nvd", "cve-genie"],
            },
        )
        planner = FixedAgent(
            "planner",
            {
                "primary_strategy": "union-based SQL injection",
                "steps": [
                    "identify input fields",
                    "test single-quote escape",
                    "inject UNION SELECT",
                ],
            },
        )
        detector = FixedAgent(
            "detector",
            {
                "rules": ["sigma_sqli_login_bypass", "snort_union_select"],
            },
        )

        # Generator: mock the generate() method directly
        mock_app = _mock_generated_app()
        generator = AsyncMock(spec=GeneratorAgent)
        generator.generate = AsyncMock(
            return_value=GenerationOutcome(app=mock_app, tokens=TokenUsage())
        )

        # Exploit: real ExploitAgent with mocked LLM
        # LLM oracle evaluates every turn (mock returns L3 verdict)
        session = _mock_session()
        session.exec_exploit.return_value = CommandResult(
            exit_code=0,
            stdout="uid=0(root) gid=0(root)",
        )

        llm = AsyncMock(spec=LLMClient)
        llm.complete = AsyncMock(
            side_effect=[
                (
                    _llm_tools(
                        [
                            {
                                "name": "exec_command",
                                "arguments": {"command": "id"},
                            }
                        ]
                    ),
                    _tok(200),
                ),
                (
                    _llm_text(
                        '{"exploitation_level": 3, "techniques_used": ["command_injection"]}'
                    ),
                    _tok(150),
                ),
            ]
        )
        # LLM oracle (now called every turn via llm.chat) — return L3 verdict
        llm.chat = AsyncMock(
            return_value=(
                '{"level": 3, "confidence": 0.85, "reasoning": "uid=0(root) RCE"}',
                _tok(130),
            )
        )

        exploit = ExploitAgent(
            llm=llm,
            session=session,
            config=AgentConfig(name="exploit", system_prompt="Exploit.", max_turns=30),
        )

        # Sandbox manager: mock
        # The orchestrator now creates TWO sandboxes:
        #   1. Verification sandbox — used by the generator's actor-critic loop
        #   2. Deploy sandbox — used by the exploit agent after set_session()
        # The generator is mocked so the verification sandbox just needs destroy().
        ver_session = _mock_session()
        ver_session.destroy = AsyncMock()

        # Deploy session needs deploy + exec_exploit (exploit agent targets it)
        deploy_session = _mock_session()
        deploy_session.deploy = AsyncMock(
            return_value=DeployResult(success=True, health_check_passed=True),
        )
        deploy_session.destroy = AsyncMock()
        deploy_session.exec_exploit.return_value = CommandResult(
            exit_code=0,
            stdout="uid=0(root) gid=0(root)",
        )

        sandbox_manager = AsyncMock()
        sandbox_manager.create = AsyncMock(
            side_effect=[ver_session, deploy_session],
        )

        # Wire up orchestrator
        orch = Orchestrator(
            intel=intel,
            planner=planner,
            exploit=exploit,
            detector=detector,
            generator=generator,
            sandbox_manager=sandbox_manager,
            stores=OrchestratorStores(),
        )

        result: PipelineResult = await orch.run(task)

        # Verify complete pipeline result
        assert result.cve_id == "CVE-2024-9999"
        assert result.status == PipelineStatus.COMPLETED
        assert result.exploitation_level >= 1
        assert "app.py" in result.generated_app.get("files", [])
        assert result.manifest["framework"] == "flask"
        assert result.manifest["vulnerable_endpoint"] == "/search"
        assert len(result.detection_rules) == 2
        assert result.tokens.total_tokens > 0
        assert result.wall_clock_seconds > 0
        assert result.generation_attempts == 1

        # All agents ran
        assert AgentRole.INTEL in result.agent_results
        assert AgentRole.GENERATOR in result.agent_results
        assert AgentRole.PLANNER in result.agent_results
        assert AgentRole.EXPLOIT in result.agent_results
        assert AgentRole.DETECTOR in result.agent_results

        # Sandbox lifecycle: 2 creates (verification + deploy)
        assert sandbox_manager.create.await_count == 2
        deploy_session.deploy.assert_awaited_once()
        ver_session.destroy.assert_awaited_once()  # verification sandbox cleaned up
        deploy_session.destroy.assert_awaited_once()  # deploy sandbox cleaned up

        # Generator was called with the intel report
        generator.generate.assert_awaited_once()
        call_kwargs = generator.generate.call_args
        intel_report = call_kwargs[0][0] if call_kwargs[0] else call_kwargs[1].get("intel_report")
        assert intel_report["cve_id"] == "CVE-2024-9999"

    @pytest.mark.asyncio
    async def test_pipeline_generation_failure(
        self,
        config: ForgeConfig,
        tmp_path: Path,
    ) -> None:
        """Generator fails all 3 attempts -> GenerationFailed status.

        Pipeline short-circuits: Planner, Exploit, Detector never run.
        """
        task = _make_task()

        intel = FixedAgent("intel", {"root_cause": "SQLi in login"})
        planner = FixedAgent("planner", {"plan": "inject"})
        exploit = FixedAgent("exploit", {"running_max_level": 0})

        generator = AsyncMock(spec=GeneratorAgent)
        generator.generate = AsyncMock(
            side_effect=GenerationFailedError(
                cve_id="CVE-2024-9999",
                attempts=3,
                last_error="Dockerfile missing EXPOSE directive",
            ),
        )

        orch = Orchestrator(
            intel=intel,
            planner=planner,
            exploit=exploit,
            generator=generator,
            stores=OrchestratorStores(),
        )

        result = await orch.run(task)

        assert result.status == PipelineStatus.GENERATION_FAILED
        assert result.generation_attempts == 3
        assert "Dockerfile missing" in (result.error_message or "")
        assert result.exploitation_level == 0

        # Planner/Exploit/Detector did NOT run
        assert AgentRole.PLANNER not in result.agent_results
        assert AgentRole.EXPLOIT not in result.agent_results
        assert AgentRole.DETECTOR not in result.agent_results

        # Intel DID run (it runs before generator)
        assert AgentRole.INTEL in result.agent_results

    @pytest.mark.asyncio
    async def test_pipeline_exploit_l0_skips_detector(
        self,
        config: ForgeConfig,
    ) -> None:
        """When exploit reaches L0, detector is skipped."""
        task = _make_task()

        intel = FixedAgent("intel", {"root_cause": "SQLi"})
        planner = FixedAgent("planner", {"plan": "test"})
        exploit = FixedAgent("exploit", {"running_max_level": 0})

        mock_app = _mock_generated_app()
        generator = AsyncMock(spec=GeneratorAgent)
        generator.generate = AsyncMock(
            return_value=GenerationOutcome(app=mock_app, tokens=TokenUsage())
        )

        mock_session = _mock_session()
        mock_session.deploy = AsyncMock(
            return_value=DeployResult(success=True, health_check_passed=True),
        )
        mock_session.destroy = AsyncMock()

        sandbox_manager = AsyncMock()
        sandbox_manager.create = AsyncMock(return_value=mock_session)

        detector_called = False

        def detector_factory(query: Any) -> BaseAgent:
            nonlocal detector_called
            detector_called = True
            return FixedAgent("detector", {"rules": ["should_not_appear"]})

        orch = Orchestrator(
            intel=intel,
            planner=planner,
            exploit=exploit,
            detector_factory=detector_factory,
            generator=generator,
            sandbox_manager=sandbox_manager,
            stores=OrchestratorStores(),
        )

        result = await orch.run(task)

        assert result.exploitation_level == 0
        assert result.detection_rules == []
        assert not detector_called
        assert AgentRole.DETECTOR not in result.agent_results
