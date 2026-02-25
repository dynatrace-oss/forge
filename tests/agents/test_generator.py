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
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from forge.agents.base import AgentConfig
from forge.agents.generator import GenerationOutcome, GeneratorAgent, _find_main_app_file
from forge.generator.exceptions import GenerationFailedError
from forge.generator.verification import AppVerifier, VerificationResult
from forge.models import TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.tools.base import ToolCall, ToolResult
from forge.tools.generator_tools import register_generator_tools

_GENERATOR_CONFIG = AgentConfig(
    name="generator",
    system_prompt="Generate a vulnerable web app.",
    max_turns=20,
)

_INTEL_REPORT: dict[str, Any] = {
    "cve_id": "CVE-2024-1234",
    "cwe_id": "CWE-89",
    "description": "SQL injection in search endpoint",
    "framework": "flask",
    "language": "python",
    "tech_stack": "cpe:2.3:a:pallets:flask:2.3.0",
    "patch_analysis": "",
    "existing_pocs": "",
    "vulnerable_component": "flask search module",
    "affected_versions": "< 2.4.0",
}


def _llm_response(
    content: str | None = None,
    tool_calls: list[dict[str, Any]] | None = None,
) -> MagicMock:
    msg = MagicMock()
    msg.content = content
    if tool_calls:
        tcs = []
        for tc in tool_calls:
            m = MagicMock()
            m.id = tc.get("id", "call_1")
            m.function.name = tc["name"]
            m.function.arguments = json.dumps(tc.get("arguments", {}))
            tcs.append(m)
        msg.tool_calls = tcs
    else:
        msg.tool_calls = None
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    return resp


class TestGeneratorAgent:
    @pytest.mark.asyncio
    async def test_successful_generation(self) -> None:
        """Agent generates app, verifier approves on first attempt."""
        app_state: dict[str, str] = {}

        # Mock verifier that always succeeds
        verifier = AsyncMock(spec=AppVerifier)
        verifier.verify.return_value = VerificationResult(
            success=True,
            build_ok=True,
            deploy_ok=True,
            health_ok=True,
            vuln_present=True,
        )

        tools = register_generator_tools(verifier, app_state)

        # LLM calls: write all files at once -> final JSON
        llm = AsyncMock(spec=LLMClient)
        llm.complete = AsyncMock(
            side_effect=[
                (
                    _llm_response(
                        tool_calls=[
                            {
                                "name": "write_app_files",
                                "arguments": {
                                    "files": {
                                        "Dockerfile": (
                                            "FROM python:3.12-slim\n"
                                            "WORKDIR /app\nCOPY . .\n"
                                            "RUN pip install flask\n"
                                            "EXPOSE 8080\n"
                                            'CMD ["python", "app.py"]\n'
                                        ),
                                        "app.py": (
                                            "from flask import Flask\n"
                                            "app = Flask('x')\n"
                                            "@app.route('/health')\n"
                                            "def h(): return 'ok'\n"
                                            "@app.route('/search')\n"
                                            "def s(): return 'vuln'\n"
                                            "if __name__=='__main__':\n"
                                            "    app.run(port=8080)\n"
                                        ),
                                    }
                                },
                            }
                        ]
                    ),
                    TokenUsage(
                        prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1
                    ),
                ),
                (
                    _llm_response(
                        content=json.dumps(
                            {
                                "generation_complete": True,
                                "framework": "flask",
                                "vulnerable_endpoint": "/search",
                                "cwe_id": "CWE-89",
                            }
                        )
                    ),
                    TokenUsage(
                        prompt_tokens=300, completion_tokens=80, total_tokens=380, llm_calls=1
                    ),
                ),
            ]
        )

        agent = GeneratorAgent(
            llm=llm,
            config=_GENERATOR_CONFIG,
            tools=tools,
            verifier=verifier,
            app_state=app_state,
        )

        outcome = await agent.generate(_INTEL_REPORT)

        assert isinstance(outcome, GenerationOutcome)
        app = outcome.app
        assert app.cve_id == "CVE-2024-1234"
        assert len(app.project_files) > 0
        assert "Dockerfile" in app.project_files

    @pytest.mark.asyncio
    async def test_retry_on_verification_failure(self) -> None:
        """Agent retries when verifier rejects the app, succeeds on attempt 2."""
        app_state: dict[str, str] = {}

        verifier = AsyncMock(spec=AppVerifier)
        # First attempt fails, second succeeds
        verifier.verify.side_effect = [
            VerificationResult(
                success=False,
                build_ok=True,
                deploy_ok=False,
                failure_reason="Deploy failed: port mismatch",
            ),
            VerificationResult(
                success=True,
                build_ok=True,
                deploy_ok=True,
                health_ok=True,
                vuln_present=True,
            ),
        ]

        tools = register_generator_tools(verifier, app_state)

        # Each attempt: one tool call + final JSON (x2 attempts)
        token = TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1)
        llm = AsyncMock(spec=LLMClient)
        llm.complete = AsyncMock(
            side_effect=[
                # Attempt 1
                (
                    _llm_response(
                        tool_calls=[
                            {
                                "name": "write_app_files",
                                "arguments": {
                                    "files": {
                                        "Dockerfile": "FROM python:3.12-slim\nEXPOSE 8080\n",
                                    }
                                },
                            }
                        ]
                    ),
                    token,
                ),
                (
                    _llm_response(
                        content='{"generation_complete": true, "vulnerable_endpoint": "/x"}'
                    ),
                    token,
                ),
                # Attempt 2
                (
                    _llm_response(
                        tool_calls=[
                            {
                                "name": "write_app_files",
                                "arguments": {
                                    "files": {
                                        "Dockerfile": "FROM python:3.12-slim\nEXPOSE 8080\n",
                                    }
                                },
                            }
                        ]
                    ),
                    token,
                ),
                (
                    _llm_response(
                        content='{"generation_complete": true, "vulnerable_endpoint": "/x"}'
                    ),
                    token,
                ),
            ]
        )

        agent = GeneratorAgent(
            llm=llm,
            config=_GENERATOR_CONFIG,
            tools=tools,
            verifier=verifier,
            app_state=app_state,
        )

        outcome = await agent.generate(_INTEL_REPORT)
        assert isinstance(outcome, GenerationOutcome)
        assert verifier.verify.call_count == 2

    @pytest.mark.asyncio
    async def test_generation_failed_after_max_retries(self) -> None:
        """Raises GenerationFailed after 2 failed attempts."""
        app_state: dict[str, str] = {}

        verifier = AsyncMock(spec=AppVerifier)
        verifier.verify.return_value = VerificationResult(
            success=False,
            build_ok=False,
            failure_reason="Build failed: syntax error",
        )

        tools = register_generator_tools(verifier, app_state)

        token = TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1)
        # 2 attempts, each with 1 tool call + final text
        responses = []
        for _ in range(2):
            responses.append(
                (
                    _llm_response(
                        tool_calls=[
                            {
                                "name": "write_app_files",
                                "arguments": {
                                    "files": {
                                        "Dockerfile": "FROM python:3.12-slim\nEXPOSE 8080\n",
                                    }
                                },
                            }
                        ]
                    ),
                    token,
                )
            )
            responses.append((_llm_response(content='{"generation_complete": true}'), token))

        llm = AsyncMock(spec=LLMClient)
        llm.complete = AsyncMock(side_effect=responses)

        agent = GeneratorAgent(
            llm=llm,
            config=_GENERATOR_CONFIG,
            tools=tools,
            verifier=verifier,
            app_state=app_state,
        )

        with pytest.raises(GenerationFailedError, match="2 attempts"):
            await agent.generate(_INTEL_REPORT)

        assert verifier.verify.call_count == 2

    @pytest.mark.asyncio
    async def test_format_input_includes_build_experience(self) -> None:
        """format_input includes package build experience when injected."""
        llm = AsyncMock(spec=LLMClient)

        agent = GeneratorAgent(
            llm=llm,
            config=_GENERATOR_CONFIG,
        )

        intel = {
            **_INTEL_REPORT,
            "package_build_experience": (
                "BUILD EXPERIENCE FOR flask:\n"
                "  * Working base image: python:3.12-slim\n"
                "  * Known issue: pip install fails without --no-cache-dir"
            ),
        }
        input_data = agent._build_input(intel, None, "", 1)
        msg = agent.format_input(input_data)

        assert "CVE-2024-1234" in msg
        assert "CWE-89" in msg
        assert "BUILD EXPERIENCE FOR flask" in msg
        assert "--no-cache-dir" in msg

    @pytest.mark.asyncio
    async def test_build_input_includes_full_intel_data(self) -> None:
        """_build_input passes technology fields from the intel report."""
        llm = AsyncMock(spec=LLMClient)

        agent = GeneratorAgent(
            llm=llm,
            config=_GENERATOR_CONFIG,
        )

        intel = {
            "cve_id": "CVE-2024-9999",
            "cwe_id": "CWE-79",
            "description": "XSS in admin panel",
            "framework": "spring",
            "language": "java",
            "tech_stack": "cpe:2.3:a:vmware:spring_framework:5.3.0",
            "patch_analysis": "Fixed in commit abc123",
            "existing_pocs": "github.com/example/poc",
            "vulnerable_component": "spring-web",
            "affected_versions": [">=5.0.0,<5.3.1"],
            "fix_versions": ["5.3.1"],
        }
        input_data = agent._build_input(intel, None, "", 1)

        assert input_data["language"] == "java"
        assert input_data["framework"] == "spring"
        assert "spring_framework" in input_data["tech_stack"]
        assert input_data["patch_analysis"] == "Fixed in commit abc123"
        assert input_data["existing_pocs"] == "github.com/example/poc"
        assert input_data["vulnerable_component"] == "spring-web"
        assert input_data["affected_versions"] == [">=5.0.0,<5.3.1"]
        assert input_data["fix_versions"] == ["5.3.1"]

        # Verify format_input renders these fields
        msg = agent.format_input(input_data)
        assert "language=java" in msg
        assert "framework=spring" in msg
        assert "spring_framework" in msg
        assert "spring-web" in msg
        assert ">=5.0.0,<5.3.1" in msg
        assert "5.3.1" in msg

    @pytest.mark.asyncio
    async def test_format_input_renders_cookbook_tips(self) -> None:
        """format_input renders cookbook_tips when injected."""
        llm = AsyncMock(spec=LLMClient)

        agent = GeneratorAgent(
            llm=llm,
            config=_GENERATOR_CONFIG,
        )

        intel = {
            **_INTEL_REPORT,
            "cookbook_tips": (
                "COMMON PATTERNS AND GOTCHAS FOR GO APPS:\n"
                "  * Go modules require all source files before go mod tidy."
            ),
        }
        input_data = agent._build_input(intel, None, "", 1)
        msg = agent.format_input(input_data)
        assert "COMMON PATTERNS AND GOTCHAS" in msg
        assert "go mod tidy" in msg


class TestGetContinuePrompt:
    """Tests for turn-budget-aware continuation prompts."""

    def _make_agent(self, max_turns: int = 8) -> GeneratorAgent:
        config = AgentConfig(
            name="generator",
            system_prompt="test",
            max_turns=max_turns,
        )
        return GeneratorAgent(
            llm=AsyncMock(spec=LLMClient),
            config=config,
        )

    def test_validate_not_called_prompts_action(self) -> None:
        agent = self._make_agent()
        agent._validate_called = False
        agent._current_turn = 2
        msg = agent._get_continue_prompt()
        assert "validate_app" in msg
        assert "write_app_files" in msg

    def test_low_budget_shows_urgency(self) -> None:
        agent = self._make_agent(max_turns=8)
        agent._validate_called = True
        agent._current_turn = 6  # remaining = 8 - 6 = 2
        msg = agent._get_continue_prompt()
        assert "2 turn" in msg
        assert "MUST" in msg

    def test_normal_continuation_shows_remaining(self) -> None:
        agent = self._make_agent(max_turns=8)
        agent._validate_called = True
        agent._current_turn = 3  # remaining = 5
        msg = agent._get_continue_prompt()
        assert "5 turns remaining" in msg
        assert "Fix ONLY" in msg

    @pytest.mark.parametrize(
        "current_turn,expected_remaining",
        [
            pytest.param(7, 1, id="last-turn"),
            pytest.param(6, 2, id="penultimate-turn"),
        ],
    )
    def test_urgency_threshold(self, current_turn: int, expected_remaining: int) -> None:
        agent = self._make_agent(max_turns=8)
        agent._validate_called = True
        agent._current_turn = current_turn
        msg = agent._get_continue_prompt()
        assert f"{expected_remaining} turn" in msg
        assert "MUST" in msg


class TestOnToolResult:
    """Tests for validate_app tracking via on_tool_result."""

    def _make_agent(self) -> GeneratorAgent:
        config = AgentConfig(
            name="generator",
            system_prompt="test",
            max_turns=8,
        )
        return GeneratorAgent(
            llm=AsyncMock(spec=LLMClient),
            config=config,
        )

    @pytest.mark.asyncio
    async def test_validate_app_sets_flag(self) -> None:
        agent = self._make_agent()
        agent._validate_called = False
        tc = ToolCall(id="call_1", name="validate_app", arguments={})
        result = ToolResult(tool_call_id="call_1", content="{}")
        await agent.on_tool_result(tc, result, turn=1)
        assert agent._validate_called is True

    @pytest.mark.asyncio
    async def test_other_tool_does_not_set_flag(self) -> None:
        agent = self._make_agent()
        agent._validate_called = False
        tc = ToolCall(id="call_1", name="write_app_files", arguments={})
        result = ToolResult(tool_call_id="call_1", content="{}")
        await agent.on_tool_result(tc, result, turn=1)
        assert agent._validate_called is False

    @pytest.mark.asyncio
    async def test_on_tool_result_tracks_turn(self) -> None:
        agent = self._make_agent()
        tc = ToolCall(id="call_1", name="write_app_files", arguments={})
        result = ToolResult(tool_call_id="call_1", content="{}")
        await agent.on_tool_result(tc, result, turn=4)
        assert agent._current_turn == 4


class TestSmartRetry:
    """Tests for smart retry format — key files full, others path-only."""

    def _make_agent(self) -> GeneratorAgent:
        config = AgentConfig(
            name="generator",
            system_prompt="test",
            max_turns=8,
        )
        return GeneratorAgent(
            llm=AsyncMock(spec=LLMClient),
            config=config,
        )

    def test_retry_shows_key_files_full(self) -> None:
        agent = self._make_agent()
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-1234",
            "existing_files": {
                "Dockerfile": "FROM python:3.12-slim\nEXPOSE 8080\n",
                "requirements.txt": "flask==3.1.0\n",
                "app.py": "from flask import Flask\napp = Flask(__name__)\n",
                "config/secrets.ini": "[db]\npassword=test123\n",
            },
            "prior_feedback": "Build failed: syntax error in app.py",
            "attempt": 2,
        }
        msg = agent.format_input(input_data)

        # Key files should appear with full content
        assert "FROM python:3.12-slim" in msg
        assert "flask==3.1.0" in msg
        # Main app file (largest) should also appear with full content
        assert "from flask import Flask" in msg

    def test_retry_hides_non_key_files(self) -> None:
        agent = self._make_agent()
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-1234",
            "existing_files": {
                "Dockerfile": "FROM python:3.12-slim\nEXPOSE 8080\n",
                "requirements.txt": "flask==3.1.0\n",
                "app.py": "from flask import Flask\napp = Flask(__name__)\n" * 10,
                "config/secrets.ini": "[db]\npassword=test123\n",
                "templates/index.html": "<html><body>test</body></html>",
            },
            "attempt": 2,
        }
        msg = agent.format_input(input_data)

        # Non-key, non-main files should only appear as path-only
        assert "Also present (not shown):" in msg
        assert "config/secrets.ini" in msg
        assert "templates/index.html" in msg
        # Their content should NOT appear
        assert "[db]" not in msg
        assert "<html><body>test</body></html>" not in msg

    def test_retry_includes_error_prominently(self) -> None:
        agent = self._make_agent()
        input_data: dict[str, Any] = {
            "cve_id": "CVE-2024-1234",
            "existing_files": {
                "Dockerfile": "FROM python:3.12-slim\n",
            },
            "prior_feedback": "Build failed: missing dependency flask",
            "attempt": 2,
        }
        msg = agent.format_input(input_data)
        assert "Build failed: missing dependency flask" in msg
        assert "Do NOT regenerate all files" in msg


class TestFindMainAppFile:
    """Tests for the _find_main_app_file helper."""

    def test_finds_largest_non_key_file(self) -> None:
        files = {
            "Dockerfile": "FROM python:3.12-slim\n",
            "requirements.txt": "flask\n",
            "app.py": "x" * 500,
            "utils.py": "x" * 100,
        }
        assert _find_main_app_file(files) == "app.py"

    def test_skips_dockerfile_and_deps(self) -> None:
        files = {
            "Dockerfile": "x" * 1000,
            "requirements.txt": "x" * 900,
            "app.py": "x" * 50,
        }
        assert _find_main_app_file(files) == "app.py"

    def test_returns_none_for_only_key_files(self) -> None:
        files = {
            "Dockerfile": "FROM python:3.12-slim\n",
            "requirements.txt": "flask\n",
        }
        assert _find_main_app_file(files) is None
