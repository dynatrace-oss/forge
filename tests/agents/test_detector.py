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
from forge.agents.detector import DetectorAgent
from forge.config import BaseAgentSettings
from forge.models import CWEModule, TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.pipeline.prompt_engine import PromptEngine
from forge.signals.collector import SpanCollector
from forge.signals.query import SpanQuery
from forge.tools.base import ToolCall, ToolResult

_DETECTOR_CONFIG = AgentConfig(
    name="detector",
    system_prompt="Generate detection rules.",
    max_turns=5,
)


def _populated_query() -> SpanQuery:
    """Create a SpanQuery with sample spans."""
    collector = SpanCollector(cve_id="CVE-2024-9999")
    collector.record(
        ToolCall(
            name="http_request",
            arguments={"method": "POST", "url": "/api/login", "body": "' OR 1=1--"},
        ),
        ToolResult(content="SQL syntax error"),
        level_before=0,
        level_after=2,
    )
    collector.record(
        ToolCall(name="exec_command", arguments={"command": "cat /etc/passwd"}),
        ToolResult(content="root:x:0:0:root:/root:/bin/bash"),
        level_before=2,
        level_after=3,
    )
    return SpanQuery(collector)


def _cwe89_module() -> CWEModule:
    """Create a CWEModule for CWE-89 (SQL Injection)."""
    return CWEModule(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
    )


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


# ---------------------------------------------------------------------------
# Existing regression tests
# ---------------------------------------------------------------------------


class TestDetectorAgent:
    def test_format_input(self) -> None:
        agent = DetectorAgent(
            llm=AsyncMock(spec=LLMClient),
            span_query=_populated_query(),
            config=_DETECTOR_CONFIG,
        )
        msg = agent.format_input({"exploitation_level": 3})
        assert "CVE-2024-9999" in msg
        assert "L3" in msg
        assert "2 OTEL spans" in msg

    @pytest.mark.parametrize(
        ("raw_text", "check_field"),
        [
            pytest.param(
                '{"sigma_rule": "title: test", "snort_rule": "alert tcp...", "summary": "ok"}',
                "sigma_rule",
                id="valid_json",
            ),
            pytest.param(
                "no json here at all",
                "raw_output",
                id="invalid_json",
            ),
        ],
    )
    def test_parse_output(self, raw_text: str, check_field: str) -> None:
        agent = DetectorAgent(
            llm=AsyncMock(spec=LLMClient),
            span_query=_populated_query(),
            config=_DETECTOR_CONFIG,
        )
        output = agent.parse_output(raw_text)
        if check_field == "sigma_rule":
            assert output["sigma_rule"] == "title: test"
            assert output["snort_rule"] == "alert tcp..."
            assert len(output["rules"]) == 2
        else:
            assert "raw_output" in output or output["rules"] == []

    @pytest.mark.asyncio
    async def test_run_tool_then_text(self) -> None:
        llm = AsyncMock(spec=LLMClient)
        llm.complete = AsyncMock(
            side_effect=[
                (
                    _llm_response(
                        tool_calls=[
                            {
                                "name": "query_exploit_signals",
                                "arguments": {"mode": "summary"},
                            }
                        ]
                    ),
                    TokenUsage(
                        prompt_tokens=100,
                        completion_tokens=50,
                        total_tokens=150,
                        llm_calls=1,
                    ),
                ),
                (
                    _llm_response(
                        content=json.dumps(
                            {
                                "sigma_rule": "title: CVE-2024-9999",
                                "snort_rule": "alert tcp...",
                                "summary": "Generated rules",
                            }
                        )
                    ),
                    TokenUsage(
                        prompt_tokens=200,
                        completion_tokens=100,
                        total_tokens=300,
                        llm_calls=1,
                    ),
                ),
            ]
        )
        agent = DetectorAgent(llm=llm, span_query=_populated_query(), config=_DETECTOR_CONFIG)
        result = await agent.run({"exploitation_level": 3})

        assert result.turns_used == 2
        assert len(result.tool_calls) == 1
        assert result.output["cve_id"] == "CVE-2024-9999"
        assert result.output["total_spans"] == 2
        assert "sigma_rule" in result.output

    @pytest.mark.asyncio
    async def test_exhaustion_produces_output_via_final_demand(self) -> None:
        """With max_turns=3 and all tool calls, final JSON demand should produce rules."""
        config = AgentConfig(
            name="detector",
            system_prompt="Generate detection rules.",
            max_turns=3,
        )

        tool_responses = [
            (
                _llm_response(
                    tool_calls=[
                        {
                            "id": f"call_{i}",
                            "name": "query_exploit_signals",
                            "arguments": {"mode": "summary"},
                        }
                    ]
                ),
                TokenUsage(prompt_tokens=50, completion_tokens=25, total_tokens=75, llm_calls=1),
            )
            for i in range(3)
        ]

        final_response = (
            _llm_response(
                content=json.dumps(
                    {
                        "sigma_rule": "title: CVE-2024-9999 exhaustion test",
                        "snort_rule": "alert tcp any any -> any any (msg:test;)",
                        "summary": "Generated via final demand",
                    }
                )
            ),
            TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1),
        )

        llm = AsyncMock(spec=LLMClient)
        llm.complete = AsyncMock(side_effect=[*tool_responses, final_response])

        agent = DetectorAgent(llm=llm, span_query=_populated_query(), config=config)
        result = await agent.run({"exploitation_level": 3})

        assert "rules" in result.output


# ---------------------------------------------------------------------------
# Phase 3.1: Detector prompt references KB tools
# ---------------------------------------------------------------------------


class TestDetectorPrompt:
    """Verify the detector prompt file mentions required tools."""

    def test_detector_prompt_mentions_json_output(self) -> None:
        """Detector system prompt specifies JSON output keys."""
        engine = PromptEngine()
        prompt = engine.render("agents/detector")
        assert "sigma_rule" in prompt
        assert "snort_rule" in prompt


# ---------------------------------------------------------------------------
# Phase 3.3: CWE context injection
# ---------------------------------------------------------------------------


class TestDetectorCWEContext:
    """Verify CWE-specific detection context is injected."""

    def test_detector_receives_cwe_context(self) -> None:
        """DetectorAgent with CWE-89 module has SQL Injection in system prompt."""
        config = AgentConfig(
            name="detector",
            system_prompt="Generate detection rules.",
            max_turns=5,
        )
        agent = DetectorAgent(
            llm=AsyncMock(spec=LLMClient),
            span_query=_populated_query(),
            config=config,
            cwe_module=_cwe89_module(),
        )
        # The system prompt should have been augmented with CWE context
        assert "SQL Injection" in agent.config.system_prompt
        assert "CWE-89" in agent.config.system_prompt


# ---------------------------------------------------------------------------
# Phase 3.2: Per-agent base_config overrides
# ---------------------------------------------------------------------------


class TestDetectorBaseConfig:
    """Verify per-agent overrides for max_continues / max_nudges."""

    def test_base_config_passed_to_agent(self) -> None:
        """DetectorAgent accepts and stores custom BaseAgentSettings."""
        custom = BaseAgentSettings(max_continues=2, max_nudges=1)
        agent = DetectorAgent(
            llm=AsyncMock(spec=LLMClient),
            span_query=_populated_query(),
            config=_DETECTOR_CONFIG,
            base_config=custom,
        )
        assert agent._base_config.max_continues == 2
        assert agent._base_config.max_nudges == 1
