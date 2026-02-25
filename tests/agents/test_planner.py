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
from forge.agents.planner import PlannerAgent
from forge.models import TokenUsage
from forge.pipeline.llm_client import LLMClient

_PLANNER_CONFIG = AgentConfig(
    name="planner",
    system_prompt="Create an attack plan.",
    max_turns=5,
)


def _llm_response(content: str) -> MagicMock:
    """Create a mock LLM response with text content (no tool calls)."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = None
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    return resp


class TestPlannerAgent:
    def test_format_input_with_intel_report(self) -> None:
        agent = PlannerAgent(llm=AsyncMock(spec=LLMClient), config=_PLANNER_CONFIG)
        intel_report: dict[str, Any] = {
            "cve_id": "CVE-2024-1234",
            "root_cause": "SQL injection in login form",
            "cwe_ids": ["CWE-89"],
            "attack_surface": {
                "endpoints": ["/api/login"],
                "inputs": ["username", "password"],
            },
        }
        msg = agent.format_input({"intel_report": intel_report})
        assert "CVE-2024-1234" in msg
        assert "SQL injection" in msg
        assert "/api/login" in msg
        assert "CWE-89" in msg

    def test_format_input_renders_prior_knowledge(self) -> None:
        """Bug 1 regression: planner must include KB context when prior_knowledge is provided."""
        agent = PlannerAgent(llm=AsyncMock(spec=LLMClient), config=_PLANNER_CONFIG)
        msg = agent.format_input(
            {
                "intel_report": {"cve_id": "CVE-2024-9999"},
                "prior_knowledge": "CWE-89: UNION-based extraction succeeds 80%.",
            }
        )
        assert "Prior Knowledge" in msg
        assert "UNION-based extraction" in msg
        assert "CVE-2024-9999" in msg

    def test_format_input_omits_prior_knowledge_when_empty(self) -> None:
        """prior_knowledge should not appear when empty string is provided."""
        agent = PlannerAgent(llm=AsyncMock(spec=LLMClient), config=_PLANNER_CONFIG)
        msg = agent.format_input(
            {
                "intel_report": {"cve_id": "CVE-2024-9999"},
                "prior_knowledge": "",
            }
        )
        assert "Prior Knowledge" not in msg

    @pytest.mark.asyncio
    async def test_run_parses_json_plan(self) -> None:
        plan = {
            "primary_strategy": {
                "technique": "SQL injection via username",
                "steps": ["Send ' OR 1=1--"],
                "success_indicators": ["Login bypass"],
            },
            "escalation_paths": [],
            "fallback_strategies": [],
            "key_targets": ["/api/login"],
            "estimated_difficulty": "low",
        }
        llm = AsyncMock(spec=LLMClient)
        llm.complete = AsyncMock(
            return_value=(
                _llm_response(json.dumps(plan)),
                TokenUsage(prompt_tokens=500, completion_tokens=200, total_tokens=700, llm_calls=1),
            )
        )
        agent = PlannerAgent(llm=llm, config=_PLANNER_CONFIG)
        result = await agent.run({"intel_report": {"cve_id": "CVE-2024-1234"}})

        assert result.turns_used == 1
        assert result.output["primary_strategy"]["technique"] == "SQL injection via username"
        assert result.output["estimated_difficulty"] == "low"
        assert len(result.tool_calls) == 0
