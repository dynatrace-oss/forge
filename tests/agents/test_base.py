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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forge.agents.base import AgentConfig, BaseAgent
from forge.models import TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.tools.base import ToolRegistry


class StubAgent(BaseAgent):
    """Minimal concrete agent for testing."""

    def format_input(self, input_data: dict[str, Any]) -> str:
        return json.dumps(input_data)

    def parse_output(self, content: str) -> dict[str, Any]:
        try:
            return dict(json.loads(content))
        except (json.JSONDecodeError, TypeError):
            return {"raw": content}


def _make_llm_response(
    content: str | None = None,
    tool_calls: list[Any] | None = None,
) -> MagicMock:
    """Build a mock litellm response."""
    message = MagicMock()
    message.content = content
    message.tool_calls = tool_calls

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = "tool_calls" if tool_calls else "stop"

    response = MagicMock()
    response.choices = [choice]

    usage = MagicMock()
    usage.prompt_tokens = 100
    usage.completion_tokens = 50
    usage.total_tokens = 150
    response.usage = usage

    return response


def _make_tool_call_obj(call_id: str, name: str, arguments: dict[str, Any]) -> MagicMock:
    """Build a mock OpenAI-format tool call."""
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


class TestBaseAgentTextOnly:
    @pytest.mark.asyncio
    async def test_simple_text_response(self) -> None:
        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="test", system_prompt="Be helpful.", max_turns=5)
        agent = StubAgent(config=config, llm=llm)

        response = _make_llm_response(content='{"answer": "42"}')
        with patch.object(
            llm,
            "complete",
            new_callable=AsyncMock,
            return_value=(response, TokenUsage(total_tokens=150, llm_calls=1)),
        ):
            result = await agent.run({"question": "what?"})

        assert result.output == {"answer": "42"}
        assert result.turns_used == 1
        assert result.tokens.total_tokens == 150
        assert len(result.tool_calls) == 0


class TestBaseAgentWithTools:
    @pytest.mark.asyncio
    async def test_tool_call_then_text(self) -> None:
        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="test", system_prompt="Use tools.", max_turns=5)

        registry = ToolRegistry()
        from tests.tools.test_base import EchoTool

        registry.register(EchoTool())
        agent = StubAgent(config=config, llm=llm, tools=registry)

        # Turn 1: LLM calls echo tool
        tc_obj = _make_tool_call_obj("call_1", "echo", {"message": "hello"})
        tool_response = _make_llm_response(content=None, tool_calls=[tc_obj])

        # Turn 2: LLM returns final text
        text_response = _make_llm_response(content='{"result": "done"}')

        tokens = TokenUsage(total_tokens=100, llm_calls=1)
        with patch.object(
            llm,
            "complete",
            new_callable=AsyncMock,
            side_effect=[(tool_response, tokens), (text_response, tokens)],
        ):
            result = await agent.run({"task": "echo test"})

        assert result.output == {"result": "done"}
        assert result.turns_used == 2
        assert result.tokens.total_tokens == 200
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].name == "echo"
        assert len(result.tool_results) == 1
        assert result.tool_results[0].content == "Echo: hello"


class TestBaseAgentMaxTurns:
    @pytest.mark.asyncio
    async def test_max_turns_exhaustion(self) -> None:
        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="test", system_prompt="Use tools.", max_turns=2)

        registry = ToolRegistry()
        from tests.tools.test_base import EchoTool

        registry.register(EchoTool())
        agent = StubAgent(config=config, llm=llm, tools=registry)

        tc = _make_tool_call_obj("call_1", "echo", {"message": "x"})
        tool_response = _make_llm_response(content=None, tool_calls=[tc])

        tokens = TokenUsage(total_tokens=50, llm_calls=1)
        with patch.object(
            llm,
            "complete",
            new_callable=AsyncMock,
            return_value=(tool_response, tokens),
        ):
            result = await agent.run({"task": "loop"})

        assert result.turns_used == 2
        assert result.output == {}  # No text content from tool-only responses


class TestToolOutputPairing:
    """Bug 4 regression: tool_call.output must be populated after execution."""

    @pytest.mark.asyncio
    async def test_tool_call_output_populated(self) -> None:
        """After tool execution, the ToolCall.output field should contain the result."""
        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="test", system_prompt="Use tools.", max_turns=5)

        registry = ToolRegistry()
        from tests.tools.test_base import EchoTool

        registry.register(EchoTool())
        agent = StubAgent(config=config, llm=llm, tools=registry)

        tc_obj = _make_tool_call_obj("call_1", "echo", {"message": "hello"})
        tool_response = _make_llm_response(content=None, tool_calls=[tc_obj])
        text_response = _make_llm_response(content='{"done": true}')

        tokens = TokenUsage(total_tokens=100, llm_calls=1)
        with patch.object(
            llm,
            "complete",
            new_callable=AsyncMock,
            side_effect=[(tool_response, tokens), (text_response, tokens)],
        ):
            result = await agent.run({"task": "echo test"})

        assert len(result.tool_calls) == 1
        tc = result.tool_calls[0]
        assert tc.output == "Echo: hello", f"Expected paired output, got {tc.output!r}"
        assert tc.error is False

    @pytest.mark.asyncio
    async def test_tool_call_error_flag_on_failure(self) -> None:
        """When a tool raises, the ToolCall.error flag should be True."""
        from forge.tools.base import Tool, ToolResult

        class FailTool(Tool):
            @property
            def name(self) -> str:
                return "fail_tool"

            @property
            def description(self) -> str:
                return "Always fails"

            @property
            def parameters(self) -> dict[str, Any]:
                return {"type": "object", "properties": {}}

            async def execute(self, arguments: dict[str, Any]) -> ToolResult:
                return ToolResult(content="something went wrong", error=True)

        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="test", system_prompt="Use tools.", max_turns=5)

        registry = ToolRegistry()
        registry.register(FailTool())
        agent = StubAgent(config=config, llm=llm, tools=registry)

        tc_obj = _make_tool_call_obj("call_1", "fail_tool", {})
        tc_obj2 = _make_tool_call_obj("call_2", "fail_tool", {})
        tool_response = _make_llm_response(content=None, tool_calls=[tc_obj])
        tool_response2 = _make_llm_response(content=None, tool_calls=[tc_obj2])
        text_response = _make_llm_response(content='{"done": true}')

        tokens = TokenUsage(total_tokens=100, llm_calls=1)
        with patch.object(
            llm,
            "complete",
            new_callable=AsyncMock,
            # Turn 1: force_tool → fail, Turn 2: force_tool retry → fail,
            # Turn 3: auto → text output (force attempts exhausted)
            side_effect=[
                (tool_response, tokens),
                (tool_response2, tokens),
                (text_response, tokens),
            ],
        ):
            result = await agent.run({"task": "fail"})

        assert len(result.tool_calls) == 2
        assert result.tool_calls[0].error is True
        assert result.tool_calls[0].output == "something went wrong"
        assert result.tool_calls[1].error is True


class TestPartialTokens:
    """Bug 5 regression: _partial_tokens must persist per-turn totals even if run() crashes."""

    @pytest.mark.asyncio
    async def test_partial_tokens_updated_each_turn(self) -> None:
        """_partial_tokens should reflect accumulated tokens even mid-loop."""
        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="test", system_prompt="Use tools.", max_turns=5)

        registry = ToolRegistry()
        from tests.tools.test_base import EchoTool

        registry.register(EchoTool())
        agent = StubAgent(config=config, llm=llm, tools=registry)

        tc_obj = _make_tool_call_obj("call_1", "echo", {"message": "hi"})
        tool_response = _make_llm_response(content=None, tool_calls=[tc_obj])
        text_response = _make_llm_response(content='{"ok": true}')

        tokens = TokenUsage(total_tokens=75, llm_calls=1)
        with patch.object(
            llm,
            "complete",
            new_callable=AsyncMock,
            side_effect=[(tool_response, tokens), (text_response, tokens)],
        ):
            await agent.run({"task": "test"})

        # After 2 turns: 75 + 75 = 150
        assert agent._partial_tokens.total_tokens == 150

    @pytest.mark.asyncio
    async def test_partial_tokens_survives_crash(self) -> None:
        """If the LLM crashes on turn 2, _partial_tokens still has turn 1 totals."""
        llm = LLMClient(enable_otel=False)
        config = AgentConfig(name="test", system_prompt="Use tools.", max_turns=5)

        registry = ToolRegistry()
        from tests.tools.test_base import EchoTool

        registry.register(EchoTool())
        agent = StubAgent(config=config, llm=llm, tools=registry)

        tc_obj = _make_tool_call_obj("call_1", "echo", {"message": "hi"})
        tool_response = _make_llm_response(content=None, tool_calls=[tc_obj])

        tokens_turn1 = TokenUsage(total_tokens=80, llm_calls=1)

        call_count = 0

        async def _mock_complete(**kwargs: Any) -> tuple[MagicMock, TokenUsage]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return tool_response, tokens_turn1
            raise RuntimeError("LLM connection lost")

        with (
            patch.object(llm, "complete", side_effect=_mock_complete),
            pytest.raises(RuntimeError, match="LLM connection lost"),
        ):
            await agent.run({"task": "test"})

        # Turn 1 completed before crash → _partial_tokens has 80
        assert agent._partial_tokens.total_tokens == 80
