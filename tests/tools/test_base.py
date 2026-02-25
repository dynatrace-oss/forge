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
from unittest.mock import MagicMock

import pytest

from forge.tools.base import Tool, ToolCall, ToolRegistry, ToolResult


class EchoTool(Tool):
    """Test tool that echoes its arguments."""

    @property
    def name(self) -> str:
        return "echo"

    @property
    def description(self) -> str:
        return "Echoes the input message"

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        return ToolResult(content=f"Echo: {arguments.get('message', '')}")


class FailingTool(Tool):
    """Test tool that always raises."""

    @property
    def name(self) -> str:
        return "fail"

    @property
    def description(self) -> str:
        return "Always fails"

    @property
    def parameters(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        raise RuntimeError("intentional failure")


class TestToolCall:
    def test_from_openai_string_args(self) -> None:
        mock_tc = MagicMock()
        mock_tc.id = "call_abc123"
        mock_tc.function.name = "echo"
        mock_tc.function.arguments = '{"message": "hello"}'
        result = ToolCall.from_openai(mock_tc)
        assert result.id == "call_abc123"
        assert result.name == "echo"
        assert result.arguments == {"message": "hello"}

    def test_from_openai_none_args(self) -> None:
        """Bug 3 regression: None arguments should produce empty dict, not crash."""
        mock_tc = MagicMock()
        mock_tc.id = "call_none"
        mock_tc.function.name = "http_request"
        mock_tc.function.arguments = None
        result = ToolCall.from_openai(mock_tc)
        assert result.name == "http_request"
        assert result.arguments == {}

    def test_from_openai_dict_args(self) -> None:
        """LiteLLM sometimes returns pre-parsed dict arguments."""
        mock_tc = MagicMock()
        mock_tc.id = "call_dict"
        mock_tc.function.name = "exec_command"
        mock_tc.function.arguments = {"command": "whoami"}
        result = ToolCall.from_openai(mock_tc)
        assert result.name == "exec_command"
        assert result.arguments == {"command": "whoami"}

    def test_output_field_default_none(self) -> None:
        """Bug 4 regression: ToolCall has output/error fields for paired serialization."""
        tc = ToolCall(name="test", arguments={})
        assert tc.output is None
        assert tc.error is False


class TestCoerceDict:
    """Bug 5 regression: coerce_dict handles dict, JSON string, and bad types."""

    def test_passthrough_dict(self) -> None:
        """A real dict passes through unchanged."""
        from forge.tools.base import coerce_dict

        d = {"Content-Type": "application/json"}
        assert coerce_dict(d, "headers") == d

    def test_parses_json_string(self) -> None:
        """A JSON-encoded dict string is parsed to a dict."""
        from forge.tools.base import coerce_dict

        result = coerce_dict('{"Authorization": "Bearer tok"}', "headers")
        assert result == {"Authorization": "Bearer tok"}

    def test_invalid_type_raises_typeerror(self) -> None:
        """Non-dict, non-string values raise TypeError."""
        from forge.tools.base import coerce_dict

        with pytest.raises(TypeError, match="must be a dict"):
            coerce_dict(42, "headers")


class TestToolRegistry:
    @pytest.mark.asyncio
    async def test_execute_success(self) -> None:
        reg = ToolRegistry()
        reg.register(EchoTool())
        tc = ToolCall(id="c1", name="echo", arguments={"message": "hi"})
        result = await reg.execute(tc)
        assert result.content == "Echo: hi"
        assert result.tool_call_id == "c1"
        assert result.error is False
