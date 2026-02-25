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
