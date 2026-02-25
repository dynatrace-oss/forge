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
import logging
import re
from abc import ABC, abstractmethod
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Matches malformed \uXXXX sequences (incomplete, non-hex digits)
_BAD_UNICODE_RE = re.compile(r"\\u(?![0-9a-fA-F]{4})[^\s\"\\]{0,4}")


def _repair_json(raw: str) -> str:
    r"""Best-effort repair of common LLM JSON malformations.

    Handles:
    - Invalid ``\uXXXX`` escapes (replace with U+FFFD)
    - Unescaped control characters (strip)
    """
    # Fix invalid \uXXXX sequences
    repaired = _BAD_UNICODE_RE.sub("\ufffd", raw)
    # Strip bare control characters (except newline/tab within strings)
    repaired = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", repaired)
    return repaired


def safe_json_loads(raw: str) -> Any:
    """Parse JSON with automatic repair for common LLM malformations.

    Tries ``json.loads`` first; on failure, repairs the string and retries.
    Raises ``json.JSONDecodeError`` only if both attempts fail.
    """
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        repaired = _repair_json(raw)
        return json.loads(repaired)


def coerce_dict(value: Any, field_name: str = "field") -> dict[str, Any]:
    """Coerce a JSON-string-encoded dict to an actual dict.

    LLMs sometimes double-serialize dict arguments — e.g., passing
    ``headers`` as ``'{"Content-Type": "application/json"}'`` instead of
    a proper dict.  This helper transparently handles both forms.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError as exc:
            raise TypeError(
                f"{field_name} must be a dict or JSON string, got unparseable string"
            ) from exc
        if isinstance(parsed, dict):
            return parsed
        raise TypeError(f"{field_name} JSON string did not decode to a dict")
    raise TypeError(f"{field_name} must be a dict, got {type(value).__name__}")


class ToolCall(BaseModel):
    """A tool call requested by the LLM."""

    id: str = Field(default_factory=lambda: f"call_{uuid4().hex[:12]}")
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    output: str | None = None
    error: bool = False

    @classmethod
    def from_openai(cls, tool_call: Any) -> "ToolCall":
        """Parse from an OpenAI-format tool call in a litellm response.

        Uses ``safe_json_loads`` to handle malformed JSON from the LLM
        (invalid unicode escapes, control characters, etc.).
        """
        raw_args = tool_call.function.arguments
        if raw_args is None:
            logger.warning(
                "Tool call %s for %s has null arguments — likely output "
                "truncation (max_tokens too low for tool payload)",
                tool_call.id,
                tool_call.function.name,
            )
            args: dict[str, Any] = {}
        elif isinstance(raw_args, str):
            if raw_args.strip() in ("", "{}"):
                logger.warning(
                    "Tool call %s for %s has empty arguments string (%r) — "
                    "possible output truncation",
                    tool_call.id,
                    tool_call.function.name,
                    raw_args[:50],
                )
            try:
                args = safe_json_loads(raw_args)
            except json.JSONDecodeError:
                logger.warning(
                    "Unparseable tool call arguments for %s (len=%d), using empty args",
                    tool_call.function.name,
                    len(raw_args),
                )
                args = {}
        else:
            args = dict(raw_args)
        return cls(id=tool_call.id, name=tool_call.function.name, arguments=args)


class ToolResult(BaseModel):
    """Result of executing a tool."""

    tool_call_id: str = ""
    content: str
    error: bool = False


class Tool(ABC):
    """Abstract base class for all FORGE tools.

    Concrete tools implement ``name``, ``description``, ``parameters``,
    and ``execute``. The ``ToolRegistry`` handles call routing, error
    wrapping, and OpenAI-schema generation.
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def parameters(self) -> dict[str, Any]:
        """JSON Schema describing the tool's accepted arguments."""
        ...

    @abstractmethod
    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        """Execute the tool with parsed arguments.

        Return a ``ToolResult`` with content. The ``tool_call_id`` field
        is set by the registry after execution — tools should leave it
        as the default empty string.
        """
        ...

    def to_openai_schema(self) -> dict[str, Any]:
        """Generate OpenAI-compatible tool definition for LiteLLM."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    """Registry of available tools with lookup and schema generation."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register a tool. Raises ``ValueError`` on duplicate names."""
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name!r}")
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s", tool.name)

    def get(self, name: str) -> Tool:
        """Get a tool by name. Raises ``KeyError`` if not found."""
        try:
            return self._tools[name]
        except KeyError:
            raise KeyError(f"Unknown tool: {name!r}") from None

    def list_names(self) -> list[str]:
        """Return sorted list of registered tool names."""
        return sorted(self._tools)

    def to_openai_schemas(self) -> list[dict[str, Any]]:
        """Generate OpenAI-compatible tool definitions for all registered tools."""
        return [tool.to_openai_schema() for tool in self._tools.values()]

    async def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a tool call. Returns an error result for unknown tools or exceptions."""
        try:
            tool = self.get(tool_call.name)
        except KeyError:
            return ToolResult(
                tool_call_id=tool_call.id,
                content=f"Error: unknown tool {tool_call.name!r}",
                error=True,
            )
        try:
            result = await tool.execute(tool_call.arguments)
            result.tool_call_id = tool_call.id
            return result
        except Exception as exc:
            logger.exception("Tool %s raised an exception", tool_call.name)
            return ToolResult(
                tool_call_id=tool_call.id,
                content=f"Error executing {tool_call.name}: {exc}",
                error=True,
            )

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
