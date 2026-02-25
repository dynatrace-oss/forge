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

import logging
from typing import Any

from forge.sandbox.protocols import SandboxSession
from forge.tools.base import Tool, ToolResult

logger = logging.getLogger(__name__)

_MAX_OUTPUT = 16_000


class GetAppLogs(Tool):
    """Retrieve application and server logs from the target container."""

    def __init__(self, session: SandboxSession) -> None:
        self._session = session

    @property
    def name(self) -> str:
        return "get_app_logs"

    @property
    def description(self) -> str:
        return (
            "Retrieve application logs from the target container. "
            "Shows server-side errors, access logs, and debug output. "
            "Use this after sending requests to see server-side effects."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "integer",
                    "description": "Number of recent log lines to retrieve (default 100)",
                    "default": 100,
                },
                "filter": {
                    "type": "string",
                    "description": "Optional grep pattern to filter logs",
                },
            },
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        lines = min(int(arguments.get("lines", 100)), 500)
        log_filter: str | None = arguments.get("filter")

        snapshot = await self._session.snapshot()
        app_logs = snapshot.app_logs

        if not app_logs:
            return ToolResult(content="(no application logs available)")

        log_lines = app_logs.splitlines()
        if log_filter:
            log_lines = [ln for ln in log_lines if log_filter.lower() in ln.lower()]

        log_lines = log_lines[-lines:]
        output = "\n".join(log_lines)

        if len(output) > _MAX_OUTPUT:
            output = output[:_MAX_OUTPUT] + f"\n... truncated ({len(output)} chars total)"

        return ToolResult(content=output or "(no matching log lines)")


def register_observation_tools(session: SandboxSession) -> list[Tool]:
    """Create and return all observation tools for the given session."""
    return [
        GetAppLogs(session),
    ]
