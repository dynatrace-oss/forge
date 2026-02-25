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
