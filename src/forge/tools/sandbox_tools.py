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


class ExecCommand(Tool):
    """Execute a shell command inside the sandbox exploit container."""

    def __init__(self, session: SandboxSession) -> None:
        self._session = session

    @property
    def name(self) -> str:
        return "exec_command"

    @property
    def description(self) -> str:
        return (
            "Execute a shell command inside the exploit container. "
            "Use this for running exploit scripts, installing tools, "
            "or inspecting the target. Commands run as root. "
            "The target application is reachable at $TARGET_URL "
            "(environment variable) from inside this container."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default 30, max 120)",
                    "default": 30,
                },
            },
            "required": ["command"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        command: str = arguments["command"]
        timeout = min(int(arguments.get("timeout", 30)), 120)

        result = await self._session.exec_exploit(command, timeout=timeout)

        output_parts: list[str] = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            output_parts.append(f"[stderr]\n{result.stderr}")
        if result.timed_out:
            output_parts.append("[timed out]")

        output = "\n".join(output_parts) or "(no output)"
        output = f"exit_code={result.exit_code}\n{output}"

        if len(output) > _MAX_OUTPUT:
            output = output[:_MAX_OUTPUT] + f"\n... truncated ({len(output)} chars total)"

        return ToolResult(content=output, error=result.exit_code != 0)


class ReadFile(Tool):
    """Read a file from the target application container."""

    def __init__(self, session: SandboxSession) -> None:
        self._session = session

    @property
    def name(self) -> str:
        return "read_file"

    @property
    def description(self) -> str:
        return (
            "Read a file from the target application container filesystem. "
            "Use this for reading configuration files, source code, "
            "or sensitive data from the target."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file (e.g. /app/config.py)",
                },
            },
            "required": ["path"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        path: str = arguments["path"]

        try:
            content = await self._session.read_file(path)
        except Exception as exc:
            return ToolResult(content=f"Error reading {path}: {exc}", error=True)

        if len(content) > _MAX_OUTPUT:
            content = content[:_MAX_OUTPUT] + f"\n... truncated ({len(content)} chars total)"

        return ToolResult(content=content)


class RunExploitScript(Tool):
    """Write and execute a Python exploit script in the exploit container."""

    def __init__(self, session: SandboxSession) -> None:
        self._session = session

    @property
    def name(self) -> str:
        return "run_exploit_script"

    @property
    def description(self) -> str:
        return (
            "Write a Python exploit script and execute it in the exploit container. "
            "The script has access to: requests, httpx, urllib3, socket, subprocess, "
            "and the TARGET_URL environment variable. "
            "The script should print evidence of exploitation to stdout. "
            "Use this as your PRIMARY exploitation tool — write complete Python scripts "
            "that perform the attack, analyze responses, and escalate."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "script": {
                    "type": "string",
                    "description": (
                        "Complete Python script to execute. Must be self-contained. "
                        "Use os.environ['TARGET_URL'] for the target base URL. "
                        "Print all relevant output (responses, errors, evidence)."
                    ),
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default 60, max 120)",
                    "default": 60,
                },
            },
            "required": ["script"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        script: str = arguments["script"]
        timeout = min(int(arguments.get("timeout", 60)), 120)

        # Write script to a temp file and execute it
        script_path = "/tmp/exploit_script.py"
        try:
            await self._session.write_exploit_file(script_path, script)
        except Exception as exc:
            return ToolResult(content=f"Error writing script: {exc}", error=True)

        result = await self._session.exec_exploit(f"python3 {script_path}", timeout=timeout)

        output_parts: list[str] = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            output_parts.append(f"[stderr]\n{result.stderr}")
        if result.timed_out:
            output_parts.append("[script timed out]")

        output = "\n".join(output_parts) or "(no output)"
        output = f"exit_code={result.exit_code}\n{output}"

        if len(output) > _MAX_OUTPUT:
            output = output[:_MAX_OUTPUT] + f"\n... truncated ({len(output)} chars total)"

        return ToolResult(content=output, error=result.exit_code != 0)


def register_sandbox_tools(session: SandboxSession) -> list[Tool]:
    """Create and return all sandbox tools for the given session."""
    return [
        ExecCommand(session),
        ReadFile(session),
        RunExploitScript(session),
    ]
