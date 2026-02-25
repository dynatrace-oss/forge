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

from unittest.mock import AsyncMock

import pytest

from forge.sandbox.models import CommandResult
from forge.tools.sandbox_tools import (
    ExecCommand,
    ReadFile,
    RunExploitScript,
)


def _session() -> AsyncMock:
    s = AsyncMock()
    s.exec_exploit = AsyncMock()
    s.exec = AsyncMock()
    s.read_file = AsyncMock()
    s.write_exploit_file = AsyncMock()
    return s


class TestSandboxTools:
    @pytest.mark.asyncio
    async def test_exec_command_success_and_failure(self) -> None:
        s = _session()
        s.exec_exploit.return_value = CommandResult(exit_code=0, stdout="hello")
        r = await ExecCommand(s).execute({"command": "echo hello"})
        assert not r.error and "hello" in r.content

        s.exec_exploit.return_value = CommandResult(exit_code=1, stderr="bad", timed_out=True)
        r = await ExecCommand(s).execute({"command": "bad", "timeout": 5})
        assert "[timed out]" in r.content

    @pytest.mark.asyncio
    async def test_read_file(self) -> None:
        s = _session()
        s.read_file.return_value = "content"
        r = await ReadFile(s).execute({"path": "/app/x"})
        assert "content" in r.content

    @pytest.mark.asyncio
    async def test_run_exploit_script(self) -> None:
        s = _session()
        s.exec_exploit.return_value = CommandResult(exit_code=0, stdout="pwned")
        r = await RunExploitScript(s).execute({"script": "print('pwned')"})
        assert not r.error
        assert "pwned" in r.content
        s.write_exploit_file.assert_called_once_with("/tmp/exploit_script.py", "print('pwned')")

    @pytest.mark.asyncio
    async def test_run_exploit_script_write_error(self) -> None:
        s = _session()
        s.write_exploit_file.side_effect = RuntimeError("disk full")
        r = await RunExploitScript(s).execute({"script": "x"})
        assert r.error
        assert "disk full" in r.content
