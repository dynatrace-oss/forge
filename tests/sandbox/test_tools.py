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
