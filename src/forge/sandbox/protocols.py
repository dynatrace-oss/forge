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

from typing import Protocol

from forge.models import CVETask
from forge.sandbox.models import (
    CommandResult,
    DeployResult,
    HttpResponse,
    SandboxSnapshot,
)


class SandboxSession(Protocol):
    """Protocol for sandbox execution environments.

    After Phase G every sandbox is a *pod* containing two containers:

    - **app**: the vulnerable target application (Node/Go/PHP/Java/C/Python).
    - **exploit**: a pre-built Python 3.12 runner with ``requests`` + ``httpx``.

    The ``exec`` / ``write_file`` / ``read_file`` methods target the **app**
    container.  The ``exec_exploit`` / ``write_exploit_file`` methods target the
    **exploit** container.  Both containers share ``localhost`` within the pod,
    so exploit scripts reach the app via ``http://localhost:<app_port>``.
    """

    @property
    def base_url(self) -> str:
        """HTTP base URL for the application running in the sandbox."""
        ...

    @property
    def exploit_url(self) -> str:
        """URL the exploit runner should use to reach the app.

        Inside the pod this is ``http://localhost:<app_port>`` — *not* the
        host-mapped port that ``base_url`` exposes for health checks.
        """
        ...

    async def deploy(
        self,
        project_files: dict[str, str],
        *,
        health_path: str = "/health",
    ) -> DeployResult:
        """Write project files, build, and start the application."""
        ...

    async def exec(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute a command inside the **app** container."""
        ...

    async def exec_exploit(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute a command inside the **exploit** container."""
        ...

    async def write_file(self, path: str, content: str) -> None:
        """Write a file inside the **app** container."""
        ...

    async def write_exploit_file(self, path: str, content: str) -> None:
        """Write a file inside the **exploit** container."""
        ...

    async def read_file(self, path: str) -> str:
        """Read a file from the **app** container."""
        ...

    async def http_request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        files: list[tuple[str, tuple[str, bytes, str]]] | None = None,
    ) -> HttpResponse:
        """Send an HTTP request to the application running in the sandbox."""
        ...

    async def snapshot(self) -> SandboxSnapshot:
        """Capture filesystem + process state for oracle evaluation."""
        ...

    async def destroy(self) -> None:
        """Tear down the sandbox and clean up resources."""
        ...


class SandboxManager(Protocol):
    """Protocol for creating and managing sandbox sessions."""

    async def create(self, task: CVETask, *, port: int | None = None) -> SandboxSession:
        """Create a new sandbox session for a CVE task.

        Args:
            task: CVE task to create the sandbox for.
            port: Optional container port override (detected from Dockerfile EXPOSE).
        """
        ...

    async def destroy(self, session: SandboxSession) -> None:
        """Destroy a sandbox session."""
        ...

    async def cleanup_stale_containers(self) -> None:
        """Remove stale forge-cve-* pods from previous runs.

        Called at the start of each pipeline run to prevent container
        accumulation during batch execution.
        """
        ...
