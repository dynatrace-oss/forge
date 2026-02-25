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
