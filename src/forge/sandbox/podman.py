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

import asyncio
import logging
import re
import shlex
import shutil
import tempfile
from pathlib import Path

from forge.models import CVETask
from forge.sandbox._base import (
    do_http_request,
    extract_error_summary,
    find_free_port,
    qualify_dockerfile_images,
    run_podman,
    wait_for_health,
)
from forge.sandbox.models import (
    CommandResult,
    DeployResult,
    HttpResponse,
    SandboxInfo,
    SandboxSnapshot,
)
from forge.sandbox.protocols import SandboxSession

logger = logging.getLogger(__name__)

DEFAULT_BASE_IMAGE = "python:3.12-slim"
EXPLOIT_RUNNER_IMAGE = "forge-exploit-runner:latest"


class PodmanSandbox:
    """Podman pod-based sandbox with dual containers (app + exploit runner).

    A Podman *pod* groups two containers sharing a network namespace —
    ``app`` (the vulnerable target) and ``exploit`` (pre-built Python 3.12
    runner).
    """

    def __init__(
        self,
        pod_name: str,
        *,
        base_image: str = DEFAULT_BASE_IMAGE,
        port: int = 8080,
        timeout: int = 120,
        memory: str = "512m",
        cpus: float = 1.0,
    ) -> None:
        self._pod_name = pod_name
        self._app_ctr = f"{pod_name}-app"
        self._exploit_ctr = f"{pod_name}-exploit"
        self.info = SandboxInfo(container_name=pod_name, image=base_image, port=port)
        self._timeout = timeout
        self._memory = memory
        self._cpus = cpus
        self._host_port: int | None = None
        self._temp_dir: Path | None = None

    @property
    def base_url(self) -> str:
        return f"http://localhost:{self._host_port or self.info.port}"

    @property
    def exploit_url(self) -> str:
        return f"http://localhost:{self.info.port}"

    async def deploy(
        self,
        project_files: dict[str, str],
        *,
        health_path: str = "/health",
    ) -> DeployResult:
        """Build app image, create pod with both containers, health check."""
        result = DeployResult()
        try:
            result = await self._do_deploy(project_files, result, health_path=health_path)
        except Exception as e:
            result.error = f"Deploy error: {e}"
            logger.exception("Deploy failed for %s", self._pod_name)
        return result

    async def _do_deploy(
        self,
        project_files: dict[str, str],
        result: DeployResult,
        *,
        health_path: str = "/health",
    ) -> DeployResult:
        # Clean up any previous deploy attempt (idempotent)
        await run_podman(["pod", "rm", "-f", self._pod_name], timeout=15)
        old_image = f"forge-{self._pod_name}:latest"
        await run_podman(["rmi", "-f", old_image], timeout=10)
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)

        # Auto-detect the port the app actually listens on
        detected_port = _detect_app_port(project_files)
        if detected_port != self.info.port:
            logger.info(
                "Port auto-detect: app listens on %d (was %d)",
                detected_port,
                self.info.port,
            )
            self.info.port = detected_port

        self._temp_dir = Path(tempfile.mkdtemp(prefix=f"forge-{self._pod_name}-"))
        app_dir = self._temp_dir / "app"
        app_dir.mkdir()
        for fp, content in project_files.items():
            p = app_dir / fp
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)

        if "Dockerfile" not in project_files:
            result.error = "No Dockerfile in project files"
            return result

        # Qualify unqualified FROM image names for Podman compatibility.
        # Podman (unlike Docker) rejects short names like "golang:1.20"
        # when no unqualified-search-registries are configured.
        dockerfile_path = app_dir / "Dockerfile"
        original_df = dockerfile_path.read_text()
        qualified_df = qualify_dockerfile_images(original_df)
        if qualified_df != original_df:
            dockerfile_path.write_text(qualified_df)

        # Build app image
        image = f"forge-{self._pod_name}:latest"
        build = await run_podman(
            ["build", "-t", image, "-f", str(app_dir / "Dockerfile"), str(app_dir)],
            timeout=self._timeout,
        )
        result.build_log = build.stdout + build.stderr
        if build.exit_code != 0:
            # Extract the important error lines instead of blindly truncating.
            combined = (build.stdout + "\n" + build.stderr).strip()
            error_summary = extract_error_summary(combined)
            result.error = f"Build failed (exit {build.exit_code}):\n{error_summary}"
            return result
        self.info.image = image

        # Create pod
        self._host_port = await find_free_port()
        pod = await run_podman(
            [
                "pod",
                "create",
                "--name",
                self._pod_name,
                "-p",
                f"{self._host_port}:{self.info.port}",
            ],
        )
        if pod.exit_code != 0:
            result.error = f"Pod creation failed: {pod.stderr[-500:]}"
            return result

        # Start app container
        app = await run_podman(
            [
                "run",
                "-d",
                "--pod",
                self._pod_name,
                "--name",
                self._app_ctr,
                "--memory",
                self._memory,
                "--cpus",
                str(self._cpus),
                image,
            ],
        )
        result.start_log = app.stdout + app.stderr
        if app.exit_code != 0:
            result.error = f"App container start failed: {app.stderr[-500:]}"
            return result
        self.info.container_id = app.stdout.strip()[:12]

        # Start exploit container
        exp = await run_podman(
            [
                "run",
                "-d",
                "--pod",
                self._pod_name,
                "--name",
                self._exploit_ctr,
                "-e",
                f"TARGET_URL={self.exploit_url}",
                EXPLOIT_RUNNER_IMAGE,
            ],
        )
        if exp.exit_code != 0:
            result.error = f"Exploit container start failed: {exp.stderr[-500:]}"
            return result

        self.info.status = "running"
        logger.info("Pod %s running on port %d", self._pod_name, self._host_port)

        # Health check
        result.health_check_passed = await wait_for_health(
            self.base_url, self._pod_name, health_path=health_path, timeout=30
        )
        result.success = result.health_check_passed
        if not result.health_check_passed:
            logs = await run_podman(["logs", "--tail", "50", self._app_ctr])
            combined_logs = (logs.stdout + "\n" + logs.stderr).strip()
            log_summary = extract_error_summary(combined_logs)
            result.error = f"Health check failed. Container logs:\n{log_summary}"
        return result

    async def exec(self, command: str, timeout: int = 30) -> CommandResult:
        if self.info.status != "running":
            return CommandResult(exit_code=-1, stderr="Container not running")
        try:
            async with asyncio.timeout(timeout):
                return await run_podman(["exec", self._app_ctr, "sh", "-c", command])
        except TimeoutError:
            return CommandResult(exit_code=-1, stderr="Command execution timed out")

    async def exec_exploit(
        self,
        command: str,
        timeout: int = 30,
    ) -> CommandResult:
        if self.info.status != "running":
            return CommandResult(exit_code=-1, stderr="Container not running")
        try:
            async with asyncio.timeout(timeout):
                return await run_podman(["exec", self._exploit_ctr, "sh", "-c", command])
        except TimeoutError:
            return CommandResult(exit_code=-1, stderr="Command execution timed out")

    async def write_file(self, path: str, content: str) -> None:
        await self._write_to(self._app_ctr, path, content)

    async def write_exploit_file(self, path: str, content: str) -> None:
        await self._write_to(self._exploit_ctr, path, content)

    async def read_file(self, path: str) -> str:
        result = await self.exec(f"cat {shlex.quote(path)}")
        if result.exit_code != 0:
            raise FileNotFoundError(f"Cannot read {path}: {result.stderr}")
        return result.stdout

    async def http_request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        files: list[tuple[str, tuple[str, bytes, str]]] | None = None,
    ) -> HttpResponse:
        return await do_http_request(
            self.base_url,
            method,
            path,
            headers=headers,
            body=body,
            files=files,
        )

    async def snapshot(self) -> SandboxSnapshot:
        snap = SandboxSnapshot()
        if self.info.status != "running":
            return snap
        mc = await self.exec(
            "find /tmp -name 'pwned*' -o -name 'marker*' -o -name 'rce*' 2>/dev/null"
        )
        if mc.stdout.strip():
            snap.files_created = mc.stdout.strip().split("\n")
        ps = await self.exec("ps aux 2>/dev/null || ps -ef 2>/dev/null")
        if ps.exit_code == 0:
            for line in ps.stdout.strip().split("\n")[1:]:
                snap.processes.append({"raw": line})
        logs = await run_podman(["logs", "--tail", "100", self._app_ctr])
        snap.app_logs = logs.stdout + logs.stderr
        return snap

    async def destroy(self) -> None:
        try:
            await run_podman(["pod", "rm", "-f", self._pod_name], timeout=15)
            if self.info.image.startswith("forge-"):
                await run_podman(["rmi", "-f", self.info.image], timeout=10)
            # Prune dangling images left by podman build to prevent
            # build-cache accumulation during batch runs (500+ CVEs).
            await run_podman(["image", "prune", "-f"], timeout=30)
        except Exception:
            logger.warning("Cleanup error for %s", self._pod_name, exc_info=True)
        finally:
            self.info.status = "destroyed"
            if self._temp_dir and self._temp_dir.exists():
                shutil.rmtree(self._temp_dir, ignore_errors=True)
        logger.info("Destroyed sandbox %s", self._pod_name)

    async def _write_to(self, container: str, path: str, content: str) -> None:
        if self.info.status != "running":
            raise RuntimeError("Container not running")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as f:
            f.write(content)
            temp_path = f.name
        try:
            cp = await run_podman(["cp", temp_path, f"{container}:{path}"])
            if cp.exit_code != 0:
                raise OSError(f"podman cp failed (exit {cp.exit_code}): {cp.stderr[:500]}")
        finally:
            Path(temp_path).unlink(missing_ok=True)


class PodmanSandboxManager:
    """Creates and manages PodmanSandbox instances."""

    def __init__(
        self,
        *,
        base_image: str = DEFAULT_BASE_IMAGE,
        default_port: int = 8080,
        timeout: int = 120,
        memory: str = "512m",
        cpus: float = 1.0,
    ) -> None:
        self._base_image = base_image
        self._default_port = default_port
        self._timeout = timeout
        self._memory = memory
        self._cpus = cpus
        self._counter = 0

    async def create(self, task: CVETask, *, port: int | None = None) -> PodmanSandbox:
        self._counter += 1
        name = f"forge-{task.cve_id.lower()}-{self._counter}"
        proc = await asyncio.create_subprocess_exec(
            "podman",
            "pod",
            "rm",
            "-f",
            name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return PodmanSandbox(
            pod_name=name,
            base_image=self._base_image,
            port=port or self._default_port,
            timeout=self._timeout,
            memory=self._memory,
            cpus=self._cpus,
        )

    async def destroy(self, session: SandboxSession) -> None:
        await session.destroy()

    async def cleanup_stale_containers(self) -> None:
        """Remove forge-cve-* pods left from previous runs.

        Preserves the forge-exploit-runner image -- only removes
        pods/containers.  Called at the start of each pipeline run to
        prevent accumulation during batch execution.
        """
        result = await run_podman(
            ["pod", "ls", "--format", "{{.Name}}", "--noheading"],
            timeout=15,
        )
        if result.exit_code != 0:
            logger.warning("Failed to list pods for cleanup: %s", result.stderr[:200])
            return

        pod_names = [
            name.strip()
            for name in result.stdout.strip().split("\n")
            if name.strip().startswith("forge-cve-")
        ]
        if not pod_names:
            return

        logger.info("Cleaning up %d stale forge-cve pod(s)", len(pod_names))
        for pod_name in pod_names:
            await run_podman(["pod", "rm", "-f", pod_name], timeout=15)


def _detect_app_port(project_files: dict[str, str]) -> int:
    """Detect the port the application will actually listen on.

    Scans project files in priority order:
    1. Python ``app.run(port=...)`` or ``uvicorn.run(..., port=...)``
    2. JavaScript ``.listen(PORT)``
    3. Dockerfile CMD/ENTRYPOINT ``--bind HOST:PORT`` (gunicorn)
    4. Dockerfile CMD ``-S HOST:PORT`` (PHP built-in server)
    5. Dockerfile ``EXPOSE PORT``
    6. Default 8080
    """
    # Python: app.run(port=N) or uvicorn.run(..., port=N)
    for name, content in project_files.items():
        if name.endswith(".py"):
            m = re.search(r"\.run\([^)]*port\s*=\s*(\d+)", content)
            if m:
                return int(m.group(1))

    # JavaScript: .listen(PORT)
    for name, content in project_files.items():
        if name.endswith(".js"):
            m = re.search(r"\.listen\(\s*(\d+)", content)
            if m:
                return int(m.group(1))

    # Dockerfile CMD/ENTRYPOINT for port hints
    dockerfile = project_files.get("Dockerfile", "")
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith(("CMD", "ENTRYPOINT")):
            # gunicorn --bind 0.0.0.0:PORT
            m = re.search(r"--bind\s+[\w.]+:(\d+)", stripped)
            if m:
                return int(m.group(1))
            # PHP: -S 0.0.0.0:PORT
            m = re.search(r"-S\s+[\w.]+:(\d+)", stripped)
            if m:
                return int(m.group(1))
            # Generic --port PORT
            m = re.search(r"--port\s+(\d+)", stripped)
            if m:
                return int(m.group(1))

    # EXPOSE directive (last resort — it's metadata, not enforcement)
    for line in dockerfile.splitlines():
        m = re.match(r"^\s*EXPOSE\s+(\d+)", line)
        if m:
            return int(m.group(1))

    return 8080
