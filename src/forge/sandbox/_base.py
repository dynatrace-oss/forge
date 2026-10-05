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
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

import httpx

from forge.sandbox.models import CommandResult, HttpResponse, SandboxSnapshot

logger = logging.getLogger(__name__)


async def _run_container_cli(
    binary: str,
    args: list[str],
    timeout: int,
) -> CommandResult:
    """Execute a container-engine CLI command (``podman`` or ``docker``).

    Default timeout is 120s (increased from 60s to accommodate slow
    ``pod rm`` / ``rm`` operations on resource-constrained instances).
    """
    cmd = [binary, *args]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:
        logger.warning("%s command failed to start: %s — %s", binary, " ".join(cmd), e)
        return CommandResult(exit_code=-1, stderr=str(e))

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        return CommandResult(
            exit_code=proc.returncode or 0,
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
        )
    except TimeoutError:
        logger.warning("%s command timed out: %s", binary, " ".join(cmd))
        # Kill the leaked process to prevent accumulation over batch runs
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass  # already dead
        except Exception:
            logger.debug("Failed to kill timed-out process", exc_info=True)
        return CommandResult(exit_code=-1, stderr="Command timed out", timed_out=True)
    except Exception as e:
        logger.warning("%s command failed: %s — %s", binary, " ".join(cmd), e)
        return CommandResult(exit_code=-1, stderr=str(e))


async def run_podman(
    args: list[str],
    timeout: int = 120,
) -> CommandResult:
    """Execute a podman CLI command."""
    return await _run_container_cli("podman", args, timeout)


async def run_docker(
    args: list[str],
    timeout: int = 120,
) -> CommandResult:
    """Execute a docker CLI command."""
    return await _run_container_cli("docker", args, timeout)


async def do_http_request(
    base_url: str,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    files: list[tuple[str, tuple[str, bytes, str]]] | None = None,
) -> HttpResponse:
    """Send an HTTP request to a sandbox application.

    Shared helper used by both Podman and Kind backends.

    Args:
        files: Optional multipart file tuples for upload.
            Each tuple is ``(field_name, (filename, content_bytes, mime_type))``.
            When provided, the request uses ``multipart/form-data`` and
            *body* is ignored.
    """
    url = f"{base_url}{path}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            if files is not None:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    files=files,
                )
            else:
                content: bytes | None = None
                if isinstance(body, str):
                    content = body.encode()
                elif isinstance(body, bytes):
                    content = body

                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=content,
                )

            return HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
            )
    except Exception as e:
        return HttpResponse(error=str(e))


async def wait_for_tcp(
    host: str,
    port: int,
    container_name: str,
    *,
    timeout: int = 30,
) -> bool:
    """Wait for a TCP port to accept connections.

    Used for non-HTTP services (SSH, databases, custom protocols) where an
    HTTP GET probe would never succeed.
    """
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
            writer.close()
            await writer.wait_closed()
            logger.info(
                "TCP health check passed: %s port %d",
                container_name,
                port,
            )
            return True
        except (OSError, TimeoutError, ConnectionRefusedError):
            await asyncio.sleep(1.0)

    logger.warning(
        "TCP health check FAILED: %s port %d — no connection within %ds",
        container_name,
        port,
        timeout,
    )
    return False


async def wait_for_health(
    base_url: str,
    container_name: str,
    *,
    health_path: str = "/health",
    health_mode: str = "http",
    timeout: int = 30,
) -> bool:
    """Wait for an application to become healthy.

    Dispatches to the appropriate probe strategy based on *health_mode*:

    - ``"http"`` — HTTP GET probe (two-stage liveness + readiness).
    - ``"tcp"`` — TCP socket connect (for non-HTTP services like SSH).
    - ``"skip"`` — assume healthy immediately (for exotic protocols).

    Two-stage HTTP probe:

    1. **Liveness** — poll ``health_path`` then ``/`` until *any* HTTP response
       (even 500) proves the TCP listener is alive.
    2. **Readiness** — once alive, verify at least one path returns a non-5xx
       status.  If both ``health_path`` and ``/`` return 5xx the app is
       considered *not healthy* (functionally broken despite the server running).

    This catches the failure mode where a PHP/Java app starts its web server
    but every route returns 500 due to a missing DB or broken initialisation.
    """
    # Mode dispatch
    if health_mode == "skip":
        logger.info("Health check skipped for %s", container_name)
        return True

    if health_mode == "tcp":
        parsed = urlparse(base_url)
        return await wait_for_tcp(
            parsed.hostname or "localhost",
            parsed.port or 80,
            container_name,
            timeout=timeout,
        )

    # HTTP probe (default)
    deadline = asyncio.get_event_loop().time() + timeout
    probe_paths = [health_path]
    if health_path != "/":
        probe_paths.append("/")

    # Stage 1: wait for any HTTP response (liveness)
    alive = False
    last_status: dict[str, int] = {}

    while asyncio.get_event_loop().time() < deadline:
        for path in probe_paths:
            try:
                resp = await do_http_request(base_url, "GET", path)
                if resp.status_code > 0:
                    last_status[path] = resp.status_code
                    alive = True
            except Exception:
                pass

        if alive:
            break
        await asyncio.sleep(1.0)

    if not alive:
        logger.warning("Health check: %s — no HTTP response within %ds", container_name, timeout)
        return False

    # Stage 2: readiness — at least one path must return non-5xx
    has_healthy_path = any(200 <= code < 500 for code in last_status.values())

    if has_healthy_path:
        best_path = min(last_status, key=lambda p: last_status[p])
        logger.info(
            "Health check passed: %s %s -> %d",
            container_name,
            best_path,
            last_status[best_path],
        )
        return True

    # All paths returned 5xx — keep retrying until the original deadline.
    # Benchmark containers often need 30–90 s for DB init / PHP warm-up.
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(2.0)
        for path in probe_paths:
            try:
                resp = await do_http_request(base_url, "GET", path)
                if 200 <= resp.status_code < 500:
                    logger.info(
                        "Health check passed (readiness retry): %s %s -> %d",
                        container_name,
                        path,
                        resp.status_code,
                    )
                    return True
                last_status[path] = resp.status_code
            except Exception:
                pass

    status_summary = ", ".join(f"{p}={c}" for p, c in last_status.items())
    logger.warning(
        "Health check FAILED (all 5xx): %s — %s",
        container_name,
        status_summary,
    )
    return False


async def take_snapshot(
    exec_fn: "Callable[..., Awaitable[CommandResult]]",
    logs_fn: "Callable[[], Awaitable[str]]",
) -> SandboxSnapshot:
    """Capture filesystem + process state for oracle evaluation.

    Args:
        exec_fn: Callable(command, timeout) -> CommandResult — runs inside the
            *app* container (marker files and process list live there).
        logs_fn: Callable() -> str — returns recent container/pod logs.
    """
    snap = SandboxSnapshot()

    marker_check = await exec_fn(
        "find /tmp -name 'pwned*' -o -name 'marker*' -o -name 'rce*' 2>/dev/null"
    )
    if marker_check.stdout.strip():
        snap.files_created = marker_check.stdout.strip().split("\n")

    ps_result = await exec_fn("ps aux 2>/dev/null || ps -ef 2>/dev/null")
    if ps_result.exit_code == 0:
        for line in ps_result.stdout.strip().split("\n")[1:]:
            snap.processes.append({"raw": line})

    snap.app_logs = await logs_fn()

    return snap


async def find_free_port() -> int:
    """Find a free TCP port on localhost."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        port: int = s.getsockname()[1]
        return port

# Patterns that signal an actionable error line in build or runtime output.
_ERROR_INDICATORS: tuple[str, ...] = (
    "error",
    "fatal",
    "failed",
    "cannot",
    "not found",
    "no such",
    "denied",
    "exception",
    "does not exist",
    "unresolved",
    "could not",
    "unable to",
    "exit code",
    "exit status",
    "traceback",
    "importerror",
    "modulenotfounderror",
    "syntaxerror",
    "typeerror",
    "nameerror",
    "permission denied",
    "segmentation fault",
)


def extract_error_summary(output: str, *, max_chars: int = 2000) -> str:
    """Extract the important error lines from build / deploy output.

    Instead of blindly returning the last *max_chars* characters (which may
    be dominated by cleanup or subsequent ``STEP`` noise), this function:

    1. Scans every line for common error indicators (case-insensitive).
    2. Includes 2 context lines *before* each matching line so the reader
       can see what command or step produced the error.
    3. Always appends the **last 15 lines** of output (typically the
       builder summary or final exit message).
    4. De-duplicates and truncates to *max_chars*.

    Returns a string suitable for embedding in an LLM prompt.
    """
    if not output:
        return ""

    lines = output.splitlines()

    # Collect indices of error-relevant lines
    error_indices: set[int] = set()
    lower_output_lines = [ln.lower() for ln in lines]

    for idx, lower_line in enumerate(lower_output_lines):
        if any(indicator in lower_line for indicator in _ERROR_INDICATORS):
            # Include 2 context lines before the error
            for ctx in range(max(0, idx - 2), idx + 1):
                error_indices.add(ctx)

    # Always include the last 15 lines (summary / exit info)
    tail_start = max(0, len(lines) - 15)
    tail_indices = set(range(tail_start, len(lines)))

    # Merge and sort
    selected = sorted(error_indices | tail_indices)

    # Build output with gap markers when lines are skipped
    parts: list[str] = []
    prev = -2  # sentinel
    for idx in selected:
        if idx > prev + 1:
            parts.append("...")  # gap marker
        parts.append(lines[idx])
        prev = idx

    summary = "\n".join(parts)

    # Truncate to max_chars (keep the end which has the summary)
    if len(summary) > max_chars:
        summary = "...\n" + summary[-(max_chars - 4) :]

    return summary


# ---------------------------------------------------------------------------
# Dockerfile image-name qualification
# ---------------------------------------------------------------------------

# Matches a Dockerfile FROM instruction with an unqualified image name
# (no slash → official Docker Hub image).  Captures:
#   prefix  – "FROM " with optional leading whitespace
#   image   – bare image name (letters, digits, hyphens, underscores)
#   rest    – :tag, @digest, " AS alias", or end-of-line
_FROM_RE = re.compile(
    r"^(?P<prefix>\s*FROM\s+)"
    r"(?P<image>[a-zA-Z0-9_-]+)"
    r"(?P<rest>[:\s@].*)?$",
    re.IGNORECASE,
)


def qualify_dockerfile_images(dockerfile: str) -> str:
    """Rewrite unqualified ``FROM`` image names to ``docker.io/library/…``.

    Podman without ``unqualified-search-registries`` (the default on Ubuntu)
    rejects short names like ``golang:1.20-alpine`` that Docker Hub resolves
    transparently.  This adds ``docker.io/library/`` to every ``FROM`` whose
    image name contains no ``/`` (i.e. is an official Docker Hub library
    image).

    Already-qualified names (``docker.io/library/python:3.11-slim``,
    ``ghcr.io/foo/bar:latest``) are left unchanged.  Build-arg references
    (``FROM ${BASE_IMAGE}``) are also skipped.
    """
    lines = dockerfile.splitlines()
    rewritten = False

    for i, line in enumerate(lines):
        m = _FROM_RE.match(line)
        if m:
            image = m.group("image")
            if image.startswith("$"):
                continue
            rest = m.group("rest") or ""
            lines[i] = f"{m.group('prefix')}docker.io/library/{image}{rest}"
            rewritten = True

    if rewritten:
        logger.debug("Qualified Dockerfile FROM images for Podman compatibility")

    return "\n".join(lines)
