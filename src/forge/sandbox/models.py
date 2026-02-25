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
from typing import Any, Literal

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CommandResult(BaseModel):
    """Result of executing a command in the sandbox."""

    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


class HttpResponse(BaseModel):
    """Result of an HTTP request to the sandbox application."""

    status_code: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    error: str | None = None


class DeployResult(BaseModel):
    """Result of deploying an application in the sandbox."""

    success: bool = False
    build_log: str = ""
    start_log: str = ""
    health_check_passed: bool = False
    error: str | None = None


class SandboxSnapshot(BaseModel):
    """Filesystem + process state snapshot for oracle evaluation."""

    files_created: list[str] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    processes: list[dict[str, Any]] = Field(default_factory=list)
    app_logs: str = ""
    network_connections: list[str] = Field(default_factory=list)


class SandboxInfo(BaseModel):
    """Metadata about a running sandbox."""

    container_id: str = ""
    container_name: str = ""
    image: str = ""
    host: str = "localhost"
    port: int = 8080
    status: Literal["created", "running", "stopped", "destroyed"] = "created"
