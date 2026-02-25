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
