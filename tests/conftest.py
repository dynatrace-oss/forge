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

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from forge.config import ForgeConfig
from forge.models import CVETask, TokenUsage


@pytest.fixture()
def forge_config(tmp_path: pytest.TempPathFactory) -> ForgeConfig:
    """ForgeConfig with default values and tmp_path-based directories."""
    return ForgeConfig()


@pytest.fixture()
def sample_task() -> CVETask:
    """Standard CVETask for integration tests."""
    return CVETask(
        cve_id="CVE-2024-9999",
        cwe_ids=["CWE-89"],
        description="SQL injection in login endpoint",
        severity="critical",
        language="python",
        framework="flask",
        vulnerable_package="flask-app",
        vulnerable_version="1.0.0",
    )


@pytest.fixture()
def mock_sandbox_session() -> AsyncMock:
    """Mock SandboxSession with all protocol methods."""
    session = AsyncMock()
    for attr in ("exec_exploit", "exec", "read_file", "write_exploit_file", "http_request"):
        setattr(session, attr, AsyncMock())
    session.base_url = "http://localhost:8080"
    session.exploit_url = "http://localhost:8080"
    return session


def make_llm_text_response(content: str) -> MagicMock:
    """Build a mock LLM response with text content, no tool calls."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = None
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    return resp


def make_llm_tool_response(tool_calls: list[dict[str, Any]]) -> MagicMock:
    """Build a mock LLM response with tool calls."""
    msg = MagicMock()
    msg.content = None
    tcs = []
    for i, tc in enumerate(tool_calls):
        m = MagicMock()
        m.id = f"call_{i}"
        m.function.name = tc["name"]
        m.function.arguments = json.dumps(tc.get("arguments", {}))
        tcs.append(m)
    msg.tool_calls = tcs
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    return resp


def make_llm_complete_side_effect(
    responses: list[MagicMock],
) -> list[tuple[MagicMock, TokenUsage]]:
    """Wrap raw LLM responses into (response, TokenUsage) tuples for LLMClient.complete()."""
    return [(r, TokenUsage(total_tokens=100, llm_calls=1)) for r in responses]
