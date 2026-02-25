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
