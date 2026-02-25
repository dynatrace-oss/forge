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

import pytest

from forge.detection.artifacts import (
    _extract_http_exchanges,
    collect_artifacts,
)
from forge.detection.models import ConfidenceTier
from forge.models import CVETask, ExploitResult
from forge.oracle.models import OracleVerdict
from forge.sandbox.models import SandboxSnapshot


@pytest.fixture()
def basic_task() -> CVETask:
    return CVETask(
        cve_id="CVE-2024-1234",
        cwe_ids=["CWE-79"],
        language="python",
    )


@pytest.fixture()
def basic_snapshot() -> SandboxSnapshot:
    return SandboxSnapshot(
        files_created=["/tmp/marker.txt", "/tmp/exploit_output.json"],
        files_modified=["/var/log/app.log"],
        processes=[
            {"name": "python3", "cmdline": "python3 exploit.py"},
            {"name": "sh", "cmdline": "sh -c id"},
        ],
        app_logs=(
            "WARNING: Injection attempt detected on /api/search\n"
            "ERROR: Unhandled exception in request handler\n"
            "INFO: Request to http://localhost:8080/api/search completed\n"
        ),
        network_connections=["tcp://10.0.0.1:8080", "tcp://10.0.0.1:3306"],
    )


@pytest.fixture()
def exploit_with_http() -> ExploitResult:
    return ExploitResult(
        exploit_files={
            "exploit.py": (
                "import requests\n"
                'r = requests.post("http://localhost:8080/api/search", '
                'data={"q": "<script>alert(1)</script>"})\n'
                'print(f"status_code: {r.status_code}")\n'
                'r2 = requests.get("http://localhost:8080/api/users")\n'
            ),
        },
        execution_log=(
            "Running exploit.py...\n"
            'requests.post("http://localhost:8080/api/search", data=...)\n'
            "status_code: 200\n"
            'Response: {"results": [{"name": "<script>alert(1)</script>"}]}\n'
            'requests.get("http://localhost:8080/api/users")\n'
            "status_code: 403\n"
        ),
        completed=True,
        turns_used=3,
        max_level_reached=3,
    )


@pytest.fixture()
def verdict_level3() -> OracleVerdict:
    return OracleVerdict(
        binary_success=True,
        exploitation_level=3,
        confidence=0.8,
        tier_used="template",
    )


# ---------------------------------------------------------------------------
# _extract_http_exchanges
# ---------------------------------------------------------------------------


def test_extract_http_exchanges_from_execution_log() -> None:
    log = (
        'requests.post("http://localhost:8080/login", data=...)\n'
        "status_code: 200\n"
        'requests.get("http://localhost:8080/admin")\n'
        "HTTP/1.1 403 Forbidden\n"
    )
    exchanges = _extract_http_exchanges(log, "")
    assert len(exchanges) == 2
    assert exchanges[0].method == "POST"
    assert exchanges[0].url == "http://localhost:8080/login"
    assert exchanges[0].status_code == 200
    assert exchanges[1].method == "GET"
    assert exchanges[1].url == "http://localhost:8080/admin"
    assert exchanges[1].status_code == 403


def test_collect_artifacts_integration(
    exploit_with_http: ExploitResult,
    basic_snapshot: SandboxSnapshot,
    verdict_level3: OracleVerdict,
    basic_task: CVETask,
) -> None:
    artifacts = collect_artifacts(exploit_with_http, basic_snapshot, verdict_level3, basic_task)

    assert artifacts.cve_id == "CVE-2024-1234"
    assert artifacts.cwe_id == "CWE-79"
    assert artifacts.exploitation_level == 3
    assert artifacts.confidence_tier == ConfidenceTier.HIGH

    # HTTP exchanges extracted from execution log
    assert len(artifacts.http_exchanges) >= 2

    # File artifacts from snapshot
    assert len(artifacts.file_artifacts) == 3

    # Payloads from exploit files
    assert len(artifacts.payloads) == 1
    assert "exploit.py" in artifacts.payloads[0]

    # Network connections from snapshot
    assert len(artifacts.network_connections) == 2

    # Processes from snapshot
    assert len(artifacts.processes) == 2
    assert "python3 exploit.py" in artifacts.processes[0]

    # Log patterns from app_logs
    assert len(artifacts.log_patterns) >= 1
