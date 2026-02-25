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

import pytest
from pydantic import ValidationError

from forge.generator.verification import (
    VerificationResult,
    check_dependency_usage,
    check_fabrication_patterns,
)
from forge.models import (
    AppManifest,
    ExperimentCondition,
    ExploitAttempt,
    GeneratedApp,
    TokenUsage,
)


class TestTokenUsage:
    def test_addition(self) -> None:
        a = TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1)
        b = TokenUsage(prompt_tokens=200, completion_tokens=100, total_tokens=300, llm_calls=2)
        result = a + b
        assert result.prompt_tokens == 300
        assert result.completion_tokens == 150
        assert result.total_tokens == 450
        assert result.llm_calls == 3


class TestExploitAttempt:
    def test_exploitation_level_too_high(self) -> None:
        with pytest.raises(ValidationError):
            ExploitAttempt(
                cve_id="CVE-2025-27520",
                condition=ExperimentCondition.GENERIC,
                exploitation_level=7,
            )


class TestAppManifest:
    def test_vulnerable_endpoint_string(self) -> None:
        """Normal case: string endpoint is preserved."""
        m = AppManifest(
            cve_id="CVE-2024-1234",
            cwe="CWE-89",
            language="python",
            framework="flask",
            vulnerable_endpoint="/login",
        )
        assert m.vulnerable_endpoint == "/login"

    def test_vulnerable_endpoint_dict_with_path(self) -> None:
        """Bug 2 regression: LLM returns dict with 'path' key."""
        m = AppManifest(
            cve_id="CVE-2024-1234",
            cwe="CWE-89",
            language="python",
            framework="flask",
            vulnerable_endpoint={"path": "/api/vuln", "method": "POST"},  # type: ignore[arg-type]
        )
        assert m.vulnerable_endpoint == "/api/vuln"

    def test_vulnerable_endpoint_dict_with_url(self) -> None:
        """Bug 2 regression: LLM returns dict with 'url' key."""
        m = AppManifest(
            cve_id="CVE-2024-1234",
            cwe="CWE-89",
            language="python",
            framework="flask",
            vulnerable_endpoint={"url": "/upload"},  # type: ignore[arg-type]
        )
        assert m.vulnerable_endpoint == "/upload"

    def test_vulnerable_endpoint_dict_fallback(self) -> None:
        """Bug 2 regression: dict without path/url falls back to /vulnerable."""
        m = AppManifest(
            cve_id="CVE-2024-1234",
            cwe="CWE-89",
            language="python",
            framework="flask",
            vulnerable_endpoint={"unexpected": "value"},  # type: ignore[arg-type]
        )
        assert m.vulnerable_endpoint == "/vulnerable"


class TestGeneratedApp:
    def test_creation(self) -> None:
        manifest = AppManifest(
            cve_id="CVE-2024-1234",
            cwe="CWE-89",
            language="python",
            framework="flask",
            vulnerable_endpoint="/login",
        )
        app = GeneratedApp(
            cve_id="CVE-2024-1234",
            project_files={"app.py": "from flask import Flask\n", "Dockerfile": "FROM python:3.12"},
            manifest=manifest,
        )
        assert app.cve_id == "CVE-2024-1234"
        assert len(app.project_files) == 2
        assert app.manifest.health_endpoint == "/health"
        assert app.manifest.health_port == 8080
        assert app.manifest.complexity_level == "L1"


class TestVerificationResult:
    """Merged from tests/test_verification.py."""

    @pytest.mark.parametrize(
        "build_ok,deploy_ok,health_ok,vuln_present,expected_success,failure_reason,details",
        [
            pytest.param(True, True, True, True, True, None, None, id="all-pass"),
            pytest.param(False, False, False, False, False, None, None, id="build-fail"),
        ],
    )
    def test_result_combinations(
        self,
        build_ok: bool,
        deploy_ok: bool,
        health_ok: bool,
        vuln_present: bool,
        expected_success: bool,
        failure_reason: str | None,
        details: str | None,
    ) -> None:
        result = VerificationResult(
            success=expected_success,
            build_ok=build_ok,
            deploy_ok=deploy_ok,
            health_ok=health_ok,
            vuln_present=vuln_present,
            failure_reason=failure_reason,
            details=details,
        )
        assert result.success is expected_success
        assert result.failure_reason == failure_reason
        assert result.details == details


class TestCheckDependencyUsage:
    def test_python_unused_dep(self) -> None:
        files = {
            "requirements.txt": "flask==2.0\nredis==4.0\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        }
        unused = check_dependency_usage(files, "python")
        assert unused == ["redis"]

    def test_python_all_used(self) -> None:
        files = {
            "requirements.txt": "flask==2.0\nredis==4.0\n",
            "app.py": "from flask import Flask\nimport redis\n",
        }
        assert check_dependency_usage(files, "python") == []

    def test_python_hyphen_underscore_normalisation(self) -> None:
        files = {
            "requirements.txt": "python-dateutil>=2.8\n",
            "app.py": "import python_dateutil\n",
        }
        assert check_dependency_usage(files, "python") == []

    def test_python_skips_runtime_packages(self) -> None:
        files = {
            "requirements.txt": "flask==2.0\ngunicorn==21.0\n",
            "app.py": "from flask import Flask\n",
        }
        # gunicorn is runtime-only, should not be flagged
        assert check_dependency_usage(files, "python") == []

    def test_node_unused_dep(self) -> None:
        files = {
            "package.json": '{"dependencies": {"express": "^4.0", "redis": "^3.0"}}',
            "index.js": "const express = require('express');\n",
        }
        unused = check_dependency_usage(files, "javascript")
        assert unused == ["redis"]

    def test_node_esm_import(self) -> None:
        files = {
            "package.json": '{"dependencies": {"express": "^4.0"}}',
            "index.ts": "import express from 'express';\n",
        }
        assert check_dependency_usage(files, "typescript") == []

    def test_go_unused_dep(self) -> None:
        files = {
            "go.mod": (
                "module myapp\n\ngo 1.21\n\n"
                "require (\n"
                "\tgithub.com/go-redis/redis/v8 v8.11.5\n"
                "\tgithub.com/gin-gonic/gin v1.9.0\n"
                ")\n"
            ),
            "main.go": 'import "github.com/gin-gonic/gin"\n',
        }
        unused = check_dependency_usage(files, "go")
        assert unused == ["github.com/go-redis/redis/v8"]

    def test_unsupported_language_returns_empty(self) -> None:
        assert check_dependency_usage({}, "rust") == []

    def test_no_dep_file_returns_empty(self) -> None:
        files = {"app.py": "print('hello')"}
        assert check_dependency_usage(files, "python") == []


class TestFabricationPatterns:
    """Tests for check_fabrication_patterns static analysis."""

    def test_detects_fake_redis_function(self) -> None:
        files = {
            "app.py": "def startFakeRedis():\n    sock = socket.socket()\n",
        }
        findings = check_fabrication_patterns(files)
        assert len(findings) >= 1
        assert any("Fake" in f for f in findings)

    def test_detects_mock_server_class(self) -> None:
        files = {
            "server.py": "class MockRedisServer:\n    pass\n",
        }
        findings = check_fabrication_patterns(files)
        assert len(findings) >= 1
        assert any("Mock" in f for f in findings)

    def test_detects_ok_sendall(self) -> None:
        files = {
            "fake.py": "conn.sendall(b'+OK\\r\\n')\n",
        }
        findings = check_fabrication_patterns(files)
        assert len(findings) >= 1
        assert any("+OK" in f for f in findings)

    def test_clean_code_no_findings(self) -> None:
        files = {
            "app.py": "import redis\nr = redis.Redis()\nr.get('key')\n",
        }
        findings = check_fabrication_patterns(files)
        assert findings == []

    def test_ignores_vendor_files(self) -> None:
        files = {
            "/vendor/lib/mock.py": "class MockRedisServer:\n    pass\n",
        }
        findings = check_fabrication_patterns(files)
        assert findings == []

    def test_no_source_files(self) -> None:
        files = {"Dockerfile": "FROM python:3.12\n"}
        findings = check_fabrication_patterns(files)
        assert findings == []
