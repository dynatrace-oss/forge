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
from pathlib import Path

import pytest
import yaml

from forge.signals.collector import SpanCollector
from forge.signals.query import SpanQuery
from forge.tools.base import ToolCall, ToolResult
from forge.tools.detection_tools import (
    GetDetectionReference,
    GetSigmaTemplate,
    GetSnortTemplate,
    QueryExploitSignals,
    ValidateRule,
)


def _populated_query() -> SpanQuery:
    """Create a SpanQuery with sample exploitation spans."""
    collector = SpanCollector(cve_id="CVE-2024-5678")
    collector.record(
        ToolCall(
            name="http_request",
            arguments={"method": "POST", "url": "/api/login", "body": "admin' OR 1=1--"},
        ),
        ToolResult(content="SQL syntax error"),
        level_before=0,
        level_after=3,
    )
    collector.record(
        ToolCall(name="exec_command", arguments={"command": "id"}),
        ToolResult(content="uid=0(root)"),
        level_before=3,
        level_after=6,
    )
    return SpanQuery(collector)


def _sqli_query() -> SpanQuery:
    """SpanQuery with realistic SQL injection exploitation spans."""
    collector = SpanCollector(cve_id="CVE-2024-9999")
    collector.record(
        ToolCall(
            name="http_request",
            arguments={
                "method": "GET",
                "url": "http://target:8080/api/search?q=test",
                "body": "",
            },
        ),
        ToolResult(content="200 OK"),
        level_before=0,
        level_after=1,
    )
    collector.record(
        ToolCall(
            name="http_request",
            arguments={
                "method": "POST",
                "url": "http://target:8080/api/login",
                "body": "admin' OR 1=1--",
            },
        ),
        ToolResult(content="SQL syntax error near 'OR'"),
        level_before=1,
        level_after=3,
    )
    collector.record(
        ToolCall(name="exec_command", arguments={"command": "cat /etc/passwd"}),
        ToolResult(content="root:x:0:0:root:/root:/bin/bash"),
        level_before=3,
        level_after=5,
    )
    return SpanQuery(collector)


def _file_spans_query() -> SpanQuery:
    """SpanQuery with file-access spans for file focus testing."""
    collector = SpanCollector(cve_id="CVE-2024-FILE")
    collector.record(
        ToolCall(
            name="read_file",
            arguments={"path": "/etc/passwd"},
        ),
        ToolResult(content="root:x:0:0:root:/root:/bin/bash"),
        level_before=2,
        level_after=4,
    )
    return SpanQuery(collector)


class TestQueryExploitSignals:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("mode", "extra_args", "expected_content"),
        [
            pytest.param("summary", {}, "total_spans", id="summary"),
        ],
    )
    async def test_mode(self, mode: str, extra_args: dict, expected_content: str) -> None:
        tool = QueryExploitSignals(_populated_query())
        result = await tool.execute({"mode": mode, **extra_args})
        assert not result.error
        assert expected_content in result.content

    @pytest.mark.asyncio
    async def test_invalid_mode(self) -> None:
        tool = QueryExploitSignals(_populated_query())
        result = await tool.execute({"mode": "bogus"})
        assert result.error


class TestSigmaTemplateFieldMatchers:
    """Sigma templates must produce real field matchers, not YAML comments."""

    @pytest.mark.asyncio
    async def test_sigma_template_has_real_field_matchers(self) -> None:
        """detection.selection contains field keys, not comments."""
        tool = GetSigmaTemplate(_sqli_query())
        result = await tool.execute({"focus": "web"})
        assert not result.error

        data = yaml.safe_load(result.content)
        selection = data["detection"]["selection"]
        assert isinstance(selection, dict), "selection must be a dict of field matchers"

        # None of the keys should start with '#' (comment artifact)
        for key in selection:
            assert not str(key).startswith("#"), f"Found comment key: {key}"

        # At least one real Sigma field modifier present
        all_keys = " ".join(str(k) for k in selection)
        assert any(field in all_keys for field in ("cs-uri-stem", "cs-body", "cs-method")), (
            f"No real web field matchers in selection keys: {list(selection.keys())}"
        )

    @pytest.mark.asyncio
    async def test_sigma_template_valid_yaml(self) -> None:
        """Generated Sigma template is valid YAML that loads without error."""
        tool = GetSigmaTemplate(_sqli_query())
        result = await tool.execute({"focus": "web"})
        data = yaml.safe_load(result.content)
        assert isinstance(data, dict)
        assert "detection" in data
        assert "logsource" in data

    @pytest.mark.asyncio
    async def test_sigma_web_focus_has_webserver_logsource(self) -> None:
        tool = GetSigmaTemplate(_populated_query())
        result = await tool.execute({"focus": "web"})
        assert not result.error
        assert "CVE-2024-5678" in result.content
        assert "webserver" in result.content



class TestSnortTemplateContent:
    """Snort templates must use path-only content, not scheme+host."""

    @pytest.mark.asyncio
    async def test_snort_has_path_content(self) -> None:
        """Snort output must contain path-only content matches."""
        tool = GetSnortTemplate(_sqli_query())
        result = await tool.execute({})
        # Should have path extracted from http://target:8080/api/search?q=test
        assert "/api/search" in result.content or "/api/login" in result.content

    @pytest.mark.asyncio
    async def test_snort_generates_basic_template(self) -> None:
        """Regression: basic Snort template generation."""
        tool = GetSnortTemplate(_populated_query())
        result = await tool.execute({})
        assert not result.error
        assert "CVE-2024-5678" in result.content
        assert "alert tcp" in result.content
        assert "sid:" in result.content



_DETECTION_KB = Path("data/knowledge/detection")


class TestGetDetectionReference:
    """GetDetectionReference queries the detection KB."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not _DETECTION_KB.exists(),
        reason="requires forge-artifacts knowledge base",
    )
    async def test_get_detection_reference_cwe_89(self) -> None:
        """CWE-89 has both Sigma and Snort rules in the KB."""
        tool = GetDetectionReference()
        result = await tool.execute({"cwe_id": "CWE-89"})
        assert not result.error
        assert "Sigma Rule" in result.content
        assert "Snort Rules" in result.content
        assert "Detection Strategy" in result.content

    @pytest.mark.asyncio
    async def test_get_detection_reference_unknown_cwe(self) -> None:
        """Unknown CWE returns generic guidance, no crash."""
        tool = GetDetectionReference()
        result = await tool.execute({"cwe_id": "CWE-999999"})
        assert not result.error
        assert "generic" in result.content.lower() or "No detection KB" in result.content


class TestValidateRuleDeep:
    """ValidateRule performs deep structural validation."""

    @pytest.mark.asyncio
    async def test_validate_sigma_valid_rule(self) -> None:
        """Well-formed Sigma rule returns valid=True, errors=[]."""
        tool = ValidateRule()
        sigma_yaml = (
            "title: Test Rule\n"
            "level: medium\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-uri-query|contains: 'OR 1=1'\n"
            "  condition: selection\n"
        )
        result = await tool.execute({"rule_type": "sigma", "rule_content": sigma_yaml})
        assert not result.error
        data = json.loads(result.content)
        assert data["valid"] is True
        assert data["errors"] == []
