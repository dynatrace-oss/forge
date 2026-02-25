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

from forge.signals.collector import (
    SpanCollector,
    SpanKind,
    ToolSpan,
)
from forge.signals.query import SpanQuery
from forge.tools.base import ToolCall, ToolResult


def _make_collector() -> SpanCollector:
    """Create a collector with sample spans for testing."""
    collector = SpanCollector(cve_id="CVE-2024-1234", trace_id="abc123")

    # HTTP recon span (L0 → L1)
    collector.record(
        ToolCall(name="http_request", arguments={"method": "GET", "url": "/api/users"}),
        ToolResult(content='HTTP 200 OK\n{"users": []}'),
        level_before=0,
        level_after=1,
        duration_ms=50.0,
    )
    # HTTP exploit span (L1 → L2)
    collector.record(
        ToolCall(
            name="http_request",
            arguments={"method": "POST", "url": "/api/login", "body": "' OR 1=1--"},
        ),
        ToolResult(content="SQL syntax error near '1=1'"),
        level_before=1,
        level_after=2,
        duration_ms=120.0,
    )
    # Exec span (L2 → L2, no progress)
    collector.record(
        ToolCall(name="exec_command", arguments={"command": "ls /tmp"}),
        ToolResult(content="file1.txt\nfile2.txt"),
        level_before=2,
        level_after=2,
        duration_ms=30.0,
    )
    # File read span (L2 → L3)
    collector.record(
        ToolCall(name="read_file", arguments={"path": "/etc/passwd"}),
        ToolResult(content="root:x:0:0:root:/root:/bin/bash"),
        level_before=2,
        level_after=3,
        duration_ms=10.0,
    )
    # Error span
    collector.record(
        ToolCall(name="exec_command", arguments={"command": "cat /secret"}),
        ToolResult(content="Permission denied", error=True),
        level_before=3,
        level_after=3,
        duration_ms=5.0,
    )

    return collector


class TestSpanCollector:
    def test_record_and_count(self) -> None:
        collector = SpanCollector(cve_id="CVE-2024-0001")
        assert collector.count() == 0

        span = collector.record(
            ToolCall(name="http_request", arguments={"method": "GET", "url": "/"}),
            ToolResult(content="OK"),
            level_before=0,
            level_after=1,
        )
        assert collector.count() == 1
        assert isinstance(span, ToolSpan)
        assert span.tool_name == "http_request"
        assert span.span_kind == SpanKind.HTTP
        assert span.cve_id == "CVE-2024-0001"

    def test_http_span_enrichment(self) -> None:
        collector = SpanCollector(cve_id="CVE-2024-0002")
        span = collector.record(
            ToolCall(
                name="http_request",
                arguments={"method": "POST", "url": "/api/login", "body": "test"},
            ),
            ToolResult(content="response"),
            level_before=0,
            level_after=2,
        )
        assert span.http_method == "POST"
        assert span.http_url == "/api/login"
        assert span.http_request_body == "test"


class TestSpanQuery:
    def test_summary(self) -> None:
        query = SpanQuery(_make_collector())
        s = query.summary()
        assert s["cve_id"] == "CVE-2024-1234"
        assert s["total_spans"] == 5
        assert s["max_level"] == 3
        assert len(s["level_transitions"]) == 3
        assert len(s["key_http_exchanges"]) == 2

    def test_format_for_llm(self) -> None:
        query = SpanQuery(_make_collector())
        text = query.format_for_llm()
        assert "CVE-2024-1234" in text
        assert "Level Transitions" in text
        assert "HTTP Exchanges" in text
        assert "Commands Executed" in text
