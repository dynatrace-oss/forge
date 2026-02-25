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
