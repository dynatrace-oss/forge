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
from typing import Any

from forge.signals.collector import SpanCollector, SpanKind, ToolSpan

logger = logging.getLogger(__name__)


class SpanQuery:
    """Query API for filtering and summarizing collected OTEL spans.

    Wraps a SpanCollector and provides filtering by span kind, tool name,
    exploitation level, and time range. Used by detection tools to extract
    relevant exploitation signals.
    """

    def __init__(self, collector: SpanCollector) -> None:
        self._collector = collector

    @property
    def cve_id(self) -> str:
        return self._collector.cve_id

    @property
    def trace_id(self) -> str:
        return self._collector.trace_id

    def all_spans(self) -> list[ToolSpan]:
        """Return all collected spans."""
        return self._collector.spans

    def by_kind(self, kind: SpanKind) -> list[ToolSpan]:
        """Filter spans by span kind."""
        return [s for s in self._collector.spans if s.span_kind == kind]

    def by_tool(self, tool_name: str) -> list[ToolSpan]:
        """Filter spans by tool name."""
        return [s for s in self._collector.spans if s.tool_name == tool_name]

    def by_level_range(self, min_level: int = 0, max_level: int = 6) -> list[ToolSpan]:
        """Filter spans where level_after is within [min_level, max_level]."""
        return [s for s in self._collector.spans if min_level <= s.level_after <= max_level]

    def level_transitions(self) -> list[ToolSpan]:
        """Return spans where exploitation level increased."""
        return [s for s in self._collector.spans if s.level_after > s.level_before]

    def http_spans(self) -> list[ToolSpan]:
        """Return all HTTP interaction spans."""
        return self.by_kind(SpanKind.HTTP)

    def exec_spans(self) -> list[ToolSpan]:
        """Return all command execution spans."""
        return self.by_kind(SpanKind.EXEC)

    def summary(self) -> dict[str, Any]:
        """Generate a summary of all collected spans for the Detector Agent."""
        spans = self._collector.spans
        if not spans:
            return {
                "cve_id": self.cve_id,
                "trace_id": self.trace_id,
                "total_spans": 0,
                "max_level": 0,
                "span_kinds": {},
                "level_transitions": [],
                "key_http_exchanges": [],
                "commands_executed": [],
                "files_accessed": [],
            }

        max_level = max(s.level_after for s in spans)

        kind_counts: dict[str, int] = {}
        for s in spans:
            kind_counts[s.span_kind] = kind_counts.get(s.span_kind, 0) + 1

        transitions = [
            {
                "tool": s.tool_name,
                "from": s.level_before,
                "to": s.level_after,
                "output_snippet": s.output_snippet[:500],
            }
            for s in self.level_transitions()
        ]

        http_exchanges = [
            {
                "method": s.http_method,
                "url": s.http_url,
                "status": s.http_status_code,
                "body": s.http_request_body[:500],
                "level_after": s.level_after,
            }
            for s in self.http_spans()
            if s.http_url
        ]

        commands = [
            {
                "command": s.command,
                "level_after": s.level_after,
                "error": s.error,
            }
            for s in self.exec_spans()
            if s.command
        ]

        files = [
            {
                "path": s.file_path,
                "action": "write" if s.span_kind == SpanKind.FILE_WRITE else "read",
                "level_after": s.level_after,
            }
            for s in spans
            if s.file_path
        ]

        return {
            "cve_id": self.cve_id,
            "trace_id": self.trace_id,
            "total_spans": len(spans),
            "max_level": max_level,
            "span_kinds": kind_counts,
            "level_transitions": transitions,
            "key_http_exchanges": http_exchanges,
            "commands_executed": commands,
            "files_accessed": files,
        }

    def format_for_llm(self) -> str:
        """Format span data as a readable string for the Detector Agent LLM."""
        spans = self._collector.spans
        if not spans:
            return "No exploitation spans collected."

        max_level = max(s.level_after for s in spans)
        lines = [
            f"CVE: {self.cve_id}",
            f"Total spans: {len(spans)}",
            f"Max exploitation level: L{max_level}",
            "",
            "=== Level Transitions ===",
        ]

        for s in self.level_transitions():
            lines.append(
                f"  L{s.level_before}→L{s.level_after}: {s.tool_name} | {s.output_snippet[:200]}"
            )

        http = self.http_spans()
        if http:
            lines.append("")
            lines.append("=== HTTP Exchanges ===")
            for s in http:
                status = f" → {s.http_status_code}" if s.http_status_code else ""
                lines.append(f"  {s.http_method} {s.http_url}{status} (L{s.level_after})")
                if s.http_request_body:
                    lines.append(f"    body: {s.http_request_body[:300]}")

        execs = self.exec_spans()
        if execs:
            lines.append("")
            lines.append("=== Commands Executed ===")
            for s in execs:
                err = " [ERROR]" if s.error else ""
                lines.append(f"  $ {s.command}{err} (L{s.level_after})")

        file_spans = [s for s in spans if s.file_path]
        if file_spans:
            lines.append("")
            lines.append("=== Files Accessed ===")
            for s in file_spans:
                action = "WRITE" if s.span_kind == SpanKind.FILE_WRITE else "READ"
                lines.append(f"  [{action}] {s.file_path} (L{s.level_after})")

        return "\n".join(lines)
