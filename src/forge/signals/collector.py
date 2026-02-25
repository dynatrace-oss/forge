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
import time
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from forge.tools.base import ToolCall, ToolResult

logger = logging.getLogger(__name__)


class SpanKind(StrEnum):
    """Category of exploitation span for detection rule mapping."""

    HTTP = "http"
    EXEC = "exec"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SCAN = "scan"
    RECON = "recon"
    OBSERVATION = "observation"


_TOOL_TO_SPAN_KIND: dict[str, SpanKind] = {
    "http_request": SpanKind.HTTP,
    "exec_command": SpanKind.EXEC,
    "read_file": SpanKind.FILE_READ,
    "get_app_logs": SpanKind.OBSERVATION,
    "run_exploit_script": SpanKind.EXEC,
}


class ToolSpan(BaseModel):
    """A structured span capturing one tool call during exploitation.

    Maps directly to OTEL span semantics: each tool call is one span
    with typed attributes for detection rule generation.
    """

    span_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    trace_id: str = ""
    cve_id: str = ""
    tool_name: str
    span_kind: SpanKind
    timestamp: float = Field(default_factory=time.time)
    duration_ms: float = 0.0

    # Tool call details
    arguments: dict[str, object] = Field(default_factory=dict)
    output_snippet: str = ""
    error: bool = False

    # Exploitation context
    level_before: int = 0
    level_after: int = 0

    # HTTP-specific attributes (populated for HTTP spans)
    http_method: str = ""
    http_url: str = ""
    http_status_code: int = 0
    http_request_body: str = ""

    # Exec-specific attributes
    command: str = ""

    # File-specific attributes
    file_path: str = ""


def tool_name_to_span_kind(tool_name: str) -> SpanKind:
    """Map a tool name to its span kind."""
    return _TOOL_TO_SPAN_KIND.get(tool_name, SpanKind.OBSERVATION)


class SpanCollector:
    """In-memory collector for exploitation tool spans.

    Collects ToolSpan objects during an exploitation run. The Detector
    Agent queries these spans to generate detection rules.

    One collector per CVE run — create a new instance for each CVE.
    """

    def __init__(self, cve_id: str, trace_id: str = "") -> None:
        self._cve_id = cve_id
        self._trace_id = trace_id or uuid4().hex
        self._spans: list[ToolSpan] = []

    @property
    def cve_id(self) -> str:
        return self._cve_id

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @property
    def spans(self) -> list[ToolSpan]:
        return list(self._spans)

    def record(
        self,
        tool_call: ToolCall,
        result: ToolResult,
        level_before: int,
        level_after: int,
        duration_ms: float = 0.0,
    ) -> ToolSpan:
        """Record a tool call as a structured span.

        Args:
            tool_call: The tool call that was executed.
            result: The result of the tool call.
            level_before: Exploitation level before this call.
            level_after: Exploitation level after oracle evaluation.
            duration_ms: Execution duration in milliseconds.

        Returns:
            The created ToolSpan.
        """
        kind = tool_name_to_span_kind(tool_call.name)
        output_snippet = result.content[:2000] if result.content else ""

        span = ToolSpan(
            trace_id=self._trace_id,
            cve_id=self._cve_id,
            tool_name=tool_call.name,
            span_kind=kind,
            duration_ms=duration_ms,
            arguments=dict(tool_call.arguments),
            output_snippet=output_snippet,
            error=result.error,
            level_before=level_before,
            level_after=level_after,
        )

        # Enrich with tool-specific attributes
        _enrich_span(span, tool_call.arguments, result)

        self._spans.append(span)
        logger.debug(
            "Recorded span %s: %s (L%d→L%d)",
            span.span_id,
            tool_call.name,
            level_before,
            level_after,
        )
        return span

    def count(self) -> int:
        """Return the number of collected spans."""
        return len(self._spans)

    def clear(self) -> None:
        """Clear all collected spans."""
        self._spans.clear()


def _enrich_span(span: ToolSpan, arguments: dict[str, object], result: ToolResult) -> None:
    """Enrich a span with tool-specific attributes from arguments and result."""
    if span.span_kind == SpanKind.HTTP:
        span.http_method = str(arguments.get("method", "")).upper()
        span.http_url = str(arguments.get("url", ""))
        span.http_request_body = str(arguments.get("body", ""))[:2000]
        # Extract status code from result content
        span.http_status_code = _extract_status_code(result.content)
    elif span.span_kind == SpanKind.EXEC:
        span.command = str(arguments.get("command", ""))
    elif span.span_kind in (SpanKind.FILE_READ, SpanKind.FILE_WRITE):
        span.file_path = str(arguments.get("path", ""))


def _extract_status_code(content: str) -> int:
    """Extract HTTP status code from tool result content."""
    import re

    # Match patterns like "HTTP 200", "Status: 200", "status_code: 200", "HTTP/1.1 200"
    match = re.search(r"(?:HTTP[/ ]\d\.?\d?\s+|[Ss]tatus(?:_code)?:\s*)(\d{3})\b", content)
    if match:
        return int(match.group(1))
    return 0
