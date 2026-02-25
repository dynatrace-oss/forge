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
from urllib.parse import urlparse

from forge.tools.base import ToolResult


def _format_spans(spans: list[Any]) -> str:
    """Format a list of ToolSpan objects as readable text."""
    if not spans:
        return "No spans found matching the query."

    lines: list[str] = [f"Found {len(spans)} span(s):"]
    for s in spans:
        header = f"[{s.span_kind}] {s.tool_name} (L{s.level_before}→L{s.level_after})"
        if s.error:
            header += " [ERROR]"
        lines.append(header)

        if s.http_url:
            lines.append(f"  {s.http_method} {s.http_url}")
        if s.command:
            lines.append(f"  $ {s.command}")
        if s.file_path:
            lines.append(f"  path: {s.file_path}")
        if s.output_snippet:
            lines.append(f"  output: {s.output_snippet[:300]}")
        lines.append("")

    return "\n".join(lines)


def _sigma_hints(focus: str, spans: list[Any]) -> tuple[str, str]:
    """Generate Sigma logsource and real field matchers based on focus area.

    Returns (logsource_yaml, selection_yaml) where selection_yaml contains
    proper Sigma field matchers (NOT YAML comments).
    """
    if focus == "web":
        return _sigma_web_selection(spans)
    if focus == "process":
        return _sigma_process_selection(spans)
    if focus == "file":
        return _sigma_file_selection(spans)
    # network
    return (
        "    product: zeek\n    category: network_connection",
        "dst_port|gt: 1024",
    )


def _sigma_web_selection(spans: list[Any]) -> tuple[str, str]:
    """Build Sigma web selection from HTTP spans with real field matchers."""
    paths: list[str] = []
    bodies: list[str] = []
    methods: set[str] = set()

    for s in spans:
        if s.http_url:
            parsed = urlparse(s.http_url)
            path = parsed.path or "/"
            if path not in paths:
                paths.append(path)
            methods.add(s.http_method or "GET")
        if getattr(s, "http_request_body", None):
            body = s.http_request_body[:80]
            if body not in bodies:
                bodies.append(body)

    lines: list[str] = []
    if paths:
        if len(paths) == 1:
            lines.append(f"cs-uri-stem|contains: '{paths[0]}'")
        else:
            lines.append("cs-uri-stem|contains:")
            for p in paths[:5]:
                lines.append(f"  - '{p}'")
    if bodies:
        lines.append("cs-body|contains:")
        for b in bodies[:5]:
            escaped = b.replace("'", "''")
            lines.append(f"  - '{escaped}'")
    if methods and not lines:
        method_list = sorted(methods)
        if len(method_list) == 1:
            lines.append(f"cs-method: '{method_list[0]}'")
        else:
            lines.append("cs-method:")
            for m in method_list:
                lines.append(f"  - '{m}'")

    # Fallback: ensure at least one real field matcher
    if not lines:
        lines.append("cs-uri-stem|contains: '/'")

    selection_block = "\n        ".join(lines)
    return (
        "    category: webserver",
        selection_block,
    )


def _sigma_process_selection(spans: list[Any]) -> tuple[str, str]:
    """Build Sigma process creation selection from exec spans."""
    cmds: list[str] = []
    for s in spans:
        if s.command and s.command not in cmds:
            cmds.append(s.command)

    lines: list[str] = []
    if cmds:
        lines.append("CommandLine|contains:")
        for c in cmds[:5]:
            escaped = c.replace("'", "''")
            lines.append(f"  - '{escaped}'")
    else:
        lines.append("CommandLine|contains: '/bin/sh'")

    selection_block = "\n        ".join(lines)
    return (
        "    product: linux\n    category: process_creation",
        selection_block,
    )


def _sigma_file_selection(spans: list[Any]) -> tuple[str, str]:
    """Build Sigma file event selection from file spans."""
    file_paths: list[str] = []
    for s in spans:
        if s.file_path and s.file_path not in file_paths:
            file_paths.append(s.file_path)

    lines: list[str] = []
    if file_paths:
        lines.append("TargetFilename|contains:")
        for fp in file_paths[:5]:
            lines.append(f"  - '{fp}'")
    else:
        lines.append("TargetFilename|contains: '/etc/passwd'")

    selection_block = "\n        ".join(lines)
    return (
        "    product: linux\n    category: file_event",
        selection_block,
    )


def _snort_content_hints(http_spans: list[Any]) -> str:
    """Generate Snort content match hints from HTTP spans.

    Extracts only path components from URLs — never includes scheme+host.
    """
    if not http_spans:
        return '    content:"/"; http_uri;'

    hints: list[str] = ["    flow:to_server,established;"]
    seen_paths: set[str] = set()

    for s in http_spans:
        if s.http_url and s.level_after >= 2:
            path = urlparse(s.http_url).path or "/"
            if path not in seen_paths:
                seen_paths.add(path)
                hints.append(f'    content:"{path}"; http_uri;')
        if getattr(s, "http_request_body", None) and s.level_after >= 2:
            body_snippet = s.http_request_body[:100].replace('"', '\\"')
            hints.append(f'    content:"{body_snippet}"; http_client_body;')

    return (
        "\n".join(hints[:6])
        if len(hints) > 1
        else '    flow:to_server,established;\n    content:"/"; http_uri;'
    )


def _level_to_sigma_level(level: int) -> str:
    """Map exploitation level to Sigma severity."""
    if level <= 1:
        return "low"
    if level <= 2:
        return "medium"
    if level <= 3:
        return "high"
    return "critical"


def _make_verror(field: str, message: str) -> Any:
    """Create a ValidationError model instance."""
    from forge.detection.models import ValidationError as VError

    return VError(field=field, message=message)


def _format_validation_result(
    errors: list[Any],
    warnings: list[str],
) -> ToolResult:
    """Format validation errors and warnings into a ToolResult."""
    parts: list[str] = []

    if not errors and not warnings:
        return ToolResult(
            content=json.dumps({"valid": True, "errors": [], "warnings": []}),
        )

    if errors:
        error_lines = [f"- {e.field}: {e.message}" for e in errors]
        parts.append(f"Validation found {len(errors)} error(s):\n" + "\n".join(error_lines))

    if warnings:
        warning_lines = [f"- {w}" for w in warnings]
        parts.append(f"Warnings ({len(warnings)}):\n" + "\n".join(warning_lines))

    result_data = {
        "valid": len(errors) == 0,
        "errors": [f"{e.field}: {e.message}" for e in errors],
        "warnings": warnings,
    }

    return ToolResult(
        content=json.dumps(result_data),
        error=len(errors) > 0,
    )
