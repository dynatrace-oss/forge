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

import hashlib
import json
import logging
import uuid
from pathlib import Path
from typing import Any

import yaml

from forge.detection.models import SigmaRule, SnortRule
from forge.detection.validator import validate_sigma, validate_snort
from forge.signals.query import SpanQuery
from forge.tools.base import Tool, ToolResult
from forge.tools.detection_helpers import (
    _format_spans,
    _format_validation_result,
    _level_to_sigma_level,
    _sigma_hints,
    _snort_content_hints,
)

logger = logging.getLogger(__name__)

# Default detection KB path — callers should pass an absolute path from
# StorageManager when available.  This relative fallback only works when
# CWD is the repository root.
_DETECTION_KB_DIR = Path("data/knowledge/detection")


class QueryExploitSignals(Tool):
    """Query OTEL spans from the exploitation phase.

    Returns structured exploitation signals filtered by span kind,
    tool name, or exploitation level. The Detector Agent uses this
    to understand what happened during exploitation.
    """

    def __init__(self, span_query: SpanQuery) -> None:
        self._query = span_query

    @property
    def name(self) -> str:
        return "query_exploit_signals"

    @property
    def description(self) -> str:
        return (
            "Query exploitation OTEL spans. Use 'summary' for overview, "
            "or filter by kind (http/exec/file_read/file_write/scan/recon), "
            "tool name, or level range. Returns structured signal data."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["summary", "by_kind", "by_tool", "by_level", "transitions", "all"],
                    "description": (
                        "Query mode: summary, by_kind, by_tool, by_level, transitions, or all."
                    ),
                },
                "kind": {
                    "type": "string",
                    "description": (
                        "Span kind filter (for by_kind mode): "
                        "http, exec, file_read, file_write, scan, "
                        "recon, observation."
                    ),
                },
                "tool_name": {
                    "type": "string",
                    "description": "Tool name filter (for by_tool mode).",
                },
                "min_level": {
                    "type": "integer",
                    "description": "Minimum exploitation level (for by_level mode).",
                },
                "max_level": {
                    "type": "integer",
                    "description": "Maximum exploitation level (for by_level mode).",
                },
            },
            "required": ["mode"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        mode = str(arguments.get("mode", "summary"))

        if mode == "summary":
            data = self._query.summary()
            return ToolResult(content=json.dumps(data, indent=2, default=str))

        if mode == "all":
            text = self._query.format_for_llm()
            return ToolResult(content=text)

        if mode == "transitions":
            spans = self._query.level_transitions()
            return ToolResult(content=_format_spans(spans))

        if mode == "by_kind":
            from forge.signals.collector import SpanKind

            kind_str = str(arguments.get("kind", "http"))
            try:
                kind = SpanKind(kind_str)
            except ValueError:
                return ToolResult(
                    content=f"Unknown kind: {kind_str}. Valid: {', '.join(SpanKind)}",
                    error=True,
                )
            spans = self._query.by_kind(kind)
            return ToolResult(content=_format_spans(spans))

        if mode == "by_tool":
            tool_name = str(arguments.get("tool_name", ""))
            if not tool_name:
                return ToolResult(content="tool_name is required for by_tool mode", error=True)
            spans = self._query.by_tool(tool_name)
            return ToolResult(content=_format_spans(spans))

        if mode == "by_level":
            min_lvl = int(arguments.get("min_level", 0))
            max_lvl = int(arguments.get("max_level", 6))
            spans = self._query.by_level_range(min_lvl, max_lvl)
            return ToolResult(content=_format_spans(spans))

        return ToolResult(content=f"Unknown mode: {mode}", error=True)


class GetSigmaTemplate(Tool):
    """Provide a Sigma rule template based on exploitation signals.

    Returns a skeleton Sigma rule pre-filled with CVE ID, exploitation
    level, and real field matchers derived from the collected spans.
    """

    def __init__(self, span_query: SpanQuery) -> None:
        self._query = span_query

    @property
    def name(self) -> str:
        return "get_sigma_template"

    @property
    def description(self) -> str:
        return (
            "Generate a Sigma detection rule template pre-filled with "
            "exploitation context from OTEL spans. Returns YAML with "
            "CVE ID, log source, and real field matchers in detection block."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "focus": {
                    "type": "string",
                    "enum": ["web", "process", "file", "network"],
                    "description": "Detection focus area for the Sigma rule.",
                },
            },
            "required": ["focus"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        focus = str(arguments.get("focus", "web"))
        cve_id = self._query.cve_id
        spans = self._query.all_spans()
        max_level = max((s.level_after for s in spans), default=0)

        logsource, selection_block = _sigma_hints(focus, spans)

        template = _SIGMA_SKELETON.format(
            cve_id=cve_id,
            rule_id=uuid.uuid5(uuid.NAMESPACE_OID, f"forge-sigma-{cve_id}"),
            level=_level_to_sigma_level(max_level),
            logsource=logsource,
            selection_block=selection_block,
        )
        return ToolResult(content=template)


class GetSnortTemplate(Tool):
    """Provide a Snort/Suricata rule template from exploitation signals.

    Returns a skeleton Snort rule pre-filled with CVE ID and network
    indicators extracted from HTTP spans. Uses path-only content matches.
    """

    def __init__(self, span_query: SpanQuery) -> None:
        self._query = span_query

    @property
    def name(self) -> str:
        return "get_snort_template"

    @property
    def description(self) -> str:
        return (
            "Generate a Snort/Suricata detection rule template pre-filled "
            "with network indicators from exploitation OTEL spans. Returns "
            "a rule skeleton with path-based content matches."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {},
            "required": [],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cve_id = self._query.cve_id
        http = self._query.http_spans()

        content_matches = _snort_content_hints(http)
        sid = 9_000_000 + (int(hashlib.sha256(cve_id.encode()).hexdigest(), 16) % 99_999)

        template = _SNORT_SKELETON.format(
            cve_id=cve_id,
            content_matches=content_matches,
            sid=sid,
        )
        return ToolResult(content=template)


class GetDetectionReference(Tool):
    """Retrieve reference detection rules from the detection KB.

    Returns curated Sigma and Snort rules for a given CWE, plus the
    CWE-specific detection strategy from meta.yaml. The detector agent
    uses these exemplars to generate higher-quality rules.
    """

    def __init__(self, kb_dir: Path | None = None) -> None:
        self._kb_dir = kb_dir or _DETECTION_KB_DIR

    @property
    def name(self) -> str:
        return "get_detection_reference"

    @property
    def description(self) -> str:
        return (
            "Get reference Sigma/Snort detection rules from the knowledge base "
            "for a specific CWE. Returns exemplar rules and detection strategy."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g., 'CWE-89', 'CWE-78').",
                },
                "tier": {
                    "type": "string",
                    "enum": ["web", "host", "network", "application"],
                    "description": "Optional tier filter. Omit for all tiers.",
                },
            },
            "required": ["cwe_id"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cwe_id = str(arguments.get("cwe_id", ""))
        tier = arguments.get("tier")

        cwe_num = cwe_id.upper().replace("CWE-", "")
        cwe_dir = self._kb_dir / f"cwe-{cwe_num}"

        if not cwe_dir.exists():
            return ToolResult(
                content=(
                    f"No detection KB entry for {cwe_id}. "
                    "Use generic web detection patterns. "
                    "Focus on HTTP request/response indicators."
                ),
            )

        parts: list[str] = []

        # Load meta.yaml
        meta_path = cwe_dir / "meta.yaml"
        if meta_path.exists():
            meta = yaml.safe_load(meta_path.read_text())
            strategy = meta.get("detection_strategy", "")
            if strategy:
                parts.append(f"Detection Strategy for {cwe_id}:\n{strategy}")

        # Load Sigma rules
        sigma_dir = cwe_dir / "sigma"
        if sigma_dir.exists():
            _tier_prefixes = {
                "web": "web_",
                "host": "linux_",
                "network": "network_",
                "application": "app_",
            }
            for yml in sorted(sigma_dir.glob("*.yml")):
                if tier and not yml.name.startswith(_tier_prefixes.get(tier, "")):
                    continue
                parts.append(f"--- Sigma Rule: {yml.name} ---\n{yml.read_text()}")

        # Load Snort rules
        snort_dir = cwe_dir / "snort"
        if snort_dir.exists() and (tier is None or tier == "web"):
            for rules_file in sorted(snort_dir.glob("*.rules")):
                parts.append(f"--- Snort Rules: {rules_file.name} ---\n{rules_file.read_text()}")

        if not parts:
            return ToolResult(
                content=f"Detection KB for {cwe_id} exists but no rules match the filter.",
            )

        return ToolResult(content="\n\n".join(parts))


class ValidateRule(Tool):
    """Validate a Sigma or Snort rule using pySigma and idstools.

    Delegates to library-based validators that perform proper structural
    and semantic checks — no hand-rolled heuristics.
    """

    @property
    def name(self) -> str:
        return "validate_rule"

    @property
    def description(self) -> str:
        return (
            "Validate a detection rule (Sigma YAML or Snort alert). "
            "Returns structured validation result: valid/invalid with errors and warnings."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "rule_type": {
                    "type": "string",
                    "enum": ["sigma", "snort"],
                    "description": "Type of detection rule to validate.",
                },
                "rule_content": {
                    "type": "string",
                    "description": "The raw rule content (YAML for Sigma, alert line for Snort).",
                },
            },
            "required": ["rule_type", "rule_content"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        rule_type = str(arguments.get("rule_type", ""))
        rule_content = str(arguments.get("rule_content", ""))

        if not rule_content.strip():
            return ToolResult(content="Error: empty rule content", error=True)

        if rule_type == "sigma":
            sigma_rule = SigmaRule(cve_id="", raw_rule=rule_content)
            errors = validate_sigma(sigma_rule)
            return _format_validation_result(errors, [])

        if rule_type == "snort":
            snort_rule = SnortRule(cve_id="", raw_rule=rule_content)
            errors = validate_snort(snort_rule)
            return _format_validation_result(errors, [])

        return ToolResult(
            content=f"Unknown rule_type: {rule_type}. Use 'sigma' or 'snort'.",
            error=True,
        )


def register_detection_tools(
    span_query: SpanQuery,
    *,
    kb_dir: Path | None = None,
) -> list[Tool]:
    """Create and return all 5 detector tools."""
    return [
        QueryExploitSignals(span_query),
        GetSigmaTemplate(span_query),
        GetSnortTemplate(span_query),
        GetDetectionReference(kb_dir=kb_dir),
        ValidateRule(),
    ]


# -- Template skeletons ------------------------------------------------------

_SIGMA_SKELETON = """title: Exploitation Attempt - {cve_id}
id: {rule_id}
status: experimental
level: {level}
description: Detects exploitation activity for {cve_id}
logsource:
{logsource}
detection:
    selection:
        {selection_block}
    condition: selection
falsepositives:
    - Legitimate application activity
tags:
    - attack.initial_access
    - cve.{cve_id}
"""

_SNORT_SKELETON = """alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"ET EXPLOIT {cve_id} Exploitation Attempt";
{content_matches}
    classtype:web-application-attack;
    sid:{sid}; rev:1;
)"""
