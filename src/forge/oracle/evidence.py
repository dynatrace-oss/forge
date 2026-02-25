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
import re
from pathlib import Path

import yaml

from forge.models import CWEModule
from forge.oracle.models import ErrorClassification

logger = logging.getLogger(__name__)

# HTTP status patterns in tool output — used by coaching and summarize_turn.
_HTTP_STATUS_RE = re.compile(
    r"(?:status[_ ]?code|HTTP(?:/\d\.\d)?)\s*[:=]?\s*(\d{3})", re.IGNORECASE
)
_CONNECTION_REFUSED_PATTERNS = [
    re.compile(r"Connection\s*Refused", re.IGNORECASE),
    re.compile(r"ConnectionRefusedError", re.IGNORECASE),
    re.compile(r"connect\s+ECONNREFUSED", re.IGNORECASE),
    re.compile(r"Failed to establish.*connection", re.IGNORECASE),
]
_TIMEOUT_PATTERNS = [
    re.compile(r"timed?\s*out", re.IGNORECASE),
    re.compile(r"ReadTimeout", re.IGNORECASE),
    re.compile(r"ConnectTimeout", re.IGNORECASE),
]
_CRASH_PATTERNS = [
    re.compile(r"Connection\s*reset\s*by\s*peer", re.IGNORECASE),
    re.compile(r"RemoteDisconnected", re.IGNORECASE),
    re.compile(r"BrokenPipeError", re.IGNORECASE),
]

# Load CWE aliases and evidence descriptions from config.
_PATTERNS_PATH = Path(__file__).resolve().parents[3] / "data" / "config" / "oracle_patterns.yaml"


def _load_oracle_config() -> tuple[dict[str, str], dict[str, dict[str, object]]]:
    """Load oracle config: CWE aliases and evidence descriptions.

    Returns:
        (aliases, cwe_evidence)
    """
    with _PATTERNS_PATH.open() as f:
        raw = yaml.safe_load(f)
    aliases: dict[str, str] = raw.get("aliases", {})
    cwe_evidence: dict[str, dict[str, object]] = raw.get("cwe_evidence", {})
    return aliases, cwe_evidence


_CWE_ALIASES, _CWE_EVIDENCE = _load_oracle_config()

# CWE families with structural level caps.  These are architectural truths,
# not pattern matching — XSS executes in the browser (max L2), path
# traversal reads files (max L2), etc.
_CWE_LEVEL_CAPS: dict[str, int] = {
    "CWE-79": 2,  # XSS — client-side only
    "CWE-22": 2,  # Path Traversal — file read, not RCE
    "CWE-601": 2,  # Open Redirect
    "CWE-400": 2,  # DoS — availability only
    "CWE-1333": 2,  # ReDoS
    "CWE-352": 2,  # CSRF
}


def _resolve_cwe(cwe_id: str | None) -> str | None:
    """Resolve CWE aliases to the canonical CWE used in cap/evidence dicts."""
    if cwe_id is None:
        return None
    return _CWE_ALIASES.get(cwe_id, cwe_id)


def get_cwe_level_cap(cwe_module: CWEModule | None) -> int | None:
    """Return the structural level cap for a CWE, or None if uncapped."""
    if cwe_module is None:
        return None
    resolved = _resolve_cwe(cwe_module.cwe_id)
    if resolved is None:
        return None
    return _CWE_LEVEL_CAPS.get(resolved)


def apply_cwe_level_cap(level: int, cwe_module: CWEModule | None) -> int:
    """Apply CWE structural cap to a proposed level.

    Returns the capped level (unchanged if CWE is uncapped).
    """
    cap = get_cwe_level_cap(cwe_module)
    if cap is not None and level > cap:
        resolved = _resolve_cwe(cwe_module.cwe_id if cwe_module else None) or "unknown"
        logger.debug("CWE cap: %s level L%d → L%d", resolved, level, cap)
        return cap
    return level


def format_oracle_criteria(cwe_module: CWEModule) -> str:
    """Format CWE-specific evidence descriptions for the LLM oracle prompt.

    Uses hand-curated evidence descriptions from oracle_patterns.yaml.
    """
    lines: list[str] = []
    resolved = _resolve_cwe(cwe_module.cwe_id)

    # Natural-language evidence descriptions from oracle_patterns.yaml
    if resolved and resolved in _CWE_EVIDENCE:
        evidence_info = _CWE_EVIDENCE[resolved]
        name = evidence_info.get("name", resolved)
        lines.append(f"CWE-SPECIFIC EVIDENCE for {resolved} ({name}):")
        indicators = evidence_info.get("indicators", {})
        if isinstance(indicators, dict):
            for level_key in sorted(indicators.keys()):
                desc = indicators[level_key]
                lines.append(f"  {level_key}: {desc}")
        max_level = evidence_info.get("max_level")
        if max_level is not None:
            lines.append(f"  Maximum level for this CWE: L{max_level}")

    return "\n".join(lines)


def _classify_connection(tool_output: str) -> str:
    """Classify the connection status from tool output."""
    for pattern in _CONNECTION_REFUSED_PATTERNS:
        if pattern.search(tool_output):
            return "refused"

    for pattern in _TIMEOUT_PATTERNS:
        if pattern.search(tool_output):
            return "timeout"

    for pattern in _CRASH_PATTERNS:
        if pattern.search(tool_output):
            return "crashed"

    # If we see HTTP status codes, the connection is healthy
    if _HTTP_STATUS_RE.search(tool_output):
        return "healthy"

    # If we see successful output with no errors, assume healthy
    if tool_output.strip() and "error" not in tool_output.lower()[:200]:
        return "healthy"

    return "unknown"


def _classify_error(
    tool_output: str,
    connection_status: str,
    max_level: int,
) -> ErrorClassification:
    """Classify the error type for refinement guidance.

    Uses connection status and the LLM oracle's assessed level.
    """
    lower = tool_output.lower()

    # Infrastructure errors
    if any(p in lower for p in ("python: not found", "oci runtime", "no such file")):
        return "infrastructure"

    # Connection issues
    if connection_status == "refused":
        return "connection_refused"

    # Wrong endpoint (404)
    if re.search(r"\b404\b", tool_output):
        return "wrong_endpoint"

    # Wrong payload format (400, 415, 422) — check only when no exploitation
    if re.search(r"\b(?:400|415|422)\b", tool_output):
        if max_level > 0:
            return "partial_trigger"
        return "wrong_payload_format"

    # Partial trigger — we got some level but not full exploitation
    if 0 < max_level < 3:
        return "partial_trigger"

    # No exploitation and no error — fundamental issue
    if max_level == 0 and connection_status == "healthy":
        status_codes = _HTTP_STATUS_RE.findall(tool_output)
        if any(int(c) == 200 for c in status_codes):
            return "fundamental"

    if max_level == 0 and connection_status in ("timeout", "crashed"):
        return "connection_refused"

    return "none"


def _analyze_response(
    tool_output: str,
    max_level: int,
    oracle_reasoning: str = "",
) -> str:
    """Build a brief analysis of the tool output for coaching injection."""
    parts: list[str] = []

    if max_level > 0:
        parts.append(f"Exploitation level L{max_level} detected.")
        if oracle_reasoning:
            parts.append(f"  Oracle: {oracle_reasoning[:200]}")
    else:
        parts.append("No exploitation indicators detected.")

    # HTTP status codes for context
    status_codes = _HTTP_STATUS_RE.findall(tool_output)
    if status_codes:
        unique = sorted(set(status_codes))
        parts.append(f"HTTP status codes seen: {', '.join(unique)}")

    return "\n".join(parts)[:500]


def _suggest_fix(
    error_class: ErrorClassification,
    tool_output: str,
    cwe_module: CWEModule | None,
) -> str | None:
    """Suggest a specific fix based on error classification."""
    suggestions: dict[ErrorClassification, str] = {
        "connection_refused": (
            "The application is not reachable. Check that you are using "
            "the correct host and port from the target URL provided."
        ),
        "wrong_endpoint": (
            "HTTP 404 — the endpoint path is wrong. Re-read the application "
            "source code and use the exact route path defined there."
        ),
        "wrong_payload_format": (
            "The server rejected the payload format. Check the Content-Type "
            "header and ensure the request body matches what the endpoint parser expects."
        ),
        "infrastructure": (
            "Infrastructure error detected. The exploit may be running in "
            "the wrong container or missing required tools."
        ),
    }

    base = suggestions.get(error_class)
    if base:
        return base

    # For partial_trigger or fundamental, no CWE-specific suggestion available.
    return None
