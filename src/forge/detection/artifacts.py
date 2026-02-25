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

from forge.detection.models import (
    ConfidenceTier,
    ExploitArtifacts,
    FileArtifact,
    HttpExchange,
)
from forge.models import CVETask, ExploitResult
from forge.oracle.models import OracleVerdict
from forge.sandbox.models import SandboxSnapshot

logger = logging.getLogger(__name__)

# Regex patterns for extracting HTTP exchanges from execution logs.
# Matches requests.get/post/put/delete/patch calls and their URLs.
_HTTP_METHOD_RE = re.compile(
    r"requests?\.(get|post|put|delete|patch|head|options)"
    r"""\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Matches "HTTP/1.1 200 OK" or "status_code: 200" style patterns.
_HTTP_STATUS_RE = re.compile(
    r"(?:HTTP/\d\.\d\s+|status[_ ]?code\s*[:=]\s*)(\d{3})",
    re.IGNORECASE,
)

# Matches URL patterns in logs (http://host:port/path).
_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)

# Crash/error indicators in logs.
_CRASH_PATTERNS = [
    re.compile(r"Segmentation\s+fault", re.IGNORECASE),
    re.compile(r"SIGSEGV|SIGABRT|SIGBUS", re.IGNORECASE),
    re.compile(r"stack\s+smashing\s+detected", re.IGNORECASE),
    re.compile(r"buffer\s+overflow", re.IGNORECASE),
    re.compile(r"heap\s+corruption", re.IGNORECASE),
    re.compile(r"double\s+free", re.IGNORECASE),
    re.compile(r"core\s+dumped", re.IGNORECASE),
    re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\)", re.IGNORECASE),
    re.compile(r"panic:", re.IGNORECASE),
]

# Max snippet length to avoid bloating artifacts.
_MAX_SNIPPET = 500
_MAX_PAYLOAD = 2000


def collect_artifacts(
    exploit_result: ExploitResult,
    snapshot: SandboxSnapshot,
    verdict: OracleVerdict,
    task: CVETask,
) -> ExploitArtifacts:
    """Extract structured exploitation artifacts from raw results.

    Args:
        exploit_result: Raw exploit output (files, execution log).
        snapshot: Sandbox filesystem/process state after exploitation.
        verdict: Oracle verdict with exploitation level.
        task: CVE task metadata.

    Returns:
        Structured artifacts suitable for detection rule generation.
    """
    cwe_id = task.cwe_ids[0] if task.cwe_ids else ""
    level = verdict.exploitation_level

    http_exchanges = _extract_http_exchanges(exploit_result.execution_log, snapshot.app_logs)
    file_artifacts = _extract_file_artifacts(snapshot)
    payloads = _extract_payloads(exploit_result.exploit_files)
    crash_signals = _extract_crash_signals(exploit_result.execution_log, snapshot.app_logs)
    log_patterns = _extract_log_patterns(snapshot.app_logs)
    processes: list[str] = []
    for p in snapshot.processes:
        if isinstance(p, dict):
            cmdline = p.get("cmdline") or p.get("name")
            processes.append(str(cmdline) if cmdline else str(p))
        else:
            processes.append(str(p))

    return ExploitArtifacts(
        cve_id=task.cve_id,
        cwe_id=cwe_id,
        exploitation_level=level,
        confidence_tier=_level_to_confidence(level),
        http_exchanges=http_exchanges,
        file_artifacts=file_artifacts,
        payloads=payloads,
        network_connections=list(snapshot.network_connections),
        processes=processes,
        crash_signals=crash_signals,
        log_patterns=log_patterns,
    )


def _level_to_confidence(level: int) -> ConfidenceTier:
    """Map exploitation level to detection rule confidence tier."""
    if level <= 1:
        return ConfidenceTier.LOW
    if level <= 2:
        return ConfidenceTier.MEDIUM
    return ConfidenceTier.HIGH


def _extract_http_exchanges(execution_log: str, app_logs: str) -> list[HttpExchange]:
    """Parse HTTP request/response patterns from logs."""
    exchanges: list[HttpExchange] = []
    seen_urls: set[str] = set()

    # Extract from explicit requests.method() calls in execution_log
    for match in _HTTP_METHOD_RE.finditer(execution_log):
        method = match.group(1).upper()
        url = match.group(2)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Try to find a status code near this request
        status = _find_nearby_status(execution_log, match.end())
        exchanges.append(
            HttpExchange(
                method=method,
                url=url,
                status_code=status,
            )
        )

    # Extract from URLs in app_logs paired with status codes
    for url_match in _URL_RE.finditer(app_logs):
        url = url_match.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        status = _find_nearby_status(app_logs, url_match.end())
        exchanges.append(HttpExchange(url=url, status_code=status))

    return exchanges


def _find_nearby_status(text: str, pos: int) -> int:
    """Find an HTTP status code within 300 chars after a position."""
    window = text[pos : pos + 300]
    match = _HTTP_STATUS_RE.search(window)
    if match:
        return int(match.group(1))
    return 0


def _extract_file_artifacts(snapshot: SandboxSnapshot) -> list[FileArtifact]:
    """Convert snapshot file lists into structured artifacts."""
    artifacts: list[FileArtifact] = []
    for path in snapshot.files_created:
        artifacts.append(FileArtifact(path=path, action="created"))
    for path in snapshot.files_modified:
        artifacts.append(FileArtifact(path=path, action="modified"))
    return artifacts


def _extract_payloads(exploit_files: dict[str, str]) -> list[str]:
    """Extract payload content from exploit scripts.

    Keeps file contents truncated to avoid bloating the artifact.
    """
    payloads: list[str] = []
    for filename, content in exploit_files.items():
        if not content.strip():
            continue
        truncated = content[:_MAX_PAYLOAD]
        if len(content) > _MAX_PAYLOAD:
            truncated += f"\n... ({len(content) - _MAX_PAYLOAD} chars truncated)"
        payloads.append(f"# {filename}\n{truncated}")
    return payloads


def _extract_crash_signals(execution_log: str, app_logs: str) -> list[str]:
    """Find crash/error indicators in logs."""
    signals: list[str] = []
    combined = f"{execution_log}\n{app_logs}"
    for pattern in _CRASH_PATTERNS:
        for match in pattern.finditer(combined):
            # Extract context around the match
            start = max(0, match.start() - 50)
            end = min(len(combined), match.end() + 50)
            context = combined[start:end].strip()
            if context not in signals:
                signals.append(context[:_MAX_SNIPPET])
    return signals


def _extract_log_patterns(app_logs: str) -> list[str]:
    """Extract distinctive log lines that could serve as detection indicators.

    Focuses on error/warning lines and lines with suspicious content.
    """
    if not app_logs:
        return []

    patterns: list[str] = []
    suspicious_re = re.compile(
        r"(error|warning|exception|unauthorized|forbidden|inject|overflow|"
        r"traversal|payload|exploit|malicious|attack|violation)",
        re.IGNORECASE,
    )

    for line in app_logs.splitlines():
        line = line.strip()
        if not line or len(line) < 10:
            continue
        if suspicious_re.search(line):
            patterns.append(line[:_MAX_SNIPPET])
            if len(patterns) >= 20:
                break

    return patterns
