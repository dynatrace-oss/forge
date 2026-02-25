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

from forge.oracle.models import OracleEvidence, OracleVerdict
from forge.sandbox.models import SandboxSnapshot

logger = logging.getLogger(__name__)


class ExploitOracle:
    """Final-verdict oracle for exploit evaluation.

    Used after the exploit phase to compute a summary verdict from
    accumulated evidence.  The per-turn evaluation is handled by
    the LLM oracle via DefaultInlineOracle.
    """

    def evaluate(
        self,
        evidence: list[OracleEvidence],
    ) -> OracleVerdict:
        """Produce a verdict from accumulated evidence.

        Args:
            evidence: Evidence collected across all exploit turns.

        Returns:
            OracleVerdict with binary success, exploitation level, and confidence.
        """
        credible = [e for e in evidence if e.confidence >= 0.5]
        max_level = max((e.level_match for e in credible), default=0)
        confidence = _compute_confidence(evidence, max_level)

        verdict = OracleVerdict(
            binary_success=max_level >= 1,
            exploitation_level=max_level,
            confidence=confidence,
            evidence=evidence,
            tier_used="llm",
        )

        logger.info(
            "Oracle verdict: level=%d binary=%s confidence=%.2f evidence=%d",
            verdict.exploitation_level,
            verdict.binary_success,
            verdict.confidence,
            len(evidence),
        )

        return verdict


def format_snapshot(snapshot: SandboxSnapshot) -> str:
    """Format a sandbox snapshot as text for the LLM oracle.

    Produces a concise summary of server-side ground truth:
    - Files created on the target (marker files, uploaded files)
    - Running processes on the target
    - Application logs (last 100 lines of target stdout/stderr)

    Returns empty string when the snapshot contains no useful data.
    """
    parts: list[str] = []

    if snapshot.files_created:
        parts.append("FILES CREATED ON TARGET:")
        for filepath in snapshot.files_created:
            parts.append(f"  - {filepath}")

    if snapshot.processes:
        parts.append("RUNNING PROCESSES ON TARGET:")
        for proc in snapshot.processes:
            raw = proc.get("raw", str(proc))
            parts.append(f"  - {raw}")

    if snapshot.app_logs.strip():
        # Truncate to last ~50 lines for cost control.
        log_lines = snapshot.app_logs.strip().split("\n")
        tail = log_lines[-50:] if len(log_lines) > 50 else log_lines
        parts.append(f"APPLICATION LOGS (last {len(tail)} lines):")
        parts.extend(f"  {line}" for line in tail)

    return "\n".join(parts) if parts else "(empty — no server-side changes detected)"


def _compute_confidence(evidence: list[OracleEvidence], max_level: int) -> float:
    """Compute confidence score based on evidence consistency.

    Uses unique source diversity and per-evidence confidence weights.
    3+ supporting items from different sources = high confidence.
    """
    if not evidence:
        return 0.0

    if max_level == 0:
        return 1.0  # No exploitation is a confident verdict

    # Count supporting evidence at or above max level, weighted by confidence
    supporting = [e for e in evidence if e.level_match >= max_level]
    weighted_count = sum(e.confidence for e in supporting)

    # Base confidence from weighted evidence count (3.0 threshold)
    base = min(weighted_count / 3.0, 1.0)

    # Bonus for multiple independent unique sources
    unique_sources = {e.source for e in supporting}
    source_bonus = min(len(unique_sources) * 0.1, 0.3)

    return round(min(base + source_bonus, 1.0), 4)
