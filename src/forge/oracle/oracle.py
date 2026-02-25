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
