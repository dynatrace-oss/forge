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
import re
from typing import Any

from forge.models import CWEModule
from forge.oracle.evidence import (
    _HTTP_STATUS_RE,
    _analyze_response,
    _classify_connection,
    _classify_error,
    _suggest_fix,
    apply_cwe_level_cap,
    format_oracle_criteria,
)
from forge.oracle.llm_critic import CriticVerdict, LLMOracleCritic
from forge.oracle.models import (
    EvidenceProvenance,
    InlineOracleFeedback,
    OracleEvidence,
)
from forge.oracle.oracle import format_snapshot
from forge.sandbox.models import SandboxSnapshot

logger = logging.getLogger(__name__)


class DefaultInlineOracle:
    """Per-turn oracle hook: LLM-primary evaluation with structural caps.

    Every exploit tool call is evaluated by the LLM oracle, which receives
    rich context (app source, server-side snapshot, CWE-specific evidence
    descriptions, sandbox architecture explanation).

    Structural caps are applied after the LLM verdict:
    - CWE level caps (XSS → L2, path traversal → L2, etc.)
    - Tool-level caps (read_file/get_app_logs capped for L3 unless
      evidence of exploit-created files)
    """

    def __init__(self, critic: LLMOracleCritic | None = None) -> None:
        self._critic = critic

    async def evaluate_turn(
        self,
        snapshot: SandboxSnapshot,
        tool_output: str,
        cwe_module: CWEModule | None,
        turn: int,
        prior_level: int,
        tool_name: str = "",
        tool_arguments: dict[str, Any] | None = None,
        app_source: str = "",
    ) -> InlineOracleFeedback:
        """Evaluate one exploit turn and return structured feedback.

        LLM-primary flow:
        1. Format server-side snapshot and CWE criteria as context.
        2. Call LLM oracle with full context (app source, snapshot, CWE).
        3. Apply structural caps (CWE caps, tool-level caps).
        4. Classify connection/error for coaching feedback.
        """
        evidence: list[OracleEvidence] = []
        max_level = 0
        oracle_reasoning = ""

        # Call LLM oracle on every turn (no pre-filter gating)
        if self._critic is not None and tool_arguments is not None:
            snapshot_text = format_snapshot(snapshot)
            cwe_id = cwe_module.cwe_id if cwe_module else "unknown"
            cwe_name = cwe_module.cwe_name if cwe_module else "unknown"
            criteria_text = format_oracle_criteria(cwe_module) if cwe_module else ""

            verdict: CriticVerdict = await self._critic.evaluate(
                tool_name=tool_name,
                tool_arguments=tool_arguments,
                tool_output=tool_output,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                oracle_criteria=criteria_text,
                app_source=app_source,
                snapshot_text=snapshot_text,
            )
            max_level = verdict.level
            oracle_reasoning = verdict.reasoning

            if max_level > 0:
                provenance: EvidenceProvenance = (
                    "server" if tool_name in ("read_file", "get_app_logs") else "client"
                )
                evidence.append(
                    OracleEvidence(
                        source="exploit_output",
                        description=f"LLM oracle: {verdict.reasoning}",
                        level_match=verdict.level,
                        confidence=verdict.confidence,
                        provenance=provenance,
                    )
                )
                logger.info(
                    "LLM oracle: L%d (conf=%.2f) for %s: %s",
                    verdict.level,
                    verdict.confidence,
                    tool_name,
                    verdict.reasoning[:100],
                )

        # --- Structural caps (code, NOT regex) ---

        # CWE level cap (e.g. XSS → L2 max, path traversal → L2 max)
        capped_level = apply_cwe_level_cap(max_level, cwe_module)
        if capped_level < max_level:
            resolved_cwe = cwe_module.cwe_id if cwe_module else "unknown"
            logger.info(
                "CWE cap: %s level L%d → L%d",
                resolved_cwe,
                max_level,
                capped_level,
            )
            max_level = capped_level
            # Update evidence to reflect the cap
            for ev in evidence:
                if ev.level_match > max_level:
                    ev.level_match = max_level
                    ev.description = f"{ev.description} [capped: CWE max L{max_level}]"

        # Tool-level caps for L3 false-positive mitigation.
        #
        # read_file: capped at L1 because target containers run as root.
        # EXCEPTION: if the file appears in snapshot.files_created (exploit-created).
        if tool_name == "read_file" and max_level > 1:
            read_path = (tool_arguments or {}).get("path", "")
            is_exploit_output = read_path and any(
                read_path == f or read_path.endswith(f.lstrip("/")) for f in snapshot.files_created
            )
            if not is_exploit_output:
                logger.debug(
                    "Capping %s from L%d to L1 (sandbox false positive)", tool_name, max_level
                )
                max_level = 1

        # exec_command: capped at L1 unless the command sends traffic to the target.
        if tool_name == "exec_command" and max_level > 1:
            cmd = (tool_arguments or {}).get("command", "")
            is_target_facing = bool(re.search(r"\b(?:curl|wget|nc|ncat|httpie|http)\b", cmd))
            if not is_target_facing:
                logger.debug(
                    "Capping exec_command from L%d to L1 (not target-facing: %.80s)",
                    max_level,
                    cmd,
                )
                max_level = 1

        # run_exploit_script: capped at L1 unless script imports HTTP libraries.
        if tool_name == "run_exploit_script" and max_level > 1:
            script_src = (tool_arguments or {}).get("script", "")
            is_target_facing = bool(
                re.search(
                    r"\b(?:requests\.|httpx\.|urllib\.request|http\.client"
                    r"|aiohttp\.|socket\.connect|urlopen"
                    r"|curl|wget|nc|ncat)\b",
                    script_src,
                )
            )
            if not is_target_facing:
                logger.debug(
                    "Capping run_exploit_script from L%d to L1 (no target-facing IO)", max_level
                )
                max_level = 1

        # Connection/error classification for coaching feedback
        connection_status = _classify_connection(tool_output)
        error_class = _classify_error(tool_output, connection_status, max_level)
        response_analysis = _analyze_response(tool_output, max_level, oracle_reasoning)
        suggested_fix = _suggest_fix(error_class, tool_output, cwe_module)

        progress_delta = max_level - prior_level

        return InlineOracleFeedback(
            turn=turn,
            exploitation_level=max_level,
            progress_delta=progress_delta,
            error_classification=error_class,
            connection_status=connection_status,
            response_analysis=response_analysis,
            suggested_fix=suggested_fix,
            evidence=evidence,
        )


def summarize_turn(
    tool_name: str,
    tool_arguments: dict[str, Any] | None,
    tool_output: str,
    feedback: InlineOracleFeedback,
) -> str:
    """Produce a ~300-char structured summary of a tool call result.

    Used by the exploit agent's sliding window to replace old full-length
    tool outputs with compact summaries, reducing context tokens by ~80%.

    Format: ``[tool] key_arg | HTTP status | L{n} | evidence | error``
    """
    parts: list[str] = [f"[{tool_name}]"]

    args = tool_arguments or {}
    if tool_name == "http_request":
        method = args.get("method", "GET")
        url = args.get("url", "")
        parts.append(f"{method} {url[:80]}")
    elif tool_name == "exec_command":
        cmd = args.get("command", "")
        parts.append(f"$ {cmd[:80]}")
    elif tool_name == "read_file":
        path = args.get("path", "")
        parts.append(path[:80])
    elif tool_name == "run_exploit_script":
        parts.append("script executed")
    elif tool_name == "get_app_logs":
        parts.append("logs checked")

    # HTTP status if visible in output
    status_m = _HTTP_STATUS_RE.search(tool_output[:500])
    if status_m:
        parts.append(f"HTTP {status_m.group(1)}")

    # Exploitation level
    parts.append(f"L{feedback.exploitation_level}")

    # Top evidence (highest level match)
    if feedback.evidence:
        top = max(feedback.evidence, key=lambda e: e.level_match)
        parts.append(top.description[:100])

    # Error classification (skip trivial states)
    if feedback.error_classification not in ("none", "partial_trigger"):
        parts.append(f"err:{feedback.error_classification}")

    # Suggested fix (truncated)
    if feedback.suggested_fix:
        parts.append(f"fix:{feedback.suggested_fix[:60]}")

    return " | ".join(parts)[:300]
