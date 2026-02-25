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
from typing import Any

from forge.agents.base import AgentResult
from forge.agents.exploit import ExploitAgent
from forge.cve.cwe_module_factory import CWEModuleFactory
from forge.cve.enricher import CWEEnricher
from forge.detection.kb_updater import DetectionKBUpdater
from forge.detection.models import DetectionRule, SigmaRule, SnortRule
from forge.intel.hooks import IntelHooks
from forge.learnings import ErrorCategory, Learning, LearningStore
from forge.models import CVETask, CWEModule

logger = logging.getLogger(__name__)

# Lazily-created module-level CWE factory (shared across orchestrator calls).
_cwe_factory: CWEModuleFactory | None = None


def classify_generation_error(reason: str) -> ErrorCategory:
    """Classify a generation failure reason into an ErrorCategory.

    Parses keywords from the error string to select the most specific
    category.  Falls back to HEALTH_CHECK_FAILURE if no pattern matches.
    """
    lower = reason.lower()
    if "build" in lower and ("fail" in lower or "error" in lower):
        return ErrorCategory.DOCKERFILE_BUILD_ERROR
    if "package" in lower and "not found" in lower:
        return ErrorCategory.PACKAGE_NOT_FOUND
    if "port" in lower and ("mismatch" in lower or "8080" in lower):
        return ErrorCategory.PORT_MISMATCH
    if "parse" in lower or "json" in lower or "syntax" in lower:
        return ErrorCategory.BUILD_PARSE_FAILURE
    return ErrorCategory.HEALTH_CHECK_FAILURE


def classify_pipeline_error(reason: str) -> ErrorCategory:
    """Classify a generic pipeline error into an ErrorCategory.

    Handles non-generation errors — LLM API failures, infrastructure
    issues, timeouts, template rendering errors.  Falls back to
    EXPLOIT_INFRA_ERROR for unrecognised patterns.
    """
    lower = reason.lower()
    if "no choices" in lower or "rate limit" in lower or "api" in lower:
        return ErrorCategory.LLM_API_ERROR
    if "timeout" in lower or "timed out" in lower:
        return ErrorCategory.EXPLOIT_TIMEOUT
    if "template" in lower or "jinja" in lower or "render" in lower:
        return ErrorCategory.TEMPLATE_RENDER_ERROR
    if "format" in lower or "json" in lower or "parse" in lower:
        return ErrorCategory.LLM_FORMAT_ERROR
    if "sandbox" in lower or "deploy" in lower or "podman" in lower:
        return ErrorCategory.EXPLOIT_INFRA_ERROR
    return ErrorCategory.EXPLOIT_INFRA_ERROR


def build_cwe_module(cwe_id: str) -> CWEModule:
    """Build a CWEModule from enrichment data for the given CWE.

    Uses a module-level CWEModuleFactory (lazily created) so
    repeated calls for the same CWE reuse the cached module.
    """
    global _cwe_factory  # noqa: PLW0603
    if _cwe_factory is None:
        enricher = CWEEnricher()
        _cwe_factory = CWEModuleFactory(enricher)
    return _cwe_factory.build(cwe_id)


def format_knowledge_context(
    task: CVETask,
    hooks: IntelHooks | None,
    learnings: LearningStore | None,
) -> str:
    """Build context text from CWE knowledge (Tier 3) and learnings (Tier 4).

    Returns empty string if no knowledge store or learnings are configured,
    or if no relevant knowledge exists for this task's CWEs.

    Knowledge is framed as *guidance* — the exploit agent should adapt
    patterns to the specific target rather than copy-pasting techniques.
    """
    parts: list[str] = []

    # Tier 3: CWE knowledge from prior exploitation runs
    if hooks is not None:
        knowledge_store = hooks.knowledge
        language = task.language or ""
        for cwe_id in task.cwe_ids:
            cwe_text = knowledge_store.format_for_prompt(cwe_id, language=language)
            if cwe_text:
                parts.append(cwe_text)

    # Tier 4: Procedural memory — error recovery learnings (with cross-CWE)
    if learnings is not None:
        for cwe_id in task.cwe_ids:
            related = learnings.query_related(cwe_id, max_results=5)
            # Filter to exploit-phase only — generation/detection
            # learnings don't help the exploit agent.
            related = [lr for lr in related if lr.phase == "exploit"]
            if related:
                lines = ["Prior exploitation insights for similar CWEs:"]
                for lr in related:
                    tag = "OK" if lr.success else "FAIL"
                    source = f" [{lr.cwe_id}]" if lr.cwe_id != cwe_id else ""
                    lines.append(f"- [{tag}]{source} {lr.error_summary}")
                parts.append("\n".join(lines))
                break  # One set of learnings is enough

    if not parts:
        logger.debug("[%s] No KB context available for CWEs %s", task.cve_id, task.cwe_ids)
        return ""

    # Frame as guidance, not a recipe to copy
    header = (
        "== PRIOR KNOWLEDGE (reference only — adapt to YOUR specific target) ==\n"
        "The following patterns worked on similar CWEs but your target may differ.\n"
        "Use these as starting points, not exact recipes.\n"
    )
    context = header + "\n\n".join(parts)
    logger.info(
        "[%s] KB context injected: %d source(s), %d chars",
        task.cve_id,
        len(parts),
        len(context),
    )
    return context


def record_exploit_outcome(
    task: CVETask,
    level: int,
    techniques_used: list[str],
    hooks: IntelHooks | None,
    learnings: LearningStore | None,
    exploit_agent: Any,
) -> None:
    """Update Tier 3 CWE knowledge, Tier 4 learnings, and Generation KB."""
    # Tier 3: CWE knowledge update via hooks
    if hooks is not None:
        hooks.on_exploit_complete(
            task,
            max_level=level,
            techniques_used=techniques_used if techniques_used else None,
        )

    # Tier 3: Record escalation paths from level history
    if hooks is not None and task.cwe_ids:
        record_escalations(task, techniques_used, hooks, exploit_agent)

    # Tier 4: Record exploitation learning — only when there's
    # actionable content (techniques or failure).
    if learnings is not None and (level >= 2 or not techniques_used):
        category = (
            ErrorCategory.EXPLOIT_SUCCESS_PATTERN
            if level >= 2
            else ErrorCategory.EXPLOIT_STRATEGY_EXHAUSTED
        )
        if level >= 2 and techniques_used:
            top_techniques = techniques_used[:3]
            summary = f"L{level} achieved via: {'; '.join(top_techniques)}"
            # Build actionable fix_summary from oracle reasoning if available.
            oracle_note = ""
            if isinstance(exploit_agent, ExploitAgent):
                oracle_note = getattr(exploit_agent, "last_oracle_reasoning", "") or ""
            if oracle_note:
                fix = f"L{level} via {'; '.join(top_techniques)}. {oracle_note[:150]}"
            else:
                fix = f"Techniques: {'; '.join(top_techniques)}"
        elif level < 2:
            summary = f"L{level} — exploitation stalled, techniques exhausted"
            fix = "Try alternative approach or different attack vector"
        else:
            summary = f"L{level} — no techniques recorded"
            fix = ""
        learnings.record(
            Learning(
                phase="exploit",
                error_category=category,
                cwe_id=task.cwe_ids[0] if task.cwe_ids else "",
                cve_id=task.cve_id,
                language=task.language or "",
                package=task.vulnerable_package or "",
                error_summary=summary,
                fix_summary=fix,
                success=level >= 2,
            )
        )


def record_escalations(
    task: CVETask,
    techniques_used: list[str],
    hooks: IntelHooks,
    exploit_agent: Any,
) -> None:
    """Record escalation paths from the exploit agent's level history.

    Walks the level history to find transitions where the running max
    increased (e.g., L0->L1, L1->L3).  For each transition, records an
    escalation path in the knowledge store with the techniques used.
    """
    if not isinstance(exploit_agent, ExploitAgent):
        return
    level_history = exploit_agent.level_history
    if len(level_history) < 2:
        return

    knowledge_store = hooks.knowledge

    cwe_id = task.cwe_ids[0]

    # Detect running-max transitions in the level history
    running_max = 0
    for lvl in level_history:
        if lvl > running_max:
            from_level = running_max
            to_level = lvl
            running_max = lvl
            knowledge_store.record_escalation(
                cwe_id=cwe_id,
                cve_id=task.cve_id,
                from_level=from_level,
                to_level=to_level,
                techniques=techniques_used,
            )
            logger.info(
                "kb.escalation | cve=%s cwe=%s from=L%d to=L%d techniques=%s",
                task.cve_id,
                cwe_id,
                from_level,
                to_level,
                techniques_used,
            )


def record_detection_rules(
    cve_id: str,
    detector_result: AgentResult,
    hooks: IntelHooks | None,
) -> None:
    """No-op — graph recording removed (S48).

    Kept as a stub so callers don't need updating.  Detection rules
    are already persisted by ``DetectionKBUpdater`` in ``expand_detection_kb``.
    """


def expand_detection_kb(
    task: CVETask,
    detector_result: AgentResult,
    exploitation_level: int,
    detection_kb_updater: DetectionKBUpdater | None,
) -> None:
    """Expand the on-disk detection KB with validated generated rules.

    Parses raw rule strings from the detector output, wraps them as
    ``SigmaRule`` or ``SnortRule`` objects, and passes them to the
    ``DetectionKBUpdater`` for validation and persistence.
    """
    if detection_kb_updater is None:
        logger.warning(
            "[%s] DetectionKBUpdater not provided — skipping KB expansion",
            task.cve_id,
        )
        return
    if not task.cwe_ids:
        return

    raw_rules: Any = detector_result.output.get("rules", [])
    if not isinstance(raw_rules, list) or not raw_rules:
        return

    cwe_id = task.cwe_ids[0]
    detection_rules: list[DetectionRule] = []

    for i, raw in enumerate(raw_rules):
        rule_str = str(raw)
        title = f"{task.cve_id}-generated-{i}"
        if "alert " in rule_str and "sid:" in rule_str:
            detection_rules.append(
                SnortRule(
                    cve_id=task.cve_id,
                    cwe_id=cwe_id,
                    title=title,
                    raw_rule=rule_str,
                    exploitation_level=exploitation_level,
                )
            )
        else:
            detection_rules.append(
                SigmaRule(
                    cve_id=task.cve_id,
                    cwe_id=cwe_id,
                    title=title,
                    raw_rule=rule_str,
                    exploitation_level=exploitation_level,
                )
            )

    written = detection_kb_updater.update(cwe_id, detection_rules)
    if written:
        logger.info(
            "[%s] Detection KB expanded: %d rules written for %s",
            task.cve_id,
            len(written),
            cwe_id,
        )


def record_detection_learning(
    task: CVETask,
    learnings: LearningStore | None,
    *,
    success: bool,
    reason: str = "",
) -> None:
    """Record a detection-phase learning to the learnings store.

    Only records failures — success metadata has no actionable value
    for future runs.
    """
    if learnings is None or success:
        return

    learnings.record(
        Learning(
            phase="detection",
            error_category=ErrorCategory.EXPLOIT_STRATEGY_EXHAUSTED,
            cwe_id=task.cwe_ids[0] if task.cwe_ids else "",
            cve_id=task.cve_id,
            package=task.vulnerable_package or "",
            error_summary=f"Detection failed: {reason}",
            fix_summary=reason[:200],
            success=False,
        )
    )


def record_generation_learning(
    task: CVETask,
    learnings: LearningStore | None,
    *,
    success: bool,
    attempts: int = 1,
    reason: str = "",
    build_errors: list[str] | None = None,
) -> None:
    """Record a generation-phase learning to the learnings store.

    Only records failures — success metadata has no actionable value
    for future runs.

    Args:
        task: CVE task being processed.
        learnings: Optional learning store.
        success: Whether generation succeeded.
        attempts: Number of generation attempts.
        reason: High-level failure reason.
        build_errors: Actual build error strings from the generator
            (podman output, verification details).  These are far more
            actionable than the generic ``reason`` string.
    """
    if learnings is None or success:
        return

    category = classify_generation_error(reason)
    summary = f"Generation failed after {attempts} attempt(s): {reason}"

    # Use actual build errors when available — these are actionable.
    fix = "; ".join(err[:100] for err in build_errors[:3]) if build_errors else reason[:200]

    learnings.record(
        Learning(
            phase="generation",
            error_category=category,
            cwe_id=task.cwe_ids[0] if task.cwe_ids else "",
            cve_id=task.cve_id,
            language=task.language or "",
            package=task.vulnerable_package or "",
            error_summary=summary,
            fix_summary=fix,
            success=False,
        )
    )
