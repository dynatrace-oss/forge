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

import json
import logging
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from forge.models import Message, TokenUsage
from forge.pipeline.budget import BudgetTracker
from forge.pipeline.llm_client import LLMClient

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).resolve().parents[3] / "data" / "prompts" / "oracle" / "critic.yaml"

# Maximum tool output chars sent to the oracle (cost control).
_MAX_OUTPUT_CHARS = 4000

# Maximum tool arguments chars sent to the oracle.
_MAX_ARGS_CHARS = 2000

# Maximum app source chars sent to the oracle.
_MAX_APP_SOURCE_CHARS = 15_000

# Maximum snapshot text chars sent to the oracle.
_MAX_SNAPSHOT_CHARS = 3000

# JSON extraction pattern — tolerant of markdown fences.
# Accepts both bare digits ("level": 2) and L-prefixed strings ("level": "L2").
_JSON_RE = re.compile(r"\{[^{}]*\"level\"\s*:\s*\"?L?\d\"?[^{}]*\}", re.DOTALL)

# Agent self-congratulatory patterns to strip before sending to the oracle.
# These phrases bias the LLM judge toward higher exploitation levels.
_NARRATIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?:^|\n).*(?:L[23]\s+(?:ACHIEVED|CONFIRMED|COMPLETE|REACHED)).*(?:\n|$)", re.IGNORECASE
    ),
    re.compile(
        r"(?:^|\n).*(?:EXPLOITATION\s+(?:COMPLETE|SUCCESSFUL|CONFIRMED)).*(?:\n|$)", re.IGNORECASE
    ),
    re.compile(r"(?:^|\n).*(?:RCE\s+(?:CONFIRMED|ACHIEVED|SUCCESSFUL)).*(?:\n|$)", re.IGNORECASE),
    re.compile(r"(?:^|\n).*(?:successfully\s+exploit(?:ed|ing)).*(?:\n|$)", re.IGNORECASE),
    re.compile(r"(?:^|\n).*(?:full\s+compromise\s+achieved).*(?:\n|$)", re.IGNORECASE),
    re.compile(
        r"(?:^|\n)\s*print\s*\(.*(?:exploit|success|achieved|compromise).*\)\s*(?:\n|$)",
        re.IGNORECASE,
    ),
]


class CriticVerdict(BaseModel):
    """Structured result from the LLM oracle."""

    level: int = Field(default=0, ge=0, le=3)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""


class LLMOracleCritic:
    """LLM-primary exploitation judge.

    Invoked on EVERY exploit tool turn.  Receives rich context including
    app source code, server-side snapshot, and CWE-specific evidence
    descriptions so the LLM can make informed level assessments.

    Replaces the old Tier 1 regex + Tier 2 LLM fallback architecture
    with a single LLM-primary evaluation.
    """

    def __init__(
        self,
        llm: LLMClient,
        *,
        model: str = "gpt-5-mini",
    ) -> None:
        self._llm = llm
        self._model = model
        prompt_data = _load_prompt()
        self._prompt_system = prompt_data["system"]
        self._prompt_user = prompt_data["user"]
        self._sandbox_annotations: dict[str, str] = prompt_data.get("sandbox_annotations", {})
        self._total_tokens = TokenUsage()
        self._budget_tracker: BudgetTracker | None = None

    def set_budget_tracker(self, tracker: BudgetTracker) -> None:
        """Wire shared BudgetTracker so oracle costs are visible pipeline-wide."""
        self._budget_tracker = tracker

    @property
    def total_tokens(self) -> TokenUsage:
        """Accumulated token usage across all oracle calls."""
        return self._total_tokens

    async def evaluate(
        self,
        tool_name: str,
        tool_arguments: dict[str, Any],
        tool_output: str,
        cwe_id: str,
        cwe_name: str,
        oracle_criteria: str = "",
        app_source: str = "",
        snapshot_text: str = "",
    ) -> CriticVerdict:
        """Ask the LLM oracle to judge a tool interaction.

        Called on EVERY exploit tool turn (no pre-filter gating).

        Args:
            tool_name: Name of the tool that produced the output.
            tool_arguments: Arguments sent to the tool.
            tool_output: Raw output from the tool.
            cwe_id: CWE identifier (e.g. "CWE-89").
            cwe_name: Human-readable CWE name.
            oracle_criteria: Pre-formatted CWE-specific evidence guidelines.
            app_source: Source code of the vulnerable application.
            snapshot_text: Formatted server-side snapshot (files, processes, logs).

        Returns a CriticVerdict with exploitation level, confidence, and reasoning.
        On any LLM failure, returns a zero-level verdict (safe fallback).
        """
        # Format prompt — strip agent self-assessment narrative first.
        args_str = _strip_narrative(
            json.dumps(tool_arguments, indent=2, default=str)[:_MAX_ARGS_CHARS]
        )
        output_str = _strip_narrative(tool_output[:_MAX_OUTPUT_CHARS])

        # Annotate sandbox context so the oracle knows the output origin.
        # Annotations are loaded from critic.yaml (sandbox_annotations section).
        annotation = self._sandbox_annotations.get(tool_name, "")
        if not annotation and tool_name in ("exec_command", "run_exploit_script"):
            annotation = self._sandbox_annotations.get("exec_command", "")
        if annotation:
            output_str = annotation + "\n" + output_str

        # Truncate app source and snapshot for cost control.
        app_source_ctx = app_source[:_MAX_APP_SOURCE_CHARS] if app_source else "(not available)"
        snapshot_ctx = (
            snapshot_text[:_MAX_SNAPSHOT_CHARS] if snapshot_text else "(no snapshot data)"
        )

        system_msg = self._prompt_system.format(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            oracle_criteria=oracle_criteria,
            app_source=app_source_ctx,
            snapshot_text=snapshot_ctx,
        )
        user_msg = self._prompt_user.format(
            tool_name=tool_name,
            tool_arguments=args_str,
            tool_output=output_str,
        )

        try:
            messages = [
                Message(role="system", content=system_msg),
                Message(role="user", content=user_msg),
            ]
            raw, tokens = await self._llm.chat(
                messages,
                model=self._model,
                temperature=0.0,
                max_tokens=512,
                phase="oracle_critic",
            )
            self._total_tokens = TokenUsage(
                prompt_tokens=self._total_tokens.prompt_tokens + tokens.prompt_tokens,
                completion_tokens=(self._total_tokens.completion_tokens + tokens.completion_tokens),
                total_tokens=self._total_tokens.total_tokens + tokens.total_tokens,
                llm_calls=self._total_tokens.llm_calls + 1,
                estimated_cost_usd=(
                    self._total_tokens.estimated_cost_usd + tokens.estimated_cost_usd
                ),
            )
            if self._budget_tracker is not None:
                self._budget_tracker.record(tokens)
            return _parse_verdict(raw)

        except Exception:
            logger.warning("LLM oracle call failed — returning L0 verdict", exc_info=True)
            return CriticVerdict(level=0, confidence=0.0, reasoning="oracle_call_failed")


def _load_prompt() -> dict[str, Any]:
    """Load oracle prompt template from YAML file.

    Returns a dict with keys: system, user, sandbox_annotations.
    """
    if _PROMPT_PATH.exists():
        with _PROMPT_PATH.open() as f:
            data = yaml.safe_load(f)
        result: dict[str, Any] = {
            "system": data["system"],
            "user": data["user"],
        }
        if "sandbox_annotations" in data and isinstance(data["sandbox_annotations"], dict):
            result["sandbox_annotations"] = data["sandbox_annotations"]
        else:
            result["sandbox_annotations"] = {}
        return result
    logger.warning("Oracle prompt YAML not found at %s — using minimal fallback", _PROMPT_PATH)
    return {
        "system": (
            "You are a security exploitation judge. Analyze this tool interaction "
            'and respond with JSON: {{"level": 0-3, "confidence": 0.0-1.0, '
            '"reasoning": "..."}}\nTarget: {cwe_id} — {cwe_name}\n{oracle_criteria}'
            "\n{app_source}\n{snapshot_text}"
        ),
        "user": "Tool: {tool_name}\nREQUEST: {tool_arguments}\nRESPONSE: {tool_output}",
        "sandbox_annotations": {},
    }


def _strip_narrative(text: str) -> str:
    """Remove agent self-congratulatory lines from tool output/args.

    Strips lines containing self-assessment phrases (e.g. "L3 ACHIEVED",
    "EXPLOITATION COMPLETE") that bias the LLM oracle toward higher scores.
    """
    result = text
    for pattern in _NARRATIVE_PATTERNS:
        result = pattern.sub("\n", result)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()


def _parse_verdict(raw: str) -> CriticVerdict:
    """Extract CriticVerdict from LLM response, tolerant of markdown fences.

    Handles three failure modes:
    1. JSON embedded in markdown or extra text -> regex extraction.
    2. Truncated JSON (missing closing ``"}``) -> append missing suffix.
    3. Partial data (only level/confidence parseable) -> field-level regex.
    """
    raw = raw.strip()

    # Try direct JSON parse first.
    try:
        data = json.loads(raw)
        return _verdict_from_dict(data)
    except (ValueError, TypeError):
        pass

    # Regex extraction for JSON embedded in markdown or extra text.
    match = _JSON_RE.search(raw)
    if match:
        try:
            data = json.loads(match.group(0))
            return _verdict_from_dict(data)
        except (ValueError, TypeError):
            pass

    # Truncated JSON recovery: Maverick often truncates the reasoning
    # field mid-sentence, leaving unclosed strings/braces.
    for suffix in ('"}', '"}}', '"}}}', "}"):
        try:
            data = json.loads(raw + suffix)
            logger.debug("Recovered truncated oracle JSON with suffix %r", suffix)
            return _verdict_from_dict(data)
        except (ValueError, TypeError):
            continue

    # Last resort: field-level regex extraction.
    verdict = _extract_fields_from_raw(raw)
    if verdict is not None:
        return verdict

    logger.warning("Failed to parse oracle response: %.200s", raw)
    return CriticVerdict(level=0, confidence=0.0, reasoning="parse_failed")


# Regex patterns for field-level extraction when JSON is completely broken.
# Accept both bare digits (2) and L-prefixed strings ("L2").
_LEVEL_RE = re.compile(r'"level"\s*:\s*"?L?(\d)"?')
_CONFIDENCE_RE = re.compile(r'"confidence"\s*:\s*"?([\d.]+)"?')


def _verdict_from_dict(data: dict[str, object]) -> CriticVerdict:
    """Build a CriticVerdict from a parsed JSON dict.

    Handles Maverick's common format variations:
    - ``"level": 2``  (integer — standard)
    - ``"level": "2"`` (string digit)
    - ``"level": "L2"`` (L-prefixed string — Maverick default)
    - ``"confidence": "0.85"`` (string instead of float)
    """
    raw_level = data.get("level", 0)
    raw_conf = data.get("confidence", 0.5)

    # Strip "L" prefix that Maverick prepends (e.g. "L2" → "2").
    level_str = str(raw_level).strip().lstrip("Ll")
    try:
        level = int(level_str)
    except (ValueError, TypeError):
        logger.warning("Unparseable level value %r — defaulting to 0", raw_level)
        level = 0

    # Confidence may arrive as string ("0.85") or int (1).
    try:
        confidence = float(str(raw_conf))
    except (ValueError, TypeError):
        logger.warning("Unparseable confidence value %r — defaulting to 0.5", raw_conf)
        confidence = 0.5

    return CriticVerdict(
        level=level,
        confidence=confidence,
        reasoning=str(data.get("reasoning", "")),
    )


def _extract_fields_from_raw(raw: str) -> CriticVerdict | None:
    """Extract level and confidence individually from malformed JSON."""
    level_match = _LEVEL_RE.search(raw)
    conf_match = _CONFIDENCE_RE.search(raw)
    if level_match:
        try:
            level = int(level_match.group(1))
            confidence = float(conf_match.group(1)) if conf_match else 0.5
            logger.debug(
                "Recovered oracle fields via regex: level=%d, confidence=%.2f",
                level,
                confidence,
            )
            return CriticVerdict(
                level=level,
                confidence=confidence,
                reasoning="recovered_from_truncated_response",
            )
        except (ValueError, TypeError):
            pass
    return None
