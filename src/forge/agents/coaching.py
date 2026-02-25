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
from enum import StrEnum
from pathlib import Path
from typing import Any

import jinja2
import yaml
from pydantic import BaseModel

from forge.config import CoachingConfig

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path("data/prompts/agents/coaching.yaml")
_templates: dict[str, str] = {}


def _load_templates() -> dict[str, str]:
    """Load coaching prompt templates from YAML (cached after first call)."""
    if _templates:
        return _templates
    if not _PROMPT_PATH.exists():
        raise FileNotFoundError(f"Coaching prompts not found: {_PROMPT_PATH}")
    with _PROMPT_PATH.open() as f:
        data: dict[str, Any] = yaml.safe_load(f)
    for key in ("reconnaissance", "escalation", "deep_exploitation", "error_recovery"):
        _templates[key] = str(data[key])
    return _templates


def _render(template_key: str, **context: Any) -> str:
    """Render a coaching prompt template with Jinja2."""
    templates = _load_templates()
    env = jinja2.Environment(undefined=jinja2.Undefined)
    template = env.from_string(templates[template_key])
    return template.render(**context).strip()


__all__ = ["CoachingConfig", "CoachingMessage", "CoachingTracker", "CoachingType"]


class CoachingType(StrEnum):
    """Types of coaching interventions."""

    RECONNAISSANCE = "reconnaissance"
    ESCALATION = "escalation"
    DEEP_EXPLOITATION = "deep_exploitation"
    ERROR_RECOVERY = "error_recovery"


class CoachingMessage(BaseModel):
    """A coaching intervention to inject into the conversation."""

    coaching_type: CoachingType
    message: str
    turn: int
    running_max: int


class CoachingTracker:
    """Tracks exploitation progress and triggers coaching interventions.

    Monitors the running level history and error count, then produces
    coaching messages when the agent appears stuck.
    """

    def __init__(self, config: CoachingConfig | None = None) -> None:
        self._config = config or CoachingConfig()
        self._level_history: list[int] = []
        self._error_streak: int = 0
        self._last_coaching_turn: int = -10
        self._coaching_counts: dict[str, int] = {}
        self._should_terminate: bool = False

    def record_turn(self, level: int, had_error: bool) -> None:
        """Record a turn's outcome for tracking."""
        self._level_history.append(level)
        if had_error:
            self._error_streak += 1
        else:
            self._error_streak = 0

    def check_coaching(
        self,
        running_max: int,
        turn: int,
        *,
        intel_summary: str = "",
        attack_plan: str = "",
        patch_analysis: str = "",
        recent_errors: list[str] | None = None,
    ) -> CoachingMessage | None:
        """Check if coaching is needed and return a message if so.

        Returns None if no coaching is needed. Enforces a minimum gap
        of 2 turns between coaching messages to avoid overwhelming the LLM.
        Once ``should_terminate`` is set, no further coaching is produced.
        """
        # Stop generating coaching after termination threshold is reached
        if self._should_terminate:
            return None

        if turn - self._last_coaching_turn < 2:
            return None

        msg = self._check_triggers(
            running_max,
            turn,
            intel_summary=intel_summary,
            attack_plan=attack_plan,
            patch_analysis=patch_analysis,
            recent_errors=recent_errors or [],
        )

        if msg is not None:
            self._last_coaching_turn = turn

            # Track how many times each coaching type has fired
            ctype = msg.coaching_type.value
            self._coaching_counts[ctype] = self._coaching_counts.get(ctype, 0) + 1
            count = self._coaching_counts[ctype]

            logger.info(
                "Coaching triggered: type=%s turn=%d running_max=%d (repeat %d/%d)",
                msg.coaching_type,
                turn,
                running_max,
                count,
                self._config.max_coaching_repeats,
            )

            # Check if this coaching type has exceeded the max repeats
            if count >= self._config.max_coaching_repeats:
                self._should_terminate = True
                logger.warning(
                    "Coaching exhausted after %d repeats of '%s', requesting termination",
                    count,
                    ctype,
                )

        return msg

    @property
    def level_history(self) -> list[int]:
        return list(self._level_history)

    @property
    def should_terminate(self) -> bool:
        """True when a coaching type has fired max_coaching_repeats times."""
        return self._should_terminate

    @property
    def coaching_counts(self) -> dict[str, int]:
        """Number of times each coaching type has fired."""
        return dict(self._coaching_counts)

    def _check_triggers(
        self,
        running_max: int,
        turn: int,
        *,
        intel_summary: str,
        attack_plan: str,
        patch_analysis: str,
        recent_errors: list[str],
    ) -> CoachingMessage | None:
        """Check all coaching trigger conditions in priority order."""
        cfg = self._config
        stuck = self._count_stuck_turns(running_max)

        # Priority 1: Error recovery (consecutive tool errors)
        if self._error_streak >= cfg.consecutive_error_turns:
            return CoachingMessage(
                coaching_type=CoachingType.ERROR_RECOVERY,
                message=_error_recovery_message(recent_errors),
                turn=turn,
                running_max=running_max,
            )

        # Priority 2: Stuck at L0 (no progress at all)
        if running_max == 0 and stuck >= cfg.stuck_at_l0_turns:
            return CoachingMessage(
                coaching_type=CoachingType.RECONNAISSANCE,
                message=_reconnaissance_message(intel_summary, attack_plan),
                turn=turn,
                running_max=running_max,
            )

        # Priority 3: Stuck at L1-L2 (triggered but not confirmed)
        if running_max in (1, 2) and stuck >= cfg.stuck_at_l1_l2_turns:
            return CoachingMessage(
                coaching_type=CoachingType.ESCALATION,
                message=_escalation_message(running_max, attack_plan),
                turn=turn,
                running_max=running_max,
            )

        # Priority 4: Stuck at L2-L3 (exploitation achieved but not fully weaponized)
        if running_max in (2, 3) and stuck >= cfg.stuck_at_l2_l3_turns:
            return CoachingMessage(
                coaching_type=CoachingType.DEEP_EXPLOITATION,
                message=_deep_exploitation_message(running_max, patch_analysis),
                turn=turn,
                running_max=running_max,
            )

        return None

    def _count_stuck_turns(self, running_max: int) -> int:
        """Count turns since last progress (new max level was achieved).

        Walks backwards from the most recent turn. A turn counts as
        progress if it achieved the current ``running_max`` for the first
        time — every turn after that (same or lower) is "stuck."
        """
        if not self._level_history:
            return 0

        # Find the last turn where running_max was first reached
        last_progress_idx = -1
        current_max = 0
        for i, lvl in enumerate(self._level_history):
            if lvl > current_max:
                current_max = lvl
                last_progress_idx = i

        # All turns after the last progress are stuck
        return len(self._level_history) - 1 - last_progress_idx


def _reconnaissance_message(intel_summary: str, attack_plan: str) -> str:
    return _render("reconnaissance", intel_summary=intel_summary, attack_plan=attack_plan)


def _escalation_message(current_level: int, attack_plan: str) -> str:
    return _render("escalation", current_level=current_level, attack_plan=attack_plan)


def _deep_exploitation_message(current_level: int, patch_analysis: str) -> str:
    return _render("deep_exploitation", current_level=current_level, patch_analysis=patch_analysis)


def _error_recovery_message(recent_errors: list[str]) -> str:
    return _render("error_recovery", recent_errors=recent_errors)
