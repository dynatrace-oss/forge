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
import logging
import shutil
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

DEFAULT_LEARNINGS_DIR = Path("data/knowledge/learnings")

# CWE sibling groups — CWEs under the same parent category share similar
# exploitation techniques, so learnings transfer across siblings.
# Key: parent CWE category → value: list of child CWE IDs.
_CWE_SIBLING_GROUPS: dict[str, list[str]] = {
    # CWE-943: Improper Neutralization in Data Query Logic
    "CWE-943": ["CWE-89", "CWE-564", "CWE-943"],
    # CWE-74: Injection
    "CWE-74": ["CWE-74", "CWE-79", "CWE-77", "CWE-78", "CWE-94"],
    # CWE-284: Improper Access Control
    "CWE-284": ["CWE-284", "CWE-285", "CWE-287", "CWE-862", "CWE-863"],
    # CWE-664: Improper Control of Resource Lifecycle
    "CWE-664": ["CWE-664", "CWE-400", "CWE-770", "CWE-772"],
    # CWE-693: Protection Mechanism Failure
    "CWE-693": ["CWE-693", "CWE-327", "CWE-330", "CWE-916"],
    # CWE-20: Improper Input Validation
    "CWE-20": ["CWE-20", "CWE-22", "CWE-611", "CWE-918"],
    # CWE-200: Exposure of Sensitive Information
    "CWE-200": ["CWE-200", "CWE-209", "CWE-532", "CWE-312"],
    # CWE-668: Exposure of Resource to Wrong Sphere
    "CWE-668": ["CWE-668", "CWE-434", "CWE-502", "CWE-601"],
}

# Build reverse lookup: CWE ID → set of sibling CWE IDs
_CWE_SIBLINGS: dict[str, set[str]] = {}
for _children in _CWE_SIBLING_GROUPS.values():
    _group = set(_children)
    for _cwe in _children:
        _CWE_SIBLINGS.setdefault(_cwe, set()).update(_group)
# Remove self from each sibling set
for _cwe_id, _siblings in _CWE_SIBLINGS.items():
    _siblings.discard(_cwe_id)


class ErrorCategory(StrEnum):
    BUILD_PARSE_FAILURE = "build_parse_failure"
    DOCKERFILE_BUILD_ERROR = "dockerfile_build_error"
    HEALTH_CHECK_FAILURE = "health_check_failure"
    PACKAGE_NOT_FOUND = "package_not_found"
    PORT_MISMATCH = "port_mismatch"
    EXPLOIT_TIMEOUT = "exploit_timeout"
    LLM_FORMAT_ERROR = "llm_format_error"
    LLM_API_ERROR = "llm_api_error"
    TEMPLATE_RENDER_ERROR = "template_render_error"
    EXPLOIT_INFRA_ERROR = "exploit_infra_error"

    # R5: Exploit-phase learning categories (§1.8b)
    EXPLOIT_WRONG_ENDPOINT = "exploit_wrong_endpoint"
    EXPLOIT_WRONG_PAYLOAD = "exploit_wrong_payload"
    EXPLOIT_STRATEGY_EXHAUSTED = "exploit_strategy_exhausted"
    EXPLOIT_SUCCESS_PATTERN = "exploit_success_pattern"
    EXPLOIT_PARTIAL_PROGRESS = "exploit_partial_progress"


class Learning(BaseModel):
    """A single error recovery learning recorded during a run."""

    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=datetime.now)
    phase: str  # "build", "deploy", "exploit"
    error_category: ErrorCategory
    language: str = ""
    cwe_id: str = ""
    cve_id: str = ""
    package: str = ""
    error_pattern: str = ""
    error_summary: str = ""
    fix_summary: str = ""
    success: bool = False


class LearningStore:
    """Append-only JSONL store for error recovery learnings.

    During pilot runs, learnings are recorded and queried to provide
    context for retry prompts. During formal experiments (Phase 5-6),
    the store is frozen (read-only) so both conditions get identical
    prior knowledge.
    """

    def __init__(
        self,
        store_dir: Path | None = None,
        *,
        frozen: bool = False,
    ) -> None:
        self._dir = store_dir or DEFAULT_LEARNINGS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "learnings.jsonl"
        self._frozen = frozen
        self._cache: list[Learning] | None = None

    @property
    def frozen(self) -> bool:
        """Whether this store is frozen (read-only experiment snapshot)."""
        return self._frozen

    def record(self, learning: Learning) -> None:
        """Append a learning to the JSONL file.

        Raises RuntimeError if the store is frozen.
        """
        if self._frozen:
            raise RuntimeError("Cannot record learnings: store is frozen for experiment")

        with self._path.open("a") as f:
            f.write(learning.model_dump_json() + "\n")

        # Invalidate cache
        self._cache = None

        logger.info(
            "Recorded learning: phase=%s category=%s cve=%s success=%s",
            learning.phase,
            learning.error_category,
            learning.cve_id,
            learning.success,
        )

    def query(
        self,
        *,
        phase: str | None = None,
        language: str | None = None,
        cwe_id: str | None = None,
        error_category: ErrorCategory | None = None,
        package: str | None = None,
        limit: int = 10,
    ) -> list[Learning]:
        """Retrieve learnings matching the given filters.

        Returns most recent matches first, up to ``limit``.
        """
        all_learnings = self._load_all()
        matches = all_learnings

        if phase:
            matches = [m for m in matches if m.phase == phase]
        if language:
            matches = [m for m in matches if m.language == language]
        if cwe_id:
            matches = [m for m in matches if m.cwe_id == cwe_id]
        if error_category:
            matches = [m for m in matches if m.error_category == error_category]
        if package:
            matches = [m for m in matches if m.package == package]

        # Most recent first
        matches.sort(key=lambda x: x.timestamp, reverse=True)
        return matches[:limit]

    def query_related(
        self,
        cwe_id: str,
        *,
        max_results: int = 5,
    ) -> list[Learning]:
        """Retrieve learnings for a CWE and its siblings.

        Returns exact CWE matches first, then sibling matches.
        This enables cross-CWE knowledge transfer — e.g., a lesson
        from CWE-89 (SQLi) is useful when processing CWE-564
        (Hibernate Injection) because the exploitation is similar.
        """
        all_learnings = self._load_all()

        exact: list[Learning] = []
        sibling: list[Learning] = []
        sibling_ids = _CWE_SIBLINGS.get(cwe_id, set())

        for lr in all_learnings:
            if lr.cwe_id == cwe_id:
                exact.append(lr)
            elif lr.cwe_id in sibling_ids:
                sibling.append(lr)

        # Sort each group by recency
        exact.sort(key=lambda x: x.timestamp, reverse=True)
        sibling.sort(key=lambda x: x.timestamp, reverse=True)

        return (exact + sibling)[:max_results]

    def freeze(self, version: str) -> Path:
        """Snapshot the current learnings to a frozen versioned file.

        Returns the path to the frozen file. Used before formal experiments
        to ensure both conditions receive identical prior knowledge.
        """
        frozen_dir = self._dir / "frozen"
        frozen_dir.mkdir(parents=True, exist_ok=True)
        frozen_path = frozen_dir / f"v{version}.jsonl"

        if self._path.exists():
            shutil.copy2(self._path, frozen_path)
            count = len(self._load_all())
            logger.info("Froze %d learnings to %s", count, frozen_path)
        else:
            frozen_path.touch()
            logger.info("Created empty frozen learnings at %s", frozen_path)

        return frozen_path

    @classmethod
    def from_frozen(cls, frozen_path: Path) -> "LearningStore":
        """Load a frozen (read-only) learning store for experiments."""
        store = cls(store_dir=frozen_path.parent, frozen=True)
        store._path = frozen_path
        return store

    def count(self) -> int:
        """Return the total number of learnings."""
        return len(self._load_all())

    def _load_all(self) -> list[Learning]:
        """Load all learnings from the JSONL file with caching."""
        if self._cache is not None:
            return self._cache

        learnings: list[Learning] = []
        if not self._path.exists():
            self._cache = learnings
            return learnings

        for line_num, line in enumerate(self._path.read_text().splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                learnings.append(Learning.model_validate(data))
            except (ValueError, ValidationError):
                logger.warning("Skipping malformed learning at line %d", line_num)

        self._cache = learnings
        return learnings
