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
import math
import re
import time
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DEFAULT_KNOWLEDGE_DIR = Path("data/knowledge/exploitation")
CONFIDENCE_HALF_LIFE_DAYS = 90
CRYSTALLIZATION_THRESHOLD = 3  # min confirmations to crystallize

# Canonical technique synonym map — maps common variations to a single
# canonical name.  Keys are lowercase patterns that appear anywhere in
# the raw technique string; values are the canonical replacement.
_TECHNIQUE_SYNONYMS: dict[str, str] = {
    "sql injection": "sqli",
    "sqli": "sqli",
    "union injection": "sqli",
    "union select": "sqli",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "xss": "xss",
    "remote code execution": "rce",
    "rce": "rce",
    "command injection": "command_injection",
    "cmd injection": "command_injection",
    "os command": "command_injection",
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    "ssrf": "ssrf",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "local file inclusion": "lfi",
    "lfi": "lfi",
    "remote file inclusion": "rfi",
    "rfi": "rfi",
    "deserialization": "deserialization",
    "deserialisation": "deserialization",
    "file upload": "file_upload",
    "unrestricted upload": "file_upload",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "buffer overflow": "buffer_overflow",
    "stack overflow": "buffer_overflow",
    "heap overflow": "buffer_overflow",
    "authentication bypass": "auth_bypass",
    "auth bypass": "auth_bypass",
    "privilege escalation": "privilege_escalation",
    "privesc": "privilege_escalation",
}

# Regex to collapse non-alphanumeric runs into single underscores
_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def normalize_technique(raw: str) -> str:
    """Normalize a technique name to a canonical lowercase form.

    1. Strip and lowercase the input.
    2. Check the synonym map for a canonical match (longest match wins).
       Matches must be whole-word to avoid partial hits (e.g., "sqli"
       in synonym map must not match "sqli_union").
    3. If no synonym matches, collapse whitespace/punctuation into
       underscores and strip trailing underscores.
    """
    cleaned = raw.strip().lower()
    if not cleaned:
        return "unknown"

    # Try synonym map — longest matching key wins; require word boundaries
    best_match = ""
    best_canonical = ""
    for pattern, canonical in _TECHNIQUE_SYNONYMS.items():
        if re.search(rf"\b{re.escape(pattern)}\b", cleaned) and len(pattern) > len(best_match):
            best_match = pattern
            best_canonical = canonical
    if best_canonical:
        return best_canonical

    # No synonym match — collapse to snake_case
    return _NORMALIZE_RE.sub("_", cleaned).strip("_")


class Technique(BaseModel):
    """An attack technique observed for a CWE."""

    name: str
    description: str = ""
    success_count: int = 0
    failure_count: int = 0
    last_seen: float = Field(default_factory=time.time)
    cve_ids: list[str] = Field(default_factory=list)

    # Per-language success counts — e.g. {"python": 3, "java": 1}.
    # Populated when the caller provides a language; older entries
    # (pre-language-awareness) will have an empty dict and still work.
    language_success: dict[str, int] = Field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    def language_success_rate(self, language: str) -> float:
        """Return success rate for a specific language, or 0.0 if unknown."""
        lang_ok = self.language_success.get(language, 0)
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return lang_ok / total


class EscalationPath(BaseModel):
    """A known escalation path from one level to another."""

    from_level: int = Field(ge=0, le=3)
    to_level: int = Field(ge=0, le=3)
    techniques: list[str] = Field(default_factory=list)
    success_count: int = 0
    cve_ids: list[str] = Field(default_factory=list)


class CWEKnowledge(BaseModel):
    """Tier 3 semantic memory — per-CWE attack knowledge.

    Gets richer with each CVE exploited. Confidence decays over time
    (90-day half-life) and strengthens with confirmations.
    """

    cwe_id: str
    cwe_name: str = ""
    description: str = ""

    techniques: list[Technique] = Field(default_factory=list)
    escalation_paths: list[EscalationPath] = Field(default_factory=list)
    common_bypasses: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)

    total_attempts: int = 0
    total_successes: int = 0
    avg_max_level: float = 0.0

    last_updated: float = Field(default_factory=time.time)
    confirmations: int = 0
    crystallized: bool = False

    @property
    def confidence(self) -> float:
        """Compute time-decayed confidence score."""
        if self.confirmations == 0:
            return 0.0
        age_days = (time.time() - self.last_updated) / 86400
        decay = math.exp(-0.693 * age_days / CONFIDENCE_HALF_LIFE_DAYS)
        base = min(self.confirmations / 10.0, 1.0)
        return base * decay

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts


class KnowledgeStore:
    """Manages per-CWE attack knowledge (Tier 3 semantic memory).

    Each CWE accumulates knowledge across CVE assessments: effective
    techniques, escalation paths, common bypasses, success rates.
    Confidence decays with a 90-day half-life and strengthens with
    new confirmations. Knowledge "crystallizes" after enough
    confirmations, making it a stable reference.
    """

    def __init__(self, knowledge_dir: Path | None = None) -> None:
        self._dir = knowledge_dir or DEFAULT_KNOWLEDGE_DIR

    def get(self, cwe_id: str) -> CWEKnowledge | None:
        """Load knowledge for a CWE, or None if not found."""
        path = self._path(cwe_id)
        if not path.exists():
            logger.debug("kb.get | cwe=%s result=miss", cwe_id)
            return None
        try:
            knowledge = CWEKnowledge.model_validate_json(path.read_text())
            logger.debug(
                "kb.get | cwe=%s result=hit confidence=%.2f techniques=%d escalations=%d",
                cwe_id,
                knowledge.confidence,
                len(knowledge.techniques),
                len(knowledge.escalation_paths),
            )
            return knowledge
        except (ValueError, OSError):
            logger.warning("kb.get | cwe=%s result=corrupt path=%s", cwe_id, path)
            return None

    def get_or_create(self, cwe_id: str, cwe_name: str = "") -> CWEKnowledge:
        """Load existing knowledge or create a new entry."""
        existing = self.get(cwe_id)
        if existing:
            return existing
        logger.debug("kb.create | cwe=%s name=%s", cwe_id, cwe_name)
        return CWEKnowledge(cwe_id=cwe_id, cwe_name=cwe_name)

    def save(self, knowledge: CWEKnowledge) -> Path:
        """Persist CWE knowledge to disk."""
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._path(knowledge.cwe_id)
        path.write_text(knowledge.model_dump_json(indent=2))
        logger.debug(
            "kb.save | cwe=%s confidence=%.2f attempts=%d successes=%d",
            knowledge.cwe_id,
            knowledge.confidence,
            knowledge.total_attempts,
            knowledge.total_successes,
        )
        return path

    def record_attempt(
        self,
        cwe_id: str,
        cve_id: str,
        max_level: int,
        techniques_used: list[str] | None = None,
        *,
        cwe_name: str = "",
        language: str = "",
    ) -> CWEKnowledge:
        """Record an exploitation attempt outcome for a CWE.

        Updates success/failure counts, technique stats, and triggers
        crystallization if the confirmation threshold is reached.

        Args:
            language: Programming language of the target (e.g. "python").
                When provided, per-language success counts are tracked on
                each technique so ``format_for_prompt`` can prioritize
                language-matched techniques.
        """
        knowledge = self.get_or_create(cwe_id, cwe_name)
        knowledge.total_attempts += 1
        knowledge.confirmations += 1
        knowledge.last_updated = time.time()

        if max_level >= 1:
            knowledge.total_successes += 1

        # Update running average max level
        n = knowledge.total_attempts
        knowledge.avg_max_level = (knowledge.avg_max_level * (n - 1) + max_level) / n

        # Update technique stats
        for tech_name in techniques_used or []:
            self._update_technique(
                knowledge,
                tech_name,
                cve_id,
                success=max_level >= 1,
                language=language,
            )

        # Crystallization check
        if not knowledge.crystallized and knowledge.confirmations >= CRYSTALLIZATION_THRESHOLD:
            knowledge.crystallized = True
            logger.info(
                "kb.crystallized | cwe=%s confirmations=%d",
                cwe_id,
                knowledge.confirmations,
            )

        self.save(knowledge)
        return knowledge

    def record_escalation(
        self,
        cwe_id: str,
        cve_id: str,
        from_level: int,
        to_level: int,
        techniques: list[str],
    ) -> None:
        """Record a successful escalation path for a CWE."""
        knowledge = self.get_or_create(cwe_id)
        normalized = [normalize_technique(t) for t in techniques]

        for path in knowledge.escalation_paths:
            if path.from_level == from_level and path.to_level == to_level:
                path.success_count += 1
                if cve_id not in path.cve_ids:
                    path.cve_ids.append(cve_id)
                # Merge new techniques into existing list (deduplicated)
                for t in normalized:
                    if t not in path.techniques:
                        path.techniques.append(t)
                self.save(knowledge)
                return

        knowledge.escalation_paths.append(
            EscalationPath(
                from_level=from_level,
                to_level=to_level,
                techniques=normalized,
                success_count=1,
                cve_ids=[cve_id],
            )
        )
        self.save(knowledge)

    def format_for_prompt(
        self,
        cwe_id: str,
        *,
        max_techniques: int = 5,
        language: str = "",
    ) -> str:
        """Format CWE knowledge as an actionable playbook for LLM consumption.

        Splits techniques into high-effectiveness (>=50% success rate) and
        low-effectiveness (<50%) so the LLM knows what to prioritize and
        what to avoid.  Techniques are sorted by success rate descending.

        When *language* is provided, techniques that have succeeded for that
        language are boosted to the top of each category.

        Returns empty string if no knowledge exists or confidence is too low.
        """
        knowledge = self.get(cwe_id)
        if not knowledge or knowledge.confidence < 0.05:
            logger.debug(
                "kb.format_for_prompt | cwe=%s result=empty reason=%s",
                cwe_id,
                "no_knowledge" if not knowledge else "low_confidence",
            )
            return ""

        logger.debug(
            "kb.format_for_prompt | cwe=%s confidence=%.2f techniques=%d escalations=%d",
            cwe_id,
            knowledge.confidence,
            len(knowledge.techniques),
            len(knowledge.escalation_paths),
        )

        lines = [f"CWE Knowledge ({knowledge.cwe_id}):"]
        rate = knowledge.success_rate
        n_ok = knowledge.total_successes
        n_all = knowledge.total_attempts
        lines.append(f"  Prior success rate: {rate:.0%} ({n_ok}/{n_all})")
        lines.append(f"  Avg max level: {knowledge.avg_max_level:.1f}")
        lines.append(f"  Confidence: {knowledge.confidence:.2f}")

        if knowledge.techniques:
            # Sort by language-specific success (if language provided), then overall rate.
            lang = language.lower().strip()

            def _sort_key(t: Technique) -> tuple[int, float]:
                """(has_language_success desc, success_rate desc)."""
                lang_match = 1 if lang and t.language_success.get(lang, 0) > 0 else 0
                return (lang_match, t.success_rate)

            sorted_techs = sorted(knowledge.techniques, key=_sort_key, reverse=True)
            effective = [t for t in sorted_techs if t.success_rate >= 0.5]
            ineffective = [t for t in sorted_techs if t.success_rate < 0.5]

            if effective:
                lines.append("  Recommended techniques (by effectiveness):")
                for tech in effective[:max_techniques]:
                    n = tech.success_count + tech.failure_count
                    lang_note = ""
                    if lang and tech.language_success.get(lang, 0) > 0:
                        lang_note = f" [verified for {lang}]"
                    lines.append(
                        f"    - {tech.name}: {tech.success_rate:.0%} success"
                        f" ({tech.success_count}/{n}){lang_note}"
                    )
            if ineffective:
                lines.append("  Low effectiveness (consider alternatives):")
                for tech in ineffective[:max_techniques]:
                    n = tech.success_count + tech.failure_count
                    lines.append(
                        f"    - {tech.name}: {tech.success_rate:.0%} success"
                        f" ({tech.success_count}/{n})"
                    )

        if knowledge.escalation_paths:
            lines.append("  Known escalation paths:")
            for ep in knowledge.escalation_paths:
                tech_label = ", ".join(ep.techniques) if ep.techniques else "unknown"
                lines.append(
                    f"    - L{ep.from_level}→L{ep.to_level}: {tech_label}"
                    f" (confirmed {ep.success_count}x)"
                )

        if knowledge.common_bypasses:
            lines.append("  Known bypasses:")
            for bypass in knowledge.common_bypasses[:3]:
                lines.append(f"    - {bypass}")

        return "\n".join(lines)

    def _update_technique(
        self,
        knowledge: CWEKnowledge,
        name: str,
        cve_id: str,
        *,
        success: bool,
        language: str = "",
    ) -> None:
        """Update or create a technique entry in the knowledge.

        Technique names are normalized before storage so that variations
        like "SQL injection via UNION" and "union-based SQLi" consolidate
        into the same canonical entry.

        When *language* is provided and the attempt succeeded, the
        per-language success counter is incremented.
        """
        canonical = normalize_technique(name)
        lang = language.lower().strip()
        for tech in knowledge.techniques:
            if tech.name == canonical:
                if success:
                    tech.success_count += 1
                    if lang:
                        tech.language_success[lang] = tech.language_success.get(lang, 0) + 1
                else:
                    tech.failure_count += 1
                tech.last_seen = time.time()
                if cve_id not in tech.cve_ids:
                    tech.cve_ids.append(cve_id)
                return

        lang_stats: dict[str, int] = {}
        if success and lang:
            lang_stats[lang] = 1
        knowledge.techniques.append(
            Technique(
                name=canonical,
                success_count=1 if success else 0,
                failure_count=0 if success else 1,
                cve_ids=[cve_id],
                language_success=lang_stats,
            )
        )

    def _path(self, cwe_id: str) -> Path:
        safe_id = cwe_id.replace("/", "_")
        return self._dir / f"{safe_id}.json"
