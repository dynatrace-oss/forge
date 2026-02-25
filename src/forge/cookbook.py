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
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from forge.pipeline.llm_client import LLMClient

logger = logging.getLogger(__name__)

DEFAULT_COOKBOOK_DIR = Path("data/knowledge/cookbook")

_PROMPT_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "prompts" / "cookbook" / "distill.yaml"
)

# Maximum tips per page — prevents unbounded growth.
_MAX_TIPS_PER_PAGE = 20

# JSON array extraction — tolerant of markdown fences.
_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)


class Tip(BaseModel):
    """A single distilled tip for LLM prompt injection."""

    id: str
    phase: str = "generation"
    tip: str
    confirmed: int = 1


class CookbookPage(BaseModel):
    """A page of tips keyed by language or CWE category."""

    language: str = ""
    cwe_category: str = ""
    tips: list[Tip] = Field(default_factory=list)


class CookbookStore:
    """Compiled knowledge store — distilled tips for LLM prompt injection.

    Curated, human-readable tips organized by language and CWE category.

    Tips are stored as YAML files under ``cookbook_dir``::

        cookbook_dir/
            languages/go.yaml
            languages/java.yaml
            cwe/injection.yaml
            cwe/deserialization.yaml
            general.yaml

    When ``llm`` and ``distill_model`` are provided, the store can auto-distill
    build errors into new tips after each generation run.
    """

    def __init__(
        self,
        cookbook_dir: Path | None = None,
        *,
        llm: "LLMClient | None" = None,
        distill_model: str = "",
    ) -> None:
        self._dir = cookbook_dir or DEFAULT_COOKBOOK_DIR
        self._pages: dict[str, CookbookPage] = {}
        self._llm = llm
        self._distill_model = distill_model
        self._load_all()

    @property
    def distill_enabled(self) -> bool:
        """True if auto-distillation is configured."""
        return self._llm is not None and bool(self._distill_model)

    def query(
        self,
        *,
        language: str | None = None,
        cwe_id: str | None = None,
        phase: str | None = None,
    ) -> list[Tip]:
        """Return tips matching the given filters.

        Collects tips from:
        1. Language-specific page (if language given)
        2. CWE-category page (if cwe_id maps to a known category)
        3. General page (always)

        Deduplicates by tip ID.
        """
        tips: dict[str, Tip] = {}

        # Language page
        if language:
            page = self._pages.get(f"languages/{language.lower()}")
            if page:
                for t in page.tips:
                    tips[t.id] = t

        # CWE category page — map CWE ID to category
        if cwe_id:
            category = _cwe_to_category(cwe_id)
            if category:
                page = self._pages.get(f"cwe/{category}")
                if page:
                    for t in page.tips:
                        tips[t.id] = t

        # General page
        general = self._pages.get("general")
        if general:
            for t in general.tips:
                tips[t.id] = t

        # Phase filter
        result = list(tips.values())
        if phase:
            result = [t for t in result if t.phase == phase]

        return result

    def format_for_prompt(
        self,
        *,
        language: str | None = None,
        cwe_id: str | None = None,
        phase: str | None = None,
    ) -> str:
        """Format matching tips as text suitable for LLM prompt injection.

        Returns an empty string if no tips match.
        """
        tips = self.query(language=language, cwe_id=cwe_id, phase=phase)
        if not tips:
            return ""

        label = language.upper() if language else "THIS TASK"
        lines = [f"COMMON PATTERNS AND GOTCHAS FOR {label} APPS:"]
        for t in tips:
            lines.append(f"  * {t.tip.strip()}")

        return "\n".join(lines)

    async def distill_tips(
        self,
        *,
        language: str,
        cwe_id: str,
        build_errors: list[str],
        success: bool,
    ) -> int:
        """Distill build errors into reusable tips via one LLM call.

        Merges new tips into the language-specific YAML page.  Skips
        if distillation is not configured or there are no errors to learn from.

        Returns the number of new tips added.
        """
        if not self.distill_enabled:
            return 0
        if not build_errors:
            return 0

        assert self._llm is not None  # noqa: S101 — guarded by distill_enabled

        # Target the language page for new tips
        page_key = f"languages/{language.lower()}" if language else "general"
        page = self._pages.get(page_key)
        existing_tips_text = _format_existing_tips(page)

        system_msg, user_msg = _load_distill_prompt()
        user_msg = user_msg.format(
            language=language or "unknown",
            cwe_id=cwe_id or "unknown",
            success=str(success),
            errors="\n".join(f"- {e}" for e in build_errors[:10]),
            existing_tips=existing_tips_text or "(none)",
        )

        try:
            from forge.models import Message

            messages = [
                Message(role="system", content=system_msg),
                Message(role="user", content=user_msg),
            ]
            raw, _tokens = await self._llm.chat(
                messages,
                model=self._distill_model,
                temperature=0.0,
                max_tokens=512,
                phase="cookbook_distill",
            )
            new_tips = _parse_tips(raw)
            if not new_tips:
                return 0

            return self._merge_tips(page_key, language, new_tips)

        except Exception:
            logger.warning("Cookbook distillation failed — skipping", exc_info=True)
            return 0

    def tip_count(self) -> int:
        """Return total number of tips across all pages."""
        return sum(len(p.tips) for p in self._pages.values())

    def page_count(self) -> int:
        """Return number of loaded cookbook pages."""
        return len(self._pages)

    def _merge_tips(
        self,
        page_key: str,
        language: str,
        new_tips: list[Tip],
    ) -> int:
        """Merge new tips into a cookbook page and persist to YAML.

        Deduplicates by ID (updates existing tips with same ID).
        Caps at _MAX_TIPS_PER_PAGE to prevent unbounded growth.
        Returns count of tips actually added (not updated).
        """
        page = self._pages.get(page_key)
        if page is None:
            page = CookbookPage(language=language)
            self._pages[page_key] = page

        existing_ids = {t.id for t in page.tips}
        added = 0

        for tip in new_tips:
            if tip.id in existing_ids:
                # Update existing tip text
                for i, existing in enumerate(page.tips):
                    if existing.id == tip.id:
                        page.tips[i] = tip
                        break
            else:
                if len(page.tips) < _MAX_TIPS_PER_PAGE:
                    page.tips.append(tip)
                    existing_ids.add(tip.id)
                    added += 1

        if added > 0:
            self._persist_page(page_key, page)
            logger.info(
                "Cookbook distilled %d new tip(s) into %s (total: %d)",
                added,
                page_key,
                len(page.tips),
            )

        return added

    def _persist_page(self, page_key: str, page: CookbookPage) -> None:
        """Write a cookbook page back to its YAML file."""
        yaml_path = self._dir / f"{page_key}.yaml"
        yaml_path.parent.mkdir(parents=True, exist_ok=True)

        data = page.model_dump(exclude_defaults=False)
        yaml_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        logger.debug("Persisted cookbook page %s (%d tips)", page_key, len(page.tips))

    def _load_all(self) -> None:
        """Load all YAML files from the cookbook directory."""
        if not self._dir.exists():
            logger.debug("Cookbook directory does not exist: %s", self._dir)
            return

        for yaml_path in sorted(self._dir.rglob("*.yaml")):
            rel = yaml_path.relative_to(self._dir).with_suffix("")
            key = str(rel)
            try:
                raw: dict[str, Any] = yaml.safe_load(yaml_path.read_text()) or {}
                page = CookbookPage.model_validate(raw)
                self._pages[key] = page
                logger.debug("Loaded cookbook page %s (%d tips)", key, len(page.tips))
            except (ValueError, OSError, yaml.YAMLError):
                logger.warning("Failed to load cookbook page: %s", yaml_path)


# CWE ID → cookbook category mapping.
# Groups related CWEs under a single cookbook page so tips transfer.
_CWE_CATEGORY_MAP: dict[str, str] = {
    # Injection family
    "CWE-74": "injection",
    "CWE-77": "injection",
    "CWE-78": "injection",
    "CWE-79": "injection",
    "CWE-89": "injection",
    "CWE-94": "injection",
    "CWE-564": "injection",
    # Deserialization
    "CWE-502": "deserialization",
    # Path traversal
    "CWE-22": "path-traversal",
    "CWE-23": "path-traversal",
    "CWE-36": "path-traversal",
    "CWE-61": "path-traversal",
    # Input validation
    "CWE-20": "input-validation",
    # Cryptographic / signature
    "CWE-327": "crypto",
    "CWE-347": "crypto",
    # Auth / access control
    "CWE-284": "auth",
    "CWE-285": "auth",
    "CWE-287": "auth",
    "CWE-862": "auth",
    "CWE-863": "auth",
}


def _cwe_to_category(cwe_id: str) -> str:
    """Map a CWE ID to a cookbook category name.

    Returns empty string if no mapping exists.
    """
    return _CWE_CATEGORY_MAP.get(cwe_id, "")


def _load_distill_prompt() -> tuple[str, str]:
    """Load the distillation prompt from YAML."""
    if _PROMPT_PATH.exists():
        with _PROMPT_PATH.open() as f:
            data = yaml.safe_load(f)
        return data["system"], data["user"]
    raise FileNotFoundError(
        f"Cookbook distill prompt not found at {_PROMPT_PATH}. "
        "All prompts must be in data/prompts/ YAML files."
    )


def _format_existing_tips(page: CookbookPage | None) -> str:
    """Format existing tips for the distillation prompt."""
    if page is None or not page.tips:
        return ""
    return "\n".join(f"- [{t.id}] {t.tip.strip()}" for t in page.tips)


def _parse_tips(raw: str) -> list[Tip]:
    """Parse distilled tips from LLM response JSON array."""
    raw = raw.strip()

    # Try direct JSON parse
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [Tip.model_validate(t) for t in data if isinstance(t, dict)]
    except (json.JSONDecodeError, ValueError):
        pass

    # Regex extraction for JSON embedded in text
    match = _JSON_ARRAY_RE.search(raw)
    if match:
        try:
            data = json.loads(match.group(0))
            if isinstance(data, list):
                return [Tip.model_validate(t) for t in data if isinstance(t, dict)]
        except (json.JSONDecodeError, ValueError):
            logger.debug("Regex-extracted JSON array parse failed: %.100s", raw)

    logger.warning("Failed to parse distill response: %.200s", raw)
    return []
