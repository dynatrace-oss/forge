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
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from forge.pipeline.llm_client import LLMClient

logger = logging.getLogger(__name__)

DEFAULT_EXPERIENCE_DIR = Path("data/knowledge/experience")

_DISTILL_PROMPT_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "prompts" / "experience" / "distill.yaml"
)

# JSON array extraction — tolerant of markdown fences.
_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)

# Maximum items per section to prevent unbounded growth.
_MAX_ITEMS_PER_SECTION = 20


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class BuildExperience(BaseModel):
    """Package-specific build knowledge accumulated across CVE runs."""

    working_base_image: str = ""
    working_deps: list[str] = Field(default_factory=list)
    env_requirements: list[str] = Field(default_factory=list)
    dockerfile_notes: list[str] = Field(default_factory=list)
    failed_approaches: list[str] = Field(default_factory=list)


class ExploitExperience(BaseModel):
    """Package-specific exploitation knowledge accumulated across CVE runs."""

    known_endpoints: list[str] = Field(default_factory=list)
    auth_mechanism: str = ""
    effective_techniques: list[str] = Field(default_factory=list)
    failed_techniques: list[str] = Field(default_factory=list)
    payload_hints: list[str] = Field(default_factory=list)


class DetectionExperience(BaseModel):
    """Package-specific detection knowledge accumulated across CVE runs."""

    effective_rule_patterns: list[str] = Field(default_factory=list)
    indicator_types: list[str] = Field(default_factory=list)


class CVEHistoryEntry(BaseModel):
    """Outcome record for a single CVE processed for this package."""

    cve_id: str
    level: int = 0
    techniques: list[str] = Field(default_factory=list)
    build_attempts: int = 1
    build_success: bool = True
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class PackageExperience(BaseModel):
    """Complete experience profile for a single package.

    Accumulates across all CVE runs that target this package.
    """

    package: str
    ecosystem: str
    cve_count: int = 0
    build: BuildExperience = Field(default_factory=BuildExperience)
    exploit: ExploitExperience = Field(default_factory=ExploitExperience)
    detection: DetectionExperience = Field(default_factory=DetectionExperience)
    cve_history: list[CVEHistoryEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class PackageExperienceStore:
    """Karpathy KSB-inspired package experience store.

    Records and retrieves package-specific knowledge across three memory
    types:

    * **Episodic** — per-CVE history entries (what happened)
    * **Semantic** — distilled patterns (build tips, exploit techniques)
    * **Procedural** — concrete recipes (Dockerfile notes, deps, env)

    Storage layout::

        experience_dir/
            npm/lunary.yaml
            pypi/flask-admin.yaml
            packagist/wegia.yaml

    When an ``LLMClient`` and ``distill_model`` are provided, the store
    auto-distills raw build/exploit artifacts into structured tips after
    each recording call.
    """

    def __init__(
        self,
        experience_dir: Path | None = None,
        *,
        llm: "LLMClient | None" = None,
        distill_model: str = "",
    ) -> None:
        self._dir = experience_dir or DEFAULT_EXPERIENCE_DIR
        self._llm = llm
        self._distill_model = distill_model
        self._cache: dict[str, PackageExperience] = {}

    @property
    def distill_enabled(self) -> bool:
        """True if LLM distillation is configured."""
        return self._llm is not None and bool(self._distill_model)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def get(self, package: str, ecosystem: str) -> PackageExperience | None:
        """Load experience for a package. Returns None if none exists."""
        key = self._cache_key(package, ecosystem)
        if key in self._cache:
            return self._cache[key]
        exp = self._load(package, ecosystem)
        if exp is not None:
            self._cache[key] = exp
        return exp

    def format_build_context(self, package: str, ecosystem: str) -> str:
        """Format build experience as text for generator prompt injection.

        Returns empty string if no experience exists.
        """
        exp = self.get(package, ecosystem)
        if exp is None:
            return ""

        b = exp.build
        lines: list[str] = []
        lines.append(f"PACKAGE BUILD EXPERIENCE FOR {package} ({ecosystem}):")
        lines.append(f"  Previously built for {exp.cve_count} CVE(s).")

        # Generation success stats from CVE history
        if exp.cve_history:
            successful = sum(1 for h in exp.cve_history if h.build_success)
            total = len(exp.cve_history)
            rate = successful / total if total else 0
            lines.append(f"  Build success rate: {successful}/{total} ({rate:.0%})")
            total_attempts = sum(h.build_attempts for h in exp.cve_history)
            if total_attempts > total:
                avg = total_attempts / total
                lines.append(f"  Total build attempts: {total_attempts} (avg {avg:.1f} per CVE)")

        if b.working_base_image:
            lines.append(f"  Working base image: {b.working_base_image}")
        if b.working_deps:
            lines.append(f"  Working dependencies: {', '.join(b.working_deps[:10])}")
        if b.env_requirements:
            lines.append(f"  Required env vars: {', '.join(b.env_requirements[:10])}")
        if b.dockerfile_notes:
            lines.append("  Build notes:")
            for note in b.dockerfile_notes[:_MAX_ITEMS_PER_SECTION]:
                lines.append(f"    * {note}")
        if b.failed_approaches:
            lines.append("  KNOWN FAILURES (do NOT repeat):")
            for fail in b.failed_approaches[:_MAX_ITEMS_PER_SECTION]:
                lines.append(f"    * {fail}")

        return "\n".join(lines)

    def format_exploit_context(self, package: str, ecosystem: str) -> str:
        """Format exploit experience as text for planner/exploit prompt injection.

        Returns empty string if no experience exists.
        """
        exp = self.get(package, ecosystem)
        if exp is None:
            return ""

        e = exp.exploit
        if not (e.known_endpoints or e.effective_techniques or e.auth_mechanism):
            return ""

        lines: list[str] = []
        lines.append(f"PACKAGE EXPLOIT EXPERIENCE FOR {package} ({ecosystem}):")
        lines.append(f"  Exploited in {exp.cve_count} prior CVE(s).")

        if e.auth_mechanism:
            lines.append(f"  Auth mechanism: {e.auth_mechanism}")
        if e.known_endpoints:
            lines.append(f"  Known endpoints: {', '.join(e.known_endpoints[:15])}")
        if e.effective_techniques:
            lines.append(f"  Effective techniques: {', '.join(e.effective_techniques[:10])}")
        if e.failed_techniques:
            lines.append(f"  Failed techniques (skip these): {', '.join(e.failed_techniques[:10])}")
        if e.payload_hints:
            lines.append("  Payload hints:")
            for hint in e.payload_hints[:_MAX_ITEMS_PER_SECTION]:
                lines.append(f"    * {hint}")

        # Include prior CVE outcomes as episodic context
        successful = [h for h in exp.cve_history if h.level >= 2]
        if successful:
            lines.append("  Prior successful exploits:")
            for h in successful[-5:]:
                techs = ", ".join(h.techniques[:3]) if h.techniques else "unknown"
                lines.append(f"    * {h.cve_id}: L{h.level} via {techs}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def record_build(
        self,
        package: str,
        ecosystem: str,
        cve_id: str,
        *,
        success: bool,
        attempts: int = 1,
        base_image: str = "",
        deps: list[str] | None = None,
        env_vars: list[str] | None = None,
        build_errors: list[str] | None = None,
    ) -> None:
        """Record a generation/build outcome for a package.

        Called by the orchestrator after the generator phase completes.
        """
        exp = self._get_or_create(package, ecosystem)

        # Update build experience
        if success and base_image:
            exp.build.working_base_image = base_image
        if success and deps:
            exp.build.working_deps = _dedupe_bounded(
                exp.build.working_deps + deps, _MAX_ITEMS_PER_SECTION
            )
        if env_vars:
            exp.build.env_requirements = _dedupe_bounded(
                exp.build.env_requirements + env_vars, _MAX_ITEMS_PER_SECTION
            )
        if build_errors:
            for err in build_errors[:5]:
                summary = err[:200].strip()
                if summary and summary not in exp.build.failed_approaches:
                    exp.build.failed_approaches.append(summary)
            exp.build.failed_approaches = exp.build.failed_approaches[-_MAX_ITEMS_PER_SECTION:]

        # Append CVE history
        existing_cves = {h.cve_id for h in exp.cve_history}
        if cve_id not in existing_cves:
            exp.cve_history.append(
                CVEHistoryEntry(
                    cve_id=cve_id,
                    build_attempts=attempts,
                    build_success=success,
                )
            )
            exp.cve_count = len(exp.cve_history)

        self._save(exp)
        logger.info(
            "experience.build | pkg=%s eco=%s cve=%s success=%s attempts=%d",
            package,
            ecosystem,
            cve_id,
            success,
            attempts,
        )

    def record_exploit(
        self,
        package: str,
        ecosystem: str,
        cve_id: str,
        *,
        level: int,
        techniques: list[str] | None = None,
        endpoints: list[str] | None = None,
        auth_mechanism: str = "",
    ) -> None:
        """Record an exploitation outcome for a package.

        Called by the orchestrator after the exploit phase completes.
        """
        exp = self._get_or_create(package, ecosystem)

        if techniques:
            for t in techniques:
                if level >= 2 and t not in exp.exploit.effective_techniques:
                    exp.exploit.effective_techniques.append(t)
                elif level < 1 and t not in exp.exploit.failed_techniques:
                    exp.exploit.failed_techniques.append(t)
            exp.exploit.effective_techniques = exp.exploit.effective_techniques[
                -_MAX_ITEMS_PER_SECTION:
            ]
            exp.exploit.failed_techniques = exp.exploit.failed_techniques[-_MAX_ITEMS_PER_SECTION:]
            # Remove techniques from failed if they later succeed
            if level >= 2:
                exp.exploit.failed_techniques = [
                    t for t in exp.exploit.failed_techniques if t not in techniques
                ]

        if endpoints:
            exp.exploit.known_endpoints = _dedupe_bounded(
                exp.exploit.known_endpoints + endpoints, _MAX_ITEMS_PER_SECTION
            )
        if auth_mechanism:
            exp.exploit.auth_mechanism = auth_mechanism

        # Update CVE history entry (may already exist from build recording)
        updated = False
        for h in exp.cve_history:
            if h.cve_id == cve_id:
                h.level = level
                h.techniques = techniques or []
                updated = True
                break
        if not updated:
            exp.cve_history.append(
                CVEHistoryEntry(
                    cve_id=cve_id,
                    level=level,
                    techniques=techniques or [],
                )
            )
            exp.cve_count = len(exp.cve_history)

        self._save(exp)
        logger.info(
            "experience.exploit | pkg=%s eco=%s cve=%s level=%d techniques=%s",
            package,
            ecosystem,
            cve_id,
            level,
            techniques,
        )

    def record_detection(
        self,
        package: str,
        ecosystem: str,
        cve_id: str,
        *,
        rule_patterns: list[str] | None = None,
        indicator_types: list[str] | None = None,
    ) -> None:
        """Record detection rule outcomes for a package.

        Called by the orchestrator after the detector phase completes.
        """
        exp = self._get_or_create(package, ecosystem)

        if rule_patterns:
            exp.detection.effective_rule_patterns = _dedupe_bounded(
                exp.detection.effective_rule_patterns + rule_patterns,
                _MAX_ITEMS_PER_SECTION,
            )
        if indicator_types:
            exp.detection.indicator_types = _dedupe_bounded(
                exp.detection.indicator_types + indicator_types,
                _MAX_ITEMS_PER_SECTION,
            )

        self._save(exp)
        logger.info(
            "experience.detection | pkg=%s eco=%s cve=%s patterns=%d",
            package,
            ecosystem,
            cve_id,
            len(rule_patterns or []),
        )

    # ------------------------------------------------------------------
    # LLM Distillation
    # ------------------------------------------------------------------

    async def distill_build(
        self,
        package: str,
        ecosystem: str,
        *,
        build_errors: list[str],
        dockerfile_content: str = "",
        success: bool = False,
    ) -> int:
        """Distill build errors/successes into reusable notes via LLM.

        Merges distilled notes into the package's build experience.
        Returns the number of new notes added.
        """
        if not self.distill_enabled:
            return 0
        if not build_errors and not dockerfile_content:
            return 0

        assert self._llm is not None  # noqa: S101 — guarded by distill_enabled

        exp = self.get(package, ecosystem)
        existing = _format_existing_build(exp)

        system_msg, user_msg = _load_distill_prompt("build")
        user_msg = user_msg.format(
            package=package,
            ecosystem=ecosystem,
            success=str(success),
            errors="\n".join(f"- {e[:200]}" for e in build_errors[:10]),
            dockerfile=dockerfile_content[:2000] or "(not provided)",
            existing=existing or "(none)",
        )

        return await self._run_distillation(
            package, ecosystem, system_msg, user_msg, section="build"
        )

    async def distill_exploit(
        self,
        package: str,
        ecosystem: str,
        *,
        level: int,
        techniques: list[str],
        tool_call_summary: str = "",
    ) -> int:
        """Distill exploitation outcomes into reusable insights via LLM.

        Returns the number of new insights added.
        """
        if not self.distill_enabled:
            return 0
        if level < 1 and not techniques:
            return 0

        assert self._llm is not None  # noqa: S101

        exp = self.get(package, ecosystem)
        existing = _format_existing_exploit(exp)

        system_msg, user_msg = _load_distill_prompt("exploit")
        user_msg = user_msg.format(
            package=package,
            ecosystem=ecosystem,
            level=level,
            techniques=", ".join(techniques) or "(none)",
            tool_summary=tool_call_summary[:3000] or "(not provided)",
            existing=existing or "(none)",
        )

        return await self._run_distillation(
            package, ecosystem, system_msg, user_msg, section="exploit"
        )

    async def _run_distillation(
        self,
        package: str,
        ecosystem: str,
        system_msg: str,
        user_msg: str,
        *,
        section: str,
    ) -> int:
        """Execute one LLM distillation call and merge results."""
        assert self._llm is not None  # noqa: S101

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
                phase="experience_distill",
            )
            notes = _parse_distilled_notes(raw)
            if not notes:
                return 0

            return self._merge_notes(package, ecosystem, section, notes)

        except Exception:
            logger.warning(
                "Experience distillation failed for %s/%s", package, ecosystem, exc_info=True
            )
            return 0

    def _merge_notes(
        self,
        package: str,
        ecosystem: str,
        section: str,
        notes: list[str],
    ) -> int:
        """Merge distilled notes into the appropriate experience section."""
        exp = self._get_or_create(package, ecosystem)
        added = 0

        if section == "build":
            for note in notes:
                if note not in exp.build.dockerfile_notes:
                    exp.build.dockerfile_notes.append(note)
                    added += 1
            exp.build.dockerfile_notes = exp.build.dockerfile_notes[-_MAX_ITEMS_PER_SECTION:]
        elif section == "exploit":
            for note in notes:
                if note not in exp.exploit.payload_hints:
                    exp.exploit.payload_hints.append(note)
                    added += 1
            exp.exploit.payload_hints = exp.exploit.payload_hints[-_MAX_ITEMS_PER_SECTION:]

        if added > 0:
            self._save(exp)
            logger.info(
                "experience.distill | pkg=%s eco=%s section=%s added=%d",
                package,
                ecosystem,
                section,
                added,
            )
        return added

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def package_count(self) -> int:
        """Return total number of packages with experience records."""
        count = 0
        if self._dir.exists():
            for eco_dir in self._dir.iterdir():
                if eco_dir.is_dir():
                    count += sum(1 for f in eco_dir.glob("*.yaml"))
        return count

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    def _cache_key(self, package: str, ecosystem: str) -> str:
        return f"{ecosystem}/{_safe_filename(package)}"

    def _get_or_create(self, package: str, ecosystem: str) -> PackageExperience:
        """Load or create a fresh experience record."""
        exp = self.get(package, ecosystem)
        if exp is not None:
            return exp
        exp = PackageExperience(package=package, ecosystem=ecosystem)
        key = self._cache_key(package, ecosystem)
        self._cache[key] = exp
        return exp

    def _load(self, package: str, ecosystem: str) -> PackageExperience | None:
        """Load a package experience file from disk."""
        path = self._yaml_path(package, ecosystem)
        if not path.exists():
            return None
        try:
            raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
            return PackageExperience.model_validate(raw)
        except (ValueError, OSError, yaml.YAMLError):
            logger.warning("Failed to load experience: %s", path)
            return None

    def _save(self, exp: PackageExperience) -> None:
        """Persist a package experience to YAML."""
        path = self._yaml_path(exp.package, exp.ecosystem)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = exp.model_dump()
        path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        key = self._cache_key(exp.package, exp.ecosystem)
        self._cache[key] = exp

    def _yaml_path(self, package: str, ecosystem: str) -> Path:
        """Return the YAML file path for a package."""
        return self._dir / ecosystem / f"{_safe_filename(package)}.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_filename(name: str) -> str:
    """Sanitize a package name for use as a filename.

    Replaces ``/`` and ``@`` (scoped npm packages) with safe characters.
    """
    return name.replace("/", "__").replace("@", "_at_").replace(" ", "_").lower()


def _dedupe_bounded(items: list[str], max_items: int) -> list[str]:
    """Deduplicate a list while preserving order, bounded to max_items."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result[-max_items:]


def _load_distill_prompt(section: str) -> tuple[str, str]:
    """Load the distillation prompt for a section from YAML."""
    if _DISTILL_PROMPT_PATH.exists():
        with _DISTILL_PROMPT_PATH.open() as f:
            data = yaml.safe_load(f)
        system = data.get(f"{section}_system", data.get("system", ""))
        user = data.get(f"{section}_user", data.get("user", ""))
        return system, user
    raise FileNotFoundError(
        f"Experience distill prompt not found at {_DISTILL_PROMPT_PATH}. "
        "All prompts must be in data/prompts/ YAML files."
    )


def _format_existing_build(exp: PackageExperience | None) -> str:
    """Format existing build notes for the distillation prompt."""
    if exp is None:
        return ""
    notes = exp.build.dockerfile_notes + exp.build.failed_approaches
    if not notes:
        return ""
    return "\n".join(f"- {n}" for n in notes[:_MAX_ITEMS_PER_SECTION])


def _format_existing_exploit(exp: PackageExperience | None) -> str:
    """Format existing exploit hints for the distillation prompt."""
    if exp is None:
        return ""
    hints = exp.exploit.payload_hints + exp.exploit.effective_techniques
    if not hints:
        return ""
    return "\n".join(f"- {h}" for h in hints[:_MAX_ITEMS_PER_SECTION])


def _parse_distilled_notes(raw: str) -> list[str]:
    """Parse distilled notes from LLM response (JSON array of strings)."""
    raw = raw.strip()

    # Try direct JSON parse
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(item).strip() for item in data if item]
    except (json.JSONDecodeError, ValueError):
        pass

    # Regex extraction for JSON embedded in markdown
    match = _JSON_ARRAY_RE.search(raw)
    if match:
        try:
            data = json.loads(match.group(0))
            if isinstance(data, list):
                return [str(item).strip() for item in data if item]
        except (json.JSONDecodeError, ValueError):
            pass

    logger.warning("Failed to parse distill response: %.200s", raw)
    return []
