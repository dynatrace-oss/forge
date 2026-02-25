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
from typing import Any

from forge.models import CVESource, CWETag, PatchCommit, SecurityAdvisory

logger = logging.getLogger(__name__)

# CWEs that indicate pure memory-safety bugs (C/C++ native-only).
# Entries with these CWEs are excluded when the project has no web component.
MEMORY_SAFETY_CWES: frozenset[str] = frozenset(
    {
        "CWE-119",  # Buffer overflow
        "CWE-120",  # Classic buffer overflow
        "CWE-121",  # Stack-based buffer overflow
        "CWE-122",  # Heap-based buffer overflow
        "CWE-125",  # Out-of-bounds read
        "CWE-126",  # Buffer over-read
        "CWE-127",  # Buffer under-read
        "CWE-131",  # Incorrect buffer size calculation
        "CWE-190",  # Integer overflow
        "CWE-191",  # Integer underflow
        "CWE-415",  # Double free
        "CWE-416",  # Use after free
        "CWE-476",  # NULL pointer dereference
        "CWE-787",  # Out-of-bounds write
        "CWE-788",  # Access of memory beyond buffer
        "CWE-805",  # Buffer access with incorrect length
        "CWE-806",  # Buffer access using size of source
        "CWE-823",  # Use of out-of-range pointer offset
        "CWE-824",  # Access of uninitialized pointer
    }
)

# File extensions that indicate web-capable languages.
_WEB_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".php",
        ".js",
        ".ts",
        ".go",
        ".rb",
        ".java",
        ".rs",
        ".jsx",
        ".tsx",
        ".vue",
        ".svelte",
        ".kt",
        ".scala",
        ".cs",
    }
)

# Extensions indicating C/C++ source.
_NATIVE_EXTENSIONS: frozenset[str] = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx"})


class CVEGENIELoader:
    """Load and parse the CVE-GENIE dataset."""

    def __init__(self, data_path: Path) -> None:
        self._data_path = data_path
        self._raw_cache: dict[str, Any] | None = None

    def get_cwes(self, cve_id: str) -> list[CWETag]:
        """Look up CWE tags for a single CVE ID.

        Returns an empty list (with a warning) if the CVE is not in the
        dataset — this is the graceful-degradation path for CVEs outside
        CVE-GENIE.
        """
        raw = self._read_json_cached()
        blob = raw.get(cve_id)
        if blob is None:
            logger.warning("CVE %s not found in CVE-GENIE data — CWE lookup skipped", cve_id)
            return []
        return self._parse_cwes(blob.get("cwe", []))

    def _read_json_cached(self) -> dict[str, Any]:
        """Return raw JSON dict, caching across repeated lookups."""
        if self._raw_cache is None:
            self._raw_cache = self._read_json()
        return self._raw_cache

    def load_all(self) -> list[CVESource]:
        """Parse all 841 entries from JSON."""
        raw = self._read_json()
        entries: list[CVESource] = []
        for cve_id, blob in raw.items():
            try:
                entries.append(self._parse_entry(cve_id, blob))
            except Exception:
                logger.warning("Skipping malformed entry %s", cve_id, exc_info=True)
        logger.info("Loaded %d CVE entries from %s", len(entries), self._data_path)
        return entries

    def load_web_suitable(self) -> list[CVESource]:
        """Filter to web-app suitable entries.

        Excludes:
        - Native-only C/C++ memory-safety CVEs (where the project has no web
          component based on patch file extensions).
        - CVEs with no valid CWE tag (``id`` == ``"n/a"``).
        """
        all_entries = self.load_all()
        filtered = [e for e in all_entries if self._is_web_suitable(e)]
        excluded = len(all_entries) - len(filtered)
        logger.info(
            "Web-suitable: %d / %d (excluded %d)",
            len(filtered),
            len(all_entries),
            excluded,
        )
        return filtered

    def _read_json(self) -> dict[str, Any]:
        text = self._data_path.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(text)
        return data

    def _parse_entry(self, cve_id: str, raw: dict[str, Any]) -> CVESource:
        """Parse a single JSON entry into a ``CVESource`` model."""
        cwes = self._parse_cwes(raw.get("cwe", []))
        patches = self._parse_patches(raw.get("patch_commits", []))
        advisories = self._parse_advisories(raw.get("sec_adv", []))

        return CVESource(
            cve_id=cve_id,
            description=raw.get("description", ""),
            cwes=cwes,
            patch_commits=patches,
            sw_version=raw.get("sw_version", ""),
            sw_version_wget=raw.get("sw_version_wget"),
            security_advisories=advisories,
            raw_data=raw,
        )

    @staticmethod
    def _parse_cwes(raw_cwes: list[dict[str, str]]) -> list[CWETag]:
        """Parse CWE list, normalising non-prefixed IDs."""
        tags: list[CWETag] = []
        for item in raw_cwes:
            cwe_id = item.get("id", "n/a")
            value = item.get("value", "")
            # Skip entries with no CWE info
            if cwe_id == "n/a":
                continue
            # Normalise bare numeric IDs like "732" → "CWE-732"
            if cwe_id.isdigit():
                cwe_id = f"CWE-{cwe_id}"
            tags.append(CWETag(id=cwe_id, value=value))
        return tags

    @staticmethod
    def _parse_patches(raw_patches: list[dict[str, str]]) -> list[PatchCommit]:
        results: list[PatchCommit] = []
        for item in raw_patches:
            results.append(
                PatchCommit(
                    url=item.get("url", ""),
                    diff_content=item.get("content"),
                )
            )
        return results

    @staticmethod
    def _parse_advisories(
        raw_advisories: list[dict[str, str]],
    ) -> list[SecurityAdvisory]:
        results: list[SecurityAdvisory] = []
        for item in raw_advisories:
            results.append(
                SecurityAdvisory(
                    url=item.get("url", ""),
                    content=item.get("content"),
                )
            )
        return results

    @staticmethod
    def _is_web_suitable(entry: CVESource) -> bool:
        """Return *True* if the entry is suitable for web-app generation."""
        # Exclude entries with no valid CWE tags.
        if not entry.cwes:
            return False

        cwe_ids = {c.id for c in entry.cwes}
        has_memory_cwe = bool(cwe_ids & MEMORY_SAFETY_CWES)
        if not has_memory_cwe:
            return True

        # Has memory-safety CWE — check if project is native-only.
        langs = languages_from_patches(entry.patch_commits)
        web_langs = langs - {"C", "C++"}
        # If all detected languages are C/C++ (and at least one was detected),
        # this is a native-only project.
        return not (langs and not web_langs)


_EXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Filename:\s*(.+?):"), "filename_line"),
    (re.compile(r"diff --git a/(.+?) b/"), "diff_header"),
    (re.compile(r"--- a/(.+)"), "diff_minus"),
]


def languages_from_patches(patches: list[PatchCommit]) -> set[str]:
    """Infer programming languages from patch file extensions.

    Public API — used by both the web-suitability filter and the CLI
    to populate ``CVETask.language`` from GENIE patch data.
    """
    langs: set[str] = set()
    for pc in patches:
        content = pc.diff_content or ""
        filenames: list[str] = []
        for pattern, _ in _EXT_PATTERNS:
            filenames.extend(pattern.findall(content))
        for fn in filenames:
            fn = fn.strip()
            suffix = Path(fn).suffix.lower()
            if suffix in _WEB_EXTENSIONS:
                langs.add(_ext_to_lang(suffix))
            elif suffix in _NATIVE_EXTENSIONS:
                langs.add("C" if suffix in {".c", ".h"} else "C++")
    return langs


def pick_primary_language(langs: set[str]) -> str:
    """Pick the single primary language from a set of detected languages.

    Priority: web languages first (by prevalence in the 600-CVE dataset),
    then native.  Returns empty string when *langs* is empty.
    """
    if not langs:
        return ""
    if len(langs) == 1:
        return next(iter(langs))

    # Ranked by prevalence in the 600-CVE evaluation dataset.
    priority: list[str] = [
        "PHP",
        "TypeScript",
        "Go",
        "Python",
        "JavaScript",
        "Ruby",
        "Rust",
        "Java",
        "C#",
        "Kotlin",
        "Scala",
        "C",
        "C++",
    ]
    for lang in priority:
        if lang in langs:
            return lang
    return next(iter(langs))


def classify_web_suitability(
    cwe_ids: list[str],
    language: str,
    description: str,
) -> bool:
    """Return *True* if the CVE is suitable for web-app reproduction.

    Non-web CVEs are memory-safety bugs in C/C++ or protocol-level
    vulnerabilities that cannot be meaningfully wrapped in an HTTP app.
    """
    # Memory-safety CWEs in native languages → non-web
    if language in {"C", "C++"} and any(c in MEMORY_SAFETY_CWES for c in cwe_ids):
        return False

    # Description keyword heuristics for protocol/library-internal bugs
    desc_lower = description.lower()
    non_web_keywords = [
        "buffer overflow",
        "memory corruption",
        "use-after-free",
        "double free",
        "null pointer dereference",
        "stack overflow",
        "heap overflow",
    ]
    return not (language in {"C", "C++"} and any(kw in desc_lower for kw in non_web_keywords))


def _ext_to_lang(suffix: str) -> str:
    """Map a file extension to a canonical language name."""
    mapping: dict[str, str] = {
        ".py": "Python",
        ".php": "PHP",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".go": "Go",
        ".rb": "Ruby",
        ".java": "Java",
        ".rs": "Rust",
        ".vue": "JavaScript",
        ".svelte": "JavaScript",
        ".kt": "Kotlin",
        ".scala": "Scala",
        ".cs": "C#",
    }
    return mapping.get(suffix, "Unknown")
