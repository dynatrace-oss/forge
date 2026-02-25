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

from pydantic import BaseModel, Field, field_validator

from forge.intel.cache import RawCache, SourceType

logger = logging.getLogger(__name__)

DEFAULT_COMPILED_DIR = Path("data/cache/compiled")


class AttackSurface(BaseModel):
    """Identified attack surface from intel gathering."""

    endpoints: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)


class VulnerableFunction(BaseModel):
    """A vulnerable function extracted from the patch diff."""

    file_path: str = ""
    function_name: str = ""
    code: str = ""


class PatchAnalysis(BaseModel):
    """Analysis of the vulnerability fix patch."""

    changed_files: list[str] = Field(default_factory=list)
    fix_description: str = ""
    vulnerable_lines: list[str] = Field(default_factory=list)  # deprecated
    vulnerable_functions: list[VulnerableFunction] = Field(default_factory=list)


class TechStack(BaseModel):
    """Target application technology stack."""

    language: str = ""
    framework: str = ""
    web_server: str = ""
    database: str = ""
    os: str = ""
    versions: dict[str, str] = Field(default_factory=dict)


class ExistingPoC(BaseModel):
    """A known proof-of-concept exploit."""

    source: str = ""
    url: str = ""
    description: str = ""
    technique: str = ""

    @field_validator("description", "source", "url", "technique", mode="before")
    @classmethod
    def _coerce_none_to_empty(cls, v: object) -> object:
        """GitHub API returns null for missing fields; coerce to empty string."""
        return v if v is not None else ""


class IntelReport(BaseModel):
    """Tier 2 compiled intelligence report for a single CVE.

    Combines raw Tier 1 sources into a structured report that the
    Planner and Exploit agents consume directly.
    """

    cve_id: str
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""
    severity: str = ""
    cvss_score: float | None = None

    root_cause: str = ""
    vulnerable_function: str = ""
    vulnerable_component: str = ""
    attack_surface: AttackSurface = Field(default_factory=AttackSurface)
    tech_stack: TechStack = Field(default_factory=TechStack)
    existing_pocs: list[ExistingPoC] = Field(default_factory=list)
    patch_analysis: PatchAnalysis = Field(default_factory=PatchAnalysis)

    affected_versions: list[str] = Field(default_factory=list)
    fix_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    sources_used: list[str] = Field(default_factory=list)


class ReportCompiler:
    """Compiles Tier 1 raw cache entries into a Tier 2 intel report.

    Reads cached raw data (NVD, advisories, patches, etc.) and merges
    them into a single structured ``IntelReport``. This is a deterministic
    merge — no LLM calls. The Intel Agent calls tools to populate cache,
    then the compiler assembles the report.
    """

    def __init__(
        self,
        cache: RawCache,
        compiled_dir: Path | None = None,
    ) -> None:
        self._cache = cache
        self._dir = compiled_dir or DEFAULT_COMPILED_DIR

    def compile(self, cve_id: str) -> IntelReport:
        """Compile all cached raw data for a CVE into a report."""
        report = IntelReport(cve_id=cve_id)
        sources: list[str] = []

        nvd = self._cache.get(SourceType.NVD, cve_id)
        if nvd:
            self._apply_nvd(report, nvd)
            sources.append("nvd")

        advisory = self._cache.get(SourceType.GITHUB_ADVISORY, cve_id)
        if advisory:
            self._apply_advisory(report, advisory)
            sources.append("github-advisory")

        patch = self._cache.get(SourceType.PATCH_DIFF, cve_id)
        if patch:
            self._apply_patch(report, patch)
            sources.append("patch-diff")

        exploitdb = self._cache.get(SourceType.EXPLOIT_DB, cve_id)
        if exploitdb:
            self._apply_exploitdb(report, exploitdb)
            sources.append("exploitdb")

        container = self._cache.get(SourceType.CONTAINER_INFO, cve_id)
        if container:
            self._apply_container(report, container)
            sources.append("container-info")

        tech = self._cache.get(SourceType.TECH_STACK, cve_id)
        if tech:
            self._apply_tech_stack(report, tech)
            sources.append("tech-stack")

        # Fallback: infer technology from description / component text when
        # CPE and tech-stack tool didn't produce results.
        if not report.tech_stack.language:
            search_text = f"{report.description} {report.vulnerable_component}"
            inferred = _infer_tech_from_description(search_text)
            if inferred.get("language"):
                report.tech_stack.language = inferred["language"]
                if inferred.get("framework") and not report.tech_stack.framework:
                    report.tech_stack.framework = inferred["framework"]
                logger.info(
                    "Description-based tech inference for %s: language=%s, framework=%s",
                    cve_id,
                    report.tech_stack.language,
                    report.tech_stack.framework,
                )

        report.sources_used = sources
        report.confidence = self._compute_confidence(sources, report)

        return report

    def save(self, report: IntelReport) -> Path:
        """Save a compiled report to disk."""
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{report.cve_id}.json"
        path.write_text(report.model_dump_json(indent=2))
        logger.debug("Saved compiled report: %s", path)
        return path

    def load(self, cve_id: str) -> IntelReport | None:
        """Load a previously compiled report from disk."""
        path = self._dir / f"{cve_id}.json"
        if not path.exists():
            return None
        try:
            return IntelReport.model_validate_json(path.read_text())
        except (ValueError, OSError):
            logger.warning("Corrupt compiled report: %s", path)
            return None

    def _apply_nvd(self, report: IntelReport, data: dict[str, Any]) -> None:
        """Extract fields from NVD JSON into the report.

        Includes CPE-derived technology information when available.
        """
        report.description = data.get("description", "")
        report.cwe_ids = data.get("cwe_ids", [])
        report.severity = data.get("severity", "")
        report.cvss_score = data.get("cvss_score")
        report.affected_versions = data.get("affected_versions", [])
        report.fix_versions = data.get("fix_versions", [])
        report.references = data.get("references", [])

        # Infer tech stack from CPE entries if not already populated
        cpe_entries: list[dict[str, str]] = data.get("cpe_entries", [])
        if cpe_entries and not report.tech_stack.language:
            tech = _infer_tech_from_cpe(cpe_entries)
            if tech.get("language"):
                report.tech_stack.language = tech["language"]
            if tech.get("framework"):
                report.tech_stack.framework = tech["framework"]
            if tech.get("vendor"):
                report.tech_stack.versions[tech["vendor"] + ":" + tech["product"]] = tech.get(
                    "version", ""
                )
            logger.debug(
                "CPE tech inference for %s: language=%s, framework=%s",
                report.cve_id,
                report.tech_stack.language,
                report.tech_stack.framework,
            )

    def _apply_advisory(self, report: IntelReport, data: dict[str, Any]) -> None:
        """Merge GitHub advisory data into the report."""
        if not report.description and data.get("description"):
            report.description = data["description"]
        report.vulnerable_component = data.get("vulnerable_component", "")
        for url in data.get("references", []):
            if url not in report.references:
                report.references.append(url)

    def _apply_patch(self, report: IntelReport, data: dict[str, Any]) -> None:
        """Extract patch analysis from cached diff data."""
        raw_funcs = data.get("vulnerable_functions", [])
        vuln_funcs: list[VulnerableFunction] = []
        for item in raw_funcs:
            if isinstance(item, dict):
                vuln_funcs.append(
                    VulnerableFunction(
                        file_path=item.get("file_path", ""),
                        function_name=item.get("function_name", ""),
                        code=item.get("code", ""),
                    )
                )
            elif isinstance(item, str):
                # Backward compat: old format stored function name strings
                vuln_funcs.append(VulnerableFunction(function_name=item))
        report.patch_analysis = PatchAnalysis(
            changed_files=data.get("changed_files", []),
            fix_description=data.get("fix_description", ""),
            vulnerable_lines=data.get("vulnerable_lines", []),
            vulnerable_functions=vuln_funcs,
        )
        if data.get("vulnerable_function"):
            report.vulnerable_function = data["vulnerable_function"]
        if data.get("root_cause"):
            report.root_cause = data["root_cause"]

    def _apply_exploitdb(self, report: IntelReport, data: dict[str, Any]) -> None:
        """Extract existing PoCs from ExploitDB cache."""
        for poc in data.get("exploits", []):
            report.existing_pocs.append(
                ExistingPoC(
                    source=poc.get("source") or "exploitdb",
                    url=poc.get("url") or "",
                    description=poc.get("description") or "",
                    technique=poc.get("technique") or "",
                )
            )

    def _apply_container(self, report: IntelReport, data: dict[str, Any]) -> None:
        """Extract container analysis into attack surface."""
        report.attack_surface = AttackSurface(
            endpoints=data.get("endpoints", []),
            inputs=data.get("inputs", []),
            protocols=data.get("protocols", []),
        )

    def _apply_tech_stack(self, report: IntelReport, data: dict[str, Any]) -> None:
        """Extract technology stack information."""
        report.tech_stack = TechStack(
            language=data.get("language", ""),
            framework=data.get("framework", ""),
            web_server=data.get("web_server", ""),
            database=data.get("database", ""),
            os=data.get("os", ""),
            versions=data.get("versions", {}),
        )

    @staticmethod
    def _compute_confidence(sources: list[str], report: IntelReport) -> float:
        """Compute report confidence from source coverage and quality signals.

        Base score comes from source coverage (NVD, patch, etc.).  Quality
        signals — high CVSS, existing PoCs, identified vulnerable functions —
        provide additional confidence boost.
        """
        if not sources:
            return 0.0

        weights: dict[str, float] = {
            "nvd": 0.25,
            "github-advisory": 0.10,
            "patch-diff": 0.25,
            "exploitdb": 0.15,
            "container-info": 0.15,
            "tech-stack": 0.10,
        }

        base = sum(weights.get(s, 0.0) for s in sources)

        # Quality boosts for strong intel signals
        boost = 0.0
        if report.cvss_score is not None and report.cvss_score >= 9.0:
            boost += 0.10
        if report.existing_pocs:
            boost += min(len(report.existing_pocs) * 0.05, 0.15)
        if report.patch_analysis.vulnerable_functions:
            boost += 0.10

        return min(base + boost, 1.0)


def load_report_as_dict(compiled_dir: Path, cve_id: str) -> dict[str, Any]:
    """Load a compiled report as a plain dict for agent input."""
    path = compiled_dir / f"{cve_id}.json"
    if not path.exists():
        return {}
    try:
        result: dict[str, Any] = json.loads(path.read_text())
        return result
    except (ValueError, OSError):
        return {}

_TECHNOLOGY_MAP_PATH = Path("data/cache/technology_map.json")

# Fallback: well-known CPE vendor:product → (language, framework) pairs.
# The generate_technology_map.py script builds a comprehensive version
# from NVD+OSV data. This is the boot-strap fallback for when the
# generated file does not yet exist.
_CPE_TECH_FALLBACK: dict[str, tuple[str, str]] = {
    "apache:struts": ("java", "struts"),
    "apache:struts2": ("java", "struts2"),
    "apache:tomcat": ("java", "tomcat"),
    "apache:log4j": ("java", "log4j"),
    "apache:http_server": ("c", "apache-httpd"),
    "wordpress:wordpress": ("php", "wordpress"),
    "drupal:drupal": ("php", "drupal"),
    "joomla\\!:joomla\\!": ("php", "joomla"),
    "django_project:django": ("python", "django"),
    "palletsprojects:flask": ("python", "flask"),
    "rubyonrails:rails": ("ruby", "rails"),
    "laravel:laravel": ("php", "laravel"),
    "spring:spring_framework": ("java", "spring"),
    "vmware:spring_boot": ("java", "spring-boot"),
    "pivotal_software:spring_framework": ("java", "spring"),
    "microsoft:asp.net": ("csharp", "asp.net"),
    "expressjs:express": ("javascript", "express"),
    "nodejs:node.js": ("javascript", "node.js"),
    "oracle:weblogic_server": ("java", "weblogic"),
    "jenkins:jenkins": ("java", "jenkins"),
    "elastic:elasticsearch": ("java", "elasticsearch"),
    "grafana:grafana": ("go", "grafana"),
    "nextjs:next.js": ("javascript", "next.js"),
    "vercel:next.js": ("javascript", "next.js"),
}

# Keyword patterns for inferring technology from description/component text.
# Checked in order; first match wins.  Each entry maps a compiled regex to
# (language, framework) — framework may be "" when only language is clear.
_TECH_KEYWORD_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # PHP frameworks / ecosystem
    (re.compile(r"\blaravel\b", re.IGNORECASE), "php", "laravel"),
    (re.compile(r"\bsymfony\b", re.IGNORECASE), "php", "symfony"),
    (re.compile(r"\bdrupal\b", re.IGNORECASE), "php", "drupal"),
    (re.compile(r"\bwordpress\b", re.IGNORECASE), "php", "wordpress"),
    (re.compile(r"\bcomposer\b", re.IGNORECASE), "php", ""),
    (re.compile(r"\bpackagist\b", re.IGNORECASE), "php", ""),
    (re.compile(r"\bphp\b", re.IGNORECASE), "php", ""),
    # JavaScript / Node.js
    (re.compile(r"\bexpress(?:\.js|js)?\b", re.IGNORECASE), "javascript", "express"),
    (re.compile(r"\bnext\.js\b", re.IGNORECASE), "javascript", "next.js"),
    (re.compile(r"\bnode\.?js\b", re.IGNORECASE), "javascript", ""),
    (re.compile(r"\bnpm\b", re.IGNORECASE), "javascript", ""),
    # Python frameworks / ecosystem
    (re.compile(r"\bdjango\b", re.IGNORECASE), "python", "django"),
    (re.compile(r"\bflask\b", re.IGNORECASE), "python", "flask"),
    (re.compile(r"\bjinja2?\b", re.IGNORECASE), "python", ""),
    (re.compile(r"\bpypi\b", re.IGNORECASE), "python", ""),
    (re.compile(r"\bpip\s+install\b", re.IGNORECASE), "python", ""),
    (re.compile(r"\bpython\b", re.IGNORECASE), "python", ""),
    # Java frameworks / ecosystem
    (re.compile(r"\bspring[\s-]?boot\b", re.IGNORECASE), "java", "spring-boot"),
    (re.compile(r"\bspring\b", re.IGNORECASE), "java", "spring"),
    (re.compile(r"\bmaven\b", re.IGNORECASE), "java", ""),
    (re.compile(r"\bgradle\b", re.IGNORECASE), "java", ""),
    (re.compile(r"\btomcat\b", re.IGNORECASE), "java", "tomcat"),
    (re.compile(r"\bjava\b", re.IGNORECASE), "java", ""),
    # Ruby
    (re.compile(r"\bruby\s+on\s+rails\b", re.IGNORECASE), "ruby", "rails"),
    (re.compile(r"\brails\b", re.IGNORECASE), "ruby", "rails"),
    (re.compile(r"\bsinatra\b", re.IGNORECASE), "ruby", "sinatra"),
    (re.compile(r"\brack\b", re.IGNORECASE), "ruby", "rack"),
    (re.compile(r"\brubygems?\b", re.IGNORECASE), "ruby", ""),
    (re.compile(r"\bruby\b", re.IGNORECASE), "ruby", ""),
    # Go
    (re.compile(r"\bgolang\b", re.IGNORECASE), "go", ""),
    # .NET
    (re.compile(r"\basp\.net\b", re.IGNORECASE), "csharp", "asp.net"),
    (re.compile(r"\bnuget\b", re.IGNORECASE), "csharp", ""),
]


def _infer_tech_from_description(text: str) -> dict[str, str]:
    """Infer language and framework from free-text description or component name.

    Scans *text* against ``_TECH_KEYWORD_PATTERNS`` in order.  Returns the
    first match as ``{"language": ..., "framework": ...}``, or an empty dict
    when nothing matches.
    """
    for pattern, language, framework in _TECH_KEYWORD_PATTERNS:
        if pattern.search(text):
            result: dict[str, str] = {"language": language}
            if framework:
                result["framework"] = framework
            return result
    return {}


def _load_technology_map() -> dict[str, dict[str, str]]:
    """Load the generated technology map if available."""
    if not _TECHNOLOGY_MAP_PATH.exists():
        return {}
    try:
        data = json.loads(_TECHNOLOGY_MAP_PATH.read_text())
        entries: dict[str, dict[str, str]] = {}
        for key, val in data.items():
            if key.startswith("_"):
                continue
            if isinstance(val, dict):
                entries[key] = val
        return entries
    except (ValueError, OSError):
        logger.warning("Failed to load technology map: %s", _TECHNOLOGY_MAP_PATH)
        return {}


# Loaded once at import time; refresh via generate_technology_map.py script
_TECHNOLOGY_MAP: dict[str, dict[str, str]] = _load_technology_map()


def _infer_tech_from_cpe(cpe_entries: list[dict[str, str]]) -> dict[str, str]:
    """Infer language and framework from CPE vendor:product entries.

    Checks the generated technology map first, then falls back to the
    built-in ``_CPE_TECH_FALLBACK`` table.
    """
    for entry in cpe_entries:
        vendor = entry.get("vendor", "")
        product = entry.get("product", "")
        version = entry.get("version", "")
        key = f"{vendor}:{product}"

        # Check generated map first
        if key in _TECHNOLOGY_MAP:
            mapped = _TECHNOLOGY_MAP[key]
            return {
                "language": mapped.get("language", ""),
                "framework": mapped.get("framework", product),
                "vendor": vendor,
                "product": product,
                "version": version,
            }

        # Fallback to built-in table
        if key in _CPE_TECH_FALLBACK:
            lang, fw = _CPE_TECH_FALLBACK[key]
            return {
                "language": lang,
                "framework": fw,
                "vendor": vendor,
                "product": product,
                "version": version,
            }

    # No match — return vendor:product as hints for LLM to figure out
    if cpe_entries:
        entry = cpe_entries[0]
        return {
            "language": "",
            "framework": "",
            "vendor": entry.get("vendor", ""),
            "product": entry.get("product", ""),
            "version": entry.get("version", ""),
        }
    return {}
