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
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from forge.oracle.models import InlineOracleFeedback

logger = logging.getLogger(__name__)

# Paths that indicate test/doc/build artifacts — patch diffs for these
# files are low-value noise that wastes generator context.
_DIFF_SKIP_PATTERNS: frozenset[str] = frozenset(
    {
        "test_",
        "tests/",
        "spec/",
        "__tests__/",
        "changelog",
        "CHANGELOG",
        "readme",
        "README",
        ".md",
        "docs/",
        "doc/",
        ".min.js",
        ".min.css",
        "dist/",
        "build/",
        "vendor/",
        "node_modules/",
    }
)


class CWETag(BaseModel):
    """A CWE identifier with human-readable name."""

    id: str  # "CWE-89"
    value: str  # "SQL Injection"


class PatchCommit(BaseModel):
    """A commit that patches a vulnerability."""

    url: str
    diff_content: str | None = None


class SecurityAdvisory(BaseModel):
    """A security advisory reference."""

    url: str
    content: str | None = None


class GeniePatchDiff(BaseModel):
    """A single patch diff from CVE-GENIE data."""

    url: str = ""
    diff: str = ""


class GenieAdvisory(BaseModel):
    """A security advisory entry from CVE-GENIE data."""

    url: str = ""
    content: str = ""


class SourceData(BaseModel):
    """Validated CVE-GENIE source data carried through the pipeline.

    Replaces the untyped ``dict[str, Any]`` that previously lived on
    ``CVETask.source_data``.  Provides validation on construction and
    convenience properties for downstream checks.
    """

    patch_diffs: list[GeniePatchDiff] = Field(default_factory=list)
    security_advisories: list[GenieAdvisory] = Field(default_factory=list)
    sw_version: str = ""
    sw_version_wget: str = ""

    @property
    def has_rich_data(self) -> bool:
        """True when at least one patch diff carries actual diff content."""
        return any(pd.diff for pd in self.patch_diffs)

    def log_summary(self) -> str:
        """One-line summary for structured logging."""
        diffs_with_content = sum(1 for pd in self.patch_diffs if pd.diff)
        advisories_with_content = sum(1 for a in self.security_advisories if a.content)
        return (
            f"patches={diffs_with_content}/{len(self.patch_diffs)}, "
            f"advisories={advisories_with_content}/{len(self.security_advisories)}, "
            f"sw_version={self.sw_version or 'none'}"
        )

    def patch_diffs_as_dicts(self) -> list[dict[str, str]]:
        """Serialise patch diffs to the dict format expected by agent input builders."""
        return [{"url": pd.url, "diff": pd.diff} for pd in self.patch_diffs if pd.diff]

    def advisories_as_dicts(self) -> list[dict[str, str]]:
        """Serialise advisories to the dict format expected by agent input builders."""
        return [{"url": a.url, "content": a.content} for a in self.security_advisories if a.content]


def _is_noise_diff(url: str) -> bool:
    """Return True if the diff URL points to test/doc/build artifacts."""
    url_lower = url.lower()
    return any(pat in url_lower for pat in _DIFF_SKIP_PATTERNS)


class CVESource(BaseModel):
    """Parsed CVE-GENIE entry — input to the FORGE pipeline."""

    cve_id: str
    description: str
    cwes: list[CWETag] = Field(default_factory=list)
    patch_commits: list[PatchCommit] = Field(default_factory=list)
    sw_version: str = ""
    sw_version_wget: str | None = None
    security_advisories: list[SecurityAdvisory] = Field(default_factory=list)
    successful: bool = False
    raw_data: dict[str, Any] = Field(default_factory=dict)


class AppManifest(BaseModel):
    """Metadata about a generated vulnerable web application."""

    cve_id: str
    cwe: str
    language: str
    framework: str
    vulnerable_endpoint: str
    health_endpoint: str = "/health"
    health_port: int = 8080
    verification_method: str = "http_probe"
    complexity_level: str = "L1"

    @field_validator("vulnerable_endpoint", mode="before")
    @classmethod
    def _coerce_endpoint(cls, v: object) -> str:
        """LLMs sometimes return a dict instead of a plain path string."""
        if isinstance(v, dict):
            return str(v.get("path", v.get("url", "/vulnerable")))
        return str(v)


class GeneratedApp(BaseModel):
    """Complete generated vulnerable web application."""

    cve_id: str
    project_files: dict[str, str] = Field(default_factory=dict)
    manifest: AppManifest


class ExperimentCondition(StrEnum):
    """Experiment conditions for exploit evaluation."""

    CWE_CONDITIONED = "cwe_conditioned"
    GENERIC = "generic"
    APP_GENERATION = "app_generation"


class Message(BaseModel):
    """A single message in an LLM conversation."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    tool_call_id: str | None = None
    name: str | None = None


class TokenUsage(BaseModel):
    """Token usage for a single LLM interaction or aggregated phase."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    llm_calls: int = 0
    estimated_cost_usd: float = 0.0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
            llm_calls=self.llm_calls + other.llm_calls,
            estimated_cost_usd=self.estimated_cost_usd + other.estimated_cost_usd,
        )


class CVETask(BaseModel):
    """One CVE to process. Loaded from CVE-GENIE data + NVD enrichment."""

    cve_id: str
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    cvss_score: float | None = None
    epss_score: float | None = None

    # Target application details
    language: str = ""
    framework: str | None = None
    vulnerable_package: str = ""
    vulnerable_version: str = ""
    package_ecosystem: str = ""  # e.g. "npm", "pypi", "maven", "go", "rubygems"

    # OSV/GHSA enrichment
    affected_versions: list[str] = Field(default_factory=list)
    fix_versions: list[str] = Field(default_factory=list)
    fix_commit_url: str | None = None
    advisory_urls: list[str] = Field(default_factory=list)
    advisory_summary: str = ""
    osv_id: str | None = None

    # Metadata
    tags: list[str] = Field(default_factory=list)
    difficulty: Literal["easy", "medium", "hard"] = "medium"

    # Container info (populated by Generator Agent or deploy step)
    container_image: str | None = None
    container_port: int = 80
    health_path: str = "/"

    # Resolved package info from LLM resolver (pre-built dict for result.json)
    resolved_package_info: dict[str, str] = Field(default_factory=dict)

    # Validated CVE-GENIE source data for downstream processing
    source_data: SourceData | None = None

    def osv_context(self) -> dict[str, object]:
        """Return OSV enrichment fields as a template context dict."""
        return {
            "osv_enriched": bool(self.osv_id),
            "affected_versions": self.affected_versions,
            "fix_versions": self.fix_versions,
            "fix_commit_url": self.fix_commit_url,
            "advisory_urls": self.advisory_urls,
            "advisory_summary": self.advisory_summary,
        }


class ExploitResult(BaseModel):
    """Result of the exploit generation and execution phase."""

    exploit_files: dict[str, str] = Field(default_factory=dict)
    execution_log: str = ""
    llm_conversation: list[Message] = Field(default_factory=list)
    tokens: TokenUsage = Field(default_factory=TokenUsage)
    compaction_tokens: TokenUsage = Field(default_factory=TokenUsage)
    completed: bool = False
    early_stopped: bool = False
    early_stop_reason: str = ""
    turns_used: int = 0
    max_level_reached: int = 0
    inline_oracle_history: list[InlineOracleFeedback] = Field(default_factory=list)
    error: str | None = None


class ExploitAttempt(BaseModel):
    """Complete result of one CVE attempt. One row in the results CSV."""

    # Identity
    cve_id: str
    cwe_ids: list[str] = Field(default_factory=list)
    language: str = ""
    framework: str | None = None

    # Condition
    condition: ExperimentCondition
    strategy_pack_id: str | None = None
    run_index: int = 0
    seed: int = 42
    model: str = "github_copilot/claude-sonnet-4.5"

    # Token measurement (separated by phase)
    build_prompt_tokens: int = 0
    build_completion_tokens: int = 0
    build_total_tokens: int = 0
    build_llm_calls: int = 0

    exploit_prompt_tokens: int = 0
    exploit_completion_tokens: int = 0
    exploit_total_tokens: int = 0
    exploit_llm_calls: int = 0

    total_tokens: int = 0
    estimated_cost_usd: float = 0.0

    # Build outcome
    build_success: bool = False
    build_retries: int = 0
    app_healthy: bool = False
    deploy_retries: int = 0
    error_category: str = ""

    # Exploit outcome
    exploit_files: dict[str, str] = Field(default_factory=dict)
    exploit_completed: bool = False
    early_stopped: bool = False
    turns_used: int = 0
    max_exploitation_level: int = 0

    # Oracle verdict
    binary_success: bool = False
    exploitation_level: int = Field(default=0, ge=0, le=3)
    oracle_evidence: list[str] = Field(default_factory=list)
    oracle_confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    # Scoring & prioritization
    cvss_score: float | None = None
    epss_score: float | None = None

    # OSV enrichment
    osv_enriched: bool = False

    # Detection
    detection_rules_generated: int = 0

    # Metadata
    wall_clock_seconds: float = 0.0
    otel_trace_id: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    error_message: str | None = None
    artifact_dir: str | None = None


class OracleCriterion(BaseModel):
    """Criteria for classifying exploitation at a specific level."""

    level: int = Field(ge=0, le=3)
    name: str
    description: str
    indicators: list[str] = Field(default_factory=list)
    automated: bool = True


class TechniqueMapping(BaseModel):
    """CAPEC attack pattern + optional ATT&CK technique mapping for a CWE."""

    capec_id: str  # "CAPEC-66"
    capec_name: str  # "SQL Injection"
    attack_id: str = ""  # "T1190" (empty if no ATT&CK mapping)
    attack_name: str = ""  # "Exploit Public-Facing Application"


class CWEModule(BaseModel):
    """CWE-specific vulnerability context for oracle, exploit, and detector agents.

    Carries only the data that is actually consumed at runtime:
    CWE identity, CAPEC/ATT&CK escalation paths, and oracle criteria
    from the hand-curated oracle_patterns.yaml.
    """

    cwe_id: str
    cwe_name: str

    oracle_criteria: list[OracleCriterion] = Field(default_factory=list)
    escalation_paths: list[str] = Field(default_factory=list)
