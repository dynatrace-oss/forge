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
from typing import Any

from forge.agents.base import AgentResult
from forge.cve.loader import classify_web_suitability
from forge.models import AppManifest, CVETask, SourceData

logger = logging.getLogger(__name__)


def task_to_intel_input(task: CVETask) -> dict[str, Any]:
    """Extract intel-relevant fields from a CVETask."""
    return {
        "cve_id": task.cve_id,
        "description": task.description,
        "cwe_ids": task.cwe_ids,
        "severity": task.severity,
        "cvss_score": task.cvss_score,
        "epss_score": task.epss_score,
        "language": task.language,
        "framework": task.framework,
        "vulnerable_package": task.vulnerable_package,
        "vulnerable_version": task.vulnerable_version,
        "advisory_urls": task.advisory_urls,
        "advisory_summary": task.advisory_summary,
        "fix_commit_url": task.fix_commit_url,
    }


def has_rich_genie_data(task: CVETask) -> bool:
    """Return True if the task carries enough GENIE data to skip the Intel Agent.

    We consider the data "rich" when it has:
    - A non-empty description, AND
    - At least one patch diff with actual diff content
    """
    if not task.source_data:
        return False
    if not task.description:
        return False
    return task.source_data.has_rich_data


def build_synthetic_intel(task: CVETask) -> dict[str, Any]:
    """Build a synthetic intel report from GENIE data carried on the task.

    Produces the same structure as a real compiled intel report so
    downstream code (generator, planner, exploit) works unchanged.
    """
    sd = task.source_data
    if sd is None:
        return {"cve_id": task.cve_id, "description": task.description}

    # Build patch analysis from actual diffs
    patch_analysis = ""
    if sd.patch_diffs:
        parts: list[str] = []
        for pd in sd.patch_diffs:
            if pd.diff:
                header = f"Commit: {pd.url}\n" if pd.url else ""
                parts.append(f"{header}{pd.diff}")
        patch_analysis = "\n\n".join(parts)

    # Build PoC hints from advisory content
    existing_pocs = ""
    if sd.security_advisories:
        poc_parts: list[str] = []
        for adv in sd.security_advisories:
            if adv.content:
                header = f"Source: {adv.url}\n" if adv.url else ""
                poc_parts.append(f"{header}{adv.content}")
        existing_pocs = "\n\n".join(poc_parts)

    return {
        "cve_id": task.cve_id,
        "description": task.description,
        "cwe_ids": task.cwe_ids,
        "patch_analysis": patch_analysis,
        "existing_pocs": existing_pocs,
        "tech_stack": {
            "language": task.language,
            "framework": task.framework or "",
        },
        "vulnerable_component": task.vulnerable_package or "",
        "vulnerable_package": task.vulnerable_package or "",
        "package_ecosystem": task.package_ecosystem or "",
        "vulnerable_version": task.vulnerable_version or "",
        "affected_versions": task.affected_versions,
        "fix_versions": task.fix_versions,
        "sources_used": ["genie_patch_diffs", "genie_advisories"],
        "confidence": 0.85,  # High confidence — direct from GENIE data
    }


def populate_task_tech_from_intel(task: CVETask, intel_output: dict[str, Any]) -> None:
    """Populate task technology and CWE fields from the compiled intel report.

    After the intel phase completes, the compiled report may contain
    tech_stack data derived from NVD CPE entries or other sources, and
    CWE IDs from NVD/advisory analysis.  We propagate these to the task
    so downstream agents (generator, exploit) have access to technology
    and CWE context.
    """
    # Propagate CWE IDs from intel to task (enables CWE-conditioned exploitation)
    cwe_ids: list[str] = intel_output.get("cwe_ids", [])
    if cwe_ids and not task.cwe_ids:
        task.cwe_ids = cwe_ids
        logger.info("[%s] CWE IDs populated from intel: %s", task.cve_id, cwe_ids)

    tech_stack = intel_output.get("tech_stack", {})
    if not tech_stack:
        return

    if tech_stack.get("language") and not task.language:
        task.language = tech_stack["language"]
    if tech_stack.get("framework") and not task.framework:
        task.framework = tech_stack["framework"]

    # Extract vendor:product as vulnerable_package if not already set
    versions = tech_stack.get("versions", {})
    if versions and not task.vulnerable_package:
        # versions dict is keyed by "vendor:product" → "version"
        first_key = next(iter(versions), "")
        if first_key:
            task.vulnerable_package = first_key

    if task.language or task.framework:
        logger.info(
            "[%s] Technology identified: language=%s, framework=%s, package=%s",
            task.cve_id,
            task.language,
            task.framework or "(unknown)",
            task.vulnerable_package or "(unknown)",
        )


def is_web_reproducible(task: CVETask) -> bool:
    """Return *True* if the CVE can be meaningfully reproduced as a web app.

    Delegates to the loader's classifier which checks CWE IDs, language,
    and description keywords.
    """
    return classify_web_suitability(
        cwe_ids=task.cwe_ids,
        language=task.language,
        description=task.description,
    )


def build_planner_input(
    intel_output: dict[str, Any],
    manifest: AppManifest | None = None,
    prior_knowledge: str = "",
    source_data: SourceData | None = None,
    *,
    package_experience: str = "",
) -> dict[str, Any]:
    """Build planner agent input from intel report, optional AppManifest, and KB context.

    When GENIE ``source_data`` is available, includes security advisory
    content (which often contains step-by-step PoC instructions) and
    patch diffs so the planner can craft CVE-specific attack plans.
    """
    result: dict[str, Any] = {"intel_report": intel_output}
    if manifest is not None:
        result["app_manifest"] = {
            "framework": manifest.framework,
            "language": manifest.language,
            "vulnerable_endpoint": manifest.vulnerable_endpoint,
            "health_endpoint": manifest.health_endpoint,
            "health_port": manifest.health_port,
            "complexity_level": manifest.complexity_level,
        }
    if prior_knowledge:
        result["prior_knowledge"] = prior_knowledge
    if package_experience:
        result["package_experience"] = package_experience

    # Inject GENIE advisory PoCs — often contains step-by-step reproduction
    if source_data is not None:
        advisories = source_data.advisories_as_dicts()
        if advisories:
            result["security_advisories"] = advisories
        diffs = source_data.patch_diffs_as_dicts()
        if diffs:
            result["patch_diffs"] = diffs

    return result


def build_exploit_input(
    intel_output: dict[str, Any],
    plan_output: dict[str, Any],
    task: CVETask,
    cwe_context: str = "",
    *,
    manifest: AppManifest | None = None,
    target_url: str | None = None,
    source_data: SourceData | None = None,
    app_source: str = "",
    package_experience: str = "",
) -> dict[str, Any]:
    """Build exploit agent input from intel, plan, task context, and deployed app info.

    The exploit input is the richest of all agents — it combines intel
    findings, the attack plan, deployed app metadata (manifest, URL),
    CWE knowledge, and GENIE advisory content.
    """
    result: dict[str, Any] = {
        "cve_id": task.cve_id,
        "cwe_ids": task.cwe_ids,
        "intel_summary": json.dumps(intel_output, indent=2),
        "attack_plan": json.dumps(plan_output, indent=2),
    }

    # Target URL: prefer deployed app, fall back to task container info
    if target_url is not None:
        result["target_url"] = target_url
    else:
        result["target_url"] = f"http://localhost:{task.container_port}"

    # Framework and language: prefer manifest, fall back to task
    if manifest is not None:
        result["framework"] = manifest.framework
        result["language"] = manifest.language
        result["vulnerable_endpoint"] = manifest.vulnerable_endpoint
    else:
        if task.language:
            result["language"] = task.language
        if task.framework:
            result["framework"] = task.framework

    # Task context
    if task.description:
        result["task_description"] = task.description
    if task.tags:
        result["tags"] = task.tags
    if task.health_path and task.health_path != "/":
        result["health_path"] = task.health_path
    if task.container_image:
        result["container_image"] = task.container_image

    # OSV enrichment context
    osv = task.osv_context()
    if osv.get("osv_enriched"):
        result["osv_context"] = osv

    # Inject CWE knowledge + procedural learnings from prior runs
    if cwe_context:
        result["prior_knowledge"] = cwe_context

    # Inject GENIE advisory PoCs for CVE-specific exploit guidance
    if source_data is not None:
        advisories = source_data.advisories_as_dicts()
        if advisories:
            result["security_advisories"] = advisories

    # Inject generated app source code for full-knowledge exploitation
    if app_source:
        result["app_source"] = app_source

    # Inject package-specific exploit experience from prior runs
    if package_experience:
        result["package_experience"] = package_experience

    return result


def extract_level(exploit_result: AgentResult) -> int:
    """Extract exploitation level — oracle ``running_max_level`` is authoritative.

    The oracle tracks the maximum exploitation level achieved across all
    tool calls.  This is strictly more reliable than the LLM's self-reported
    ``exploitation_level`` which can be inflated.
    """
    try:
        raw = exploit_result.output.get("running_max_level", 0)
        return int(raw)
    except (ValueError, TypeError, KeyError):
        logger.warning(
            "running_max_level missing or invalid in exploit output, defaulting to 0",
        )
        return 0


# Map exploit tool names to meaningful technique categories for KB recording.
# When the LLM doesn't report techniques_used, we derive categories from
# the tool call history so even L0 failures produce useful technique data.
_TOOL_TO_TECHNIQUE: dict[str, str] = {
    "http_request": "http_probing",
    "exec_command": "command_execution",
    "read_file": "file_read",
    "get_app_logs": "log_analysis",
    "run_exploit_script": "exploit_script",
}


def extract_techniques(exploit_result: AgentResult) -> list[str]:
    """Extract techniques from exploit agent result.

    Prefers the LLM-reported ``techniques_used`` list from the final JSON.
    Falls back to deriving meaningful technique categories from the tool
    call history when the LLM didn't emit a proper JSON summary (e.g.,
    turn exhaustion or L0 failure with empty techniques list).
    """
    raw: Any = exploit_result.output.get("techniques_used", [])
    if isinstance(raw, list):
        techniques = [str(t) for t in raw if t]
        if techniques:
            return techniques

    # Fallback: map tool call names to technique categories (deduplicated, ordered)
    seen: list[str] = []
    for tc in exploit_result.tool_calls:
        category = _TOOL_TO_TECHNIQUE.get(tc.name, tc.name)
        if category not in seen:
            seen.append(category)
    return seen


def extract_exploit_artifacts(exploit_result: AgentResult) -> dict[str, str]:
    """Extract exploit scripts and payloads from tool call history.

    Builds a dict of ``filename → content`` from the exploit agent's tool
    calls.  Includes HTTP payloads and command scripts so they can be saved
    as artifacts for cross-CVE learning and debugging.
    """
    files: dict[str, str] = {}
    for idx, tc in enumerate(exploit_result.tool_calls):
        if tc.name == "http_request":
            url = tc.arguments.get("url", "")
            body = tc.arguments.get("body", "")
            method = tc.arguments.get("method", "GET")
            entry = f"# {method} {url}\n"
            if body:
                entry += f"# Body:\n{body}\n"
            files[f"request_{idx:03d}.txt"] = entry
        elif tc.name == "exec_command":
            cmd = tc.arguments.get("command", "")
            if cmd:
                files[f"command_{idx:03d}.sh"] = f"#!/bin/bash\n{cmd}\n"
        elif tc.name == "run_exploit_script":
            script = tc.arguments.get("script", "")
            if script:
                files[f"exploit_{idx:03d}.py"] = script
    return files
