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
import os
import re
from pathlib import Path
from typing import Any

import httpx
import jinja2
import yaml

from forge.config import ResolverConfig
from forge.models import CVETask, Message, TokenUsage
from forge.pipeline.llm_client import LLMClient

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path("data/prompts/resolver/package_resolution.yaml")
_REGISTRIES_PATH = Path("data/config/registries.yaml")
_SEARXNG_BASE_URL = os.environ.get("SEARXNG_URL", "http://localhost:8888")
_SEARCH_TIMEOUT = 10.0


class ResolvedPackage:
    """Result of LLM-based package resolution."""

    __slots__ = (
        "package_name",
        "ecosystem",
        "language",
        "vulnerable_version",
        "confidence",
        "reasoning",
    )

    def __init__(
        self,
        *,
        package_name: str,
        ecosystem: str,
        language: str = "",
        vulnerable_version: str = "",
        confidence: str = "medium",
        reasoning: str = "",
    ) -> None:
        self.package_name = package_name
        self.ecosystem = ecosystem
        self.language = language
        self.vulnerable_version = vulnerable_version
        self.confidence = confidence
        self.reasoning = reasoning

    def __repr__(self) -> str:
        ver = f"@{self.vulnerable_version}" if self.vulnerable_version else ""
        return f"ResolvedPackage({self.package_name}{ver}, {self.ecosystem}, {self.confidence})"


def _load_prompt_templates() -> dict[str, str]:
    """Load system and user templates from the resolver prompt YAML."""
    if not _PROMPT_PATH.exists():
        raise FileNotFoundError(f"Resolver prompt not found: {_PROMPT_PATH}")
    with _PROMPT_PATH.open() as f:
        data = yaml.safe_load(f)
    return {"system": str(data["system"]), "user": str(data["user"])}


def _render_template(template_str: str, **context: Any) -> str:
    """Render a Jinja2 template string with the given context."""
    env = jinja2.Environment(undefined=jinja2.Undefined)
    template = env.from_string(template_str)
    return template.render(**context).strip()


_registry_config: dict[str, Any] | None = None


def _extract_patch_filenames(task: CVETask) -> list[str]:
    """Extract unique filenames from patch diff content.

    Parses ``--- a/path`` and ``+++ b/path`` lines from unified diffs
    attached to the task's source data.  Returns deduplicated filenames
    (without the ``a/`` or ``b/`` prefix) sorted alphabetically.
    """
    if not task.source_data or not task.source_data.patch_diffs:
        return []
    seen: set[str] = set()
    for pd in task.source_data.patch_diffs:
        if not pd.diff:
            continue
        for line in pd.diff.splitlines():
            if line.startswith(("--- a/", "+++ b/")):
                fname = line.split("/", 1)[1] if "/" in line else ""
                if fname and fname != "/dev/null":
                    seen.add(fname)
    return sorted(seen)


def _load_registry_config() -> dict[str, Any]:
    """Load registry configuration from YAML (cached after first load)."""
    global _registry_config  # noqa: PLW0603
    if _registry_config is not None:
        return _registry_config
    if not _REGISTRIES_PATH.exists():
        logger.warning("[resolver] Registry config not found: %s", _REGISTRIES_PATH)
        _registry_config = {}
        return _registry_config
    with _REGISTRIES_PATH.open() as f:
        _registry_config = yaml.safe_load(f) or {}
    return _registry_config


def _build_registry_url(url_template: str, package_name: str, ecosystem: str) -> str:
    """Build the registry URL from the template and package name."""
    replacements: dict[str, str] = {
        "package": package_name,
        "package_lower": package_name.lower(),
    }

    # Maven uses groupId:artifactId with group dots → slashes
    if ecosystem == "maven" and ":" in package_name:
        group, artifact = package_name.split(":", 1)
        replacements["group_path"] = group.replace(".", "/")
        replacements["artifact"] = artifact
    elif ecosystem == "maven":
        # No colon — treat whole name as artifact, empty group
        replacements["group_path"] = ""
        replacements["artifact"] = package_name

    # Apply replacements
    result = url_template
    for key, value in replacements.items():
        result = result.replace("{" + key + "}", value)
    return result


async def _validate_package_exists(
    package_name: str,
    ecosystem: str,
) -> tuple[bool, str]:
    """Check whether a package exists on its registry.

    Returns:
        Tuple of (exists: bool, detail: str).
        On success detail is empty; on failure it describes the error.
    """
    config = _load_registry_config()
    registries: dict[str, Any] = config.get("registries", {})
    timeout = float(config.get("timeout", 5.0))

    registry = registries.get(ecosystem)
    if registry is None:
        # No registry configured for this ecosystem — skip validation
        return True, ""

    url_template: str = registry.get("url", "")
    method: str = registry.get("method", "GET").upper()

    if not url_template:
        return True, ""

    url = _build_registry_url(url_template, package_name, ecosystem)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            if method == "HEAD":
                resp = await client.head(url)
            else:
                resp = await client.get(url)

            if resp.status_code < 400:
                logger.info(
                    "[resolver] Registry check OK: %s (%s) → %d",
                    package_name,
                    ecosystem,
                    resp.status_code,
                )
                return True, ""

            detail = (
                f"Package '{package_name}' NOT FOUND on {ecosystem} registry "
                f"(HTTP {resp.status_code} from {url}). "
                f"The package name is likely wrong — please provide the "
                f"correct installable name."
            )
            logger.warning("[resolver] Registry check FAILED: %s", detail)
            return False, detail

    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        # Network errors — don't block resolution, just warn
        logger.warning(
            "[resolver] Registry check error for %s (%s): %s",
            package_name,
            ecosystem,
            exc,
        )
        return True, ""  # Assume valid on network errors


async def _web_search(query: str) -> str:
    """Search via local SearXNG instance.  Returns formatted results or error."""
    try:
        async with httpx.AsyncClient(timeout=_SEARCH_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(
                f"{_SEARXNG_BASE_URL}/search",
                params={"q": query, "format": "json"},
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        logger.warning("[resolver] Web search failed: %s", exc)
        return f"Search failed: {exc}"

    try:
        data = resp.json()
    except ValueError:
        return "Search returned invalid response"

    results: list[str] = []
    for item in data.get("results", [])[:5]:
        title = item.get("title", "")
        snippet = item.get("content", "")[:300]
        if snippet:
            results.append(f"- {title}: {snippet}")

    return "\n".join(results) if results else "No results found"


def _parse_llm_response(text: str) -> dict[str, str] | None:
    """Extract JSON from LLM response, handling markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        # Drop first and last fence lines
        json_lines = [ln for ln in lines[1:] if not ln.startswith("```")]
        cleaned = "\n".join(json_lines).strip()

    try:
        result: dict[str, Any] = json.loads(cleaned)
        if "package_name" in result and "ecosystem" in result:
            return {k: str(v) for k, v in result.items()}
    except (json.JSONDecodeError, TypeError):
        logger.warning("[resolver] Failed to parse LLM response as JSON: %s", text[:200])
    return None


def _derive_repo_url(task: CVETask) -> str:
    """Best-effort extraction of the source repository URL from task metadata."""
    _suffixes = ("/commit/", "/pull/", "/issues/", "/releases/", "/security/")
    # Try fix_commit_url first (most reliable)
    url = task.fix_commit_url or ""
    for suffix in _suffixes:
        idx = url.find(suffix)
        if idx > 0:
            return url[:idx]
    # Fallback: try patch diff URLs from source_data
    if task.source_data:
        for pd in task.source_data.patch_diffs:
            for suffix in _suffixes:
                idx = pd.url.find(suffix)
                if idx > 0:
                    return pd.url[:idx]
    return ""


def _extract_search_query(text: str) -> str:
    """Best-effort extraction of a search query from LLM text mentioning web_search."""
    patterns = [
        r'web_search\s*\(\s*["\'](.+?)["\']\s*\)',
        r'"query"\s*:\s*"(.+?)"',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


async def resolve_package(
    task: CVETask,
    llm: LLMClient,
    config: ResolverConfig,
    *,
    hint_package: str = "",
    hint_ecosystem: str = "",
) -> tuple[ResolvedPackage | None, TokenUsage]:
    """Resolve the correct installable package for a CVE using an LLM.

    After the LLM returns a candidate, validates that the package exists
    on its registry (using ``data/config/registries.yaml``).  If validation
    fails, feeds the error back to the LLM for correction on the next turn.

    Args:
        task: The CVE task with description, advisories, etc.
        llm: LLMClient instance for making LLM calls.
        config: Resolver configuration (model, max_turns).
        hint_package: Optional heuristic guess (used as a hint, not trusted).
        hint_ecosystem: Optional heuristic ecosystem guess.

    Returns:
        Tuple of (ResolvedPackage or None, cumulative TokenUsage).
    """
    templates = _load_prompt_templates()
    total_tokens = TokenUsage()

    # Build template context from task
    patch_filenames = _extract_patch_filenames(task)
    context: dict[str, Any] = {
        "cve_id": task.cve_id,
        "description": task.description[:2000],
        "cwe_ids": ", ".join(task.cwe_ids) if task.cwe_ids else "unknown",
        "repo_url": _derive_repo_url(task),
        "advisory_urls": ", ".join(task.advisory_urls) if task.advisory_urls else "",
        "patch_urls": task.fix_commit_url or "",
        "cpe_product": "",
        "hint_package": hint_package,
        "hint_ecosystem": hint_ecosystem,
        "language": task.language,
        "patch_filenames": ", ".join(patch_filenames) if patch_filenames else "",
    }

    system_prompt = _render_template(templates["system"])
    user_prompt = _render_template(templates["user"], **context)

    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=user_prompt),
    ]

    for turn in range(config.max_turns):
        try:
            response_text, tokens = await llm.chat(
                messages,
                model=config.model,
                phase="resolver",
                max_tokens=1024,
            )
            total_tokens = total_tokens + tokens
        except Exception:
            logger.exception("[resolver] LLM call failed on turn %d", turn + 1)
            return None, total_tokens

        # Check if the response is a direct JSON answer
        parsed = _parse_llm_response(response_text)
        if parsed:
            pkg = ResolvedPackage(
                package_name=parsed.get("package_name", ""),
                ecosystem=parsed.get("ecosystem", ""),
                language=parsed.get("language", ""),
                vulnerable_version=parsed.get("vulnerable_version", ""),
                confidence=parsed.get("confidence", "medium"),
                reasoning=parsed.get("reasoning", ""),
            )
            if not (pkg.package_name and pkg.ecosystem):
                logger.warning("[resolver] LLM returned incomplete package info: %s", parsed)
                return None, total_tokens

            # Validate package exists on registry
            exists, error_detail = await _validate_package_exists(pkg.package_name, pkg.ecosystem)
            if exists:
                logger.info(
                    "[resolver] %s → %s (%s) confidence=%s: %s",
                    task.cve_id,
                    pkg.package_name,
                    pkg.ecosystem,
                    pkg.confidence,
                    pkg.reasoning,
                )
                return pkg, total_tokens

            # Package not found on registry — ask LLM to correct
            if turn < config.max_turns - 1:
                logger.warning(
                    "[resolver] %s: package '%s' not found on %s, asking LLM to correct",
                    task.cve_id,
                    pkg.package_name,
                    pkg.ecosystem,
                )
                messages.append(Message(role="assistant", content=response_text))
                messages.append(
                    Message(
                        role="user",
                        content=(
                            f"REGISTRY VALIDATION FAILED: {error_detail}\n\n"
                            f"The package name you provided does NOT exist on the "
                            f"{pkg.ecosystem} registry. Common mistakes:\n"
                            f"- npm: GitHub org name ≠ npm scope "
                            f"(e.g., 'lunary-ai/lunary' on GitHub → 'lunary' on npm)\n"
                            f"- Maven: standalone apps are NOT published as libraries\n"
                            f"- The project may not publish to any package registry\n\n"
                            f"Please provide the CORRECT installable package name, "
                            f"or set confidence to 'low' if no installable package exists. "
                            f"Respond with ONLY a JSON object."
                        ),
                    ),
                )
                continue

            # Last turn and still invalid — return with low confidence
            logger.warning(
                "[resolver] %s: package '%s' failed registry validation on final turn",
                task.cve_id,
                pkg.package_name,
            )
            pkg.confidence = "low"
            pkg.reasoning = f"UNVERIFIED — {error_detail}"
            return pkg, total_tokens

        # Check if the LLM wants to call web_search (text-based tool call detection)
        if "web_search" in response_text.lower() and turn < config.max_turns - 1:
            query = _extract_search_query(response_text)
            if query:
                logger.info("[resolver] LLM requested web search: %s", query)
                search_result = await _web_search(query)
                messages.append(Message(role="assistant", content=response_text))
                messages.append(
                    Message(
                        role="user",
                        content=f"Web search results for '{query}':\n{search_result}\n\n"
                        "Now provide your final answer as JSON.",
                    )
                )
                continue

        # Response wasn't parseable JSON and no tool call — try once more with nudge
        if turn < config.max_turns - 1:
            messages.append(Message(role="assistant", content=response_text))
            messages.append(
                Message(
                    role="user",
                    content="Respond with ONLY a JSON object. No explanation, no markdown.",
                )
            )
            continue

        logger.warning("[resolver] Failed to get structured response after %d turns", turn + 1)

    return None, total_tokens
