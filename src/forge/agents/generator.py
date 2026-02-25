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
from dataclasses import dataclass, field
from typing import Any

from forge.agents.base import AgentConfig, AgentResult, BaseAgent
from forge.generator.exceptions import GenerationFailedError
from forge.generator.verification import (
    AppVerifier,
    VerificationResult,
    check_vulnerable_package_present,
)
from forge.generator.web_search import search_build_error
from forge.models import AppManifest, GeneratedApp, TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.tools.base import Tool, ToolCall, ToolRegistry, ToolResult, safe_json_loads
from forge.tools.generator_tools import (
    ValidateApp,
    register_generator_tools,
    register_generator_tools_no_verifier,
)

logger = logging.getLogger(__name__)

_MAX_GENERATION_ATTEMPTS = 2


@dataclass(slots=True)
class GenerationOutcome:
    """Result of a generate() call — replaces private-attr coupling."""

    app: GeneratedApp
    tokens: TokenUsage
    build_errors: list[str] = field(default_factory=list)
    attempts: int = 1


# Files whose full content is always included on retry (dependency + build files).
_KEY_FILE_BASENAMES: frozenset[str] = frozenset(
    {
        "Dockerfile",
        "requirements.txt",
        "package.json",
        "composer.json",
        "Gemfile",
        "pom.xml",
        "build.gradle",
        "go.mod",
        "Cargo.toml",
    }
)


class GeneratorAgent(BaseAgent):
    """Creates synthetic vulnerable web apps for CVE assessment.

    8 turns, 5 tools, actor-critic retry (up to 3 attempts).
    The agent builds an app using its tools, then the verifier
    checks build/deploy/health/vuln. On failure, the error is
    fed back for the next attempt.

    Can be constructed without *tools* and *verifier*: in that case
    only the 4 verifier-free tools are registered and ``_verify_app``
    auto-passes.
    """

    def __init__(
        self,
        llm: LLMClient,
        config: AgentConfig,
        tools: list[Tool] | None = None,
        verifier: AppVerifier | None = None,
        *,
        app_state: dict[str, str] | None = None,
        max_generation_attempts: int = _MAX_GENERATION_ATTEMPTS,
        cost_budget: float = 0.0,
    ) -> None:
        self._app_state = app_state if app_state is not None else {}
        self._verifier = verifier
        self._last_generate_tokens: TokenUsage | None = None
        self._last_build_errors: list[str] = []
        self._max_generation_attempts = max_generation_attempts
        self._validate_called: bool = False

        if tools is not None:
            resolved_tools = tools
        elif verifier is not None:
            resolved_tools = register_generator_tools(
                verifier,
                self._app_state,
            )
        else:
            resolved_tools = register_generator_tools_no_verifier(
                self._app_state,
            )

        registry = ToolRegistry()
        for tool in resolved_tools:
            registry.register(tool)
        super().__init__(config, llm, registry, cost_budget=cost_budget)

    def set_verifier(self, verifier: AppVerifier) -> None:
        """Replace the verifier and rebuild all tools.

        Called by the Orchestrator after creating a verification sandbox
        so the generator's actor-critic loop gets real build/deploy
        feedback from ``ValidateApp``.
        """
        self._verifier = verifier
        tools = register_generator_tools(
            verifier,
            self._app_state,
        )
        registry = ToolRegistry()
        for tool in tools:
            registry.register(tool)
        self.tools = registry

    def _get_continue_prompt(self) -> str:
        """Inject turn budget into the continuation message."""
        remaining = self.config.max_turns - self._current_turn
        if remaining <= 2:
            return (
                f"WARNING: {remaining} turn(s) remaining. "
                "You MUST call validate_app now. If validation fails, make minimal fixes only."
            )
        if not self._validate_called:
            return (
                "You have not called validate_app yet. "
                "Call write_app_files with ALL files and validate_app in your next response."
            )
        return (
            f"{remaining} turns remaining. "
            "Fix ONLY the files that caused errors. Then call validate_app again."
        )

    async def on_tool_result(self, tool_call: ToolCall, result: ToolResult, turn: int) -> None:
        """Track whether validate_app has been called."""
        if tool_call.name == "validate_app":
            self._validate_called = True
        self._current_turn = turn

    async def run(self, input_data: dict[str, Any]) -> AgentResult:
        """Reset per-run state, then delegate to the base turn loop."""
        self._validate_called = False
        self._current_turn = 0
        return await super().run(input_data)

    def _set_expected_package(self, package: str) -> None:
        """Set expected_package on the ValidateApp tool for in-loop checks."""
        if "validate_app" not in self.tools:
            return
        tool = self.tools.get("validate_app")
        if isinstance(tool, ValidateApp):
            tool.expected_package = package

    async def generate(
        self,
        intel_report: dict[str, Any],
        prior_feedback: str | None = None,
    ) -> GenerationOutcome:
        """Generate a vulnerable app with actor-critic retry.

        1. Run agent (up to 20 turns) to create app files
        2. Validate via AppVerifier (build, deploy, health, vuln)
        3. On failure: feed back failure details, retry (up to 3 attempts)
        4. Return GenerationOutcome or raise GenerationFailed
        """
        cve_id = intel_report.get("cve_id", "unknown")
        cwe_id = intel_report.get("cwe_id", "")
        language = intel_report.get("language", "")
        framework = intel_report.get("framework", "")
        last_error = ""
        accumulated_tokens = TokenUsage()
        self._last_build_errors = []

        # Propagate expected_package to ValidateApp so in-loop calls
        # enforce package fidelity (not just the post-loop _verify_app).
        expected_package = intel_report.get("vulnerable_package", "")
        self._set_expected_package(expected_package)

        for attempt in range(1, self._max_generation_attempts + 1):
            # Stop retrying when the shared budget is exhausted.
            # On the first attempt we always proceed; on subsequent attempts
            # we check whether the pipeline budget has been blown.
            if (
                attempt > 1
                and self._budget_tracker is not None
                and self._budget_tracker.is_exhausted
            ):
                logger.warning(
                    "[generator] Budget exhausted before attempt %d — stopping retries",
                    attempt,
                )
                last_error = "budget_exhausted"
                break

            logger.info(
                "[generator] Attempt %d/%d for %s",
                attempt,
                self._max_generation_attempts,
                cve_id,
            )

            # On first attempt start fresh; on retries keep previous files so
            # the LLM can make targeted fixes instead of regenerating everything.
            if attempt == 1:
                self._app_state.clear()

            input_data = self._build_input(
                intel_report,
                prior_feedback,
                last_error,
                attempt,
            )

            result: AgentResult = await self.run(input_data)
            accumulated_tokens = accumulated_tokens + result.tokens

            app = self._extract_app(result, cve_id, cwe_id, language, framework)

            if not app.project_files:
                last_error = "Agent produced no project files"
                logger.warning("[generator] Attempt %d: %s", attempt, last_error)
                prior_feedback = last_error
                continue

            verification = await self._verify_app(
                app,
                expected_package=intel_report.get("vulnerable_package", ""),
            )

            if verification.success:
                logger.info(
                    "[generator] Success on attempt %d for %s (%d files)",
                    attempt,
                    cve_id,
                    len(app.project_files),
                )
                self._last_generate_tokens = accumulated_tokens
                return GenerationOutcome(
                    app=app,
                    tokens=accumulated_tokens,
                    build_errors=list(self._last_build_errors),
                    attempts=attempt,
                )

            last_error = verification.failure_reason or "Verification failed"
            details = verification.details or ""
            self._last_build_errors.append(
                f"{last_error} | build={verification.build_ok} "
                f"deploy={verification.deploy_ok} health={verification.health_ok}"
                + (f" | {details[:300]}" if details else "")
            )
            prior_feedback = (
                f"Attempt {attempt} failed verification.\n"
                f"Reason: {last_error}\n"
                f"Details: {details}\n"
                f"Build OK: {verification.build_ok}, "
                f"Deploy OK: {verification.deploy_ok}, "
                f"Health OK: {verification.health_ok}, "
                f"Vuln present: {verification.vuln_present}"
            )

            # Targeted web search for build/dependency errors.  Fires only
            # when the Docker build itself failed (not deploy or health
            # issues) and only on the last failed attempt before retry.
            if not verification.build_ok and details:
                language = intel_report.get("language", "")
                web_hint = await search_build_error(
                    details,
                    language,
                    self.llm,
                    self.config.model,
                )
                if web_hint:
                    prior_feedback += f"\n\n{web_hint}"
            logger.warning(
                "[generator] Attempt %d/%d failed for %s: %s "
                "(build=%s, deploy=%s, health=%s, vuln=%s) details=%.200s",
                attempt,
                self._max_generation_attempts,
                cve_id,
                last_error,
                verification.build_ok,
                verification.deploy_ok,
                verification.health_ok,
                verification.vuln_present,
                details,
            )

        self._last_generate_tokens = accumulated_tokens
        raise GenerationFailedError(
            cve_id=cve_id,
            attempts=self._max_generation_attempts,
            last_error=last_error,
        )

    def format_input(self, input_data: dict[str, Any]) -> str:
        """Format the generator agent's input as a user message."""
        lines: list[str] = []

        cve_id = input_data.get("cve_id", "unknown")
        lines.append(f"Generate a vulnerable web app for: {cve_id}")

        cwe_id = input_data.get("cwe_id", "")
        if cwe_id:
            lines.append(f"CWE: {cwe_id}")

        description = input_data.get("description", "")
        if description:
            lines.append(f"\nVulnerability description:\n{description}")

        # Technology context from intel
        language = input_data.get("language", "")
        framework = input_data.get("framework", "")
        if language or framework:
            tech_line = "\nTarget technology:"
            if language:
                tech_line += f" language={language}"
            if framework:
                tech_line += f" framework={framework}"
            lines.append(tech_line)

        tech_stack = input_data.get("tech_stack", "")
        if tech_stack:
            lines.append(f"\nTechnology stack from CVE data:\n{tech_stack}")

        vulnerable_component = input_data.get("vulnerable_component", "")
        if vulnerable_component:
            lines.append(f"\nVulnerable component: {vulnerable_component}")

        # Explicit package install instruction (highest priority for the LLM)
        vuln_pkg = input_data.get("vulnerable_package", "")
        pkg_eco = input_data.get("package_ecosystem", "")
        vuln_ver = input_data.get("vulnerable_version", "")
        if vuln_pkg:
            lines.append("\n══════════════════════════════════════════")
            lines.append("REQUIRED VULNERABLE PACKAGE — YOU MUST INSTALL THIS")
            lines.append("══════════════════════════════════════════")
            pkg_line = f"Package: {vuln_pkg}"
            if pkg_eco:
                pkg_line += f" ({pkg_eco} registry)"
            lines.append(pkg_line)
            if vuln_ver:
                lines.append(f"Version to install: {vuln_ver}")
            lines.append(
                f"You MUST add {vuln_pkg} to your dependency file "
                f"and import/use it in your application code."
            )
            lines.append(
                "If this package is a library, install it as a dependency. "
                "If it is a standalone application, replicate its vulnerable "
                "pattern using the same framework and code structure shown "
                "in the patch diffs."
            )

        affected_versions = input_data.get("affected_versions", [])
        if affected_versions:
            if isinstance(affected_versions, list):
                lines.append(f"\nAffected versions: {', '.join(str(v) for v in affected_versions)}")
            else:
                lines.append(f"\nAffected versions: {affected_versions}")

        fix_versions = input_data.get("fix_versions", [])
        if fix_versions:
            if isinstance(fix_versions, list):
                lines.append(f"\nFix versions: {', '.join(str(v) for v in fix_versions)}")
            else:
                lines.append(f"\nFix versions: {fix_versions}")

        patch_analysis = input_data.get("patch_analysis", "")
        if patch_analysis:
            lines.append(f"\nPatch analysis:\n{patch_analysis}")

        # Actual patch diffs from GENIE — shows the vulnerable code and fix.
        patch_diffs: list[dict[str, str]] = input_data.get("patch_diffs", [])
        if patch_diffs:
            lines.append("\n== PATCH DIFFS (from the actual vulnerability fix) ==")
            lines.append(
                "Study these diffs carefully. The REMOVED lines (-) show the "
                "vulnerable code. Replicate this vulnerability pattern in your app."
            )
            for i, pd in enumerate(patch_diffs):
                diff_text = pd.get("diff", "")
                if diff_text:
                    # Truncate very large diffs (minified files, etc.)
                    if len(diff_text) > 8000:
                        diff_text = diff_text[:8000] + "\n... [truncated]"
                    lines.append(f"\n--- Patch {i + 1} ---")
                    lines.append(diff_text)

        vulnerable_sw_version = input_data.get("vulnerable_sw_version", "")
        if vulnerable_sw_version:
            lines.append(f"\nVulnerable software version: {vulnerable_sw_version}")

        existing_pocs = input_data.get("existing_pocs", "")
        if existing_pocs:
            lines.append(f"\nExisting PoCs:\n{existing_pocs}")

        prior_feedback = input_data.get("prior_feedback", "")
        if prior_feedback:
            lines.append(f"\nPrior attempt feedback:\n{prior_feedback}")

        # Existing files from a failed prior attempt — LLM should fix, not regenerate.
        # Smart retry: show full content for key files only, path-only for others.
        existing_files: dict[str, str] = input_data.get("existing_files", {})
        if existing_files:
            lines.append("\n== EXISTING APP (from previous attempt) ==")
            lines.append("Fix the error below. Do NOT regenerate all files.")
            lines.append("\nKey files (full content):")
            main_app_file = _find_main_app_file(existing_files)
            other_paths: list[str] = []
            for filepath, content in sorted(existing_files.items()):
                basename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
                if basename in _KEY_FILE_BASENAMES or filepath == main_app_file:
                    lines.append(f"\n--- {filepath} ---")
                    lines.append(content)
                else:
                    other_paths.append(filepath)
            if other_paths:
                lines.append(f"\nAlso present (not shown): {', '.join(other_paths)}")

        # Reference app from a prior CVE with the same technology
        reference_app: dict[str, str] = input_data.get("reference_app", {})
        if reference_app:
            lines.append(
                f"\nREFERENCE APP ({len(reference_app)} files from a prior CVE "
                "with the same technology — adapt for this CVE's vulnerability):"
            )
            for filepath, content in sorted(reference_app.items()):
                lines.append(f"\n--- {filepath} ---")
                lines.append(content)

        # Cookbook tips — distilled patterns and gotchas for this language/CWE
        cookbook_tips = input_data.get("cookbook_tips", "")
        if cookbook_tips:
            lines.append(f"\n== {cookbook_tips}")

        # Package build experience from prior runs (Experience KB)
        package_build_experience = input_data.get("package_build_experience", "")
        if package_build_experience:
            lines.append(f"\n== {package_build_experience}")

        attempt = input_data.get("attempt", 1)
        if attempt > 1:
            lines.append(f"\nThis is attempt {attempt}/{self._max_generation_attempts}.")
            lines.append(
                "Fix the specific issue from the prior attempt. "
                "Only rewrite files that need changes — do NOT regenerate working files."
            )

        lines.append(
            "\nCreate all app files using write_app_files (pass files as an array of "
            "{path, content} objects in one call). "
            "Include Dockerfile, dependency file, health endpoint, and the vulnerable endpoint. "
            "When done, output JSON with generation_complete: true."
        )
        return "\n".join(lines)

    def parse_output(self, content: str) -> dict[str, Any]:
        """Parse the generator agent's final output."""
        result: dict[str, Any] = {"app_files": dict(self._app_state)}
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                parsed: dict[str, Any] = safe_json_loads(content[start:end])
                result.update(parsed)
        except ValueError:
            result["raw_output"] = content
        return result

    def should_stop(self, content: str) -> bool:
        """Stop when the LLM signals generation is complete."""
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = safe_json_loads(content[start:end])
                if parsed.get("generation_complete"):
                    return True
        except ValueError:
            pass
        return False

    def _build_input(
        self,
        intel_report: dict[str, Any],
        prior_feedback: str | None,
        last_error: str,
        attempt: int,
    ) -> dict[str, Any]:
        """Build the input_data dict for the agent turn loop.

        Passes the full intel report data so the generator can create
        technology-appropriate apps instead of defaulting to Flask.
        """
        input_data: dict[str, Any] = {
            "cve_id": intel_report.get("cve_id", "unknown"),
            "cwe_id": intel_report.get("cwe_id", ""),
            "description": intel_report.get("description", ""),
            "framework": intel_report.get("framework", ""),
            "language": intel_report.get("language", ""),
            "tech_stack": intel_report.get("tech_stack", ""),
            "patch_analysis": intel_report.get("patch_analysis", ""),
            "existing_pocs": intel_report.get("existing_pocs", ""),
            "vulnerable_component": intel_report.get("vulnerable_component", ""),
            "vulnerable_package": intel_report.get("vulnerable_package", ""),
            "package_ecosystem": intel_report.get("package_ecosystem", ""),
            "vulnerable_version": intel_report.get("vulnerable_version", ""),
            "affected_versions": intel_report.get("affected_versions", ""),
            "fix_versions": intel_report.get("fix_versions", ""),
            "attempt": attempt,
        }

        # Pass GENIE patch diffs and version data through to format_input()
        patch_diffs = intel_report.get("patch_diffs")
        if isinstance(patch_diffs, list) and patch_diffs:
            input_data["patch_diffs"] = patch_diffs
        vulnerable_sw_version = intel_report.get("vulnerable_sw_version", "")
        if vulnerable_sw_version:
            input_data["vulnerable_sw_version"] = vulnerable_sw_version

        # Pass reference app from a prior CVE with the same technology
        reference_app = intel_report.get("reference_app")
        if isinstance(reference_app, dict) and reference_app:
            input_data["reference_app"] = reference_app

        # Pass cookbook tips (distilled patterns for this language/CWE)
        cookbook_tips = intel_report.get("cookbook_tips", "")
        if cookbook_tips:
            input_data["cookbook_tips"] = cookbook_tips

        # Pass package build experience from prior runs (Experience KB)
        package_build_experience = intel_report.get("package_build_experience", "")
        if package_build_experience:
            input_data["package_build_experience"] = package_build_experience

        feedback = prior_feedback or ""
        if last_error and attempt > 1:
            feedback = feedback if feedback else last_error
        if feedback:
            input_data["prior_feedback"] = feedback

        # On retry, include existing app files so the LLM can make targeted
        # fixes instead of regenerating from scratch.
        if attempt > 1 and self._app_state:
            input_data["existing_files"] = dict(self._app_state)

        return input_data

    def _extract_app(
        self,
        result: AgentResult,
        cve_id: str,
        cwe_id: str,
        language: str,
        framework: str,
    ) -> GeneratedApp:
        """Extract GeneratedApp from agent result and app_state.

        Language and framework come from the intel report (sourced from
        GENIE patch analysis) — not inferred from generated filenames.
        """
        files = dict(self._app_state)

        # Also check if agent output contains file data
        output_files = result.output.get("app_files", {})
        if isinstance(output_files, dict):
            for path, content in output_files.items():
                if isinstance(content, str) and path not in files:
                    files[path] = content

        vuln_endpoint = result.output.get("vulnerable_endpoint", "/")

        manifest = AppManifest(
            cve_id=cve_id,
            cwe=cwe_id,
            language=language or "unknown",
            framework=framework or "unknown",
            vulnerable_endpoint=vuln_endpoint,
        )

        return GeneratedApp(
            cve_id=cve_id,
            project_files=files,
            manifest=manifest,
        )

    async def _verify_app(
        self,
        app: GeneratedApp,
        *,
        expected_package: str = "",
    ) -> VerificationResult:
        """Run verification, catching exceptions as failures.

        When no verifier is configured (no sandbox available), auto-pass
        so the agent can still produce files.  Real validation happens
        when the Orchestrator deploys the app to its own sandbox.

        If the LLM already called ``validate_app`` during its turn loop
        and got a definitive result, reuse that instead of re-deploying
        (the sandbox pod would conflict).
        """
        if self._verifier is None:
            logger.info("[generator] No verifier configured — skipping verification")
            return VerificationResult(
                success=True,
                build_ok=True,
                deploy_ok=True,
                health_ok=True,
                vuln_present=True,
            )

        # Check if validate_app already ran during the turn loop.
        # Even when reusing cached build/deploy results, we MUST
        # re-run the static package check — the in-loop ValidateApp
        # may have had a stale expected_package.
        last_validate = self._last_validate_result()
        if last_validate is not None:
            logger.info(
                "[generator] Reusing validate_app result from turn loop (success=%s)",
                last_validate.success,
            )
            # Belt-and-suspenders: run static package check even on cached
            # results.  If the cached build/deploy failed, return that as-is.
            if not last_validate.success:
                return last_validate
            if expected_package:
                pkg_error = check_vulnerable_package_present(
                    app.project_files,
                    app.manifest.language,
                    expected_package,
                )
                if pkg_error:
                    logger.warning(
                        "[generator] Post-hoc package check failed on cached result: %s",
                        pkg_error,
                    )
                    return VerificationResult(
                        success=False,
                        failure_reason=pkg_error,
                    )
            return last_validate

        try:
            return await self._verifier.verify(app, expected_package=expected_package)
        except Exception as exc:
            logger.warning("[generator] Verification exception: %s", exc)
            return VerificationResult(
                success=False,
                failure_reason=f"Verification exception: {exc}",
            )

    def _last_validate_result(self) -> VerificationResult | None:
        """Extract the last validate_app ToolResult from the turn loop, if any."""
        # Walk tool calls/results in reverse to find the last validate_app
        for call, result in zip(
            reversed(self._tool_calls),
            reversed(self._tool_results),
            strict=False,
        ):
            if call.name == "validate_app":
                try:
                    data = safe_json_loads(result.content)
                    return VerificationResult(
                        success=data.get("success", False),
                        build_ok=data.get("build_ok", False),
                        deploy_ok=data.get("deploy_ok", False),
                        health_ok=data.get("health_ok", False),
                        vuln_present=data.get("vuln_present", False),
                        failure_reason=data.get("failure_reason"),
                        details=data.get("details"),
                    )
                except (json.JSONDecodeError, KeyError):
                    return None
        return None


def _find_main_app_file(files: dict[str, str]) -> str | None:
    """Identify the main application file (largest non-Dockerfile, non-dependency).

    Used by smart retry to decide which files get full content.
    """
    best_path: str | None = None
    best_size = 0
    for path, content in files.items():
        basename = path.rsplit("/", 1)[-1] if "/" in path else path
        if basename in _KEY_FILE_BASENAMES:
            continue
        if basename == "Dockerfile":
            continue
        if len(content) > best_size:
            best_size = len(content)
            best_path = path
    return best_path
