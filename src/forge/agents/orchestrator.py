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

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from forge.agents.base import AgentResult, BaseAgent
from forge.agents.exploit import ExploitAgent
from forge.agents.generator import GenerationOutcome, GeneratorAgent
from forge.agents.intel import IntelAgent
from forge.agents.orch_helper import (
    build_exploit_input,
    build_planner_input,
    build_synthetic_intel,
    extract_exploit_artifacts,
    extract_level,
    extract_techniques,
    has_rich_genie_data,
    is_web_reproducible,
    populate_task_tech_from_intel,
    task_to_intel_input,
)
from forge.agents.orch_recording import (
    build_cwe_module,
    classify_generation_error,
    classify_pipeline_error,
    expand_detection_kb,
    format_knowledge_context,
    record_detection_learning,
    record_detection_rules,
    record_exploit_outcome,
    record_generation_learning,
)
from forge.cookbook import CookbookStore
from forge.detection.kb_updater import DetectionKBUpdater
from forge.experience import PackageExperienceStore
from forge.generator.exceptions import GenerationFailedError
from forge.generator.verification import AppVerifier
from forge.intel.hooks import IntelHooks
from forge.learnings import LearningStore
from forge.models import AppManifest, CVETask, GeneratedApp, TokenUsage
from forge.pipeline.artifact_store import ArtifactStore
from forge.pipeline.budget import BudgetTracker
from forge.sandbox.protocols import SandboxManager, SandboxSession
from forge.signals.collector import SpanCollector
from forge.signals.query import SpanQuery
from forge.storage import StorageManager

logger = logging.getLogger(__name__)

DetectorFactory = Callable[[SpanQuery], BaseAgent]


class PipelineStatus(StrEnum):
    """Outcome status for the FORGE pipeline."""

    COMPLETED = "completed"
    GENERATION_FAILED = "generation_failed"
    GENERATION_SKIPPED = "generation_skipped"
    DEPLOY_FAILED = "deploy_failed"
    COST_CAP_REACHED = "cost_cap_reached"
    ERROR = "error"


class AgentRole(StrEnum):
    """Roles in the FORGE pipeline."""

    INTEL = "intel"
    GENERATOR = "generator"
    PLANNER = "planner"
    EXPLOIT = "exploit"
    DETECTOR = "detector"


class PipelineResult(BaseModel):
    """Result of the full 5-agent pipeline for a single CVE."""

    cve_id: str
    status: PipelineStatus = PipelineStatus.COMPLETED
    intel_report: dict[str, Any] = Field(default_factory=dict)
    generated_app: dict[str, Any] = Field(default_factory=dict)
    manifest: dict[str, Any] = Field(default_factory=dict)
    attack_plan: dict[str, Any] = Field(default_factory=dict)
    exploitation_level: int = 0
    tool_calls_total: int = 0
    techniques_used: list[str] = Field(default_factory=list)
    detection_rules: list[str] = Field(default_factory=list)
    tokens: TokenUsage = Field(default_factory=TokenUsage)
    wall_clock_seconds: float = 0.0
    generation_attempts: int = 0
    oracle_confidence: float = 0.0
    app_healthy: bool = False
    resolved_package: dict[str, str] = Field(default_factory=dict)
    agent_results: dict[str, AgentResult] = Field(default_factory=dict)
    error_message: str | None = None
    error_category: str = ""
    spans: list[dict[str, Any]] = Field(default_factory=list)
    otel_trace_id: str = ""


@dataclass(slots=True)
class PipelineContext:
    """Mutable accumulator for pipeline state across phases.

    Created in ``Orchestrator.run()`` *before* the try/except so that
    error and budget handlers can access whatever state was accumulated
    before the failure.  Each pipeline phase updates the relevant fields.

    When a ``BudgetTracker`` is provided, ``tokens`` is a read-through
    property backed by the tracker.  ``add_tokens()`` delegates to the
    tracker.  This prevents double-counting since agents already record
    their LLM calls to the tracker in real time.
    """

    collector: SpanCollector
    budget: BudgetTracker | None = None
    start_time: float = field(default_factory=time.monotonic)
    _tokens: TokenUsage = field(default_factory=TokenUsage)
    agent_results: dict[str, AgentResult] = field(default_factory=dict)
    session: SandboxSession | None = None
    intel_report: dict[str, Any] = field(default_factory=dict)
    attack_plan: dict[str, Any] = field(default_factory=dict)
    generation_attempts: int = 0
    app_healthy: bool = False
    tool_calls_total: int = 0
    exploitation_level: int = 0
    oracle_confidence: float = 0.0
    techniques_used: list[str] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)

    @property
    def tokens(self) -> TokenUsage:
        """Return accumulated token usage from the tracker or local state."""
        if self.budget is not None:
            return self.budget.total_tokens
        return self._tokens

    def add_tokens(self, usage: TokenUsage) -> None:
        """Accumulate token usage.

        When a BudgetTracker is active, this is a no-op: agents record
        their tokens to the tracker in real-time during their turn loops.
        When no tracker is set, accumulates to the local ``_tokens`` field
        for backward compatibility with tests.
        """
        if self.budget is not None:
            return
        self._tokens = self._tokens + usage

    @property
    def elapsed_seconds(self) -> float:
        """Wall-clock seconds since pipeline started."""
        return time.monotonic() - self.start_time


@dataclass(frozen=True, slots=True)
class OrchestratorStores:
    """Bundle of optional stores/hooks for the Orchestrator.

    All fields default to None so callers only pass what they have.
    """

    hooks: IntelHooks | None = field(default=None)
    learnings: LearningStore | None = field(default=None)
    storage: StorageManager | None = field(default=None)
    detection_kb_updater: DetectionKBUpdater | None = field(default=None)
    artifact_store: ArtifactStore | None = field(default=None)
    cookbook: CookbookStore | None = field(default=None)
    experience: PackageExperienceStore | None = field(default=None)


class Orchestrator:
    """Sequential pipeline: Intel -> Generator -> Planner -> Exploit -> Detector.

    The Generator Agent creates a synthetic vulnerable app, which is then
    deployed via the sandbox. The Planner receives the AppManifest so it
    can craft targeted attack plans. The Exploit Agent receives the
    target URL from the deployed app. The Detector only runs if
    exploitation reaches L1+.

    The orchestrator creates a SpanCollector per CVE run and wires it
    into the ExploitAgent. After exploitation, if L1+, it creates the
    DetectorAgent via ``detector_factory`` with the populated SpanQuery.
    """

    def __init__(
        self,
        intel: BaseAgent,
        planner: BaseAgent,
        exploit: BaseAgent,
        *,
        generator: GeneratorAgent | None = None,
        detector: BaseAgent | None = None,
        detector_factory: DetectorFactory | None = None,
        sandbox_manager: SandboxManager | None = None,
        stores: OrchestratorStores | None = None,
        cost_budget: float = 0.0,
    ) -> None:
        self.intel = intel
        self.planner = planner
        self.exploit = exploit
        self.detector = detector
        self.detector_factory = detector_factory
        self._generator = generator
        self._sandbox_manager = sandbox_manager
        self._cost_budget = cost_budget
        # Unpack stores for internal use — no downstream code changes needed.
        s = stores or OrchestratorStores()
        self._hooks = s.hooks
        self._learnings = s.learnings
        self._storage = s.storage
        self._detection_kb_updater = s.detection_kb_updater
        self._artifact_store = s.artifact_store
        self._cookbook = s.cookbook
        self._experience = s.experience

    def _is_over_budget(self, ctx: PipelineContext, cve_id: str) -> bool:
        """Return True if accumulated cost exceeds the per-CVE budget."""
        if ctx.budget is not None:
            if ctx.budget.is_exhausted:
                logger.warning(
                    "[%s] Pipeline cost cap reached: $%.2f >= $%.2f budget",
                    cve_id,
                    ctx.budget.accumulated_cost,
                    ctx.budget.total_budget,
                )
                return True
            return False
        if self._cost_budget <= 0:
            return False
        cost = ctx.tokens.estimated_cost_usd
        if cost >= self._cost_budget:
            logger.warning(
                "[%s] Pipeline cost cap reached: $%.2f >= $%.2f budget",
                cve_id,
                cost,
                self._cost_budget,
            )
            return True
        return False

    @staticmethod
    def create_intel_stack(
        storage: StorageManager,
        *,
        cache_ttl_seconds: int | None = None,
    ) -> tuple[IntelHooks, LearningStore]:
        """Create the full intel hooks and learning store from a StorageManager.

        Args:
            storage: Storage manager for directory paths.
            cache_ttl_seconds: Override default cache TTL (from forge.yaml).

        Returns (hooks, learnings) ready to pass into OrchestratorStores.
        """
        hooks = IntelHooks.from_paths(
            cache_dir=storage.cache_dir(),
            compiled_dir=storage.cache_dir() / "compiled",
            knowledge_dir=storage.knowledge_dir("exploitation"),
            cache_ttl_seconds=cache_ttl_seconds,
        )
        learnings = LearningStore(store_dir=storage.knowledge_dir("learnings"))
        return hooks, learnings

    async def run(self, task: CVETask) -> PipelineResult:
        """Run the full 5-agent pipeline for a single CVE."""
        # Clean up stale containers from previous runs to prevent
        # accumulation during batch execution (critical for 600-CVE runs).
        if self._sandbox_manager is not None:
            try:
                await self._sandbox_manager.cleanup_stale_containers()
            except Exception:
                logger.warning("[%s] Stale container cleanup failed", task.cve_id, exc_info=True)

        # PipelineContext accumulates state across phases so that
        # error/budget handlers can build rich PipelineResults.
        budget = BudgetTracker(self._cost_budget) if self._cost_budget > 0 else None
        ctx = PipelineContext(collector=SpanCollector(task.cve_id), budget=budget)
        if isinstance(self.exploit, ExploitAgent):
            self.exploit.set_span_collector(ctx.collector)

        # Wire the shared budget tracker to all agents so cost is tracked
        # in real time from a single source of truth.
        if budget is not None:
            for agent in (self.intel, self.planner, self.exploit):
                agent.set_budget_tracker(budget)
            if self._generator is not None:
                self._generator.set_budget_tracker(budget)

        try:
            return await self._run_pipeline(task, ctx)
        except GenerationFailedError as exc:
            # Distill build errors even on failure — those are the most valuable.
            fail_build_errors = (
                getattr(self._generator, "_last_build_errors", [])
                if self._generator is not None
                else []
            )
            await self._distill_cookbook(task, fail_build_errors)
            return self._handle_generation_failure(task, exc, ctx)
        except Exception as exc:
            logger.exception("[%s] Pipeline error: %s", task.cve_id, exc)
            return self._handle_pipeline_error(task, exc, ctx)
        finally:
            if ctx.session is not None:
                await self._cleanup_sandbox(ctx.session, task.cve_id)

    def _handle_generation_failure(
        self,
        task: CVETask,
        exc: GenerationFailedError,
        ctx: PipelineContext,
    ) -> PipelineResult:
        """Build PipelineResult for a GenerationFailedError."""
        logger.warning("[%s] Generation failed: %s", task.cve_id, exc)
        # When no BudgetTracker is wired, recover generator tokens
        # consumed during failed attempts so they appear in the result.
        if ctx.budget is None and self._generator is not None:
            gen_tokens = getattr(self._generator, "_last_generate_tokens", None)
            if gen_tokens is not None and gen_tokens.total_tokens > 0:
                ctx.add_tokens(gen_tokens)
                logger.info(
                    "[%s] Recovered %d tokens from failed generator",
                    task.cve_id,
                    gen_tokens.total_tokens,
                )
        # Record failure to learnings
        record_generation_learning(
            task,
            self._learnings,
            success=False,
            attempts=exc.attempts,
            reason=str(exc),
            build_errors=(
                getattr(self._generator, "_last_build_errors", None)
                if self._generator is not None
                else None
            ),
        )
        # Record build failure to package experience
        if self._experience is not None and task.vulnerable_package and task.package_ecosystem:
            build_errors = (
                getattr(self._generator, "_last_build_errors", [])
                if self._generator is not None
                else []
            )
            self._experience.record_build(
                task.vulnerable_package,
                task.package_ecosystem,
                task.cve_id,
                success=False,
                attempts=exc.attempts,
                build_errors=build_errors,
            )
        return PipelineResult(
            cve_id=task.cve_id,
            status=PipelineStatus.GENERATION_FAILED,
            intel_report=ctx.agent_results.get(AgentRole.INTEL, AgentResult()).output,
            tokens=ctx.tokens,
            wall_clock_seconds=ctx.elapsed_seconds,
            generation_attempts=exc.attempts,
            resolved_package=task.resolved_package_info,
            agent_results=ctx.agent_results,
            error_message=str(exc),
            error_category=classify_generation_error(str(exc)).value,
            otel_trace_id=ctx.collector.trace_id,
        )

    def _handle_pipeline_error(
        self,
        task: CVETask,
        exc: Exception,
        ctx: PipelineContext,
    ) -> PipelineResult:
        """Build PipelineResult for an unexpected pipeline error.

        Reads accumulated state from ``ctx`` so that metadata from
        completed phases (generation_attempts, app_healthy, intel_report,
        etc.) is preserved instead of defaulting to zero/empty.
        """
        # Preserve running-max exploitation level if exploit agent made progress
        crash_level = ctx.exploitation_level
        crash_confidence = ctx.oracle_confidence
        if isinstance(self.exploit, ExploitAgent) and self.exploit.running_max > 0:
            crash_level = self.exploit.running_max
            crash_confidence = self.exploit.oracle_confidence
            logger.info(
                "[%s] Preserving running_max=%d (conf=%.2f) from crashed exploit agent",
                task.cve_id,
                crash_level,
                crash_confidence,
            )

        # Record partial exploit outcome to KB so knowledge isn't lost
        if crash_level > 0:
            record_exploit_outcome(
                task,
                crash_level,
                ctx.techniques_used,
                self._hooks,
                self._learnings,
                self.exploit,
            )

        # Capture partial tokens from agents that started but never finished.
        # When a BudgetTracker is active, agents already recorded their
        # tokens in real-time — skip to avoid double-counting.
        if ctx.budget is None:
            _role_agent: list[tuple[str, BaseAgent | GeneratorAgent | None]] = [
                (AgentRole.INTEL, self.intel),
                (AgentRole.PLANNER, self.planner),
                (AgentRole.EXPLOIT, self.exploit),
                (AgentRole.GENERATOR, self._generator),
            ]
            for role, agent in _role_agent:
                if (
                    role not in ctx.agent_results
                    and agent is not None
                    and hasattr(agent, "_partial_tokens")
                ):
                    partial: TokenUsage = agent._partial_tokens
                    if partial.total_tokens > 0:
                        ctx.add_tokens(partial)

        # Recover tool_calls_total from exploit agent if available
        tool_calls = ctx.tool_calls_total
        if tool_calls == 0 and AgentRole.EXPLOIT in ctx.agent_results:
            tool_calls = len(ctx.agent_results[AgentRole.EXPLOIT].tool_calls)

        return PipelineResult(
            cve_id=task.cve_id,
            status=PipelineStatus.ERROR,
            intel_report=ctx.intel_report,
            attack_plan=ctx.attack_plan,
            exploitation_level=crash_level,
            oracle_confidence=crash_confidence,
            techniques_used=ctx.techniques_used,
            tokens=ctx.tokens,
            wall_clock_seconds=ctx.elapsed_seconds,
            generation_attempts=ctx.generation_attempts,
            app_healthy=ctx.app_healthy,
            tool_calls_total=tool_calls,
            resolved_package=task.resolved_package_info,
            agent_results=ctx.agent_results,
            error_message=str(exc),
            error_category=classify_pipeline_error(str(exc)).value,
            spans=[s.model_dump() for s in ctx.collector.spans],
            otel_trace_id=ctx.collector.trace_id,
        )

    async def _run_pipeline(
        self,
        task: CVETask,
        ctx: PipelineContext,
    ) -> PipelineResult:
        """Core pipeline logic — separated for clean error handling."""
        collector = ctx.collector

        # Early non-web check
        if task.language and task.cwe_ids and not is_web_reproducible(task):
            logger.info("[%s] Non-web CVE skipped early", task.cve_id)
            return PipelineResult(
                cve_id=task.cve_id,
                status=PipelineStatus.GENERATION_SKIPPED,
                tokens=ctx.tokens,
                wall_clock_seconds=ctx.elapsed_seconds,
                resolved_package=task.resolved_package_info,
                agent_results=ctx.agent_results,
                error_message="non_web_vulnerability",
                otel_trace_id=ctx.collector.trace_id,
            )

        # Build CWEModule and inject into exploit agent
        if isinstance(self.exploit, ExploitAgent) and task.cwe_ids:
            cwe_module = build_cwe_module(task.cwe_ids[0])
            self.exploit.set_cwe_module(cwe_module)
            logger.info("[%s] CWEModule injected: %s", task.cve_id, cwe_module.cwe_id)

        # 1. Intel phase
        intel_output = await self._run_intel(task, ctx)
        ctx.intel_report = intel_output

        # Non-web check (post-Intel)
        if not is_web_reproducible(task):
            logger.info("[%s] Non-web CVE skipped (post-Intel)", task.cve_id)
            return PipelineResult(
                cve_id=task.cve_id,
                status=PipelineStatus.GENERATION_SKIPPED,
                intel_report=intel_output,
                tokens=ctx.tokens,
                wall_clock_seconds=ctx.elapsed_seconds,
                resolved_package=task.resolved_package_info,
                agent_results=ctx.agent_results,
                error_message="non_web_vulnerability",
                otel_trace_id=ctx.collector.trace_id,
            )

        if self._is_over_budget(ctx, task.cve_id):
            return self._budget_result(task, ctx, "intel")

        # 2. Generator + Deploy
        generated_app, manifest, target_url = await self._run_generation_and_deploy(
            task,
            intel_output,
            ctx,
        )

        if self._is_over_budget(ctx, task.cve_id):
            return self._budget_result(task, ctx, "generation")

        # 3. Planner
        cwe_context = format_knowledge_context(task, self._hooks, self._learnings)

        # Inject package exploit experience into planner context
        package_exploit_exp = ""
        if self._experience is not None and task.vulnerable_package and task.package_ecosystem:
            package_exploit_exp = self._experience.format_exploit_context(
                task.vulnerable_package, task.package_ecosystem
            )
        planner_input = build_planner_input(
            intel_output,
            manifest,
            cwe_context,
            task.source_data,
            package_experience=package_exploit_exp,
        )
        logger.info("[%s] Starting Planner Agent", task.cve_id)
        planner_result = await self.planner.run(planner_input)
        ctx.agent_results[AgentRole.PLANNER] = planner_result
        ctx.add_tokens(planner_result.tokens)
        ctx.attack_plan = planner_result.output

        if self._is_over_budget(ctx, task.cve_id):
            return self._budget_result(task, ctx, "planner")

        # 4. Exploit
        app_source = self._format_app_source(generated_app)
        exploit_input = build_exploit_input(
            intel_output,
            planner_result.output,
            task,
            cwe_context,
            manifest=manifest,
            target_url=target_url,
            source_data=task.source_data,
            app_source=app_source,
            package_experience=package_exploit_exp,
        )
        logger.info("[%s] Starting Exploit Agent", task.cve_id)
        exploit_result = await self.exploit.run(exploit_input)
        ctx.agent_results[AgentRole.EXPLOIT] = exploit_result
        ctx.add_tokens(exploit_result.tokens)

        exploitation_level = extract_level(exploit_result)
        oracle_confidence = (
            self.exploit.oracle_confidence if isinstance(self.exploit, ExploitAgent) else 0.0
        )
        techniques_used = extract_techniques(exploit_result)
        logger.info("[%s] Exploitation complete: level=%d", task.cve_id, exploitation_level)

        # Update context so error/budget handlers have post-exploit data
        ctx.exploitation_level = exploitation_level
        ctx.oracle_confidence = oracle_confidence
        ctx.techniques_used = techniques_used
        ctx.tool_calls_total = len(exploit_result.tool_calls)

        record_exploit_outcome(
            task,
            exploitation_level,
            techniques_used,
            self._hooks,
            self._learnings,
            self.exploit,
        )

        # Record exploit experience for package-level learning
        if self._experience is not None and task.vulnerable_package and task.package_ecosystem:
            endpoints = _extract_endpoints_from_tool_calls(exploit_result)
            self._experience.record_exploit(
                task.vulnerable_package,
                task.package_ecosystem,
                task.cve_id,
                level=exploitation_level,
                techniques=techniques_used,
                endpoints=endpoints,
            )
            # Distill exploitation insights (async, non-blocking)
            if exploitation_level >= 1:
                tool_summary = _format_tool_call_summary(exploit_result)
                await self._experience.distill_exploit(
                    task.vulnerable_package,
                    task.package_ecosystem,
                    level=exploitation_level,
                    techniques=techniques_used,
                    tool_call_summary=tool_summary,
                )

        # Save exploit artifacts
        if self._artifact_store is not None:
            exploit_files = extract_exploit_artifacts(exploit_result)
            if exploit_files:
                self._artifact_store.save_exploit(task.cve_id, "forge", 0, exploit_files)

        # Allow detection for successful exploits (L3+) even when over budget.
        # Detection is a single LLM call (~$0.05-0.15) — negligible vs $2.50+
        # already spent.  Skipping it loses valuable detection rules for free.
        if self._is_over_budget(ctx, task.cve_id) and ctx.exploitation_level < 3:
            return self._budget_result(task, ctx, "exploit")

        # 5. Detector (conditional on L >= 1)
        detection_rules = await self._run_detector(
            task,
            exploitation_level,
            exploit_result,
            intel_output,
            ctx,
        )

        # Return cost-cap status with detection rules when budget was exceeded
        # but detection was allowed through for L3+ exploits.
        if self._is_over_budget(ctx, task.cve_id):
            result = self._budget_result(task, ctx, "exploit")
            result.detection_rules = detection_rules
            return result

        logger.info(
            "[%s] Pipeline complete: tokens=%d, cost=$%.2f",
            task.cve_id,
            ctx.tokens.total_tokens,
            ctx.tokens.estimated_cost_usd,
        )
        return PipelineResult(
            cve_id=task.cve_id,
            status=PipelineStatus.COMPLETED,
            intel_report=intel_output,
            generated_app=(
                {"files": list(generated_app.project_files.keys())}
                if generated_app is not None
                else {}
            ),
            manifest=manifest.model_dump() if manifest is not None else {},
            attack_plan=planner_result.output,
            exploitation_level=exploitation_level,
            tool_calls_total=len(exploit_result.tool_calls),
            techniques_used=techniques_used,
            detection_rules=detection_rules,
            tokens=ctx.tokens,
            wall_clock_seconds=ctx.elapsed_seconds,
            generation_attempts=ctx.generation_attempts,
            oracle_confidence=oracle_confidence,
            app_healthy=ctx.app_healthy,
            resolved_package=task.resolved_package_info,
            agent_results=ctx.agent_results,
            spans=[s.model_dump() for s in collector.spans],
            otel_trace_id=collector.trace_id,
        )

    async def _run_intel(
        self,
        task: CVETask,
        ctx: PipelineContext,
    ) -> dict[str, Any]:
        """Run intel phase: GENIE data > cached report > Intel Agent."""
        if has_rich_genie_data(task):
            logger.info("[%s] Intel source: GENIE synthetic", task.cve_id)
            intel_output = build_synthetic_intel(task)
            ctx.agent_results[AgentRole.INTEL] = AgentResult(
                output=intel_output,
                turns_used=0,
                tokens=TokenUsage(),
            )
            if self._hooks is not None:
                self._hooks.on_intel_complete(task)
        else:
            cached_intel = self._hooks.on_cve_load(task) if self._hooks is not None else None
            if cached_intel is not None and cached_intel.sources_used:
                logger.info("[%s] Intel source: cached report", task.cve_id)
                intel_output = cached_intel.model_dump()
                ctx.agent_results[AgentRole.INTEL] = AgentResult(
                    output=intel_output,
                    turns_used=0,
                    tokens=TokenUsage(),
                )
            else:
                intel_input = task_to_intel_input(task)
                logger.info("[%s] Intel source: running Intel Agent", task.cve_id)
                intel_result = await self.intel.run(intel_input)
                ctx.agent_results[AgentRole.INTEL] = intel_result
                ctx.add_tokens(intel_result.tokens)
                intel_output = intel_result.output
                if isinstance(self.intel, IntelAgent):
                    compiled = self.intel.compile_report(task)
                    intel_output = compiled.model_dump()
                if self._hooks is not None:
                    self._hooks.on_intel_complete(task)

        populate_task_tech_from_intel(task, intel_output)
        return intel_output

    async def _run_generation_and_deploy(
        self,
        task: CVETask,
        intel_output: dict[str, Any],
        ctx: PipelineContext,
    ) -> tuple[GeneratedApp | None, AppManifest | None, str | None]:
        """Run generator + deploy phases. Returns (app, manifest, url)."""
        generated_app: GeneratedApp | None = None
        manifest: AppManifest | None = None
        target_url: str | None = None

        if self._generator is not None:
            outcome = await self._run_generator(task, intel_output)
            generated_app = outcome.app
            ctx.agent_results[AgentRole.GENERATOR] = AgentResult(
                output={"project_files": list(generated_app.project_files.keys())},
                turns_used=outcome.attempts,
                tokens=outcome.tokens,
            )
            ctx.add_tokens(outcome.tokens)
            ctx.generation_attempts = outcome.attempts
            manifest = generated_app.manifest
            ctx.manifest = manifest.model_dump() if manifest is not None else {}

            # Auto-distill build errors into cookbook tips (cost excluded from run).
            await self._distill_cookbook(task, outcome.build_errors)

            if self._sandbox_manager is not None:
                target_url, session, app_healthy = await self._deploy_app(task, generated_app)
                ctx.session = session
                ctx.app_healthy = app_healthy
                if not app_healthy:
                    logger.warning("[%s] App health check failed — continuing", task.cve_id)
                if isinstance(self.exploit, ExploitAgent):
                    self.exploit.set_session(session)

        return generated_app, manifest, target_url

    async def _run_generator(
        self,
        task: CVETask,
        intel_output: dict[str, Any],
    ) -> GenerationOutcome:
        """Run the Generator Agent to produce a vulnerable app.

        Returns GenerationOutcome with app, tokens, build_errors, attempts.
        Raises GenerationFailedError on failure.
        """
        assert self._generator is not None  # noqa: S101

        reference_app: dict[str, str] = {}
        if self._artifact_store is not None and (task.language or task.framework):
            reference_app = self._artifact_store.find_similar_app(
                task.language or "",
                task.framework or "",
            )
            if reference_app:
                logger.info("[%s] Found reference app for reuse", task.cve_id)

        # Wire up real verifier when sandbox available
        ver_session: SandboxSession | None = None
        if self._sandbox_manager is not None:
            ver_session = await self._sandbox_manager.create(task)
            verifier = AppVerifier(ver_session)
            self._generator.set_verifier(verifier)

        try:
            intel_for_generator: dict[str, Any] = {
                "cve_id": task.cve_id,
                "cwe_id": task.cwe_ids[0] if task.cwe_ids else "",
                "description": task.description,
                "framework": task.framework or "",
                "language": task.language or "",
                **intel_output,
            }
            if task.affected_versions:
                intel_for_generator["affected_versions"] = task.affected_versions
            if task.fix_versions:
                intel_for_generator["fix_versions"] = task.fix_versions
            if task.source_data:
                patch_diffs = task.source_data.patch_diffs_as_dicts()
                if patch_diffs:
                    intel_for_generator["patch_diffs"] = patch_diffs
                if task.source_data.sw_version:
                    intel_for_generator["vulnerable_sw_version"] = task.source_data.sw_version
            if reference_app:
                intel_for_generator["reference_app"] = reference_app

            # Cookbook tips replace raw learnings for generator prompt
            if self._cookbook is not None:
                cookbook_tips = self._cookbook.format_for_prompt(
                    language=task.language or None,
                    cwe_id=task.cwe_ids[0] if task.cwe_ids else None,
                )
                if cookbook_tips:
                    intel_for_generator["cookbook_tips"] = cookbook_tips
                    logger.info("[%s] Injecting cookbook tips into generator", task.cve_id)

            # Inject package build experience from prior runs
            if self._experience is not None and task.vulnerable_package and task.package_ecosystem:
                build_exp = self._experience.format_build_context(
                    task.vulnerable_package, task.package_ecosystem
                )
                if build_exp:
                    intel_for_generator["package_build_experience"] = build_exp
                    logger.info("[%s] Injecting package build experience", task.cve_id)

            outcome = await self._generator.generate(
                intel_report=intel_for_generator,
            )
            app = outcome.app
            logger.info(
                "[%s] Generator produced %d files",
                task.cve_id,
                len(app.project_files),
            )

            # Save generated app and update technology index
            if self._artifact_store is not None:
                self._artifact_store.save_build(task.cve_id, "forge", 0, app.project_files)
                self._artifact_store.save_app_index(
                    task.cve_id,
                    "forge",
                    0,
                    app.manifest.language or task.language or "",
                    app.manifest.framework or task.framework or "",
                )
            record_generation_learning(
                task, self._learnings, success=True, attempts=outcome.attempts
            )

            # Record build experience for package-level learning
            if self._experience is not None and task.vulnerable_package and task.package_ecosystem:
                base_image = _extract_base_image(app.project_files.get("Dockerfile", ""))
                deps = _extract_deps_list(app.project_files, task.language or "")
                self._experience.record_build(
                    task.vulnerable_package,
                    task.package_ecosystem,
                    task.cve_id,
                    success=True,
                    attempts=outcome.attempts,
                    base_image=base_image,
                    deps=deps,
                )
                # Distill build errors into reusable notes (async, non-blocking)
                if outcome.build_errors:
                    await self._experience.distill_build(
                        task.vulnerable_package,
                        task.package_ecosystem,
                        build_errors=outcome.build_errors,
                        dockerfile_content=app.project_files.get("Dockerfile", ""),
                        success=True,
                    )

            return outcome
        finally:
            if ver_session is not None:
                await self._cleanup_sandbox(ver_session, task.cve_id)

    async def _distill_cookbook(self, task: CVETask, build_errors: list[str] | None = None) -> None:
        """Auto-distill build errors from the generator into cookbook tips.

        Only runs if the cookbook store has distillation configured and the
        generator produced build errors during retries.  Cost is tracked
        under the 'cookbook_distill' phase, excluded from run metrics.

        When called from the success path, ``build_errors`` is passed
        directly from the GenerationOutcome.  The failure path falls back
        to the generator's internal ``_last_build_errors``.
        """
        if self._cookbook is None or not self._cookbook.distill_enabled:
            return

        errors = build_errors
        if errors is None and self._generator is not None:
            errors = getattr(self._generator, "_last_build_errors", None)
        if not errors:
            return

        language = task.language or ""
        cwe_id = task.cwe_ids[0] if task.cwe_ids else ""
        added = await self._cookbook.distill_tips(
            language=language,
            cwe_id=cwe_id,
            build_errors=errors,
            success=True,
        )
        if added:
            logger.info("[%s] Cookbook auto-distilled %d new tip(s)", task.cve_id, added)

    def _format_app_source(self, generated_app: GeneratedApp | None) -> str:
        """Format generated app source files for injection into exploit prompt."""
        if generated_app is None:
            return ""
        files = generated_app.project_files
        if not files:
            return ""

        parts: list[str] = ["== APPLICATION SOURCE CODE =="]
        # Sort files for deterministic ordering; truncate large files
        for path in sorted(files.keys()):
            content = files[path]
            if len(content) > 10_000:
                content = content[:10_000] + "\n... (truncated)"
            parts.append(f"\n--- {path} ---\n{content}")

        result = "\n".join(parts)
        # Cap total injection at 50K chars to avoid blowing context
        if len(result) > 50_000:
            result = result[:50_000] + "\n... (source truncated at 50K chars)"
        return result

    async def _deploy_app(
        self,
        task: CVETask,
        app: GeneratedApp,
    ) -> tuple[str, SandboxSession, bool]:
        """Deploy generated app to sandbox and return (target_url, session, app_healthy)."""
        assert self._sandbox_manager is not None  # noqa: S101
        session = await self._sandbox_manager.create(task, port=app.manifest.health_port)
        logger.info("[%s] Deploying generated app to sandbox", task.cve_id)
        deploy_result = await session.deploy(
            app.project_files,
            health_path=app.manifest.health_endpoint,
        )
        if not deploy_result.success:
            error_msg = deploy_result.error or "Deploy failed"
            logger.error("[%s] Deploy failed: %s", task.cve_id, error_msg)
            await session.destroy()
            msg = f"Sandbox deploy failed for {task.cve_id}: {error_msg}"
            raise RuntimeError(msg)
        target_url = session.base_url
        logger.info("[%s] App deployed at %s", task.cve_id, target_url)
        return target_url, session, deploy_result.health_check_passed

    async def _run_detector(
        self,
        task: CVETask,
        exploitation_level: int,
        exploit_result: AgentResult,
        intel_output: dict[str, Any],
        ctx: PipelineContext,
    ) -> list[str]:
        """Run detector phase if exploitation level >= 1."""
        if exploitation_level < 1:
            logger.info("[%s] Skipping Detector Agent (level=%d)", task.cve_id, exploitation_level)
            return []

        try:
            detector = self._resolve_detector(ctx.collector)
            if detector is None:
                return []

            detector_input: dict[str, Any] = {
                "exploitation_level": exploitation_level,
                "tool_calls": [tc.model_dump() for tc in exploit_result.tool_calls],
                "intel_report": intel_output,
            }
            logger.info("[%s] Starting Detector Agent", task.cve_id)
            # Wire budget tracker to detector (resolved late via factory)
            if ctx.budget is not None:
                detector.set_budget_tracker(ctx.budget)
            detector_result = await detector.run(detector_input)
            ctx.agent_results[AgentRole.DETECTOR] = detector_result
            ctx.add_tokens(detector_result.tokens)

            raw_rules: Any = detector_result.output.get("rules", [])
            detection_rules = [str(r) for r in raw_rules] if isinstance(raw_rules, list) else []
            record_detection_rules(task.cve_id, detector_result, self._hooks)

            # Save detection rule artifacts
            if self._artifact_store is not None:
                sigma_rule = detector_result.output.get("sigma_rule", "")
                snort_rule = detector_result.output.get("snort_rule", "")
                if sigma_rule:
                    self._artifact_store.save_detection(
                        task.cve_id, "forge", 0, "sigma", str(sigma_rule)
                    )
                if snort_rule:
                    self._artifact_store.save_detection(
                        task.cve_id, "forge", 0, "snort", str(snort_rule)
                    )

            expand_detection_kb(
                task, detector_result, exploitation_level, self._detection_kb_updater
            )
            record_detection_learning(task, self._learnings, success=True)

            # Record detection experience for package-level learning
            if self._experience is not None and task.vulnerable_package and task.package_ecosystem:
                self._experience.record_detection(
                    task.vulnerable_package,
                    task.package_ecosystem,
                    task.cve_id,
                    rule_patterns=detection_rules[:5],
                    indicator_types=_extract_indicator_types(detector_result),
                )

            return detection_rules
        except Exception as exc:
            logger.warning("[%s] Detector failed: %s", task.cve_id, exc, exc_info=True)
            record_detection_learning(task, self._learnings, success=False, reason=str(exc))
            return []

    async def _cleanup_sandbox(self, session: SandboxSession, cve_id: str) -> None:
        """Safely tear down a sandbox session."""
        import asyncio

        try:
            await asyncio.wait_for(session.destroy(), timeout=30)
            logger.debug("[%s] Sandbox destroyed", cve_id)
        except TimeoutError:
            logger.warning("[%s] Sandbox destroy timed out (30s), skipping", cve_id)
        except Exception:
            logger.warning("[%s] Failed to destroy sandbox", cve_id, exc_info=True)

    def _resolve_detector(self, collector: SpanCollector) -> BaseAgent | None:
        """Resolve the detector agent: factory (preferred) or pre-built."""
        if self.detector_factory is not None:
            query = SpanQuery(collector)
            return self.detector_factory(query)
        return self.detector

    def _budget_result(
        self,
        task: CVETask,
        ctx: PipelineContext,
        phase: str,
    ) -> PipelineResult:
        """Build a COST_CAP_REACHED result."""
        budget_amount = ctx.budget.total_budget if ctx.budget is not None else self._cost_budget
        return PipelineResult(
            cve_id=task.cve_id,
            status=PipelineStatus.COST_CAP_REACHED,
            intel_report=ctx.intel_report,
            manifest=ctx.manifest,
            attack_plan=ctx.attack_plan,
            exploitation_level=ctx.exploitation_level,
            oracle_confidence=ctx.oracle_confidence,
            techniques_used=ctx.techniques_used,
            tokens=ctx.tokens,
            wall_clock_seconds=ctx.elapsed_seconds,
            generation_attempts=ctx.generation_attempts,
            app_healthy=ctx.app_healthy,
            tool_calls_total=ctx.tool_calls_total,
            resolved_package=task.resolved_package_info,
            agent_results=ctx.agent_results,
            error_message=f"Cost cap ${budget_amount:.2f} reached after {phase} phase",
            error_category="cost_cap",
            spans=[s.model_dump() for s in ctx.collector.spans],
            otel_trace_id=ctx.collector.trace_id,
        )


# ---------------------------------------------------------------------------
# Package experience extraction helpers
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)", re.MULTILINE | re.IGNORECASE)

# Maps language → filenames that list dependencies
_DEPS_FILES: dict[str, list[str]] = {
    "javascript": ["package.json"],
    "typescript": ["package.json"],
    "python": ["requirements.txt", "pyproject.toml"],
    "ruby": ["Gemfile"],
    "php": ["composer.json"],
    "go": ["go.mod"],
    "rust": ["Cargo.toml"],
    "java": ["pom.xml", "build.gradle"],
}


def _extract_base_image(dockerfile: str) -> str:
    """Extract the base image from a Dockerfile's FROM instruction."""
    if not dockerfile:
        return ""
    match = _FROM_RE.search(dockerfile)
    return match.group(1) if match else ""


def _extract_deps_list(project_files: dict[str, str], language: str) -> list[str]:
    """Extract top-level dependency names from project files.

    Returns at most 20 dependency names — enough for experience context
    without bloating the YAML files.
    """
    deps: list[str] = []
    candidates = _DEPS_FILES.get(language.lower(), [])

    for fname in candidates:
        content = project_files.get(fname, "")
        if not content:
            continue

        if fname == "package.json":
            deps.extend(_parse_package_json_deps(content))
        elif fname == "requirements.txt":
            deps.extend(_parse_requirements_txt(content))
        elif fname == "Gemfile":
            deps.extend(_parse_gemfile(content))
        elif fname == "composer.json":
            deps.extend(_parse_package_json_deps(content))  # Same JSON format
        break  # One file is enough

    return deps[:20]


def _parse_package_json_deps(content: str) -> list[str]:
    """Parse dependency names from package.json / composer.json."""
    import json as _json

    try:
        data = _json.loads(content)
        dep_sections = ("dependencies", "require")
        names: list[str] = []
        for section in dep_sections:
            section_data = data.get(section, {})
            if isinstance(section_data, dict):
                names.extend(section_data.keys())
        return names
    except (ValueError, KeyError):
        return []


def _parse_requirements_txt(content: str) -> list[str]:
    """Parse package names from requirements.txt."""
    names: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # "flask==2.0" → "flask", "requests>=1.0" → "requests"
        name = re.split(r"[>=<!\[]", line)[0].strip()
        if name:
            names.append(name)
    return names


def _parse_gemfile(content: str) -> list[str]:
    """Parse gem names from Gemfile."""
    names: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        match = re.match(r"""gem\s+['"]([^'"]+)['"]""", line)
        if match:
            names.append(match.group(1))
    return names


def _extract_endpoints_from_tool_calls(exploit_result: AgentResult) -> list[str]:
    """Extract unique endpoint paths from exploit HTTP tool calls."""
    from urllib.parse import urlparse

    endpoints: list[str] = []
    seen: set[str] = set()
    for tc in exploit_result.tool_calls:
        if tc.name == "http_request":
            url = tc.arguments.get("url", "")
            if url:
                try:
                    path = urlparse(url).path
                    if path and path not in seen:
                        seen.add(path)
                        endpoints.append(path)
                except Exception:
                    pass
    return endpoints[:20]


def _format_tool_call_summary(exploit_result: AgentResult) -> str:
    """Format a brief summary of exploit tool calls for distillation."""
    lines: list[str] = []
    for tc in exploit_result.tool_calls[:15]:
        if tc.name == "http_request":
            method = tc.arguments.get("method", "GET")
            url = tc.arguments.get("url", "")
            status = (tc.output or "")[:50]
            lines.append(f"{method} {url} → {status}")
        elif tc.name == "exec_command":
            cmd = tc.arguments.get("command", "")[:80]
            lines.append(f"exec: {cmd}")
        else:
            lines.append(f"{tc.name}({list(tc.arguments.keys())})")
    return "\n".join(lines)


def _extract_indicator_types(detector_result: AgentResult) -> list[str]:
    """Extract detection indicator types from detector output."""
    output = detector_result.output
    types: list[str] = []
    if output.get("sigma_rule"):
        types.append("sigma")
    if output.get("snort_rule"):
        types.append("snort")
    raw_rules: Any = output.get("rules", [])
    if isinstance(raw_rules, list):
        for rule in raw_rules:
            rule_str = str(rule).lower()
            if "alert " in rule_str and "sid:" in rule_str and "snort" not in types:
                types.append("snort")
            elif "sigma" not in types:
                types.append("sigma")
    return types
