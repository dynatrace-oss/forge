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

import asyncio
import csv
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click

logger = logging.getLogger(__name__)


@click.group()
def main() -> None:
    """FORGE -- Automated Vulnerability Exploitability Assessment."""


@main.command()
@click.option("--count", type=int, default=500, help="Number of CVEs to select.")
@click.option("--seed", type=int, default=42, help="Random seed for reproducibility.")
@click.option(
    "--output",
    type=click.Path(),
    default="data/test/evaluation_cves.json",
    help="Output JSON path.",
)
def select(count: int, seed: int, output: str) -> None:
    """Select CVEs from CVE-GENIE pool via stratified sampling."""
    from forge.cve.loader import CVEGENIELoader
    from forge.cve.selector import DiversitySelector

    data_path = Path("data/CVE Genie Data.json")
    if not data_path.exists():
        click.echo(f"Error: CVE-GENIE data not found at {data_path}", err=True)
        raise SystemExit(1)

    loader = CVEGENIELoader(data_path)
    pool = loader.load_web_suitable()
    click.echo(f"Pool: {len(pool)} web-suitable CVEs")

    selector = DiversitySelector(seed=seed)
    selected = selector.select(pool, count=count)

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            [{"cve_id": s.cve_id, "cwes": [c.id for c in s.cwes]} for s in selected],
            indent=2,
        )
    )
    click.echo(f"Selected {len(selected)} CVEs -> {out_path}")


@main.command()
@click.argument("cve_id", required=False)
@click.option("--batch", type=int, help="Run N CVEs (stratified selection).")
@click.option("--cve-list", type=click.Path(exists=True), help="Run CVEs from file (one per line).")
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default="data/config/forge.yaml",
    help="Config YAML path.",
)
@click.option("--seed", type=int, default=42, help="Random seed.")
def run(
    cve_id: str | None,
    batch: int | None,
    cve_list: str | None,
    config_path: str,
    seed: int,
) -> None:
    """Run FORGE on one or more CVEs.

    Examples:\n
      forge run CVE-2024-12345          # Single CVE\n
      forge run --batch 500             # 500 CVEs (stratified)\n
      forge run --cve-list cves.txt     # CVEs from file
    """
    _setup_logging()

    if sum(x is not None for x in (cve_id, batch, cve_list)) != 1:
        click.echo("Error: provide exactly one of CVE_ID, --batch, or --cve-list", err=True)
        raise SystemExit(1)

    from forge.config import load_config

    cfg = load_config(Path(config_path))
    cve_sources = _resolve_cve_sources(cve_id, batch, cve_list, seed)

    click.echo(f"Running FORGE on {len(cve_sources)} CVE(s)")
    try:
        asyncio.run(_run_batch(cfg, cve_sources))
    except KeyboardInterrupt:
        click.echo("\nInterrupted — partial results saved.")
        raise SystemExit(130) from None


@main.command()
@click.option(
    "--results-dir",
    type=click.Path(),
    default="data/results",
    help="Results directory.",
)
def stats(results_dir: str) -> None:
    """Show results summary -- level distribution, cost, timing."""
    csv_path = Path(results_dir) / "results.csv"
    if not csv_path.exists():
        click.echo(f"No results found at {csv_path}", err=True)
        raise SystemExit(1)

    rows = _read_results_csv(csv_path)
    if not rows:
        click.echo("No result rows found.")
        return

    _print_stats(rows)


def _setup_logging() -> None:
    """Configure root logger: INFO to console, DEBUG to timestamped file."""
    log_fmt = "%(asctime)s %(levelname)-5s %(name)s: %(message)s"
    date_fmt = "%H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Console handler — INFO level
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(log_fmt, datefmt=date_fmt))
    root.addHandler(console)

    # File handler — DEBUG level, timestamped filename
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    file_handler = logging.FileHandler(log_dir / f"forge_{ts}.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-5s %(name)s: %(message)s")
    )
    root.addHandler(file_handler)


def _resolve_cve_sources(
    cve_id: str | None,
    batch: int | None,
    cve_list: str | None,
    seed: int,
) -> list[dict[str, Any]]:
    """Resolve the list of CVEs to process.

    Returns a list of dicts with ``cve_id``, ``cwes``, ``language``,
    ``description``, and ``source_data`` (serialised GENIE patch diffs,
    security advisories, and version info) when GENIE data is available.
    """
    from forge.cve.loader import CVEGENIELoader, languages_from_patches, pick_primary_language

    data_path = Path("data/CVE Genie Data.json")

    if cve_id is not None:
        cwes: list[str] = []
        language = ""
        description = ""
        source_data: dict[str, Any] = {}
        if data_path.exists():
            loader = CVEGENIELoader(data_path)
            cwes = [c.id for c in loader.get_cwes(cve_id)]
            # Load full CVESource to extract language from patches
            all_entries = loader._read_json_cached()
            blob = all_entries.get(cve_id)
            if blob is not None:
                source = loader._parse_entry(cve_id, blob)
                langs = languages_from_patches(source.patch_commits)
                language = pick_primary_language(langs)
                description = source.description
                source_data = _serialise_genie_source(source)
        return [
            {
                "cve_id": cve_id,
                "cwes": cwes,
                "language": language,
                "description": description,
                "source_data": source_data,
            }
        ]

    if cve_list is not None:
        lines = Path(cve_list).read_text().strip().splitlines()
        ids = [line.strip() for line in lines if line.strip()]
        if data_path.exists():
            loader = CVEGENIELoader(data_path)
            results: list[dict[str, Any]] = []
            all_entries = loader._read_json_cached()
            for cid in ids:
                cwes_for_cid = [c.id for c in loader.get_cwes(cid)]
                lang = ""
                desc = ""
                sd: dict[str, Any] = {}
                blob = all_entries.get(cid)
                if blob is not None:
                    source = loader._parse_entry(cid, blob)
                    langs = languages_from_patches(source.patch_commits)
                    lang = pick_primary_language(langs)
                    desc = source.description
                    sd = _serialise_genie_source(source)
                results.append(
                    {
                        "cve_id": cid,
                        "cwes": cwes_for_cid,
                        "language": lang,
                        "description": desc,
                        "source_data": sd,
                    }
                )
            return results
        return [
            {"cve_id": cid, "cwes": [], "language": "", "description": "", "source_data": {}}
            for cid in ids
        ]

    # --batch N: stratified selection from full pool
    assert batch is not None  # noqa: S101
    if not data_path.exists():
        click.echo(f"Error: CVE-GENIE data not found at {data_path}", err=True)
        raise SystemExit(1)

    loader = CVEGENIELoader(data_path)
    pool = loader.load_web_suitable()
    from forge.cve.selector import DiversitySelector

    selector = DiversitySelector(seed=seed)
    selected = selector.select(pool, count=batch)
    return [
        {
            "cve_id": s.cve_id,
            "cwes": [c.id for c in s.cwes],
            "language": pick_primary_language(languages_from_patches(s.patch_commits)),
            "description": s.description,
            "source_data": _serialise_genie_source(s),
        }
        for s in selected
    ]


def _serialise_genie_source(source: "CVESource") -> "SourceData":  # type: ignore[name-defined]  # noqa: F821
    """Build a validated SourceData from the rich GENIE CVESource fields.

    Filters out low-value patch diffs (test files, docs, minified assets)
    and logs a summary of what was extracted.
    """
    from forge.models import (  # noqa: F811
        CVESource,
        GenieAdvisory,
        GeniePatchDiff,
        SourceData,
        _is_noise_diff,
    )

    assert isinstance(source, CVESource)  # noqa: S101

    raw_diffs = [
        GeniePatchDiff(url=pc.url, diff=pc.diff_content or "")
        for pc in source.patch_commits
        if pc.diff_content
    ]
    # Filter out test/doc/build artifact diffs (easy-win optimisation)
    filtered_diffs = [pd for pd in raw_diffs if not _is_noise_diff(pd.url)]
    skipped = len(raw_diffs) - len(filtered_diffs)

    advisories = [
        GenieAdvisory(url=sa.url, content=sa.content or "")
        for sa in source.security_advisories
        if sa.content
    ]

    sd = SourceData(
        patch_diffs=filtered_diffs,
        security_advisories=advisories,
        sw_version=source.sw_version,
        sw_version_wget=source.sw_version_wget or "",
    )

    logger.info(
        "[%s] SourceData built: %s%s",
        source.cve_id,
        sd.log_summary(),
        f" (skipped {skipped} noise diffs)" if skipped else "",
    )
    return sd


def _cve_source_to_task(entry: dict[str, Any]) -> "CVETask":  # type: ignore[name-defined]  # noqa: F821
    """Convert a CVE source dict to a CVETask for the pipeline.

    Carries the full GENIE ``SourceData`` (patch diffs, security
    advisories, version info) through to the task so downstream agents
    can use CVE-specific intelligence instead of generic CWE patterns.
    """
    from forge.models import CVETask, SourceData

    cwe_ids: list[str] = entry.get("cwes", [])
    raw_sd = entry.get("source_data")
    source_data: SourceData | None = None
    if isinstance(raw_sd, SourceData):
        source_data = raw_sd
    elif isinstance(raw_sd, dict) and raw_sd:
        # Legacy dict format — convert to SourceData
        source_data = SourceData.model_validate(raw_sd)
    return CVETask(
        cve_id=entry["cve_id"],
        cwe_ids=cwe_ids,
        language=entry.get("language", ""),
        description=entry.get("description", ""),
        source_data=source_data,
    )


async def _run_batch(
    cfg: "ForgeConfig",  # type: ignore[name-defined]  # noqa: F821
    cve_sources: list[dict[str, Any]],
) -> None:
    """Run the pipeline on a batch of CVEs with per-CVE error isolation."""
    from forge.agents.orchestrator import PipelineResult, PipelineStatus
    from forge.cve.enrichment import EnrichmentCache, enrich_scores
    from forge.pipeline.results_store import ResultsStore

    total = len(cve_sources)
    results: list[PipelineResult] = []
    results_dir = Path(cfg.paths.results)
    store = ResultsStore(results_dir)

    # Resume support: skip CVEs already recorded in results.csv.
    completed_keys = store.get_completed_keys()
    if completed_keys:
        logger.info("Resume mode: %d CVEs already completed, skipping", len(completed_keys))

    # Pre-enrich EPSS/CVSS for all CVEs in one batch call (uses cache).
    cve_ids = [e["cve_id"] for e in cve_sources]
    cache = EnrichmentCache(Path("data/cache"))
    try:
        score_map = await enrich_scores(cve_ids, cache)
    except Exception:
        logger.warning("EPSS/CVSS enrichment failed — continuing without scores")
        score_map = {}

    for idx, entry in enumerate(cve_sources, 1):
        cve_id = entry["cve_id"]

        # Resume: skip already-completed CVEs (simple key match).
        # Key format: "cve_id|condition|run_index" — we use app_generation|0.
        resume_key = f"{cve_id}|app_generation|0"
        if resume_key in completed_keys:
            click.echo(f"[{idx}/{total}] {cve_id} ... SKIP (already completed)")
            continue

        task = _cve_source_to_task(entry)

        # Inject EPSS/CVSS from the enrichment cache
        epss, cvss = score_map.get(cve_id, (None, None))
        if epss is not None:
            task.epss_score = epss
        if cvss is not None:
            task.cvss_score = cvss

        start = time.monotonic()

        try:
            result = await _run_single(cfg, task)
        except Exception as exc:
            elapsed = time.monotonic() - start
            click.echo(f"[{idx}/{total}] {cve_id} ... ERROR: {exc} [{elapsed:.0f}s]")
            results.append(
                PipelineResult(
                    cve_id=cve_id,
                    status=PipelineStatus.ERROR,
                    wall_clock_seconds=elapsed,
                    resolved_package=task.resolved_package_info,
                    error_message=str(exc),
                )
            )
            continue

        elapsed = result.wall_clock_seconds
        cost = result.tokens.estimated_cost_usd
        status_tag = result.status.value
        level = result.exploitation_level

        if result.status == PipelineStatus.COMPLETED:
            click.echo(
                f"[{idx}/{total}] {cve_id} ... L{level} [{status_tag}, ${cost:.2f}, {elapsed:.0f}s]"
            )
        else:
            click.echo(f"[{idx}/{total}] {cve_id} ... [{status_tag}, ${cost:.2f}, {elapsed:.0f}s]")

        results.append(result)

        # Persist to results.csv
        try:
            attempt = _pipeline_result_to_attempt(result, task)
            store.save(attempt)
        except Exception:
            logger.warning(
                "[%s] Failed to persist result to CSV",
                cve_id,
                exc_info=True,
            )

        # Per-CVE artifact dump for debugging
        _save_per_cve_artifact(result, results_dir)

    _print_batch_summary(results)


async def _run_single(
    cfg: "ForgeConfig",  # type: ignore[name-defined]  # noqa: F821
    task: "CVETask",  # type: ignore[name-defined]  # noqa: F821
) -> "PipelineResult":  # type: ignore[name-defined]  # noqa: F821
    """Run the full pipeline for a single CVE.

    Constructs the Orchestrator from config with all 5 agents properly
    wired.  The Generator and sandbox are optional — when absent the
    orchestrator falls back to the 4-agent path.
    """
    from forge.agents.base import AgentConfig
    from forge.agents.orchestrator import Orchestrator, PipelineResult
    from forge.pipeline.artifact_store import ArtifactStore
    from forge.pipeline.llm_client import LLMClient
    from forge.pipeline.osv_enricher import OSVEnricher
    from forge.pipeline.prompt_engine import PromptEngine
    from forge.storage import StorageManager

    storage = StorageManager.from_config(cfg.paths)
    storage.ensure_dirs()
    artifact_store = ArtifactStore(results_dir=storage.results)

    # OSV enrichment: populate task.language, affected_versions, fix_versions
    osv = OSVEnricher()
    await osv.enrich(task)

    # Package resolution: LLM-based resolver determines the correct installable
    # package name, ecosystem, language, and version from CVE metadata.
    from forge.cve.llm_resolver import resolve_package

    resolver_llm = LLMClient(
        default_model=cfg.resolver.model,
        max_retries=cfg.llm.max_retries,
        base_retry_delay=cfg.llm.base_retry_delay,
    )
    resolved, resolver_tokens = await resolve_package(
        task,
        llm=resolver_llm,
        config=cfg.resolver,
    )
    if resolved:
        task.vulnerable_package = resolved.package_name
        if resolved.vulnerable_version:
            task.vulnerable_version = resolved.vulnerable_version
        task.package_ecosystem = resolved.ecosystem
        if resolved.language:
            task.language = resolved.language
        task.resolved_package_info = {
            "package_name": resolved.package_name,
            "ecosystem": resolved.ecosystem,
            "vulnerable_version": resolved.vulnerable_version,
            "language": resolved.language,
            "confidence": resolved.confidence,
            "reasoning": resolved.reasoning,
            "resolution_method": "llm",
        }
    else:
        logger.warning(
            "[%s] LLM resolver returned no result — proceeding without package info", task.cve_id
        )

    # EPSS/CVSS enrichment: populate scores from cache or FIRST/NVD APIs
    if task.epss_score is None:
        try:
            from forge.cve.enrichment import EnrichmentCache, enrich_scores

            cache = EnrichmentCache(Path("data/cache"))
            scores = await enrich_scores([task.cve_id], cache)
            epss, cvss = scores.get(task.cve_id, (None, None))
            if epss is not None:
                task.epss_score = epss
            if cvss is not None and task.cvss_score is None:
                task.cvss_score = cvss
        except Exception:
            logger.warning("EPSS enrichment failed for %s", task.cve_id)

    hooks, learnings = Orchestrator.create_intel_stack(
        storage, cache_ttl_seconds=cfg.cache.ttl_seconds
    )
    prompt_engine = PromptEngine(prompts_dir=storage.prompts)
    cost_budget = cfg.budget.max_cost_per_cve

    def _agent_config(name: str) -> AgentConfig:
        settings = getattr(cfg.agents, name)
        system_prompt = prompt_engine.render(f"agents/{name}")
        return AgentConfig(
            name=name,
            system_prompt=system_prompt,
            max_turns=settings.max_turns,
            model=settings.model,
            temperature=settings.temperature,
            max_tokens=settings.max_tokens,
        )

    # Helper to create LLMClients with shared retry config from forge.yaml
    def _make_llm(model: str) -> LLMClient:
        return LLMClient(
            default_model=model,
            max_retries=cfg.llm.max_retries,
            base_retry_delay=cfg.llm.base_retry_delay,
        )

    # Intel Agent — needs cache + compiler from hooks
    from forge.agents.intel import IntelAgent

    intel_llm = _make_llm(cfg.agents.intel.model)
    intel = IntelAgent(
        llm=intel_llm,
        cache=hooks.cache,
        compiler=hooks.compiler,
        hooks=hooks,
        config=_agent_config("intel"),
        cost_budget=cost_budget,
    )

    # Planner Agent — pure reasoning, no tools
    from forge.agents.planner import PlannerAgent

    planner_llm = _make_llm(cfg.agents.planner.model)
    planner = PlannerAgent(
        llm=planner_llm, config=_agent_config("planner"), cost_budget=cost_budget
    )

    # Exploit Agent — requires a sandbox session, constructed per-CVE by
    # the orchestrator when a generated app is deployed.  For the initial
    # wiring we create a minimal agent; the orchestrator replaces the
    # session after deployment via set_session().
    from forge.agents.exploit import ExploitAgent

    exploit_llm = _make_llm(cfg.agents.exploit.model)

    # Create a stub session — the orchestrator replaces it after deploy
    class _StubSession:
        """Placeholder until the orchestrator deploys a real sandbox."""

        base_url: str = "http://localhost:8080"

    exploit = ExploitAgent(
        llm=exploit_llm,
        session=_StubSession(),  # type: ignore[arg-type]
        config=_agent_config("exploit"),
        coaching_config=cfg.coaching,
        cost_budget=cost_budget,
        critic_model=cfg.oracle.critic_model,
    )

    # Generator Agent
    from forge.agents.generator import GeneratorAgent

    generator_llm = _make_llm(cfg.agents.generator.model)
    generator = GeneratorAgent(
        llm=generator_llm,
        config=_agent_config("generator"),
        cost_budget=cost_budget,
        max_generation_attempts=cfg.agents.generator.max_generation_attempts,
    )

    # Sandbox Manager (Podman)
    from forge.sandbox.podman import PodmanSandboxManager

    sandbox_manager = PodmanSandboxManager(
        memory=cfg.sandbox.resource_limits.memory,
        cpus=float(cfg.sandbox.resource_limits.cpus),
        timeout=cfg.sandbox.default_timeout,
    )

    # Detector Agent factory — creates a DetectorAgent per CVE run when
    # exploitation reaches L1+.  Uses a factory because the SpanQuery is
    # only available after exploitation completes.
    from forge.agents.detector import DetectorAgent

    detector_base_config = cfg.base_agent.with_overrides(cfg.agents.detector)
    detection_kb_dir = storage.knowledge_dir("detection")

    def _detector_factory(span_query: "SpanQuery") -> DetectorAgent:  # type: ignore[name-defined]  # noqa: F821
        from forge.signals.query import SpanQuery  # noqa: F811

        assert isinstance(span_query, SpanQuery)
        detector_llm = _make_llm(cfg.agents.detector.model)
        return DetectorAgent(
            llm=detector_llm,
            span_query=span_query,
            config=_agent_config("detector"),
            base_config=detector_base_config,
            cost_budget=cost_budget,
            detection_kb_dir=detection_kb_dir,
        )

    # Cookbook — distilled tips for generator prompt injection
    from forge.cookbook import CookbookStore

    cookbook = CookbookStore(
        llm=generator_llm,
        distill_model=cfg.oracle.critic_model,
    )

    # Package experience store — cross-CVE package-level knowledge
    from forge.experience import PackageExperienceStore

    experience = PackageExperienceStore(
        experience_dir=storage.knowledge_dir("experience"),
        llm=generator_llm,
        distill_model=cfg.oracle.critic_model,
    )

    from forge.agents.orchestrator import OrchestratorStores
    from forge.detection.kb_updater import DetectionKBUpdater

    detection_kb_updater = DetectionKBUpdater(kb_dir=detection_kb_dir)

    stores = OrchestratorStores(
        hooks=hooks,
        learnings=learnings,
        storage=storage,
        detection_kb_updater=detection_kb_updater,
        artifact_store=artifact_store,
        cookbook=cookbook,
        experience=experience,
    )

    orchestrator = Orchestrator(
        intel=intel,
        planner=planner,
        exploit=exploit,
        detector_factory=_detector_factory,
        generator=generator,
        sandbox_manager=sandbox_manager,
        stores=stores,
        cost_budget=cost_budget,
    )

    result: PipelineResult = await orchestrator.run(task)
    return result


def _pipeline_result_to_attempt(
    result: "PipelineResult",  # type: ignore[name-defined]  # noqa: F821
    task: "CVETask",  # type: ignore[name-defined]  # noqa: F821
) -> "ExploitAttempt":  # type: ignore[name-defined]  # noqa: F821
    """Convert a PipelineResult + CVETask into an ExploitAttempt for CSV storage."""
    from forge.agents.orchestrator import AgentRole, PipelineStatus
    from forge.models import ExperimentCondition, ExploitAttempt, TokenUsage

    # Extract per-agent token usage from agent_results.
    # "build" = intel + generator tokens (pre-exploit phases).
    # "exploit" = exploit agent tokens only.
    build_tokens = TokenUsage()
    exploit_tokens = TokenUsage()
    for role, agent_result in result.agent_results.items():
        role_str = role if isinstance(role, str) else str(role)
        if role_str in (AgentRole.INTEL, AgentRole.GENERATOR):
            build_tokens = build_tokens + agent_result.tokens
        elif role_str == AgentRole.EXPLOIT:
            exploit_tokens = agent_result.tokens

    return ExploitAttempt(
        cve_id=result.cve_id,
        cwe_ids=task.cwe_ids,
        language=task.language,
        framework=task.framework,
        condition=ExperimentCondition.APP_GENERATION,
        model="",
        total_tokens=result.tokens.total_tokens,
        estimated_cost_usd=result.tokens.estimated_cost_usd,
        build_prompt_tokens=build_tokens.prompt_tokens,
        build_completion_tokens=build_tokens.completion_tokens,
        build_total_tokens=build_tokens.total_tokens,
        build_llm_calls=build_tokens.llm_calls,
        exploit_prompt_tokens=exploit_tokens.prompt_tokens,
        exploit_completion_tokens=exploit_tokens.completion_tokens,
        exploit_total_tokens=exploit_tokens.total_tokens,
        exploit_llm_calls=exploit_tokens.llm_calls,
        build_success=result.status != PipelineStatus.GENERATION_FAILED,
        app_healthy=result.app_healthy,
        exploit_completed=result.status == PipelineStatus.COMPLETED,
        turns_used=result.tool_calls_total,
        max_exploitation_level=result.exploitation_level,
        exploitation_level=result.exploitation_level,
        binary_success=result.exploitation_level >= 1,
        oracle_confidence=result.oracle_confidence,
        detection_rules_generated=len(result.detection_rules),
        wall_clock_seconds=result.wall_clock_seconds,
        otel_trace_id=result.otel_trace_id,
        error_message=result.error_message,
        error_category=result.error_category,
        cvss_score=task.cvss_score,
        epss_score=task.epss_score,
        osv_enriched=bool(task.osv_id),
    )


def _read_results_csv(csv_path: Path) -> list[dict[str, str]]:
    """Read the results CSV into a list of row dicts."""
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def _print_stats(rows: list[dict[str, str]]) -> None:
    """Print a summary table from results rows."""
    total = len(rows)

    # Level distribution
    levels: dict[int, int] = {}
    total_cost = 0.0
    total_time = 0.0
    completed = 0

    for row in rows:
        level = int(row.get("exploitation_level", "0") or "0")
        levels[level] = levels.get(level, 0) + 1
        total_cost += float(row.get("estimated_cost_usd", "0") or "0")
        total_time += float(row.get("wall_clock_seconds", "0") or "0")
        if row.get("exploit_completed") == "True":
            completed += 1

    click.echo(f"\nResults: {total} rows, {completed} completed")
    click.echo(f"Cost: ${total_cost:.2f} total, ${total_cost / max(total, 1):.2f} mean")
    click.echo(f"Time: {total_time:.0f}s total, {total_time / max(total, 1):.0f}s mean")

    click.echo("\nLevel distribution:")
    for level in sorted(levels.keys()):
        count = levels[level]
        pct = 100.0 * count / total
        click.echo(f"  L{level}: {count:>4} ({pct:5.1f}%)")

    if levels:
        weighted_sum = sum(lv * ct for lv, ct in levels.items())
        click.echo(f"\nMean depth: {weighted_sum / total:.2f}")


def _save_per_cve_artifact(result: Any, results_dir: Path) -> None:
    """Save per-CVE pipeline result and OTEL spans for post-run debugging.

    Creates ``results_dir/<cve_id>/result.json`` with the full
    PipelineResult (including agent_results, spans, etc.) and
    ``results_dir/<cve_id>/otel_spans.json`` with LLM-level OTEL
    telemetry (per-call tokens, latency, model, cost).
    """
    try:
        cve_dir = results_dir / result.cve_id
        cve_dir.mkdir(parents=True, exist_ok=True)

        # Save pipeline result
        artifact_path = cve_dir / "result.json"
        artifact_path.write_text(
            result.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )

        # Export and save OTEL spans (LLM call telemetry)
        from forge.pipeline.llm_client import export_and_clear_otel_spans

        otel_spans = export_and_clear_otel_spans()
        if otel_spans:
            otel_path = cve_dir / "otel_spans.json"
            import json

            otel_path.write_text(
                json.dumps(otel_spans, indent=2, default=str),
                encoding="utf-8",
            )
    except Exception:
        logger.warning(
            "[%s] Failed to save per-CVE artifact",
            result.cve_id,
            exc_info=True,
        )


def _print_batch_summary(results: list[Any]) -> None:
    """Print summary after a batch run."""
    from forge.agents.orchestrator import PipelineStatus

    total = len(results)
    if total == 0:
        return

    completed = sum(1 for r in results if r.status == PipelineStatus.COMPLETED)
    gen_failed = sum(1 for r in results if r.status == PipelineStatus.GENERATION_FAILED)
    deploy_failed = sum(1 for r in results if r.status == PipelineStatus.DEPLOY_FAILED)
    errors = sum(1 for r in results if r.status == PipelineStatus.ERROR)
    total_cost = sum(r.tokens.estimated_cost_usd for r in results)

    levels = [r.exploitation_level for r in results if r.status == PipelineStatus.COMPLETED]
    mean_depth = sum(levels) / max(len(levels), 1)

    click.echo(
        f"\nSummary: {completed}/{total} completed, "
        f"{gen_failed} gen_failed, {deploy_failed} deploy_failed, {errors} error. "
        f"Mean depth: {mean_depth:.1f}. Total: ${total_cost:.2f}."
    )
