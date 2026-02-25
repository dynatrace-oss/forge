# FORGE End-to-End Pipeline Reference

## Pipeline Overview

FORGE processes a CVE through six sequential phases: intelligence gathering, vulnerable app generation, sandbox deployment, attack planning, exploitation, and detection rule generation. The orchestrator manages token budgets, error isolation, and per-phase cost cap checks. Each CVE runs independently with its own sandbox and span collector.

```
CLI (forge run)
 │
 ├─ CVE sourcing (GENIE / file / batch)
 │   └─ Build CVETask + SourceData
 │
 ▼
Orchestrator._run_pipeline()
 │
 ├─ Phase 1: Intel ─────────── GENIE synthetic │ cache │ Intel Agent
 ├─ Phase 1b: PackageResolver ─ NVD/OSV/GENIE → registry version validation
 ├─ Phase 2: Generator ─────── Patch-diff-guided app generation (2 retries) + package experience
 ├─ Phase 3: Deploy ────────── Podman sandbox + health check
 ├─ Phase 4: Planner ───────── CWE-aware attack plan + KB context + package experience
 ├─ Phase 5: Exploit ───────── Tool-gated exploitation + oracle + coaching + package experience
 └─ Phase 6: Detector ──────── Sigma/Snort rules (conditional on L>=1) + package experience
```

## Entry Point

**CLI commands**: `forge run CVE-2024-XXXXX`, `forge run --batch 500`, `forge run --cve-list file.txt`.

CVE sourcing (`_resolve_cve_sources`):
1. Loads CVE-GENIE data from `data/CVE Genie Data.json` via `CVEGENIELoader`.
2. Extracts CWEs, language (from patch file extensions), description, and builds `SourceData` (patch diffs, security advisories, sw_version).
3. Noise diffs (tests, docs, minified assets) are filtered via `_is_noise_diff`.
4. For `--batch`: stratified selection via `DiversitySelector`.

Task creation (`_cve_source_to_task`): builds `CVETask` with `SourceData` attached. EPSS/CVSS scores are batch-enriched before the pipeline loop. OSV enrichment populates `affected_versions`, `fix_versions`.

**Key models**: `CVETask` (pipeline input), `SourceData` (GENIE patch diffs + advisories), `CVESource` (raw GENIE entry), `PipelineResult` (pipeline output).

## Phase 1: Intel

Priority order (cost optimization):
1. **GENIE data** (preferred): If `SourceData.has_rich_data` (description + patch diffs with content), builds a synthetic intel report via `_build_synthetic_intel`. Zero tokens.
2. **Cache**: `IntelHooks.on_cve_load()` checks for a previously compiled report. Zero tokens.
3. **Intel Agent**: Last resort. Runs the full agent with 6 tools (NVD, OSV, ExploitDB, etc.). Most expensive phase.

After intel, `_populate_task_tech_from_intel` propagates language/framework/CWE IDs to the task. Non-web CVEs are filtered via `_is_web_reproducible` (checked pre- and post-intel).

### Package Resolution (post-Intel)

After intel completes, `PackageResolver.resolve()` determines the vulnerable package name, version, and ecosystem:

1. **GENIE dataset**: `sw_name` + `sw_version` from the CVE-GENIE entry
2. **NVD CPE**: parsed from `configurations.nodes[].cpeMatch`
3. **OSV**: `affected[].package.name` + ecosystem + version ranges
4. **Repository heuristics**: GitHub repo name → package name mapping

**Registry version validation** (`PackageRegistryChecker`): validates the resolved version against the actual package registry (npm, PyPI, RubyGems, Packagist). If the version doesn't exist, finds the best available version (highest version ≤ candidate). This prevents generation failures from stale GENIE `sw_version` fields.

Output: `ResolvedPackage(name, version, ecosystem, registry_validated)` — injected into the generator prompt as DEPENDENCY VERSION PINNING.

Source: `src/forge2/cve/package_resolver.py`, `src/forge2/cve/registry_checker.py`.

## Phase 2: Generator

`GeneratorAgent.generate()` implements an actor-critic retry loop:

1. Build input from intel report + CWE recipe + GENIE patch diffs + reference app (cross-CVE reuse) + cookbook tips + **resolved package info** (from PackageResolver) + **PackageExperienceStore build context** (prior build tips, Dockerfile patterns, working deps for this package).
2. Run agent turn loop (5 turns max, 4 tools: `write_app_files`, `get_cwe_recipe`, `validate_app`, `add_vulnerability`).
3. Extract `GeneratedApp` (project files + `AppManifest`).
4. **Dependency-usage verification**: Static check that declared dependencies (from requirements.txt/package.json/go.mod) are actually imported in source files. Catches fabricated apps that list a vulnerable library but build mocks instead.
5. **Package fidelity enforcement**: `GeneratorAgent` sets `expected_package` on the `ValidateApp` tool before the turn loop. Both in-loop validation and post-hoc `_verify_app()` call `check_vulnerable_package_present()` — apps that don't install the real vulnerable package fail verification.
6. Verify via `AppVerifier` (dep-usage check, then build, deploy, health check, vuln presence).
7. On failure: feed back structured error, retry with existing files (smart retry — key files shown in full, others path-only).
8. Max 2 attempts. Raises `GenerationFailedError` if exhausted.

**max_tokens**: Generator uses `max_tokens: 16384` (configured in `forge.yaml`). The `write_app_files` tool serializes entire project files into a single tool-call JSON argument (5000-10000+ tokens). The default 4096 caused response truncation, yielding `null` arguments and 80% failure rates. Each agent can have its own `max_tokens` via `forge.yaml` → `AgentSettings.max_tokens` → `AgentConfig.max_tokens` → `LLMClient.chat()`.

**Double-serialization handling**: `_normalize_files()` unwraps up to 2 levels of JSON string wrapping. LLMs sometimes send the files array as a JSON string (or a string of a string) instead of a native JSON array.

Recipe filtering: CWE recipes are filtered to language-matching frameworks. Patch diffs show the generator exactly what the vulnerability looks like. Cookbook tips inject distilled language/CWE-specific gotchas (e.g., "Go modules require COPY . . before go mod tidy").

**PackageExperienceStore** records build outcome (`record_build()`) and distills build tips (`distill_build()`) for the package.

### Web Search for Build Error Resolution

When app generation fails with a build error, the system uses a 3-tier web search to find solutions:

1. **Built-in error patterns** (zero-cost, regex): 4 patterns covering Go/musl Alpine incompatibility, Go module resolution, Python/pip dependency conflicts, and Node.js/npm build failures. Fires before any external call.
2. **SearXNG** (self-hosted meta-search at `SEARXNG_URL`, default `http://localhost:8888`): Aggregates Google, Bing, DuckDuckGo, Stack Overflow, GitHub results. LLM-based query extraction via `PromptEngine` (`data/prompts/generator/web_search_query.yaml`). No API key required.
3. **DuckDuckGo HTML scraping** (fallback): Last resort if SearXNG is unavailable.

Resolution order: built-in → SearXNG → DDG fallback. Source: `src/forge2/generator/web_search.py`.

## Phase 3: Deploy

`Orchestrator._deploy_app()`:
1. **Dockerfile qualification**: `qualify_dockerfile_images()` (in `sandbox/_base.py`) rewrites all unqualified `FROM <image>` to `FROM docker.io/library/<image>` before `podman build`. This fixes Podman short-name resolution failures on EC2 where `shortnames.conf` lacks aliases for `golang`, `maven`, `openjdk`, `ruby`, `rust`, `dotnet`.
2. Creates a Podman sandbox via `PodmanSandboxManager.create()` with resource limits (memory, CPUs from config).
3. Deploys `GeneratedApp.project_files` into the container.
4. Runs health check against `AppManifest.health_endpoint` (default `/health:8080`).
5. Returns `(target_url, session, app_healthy)`. Pipeline continues even if health check fails.
6. Swaps the exploit agent's stub session for the real sandbox session via `ExploitAgent.set_session()`.

Sandbox cleanup uses a 30-second timeout; stale pods are force-removed on next create.

## Phase 4: Planner

`PlannerAgent` — pure reasoning, no tools. Receives:
- Compiled intel report
- `AppManifest` (framework, vulnerable endpoint, language, complexity)
- CWE knowledge context (Tier 3 KB + Tier 4 learnings from prior runs)
- GENIE security advisories (often contain step-by-step PoC instructions)
- GENIE patch diffs
- **PackageExperienceStore exploit context** (prior exploit techniques, payload hints, known auth mechanisms for this package)

Knowledge context (`format_knowledge_context` in `orch_recording.py`): combines CWE exploitation knowledge from prior runs with cross-CWE procedural learnings. Framed as guidance, not recipes.

## Phase 5: Exploit

`ExploitAgent` — the core exploitation loop with 5 tools:
- **Execution**: `exec_command` (shell commands in sandbox), `run_exploit_script` (multi-line Python exploit scripts — PRIMARY weapon)
- **Network**: `http_request` (single HTTP probe for quick checks)
- **Observation**: `read_file` (read files from target container), `get_app_logs` (server-side logs)

The exploit agent also receives **PackageExperienceStore exploit context** (prior exploit techniques, payload hints, endpoints discovered for this package). After exploitation, `record_exploit()` + `distill_exploit()` capture the outcome for future CVEs targeting the same package.

**Tool gating**: Turns 1-3 (configurable via `recon_phase_turns`) only expose recon tools (`read_file`, `get_app_logs`, `http_request`). All 5 tools unlock after the recon phase.

**Coaching** (`CoachingTracker`): Injects guidance when the agent gets stuck (repeated errors, no level progress). Escalating urgency. Forces `tool_choice=required` after 2+ consecutive text-only responses. Triggers termination after too many repeated coaching messages.

**Grace period**: Once `running_max` reaches L2+, allows N additional turns for consolidation. At L3, a shorter grace window. If level increases during grace, counter resets. When grace expires, forces text-only output for final JSON.

**Oracle**: Runs `DefaultInlineOracle.evaluate_turn()` after every tool call. See Oracle System below.

**CWE injection**: `CWEModule` identity and CAPEC/ATT&CK escalation paths are injected into the system prompt. CWE-specific oracle criteria come from `oracle_patterns.yaml`.

## Phase 6: Detector

Conditional on exploitation level >= 1.

1. Creates `DetectorAgent` via factory with `SpanQuery` (populated from `SpanCollector` during exploitation).
2. Receives exploitation level, tool call history, intel report.
3. Generates Sigma and Snort detection rules.
4. Rules are saved as artifacts and recorded to the knowledge graph.
5. `DetectionKBUpdater` validates and persists rules to the on-disk detection KB, keyed by CWE.
6. Detection learnings recorded on failure only (success has no actionable value).

## Oracle System

LLM-primary evaluation per tool call. The LLM oracle is invoked on EVERY exploit turn, replacing the old Tier 1 regex + Tier 2 LLM fallback architecture.

**LLM Oracle (every turn, ~$0.003/call)**:
- `LLMOracleCritic.evaluate()` receives rich context: tool name, arguments, output, CWE info, oracle criteria, app source code, and server-side snapshot.
- CWE-specific evidence descriptions are loaded from `oracle_patterns.yaml` (natural language, 20 CWE groups) via `format_oracle_criteria()`.
- App source code is passed from `ExploitAgent._app_source` (set during `format_input()`).
- Server-side snapshot (files created, running processes, app logs) is formatted via `format_snapshot()`.
- Sandbox architecture explanation is embedded in the critic prompt to prevent confusion between agent sandbox (runs as root) and target application container.
- Agent self-congratulatory text is stripped via `_strip_narrative()` before the oracle sees it.
- Returns `CriticVerdict(level, confidence, reasoning)`.
- Uses a cheap/fast model (default `gpt-5-mini`) for cross-model diversity.
- On any LLM failure, returns a zero-level verdict (safe fallback).

**Structural caps (code, NOT regex)** — applied after the LLM verdict:
- **CWE level caps**: XSS (CWE-79) → max L2, Path Traversal (CWE-22) → max L2, Open Redirect (CWE-601) → max L2, DoS (CWE-400) → max L2, ReDoS (CWE-1333) → max L2, CSRF (CWE-352) → max L2. Uses `_CWE_ALIASES` for child CWE resolution.
- **Tool-level caps**: `read_file` capped at L1 (containers run as root — reading `/etc/passwd` is trivial), EXCEPT when the file was created by exploitation (appears in `snapshot.files_created`). `exec_command` capped at L1 unless target-facing (curl/wget/nc/ncat/httpie). `run_exploit_script` capped at L1 unless script imports HTTP libraries (requests, httpx, urllib, aiohttp, socket).

**Coaching helpers** (connection/error classification):
- `_classify_connection()`: Detects refused, timeout, crashed, healthy, unknown.
- `_classify_error()`: Classifies error type using connection status and LLM-assessed level — connection_refused, wrong_endpoint, wrong_payload_format, partial_trigger, fundamental, infrastructure.
- `_suggest_fix()`: Provides specific fix suggestions per error class.
- `_analyze_response()`: Brief analysis of tool output for coaching injection.

**Confidence**: computed from accumulated evidence across all turns via `_compute_confidence()`.

Source: `oracle/inline_oracle.py`, `oracle/llm_critic.py`, `oracle/evidence.py`, `oracle/oracle.py`.

## Knowledge System

| KB | Location | Purpose |
|----|----------|---------|
| Package Experience | `data/knowledge/experience/` | Package-specific build/exploit/detection knowledge across CVE runs |
| Cookbook | `data/knowledge/cookbook/` | Distilled tips per language/CWE — injected into generator prompt |
| CWE Knowledge (Tier 3) | `data/knowledge/exploitation/` | Escalation paths, technique effectiveness per CWE (language-aware) |
| Learnings (Tier 4) | `data/knowledge/learnings/` | Audit log of errors; exploit learnings injected into exploit agent |
| Detection KB | `data/knowledge/detection/` | Validated Sigma/Snort rules per CWE |
| Intel Cache | `data/cache/` + `data/cache/compiled/` | Compiled intel reports for reuse |
| CWE Enrichment | `data/cache/cwe/cwe_enrichment.json` | CAPEC/ATT&CK technique mappings per CWE (944 entries) |

**Package Experience Store** (Karpathy KSB-inspired): accumulates package-specific learnings across all pipeline phases. Stored as YAML files under `data/knowledge/experience/{ecosystem}/{package}.yaml`. Three memory types:
- **Episodic**: per-CVE history (outcomes, techniques used, build attempts).
- **Semantic**: LLM-distilled patterns (build tips, exploit techniques, payload hints).
- **Procedural**: concrete recipes (Dockerfile base images, working deps, env vars).

Injected into agents: build context → generator, exploit context → planner + exploit, detection context → detector. Writes occur after each phase completes. LLM distillation runs asynchronously using the critic model.

The Cookbook (Karpathy-inspired "wiki" pattern) replaces raw error event injection into the generator. Instead of dumping JSONL error logs into the prompt, curated YAML tips are organized by language (`languages/go.yaml`) and CWE category (`cwe/injection.yaml`). Tips are framed positively as "COMMON PATTERNS AND GOTCHAS" rather than "avoid these errors".

Escalation paths are recorded from the exploit agent's level history (`record_escalations`). Learnings are only recorded for actionable outcomes (L2+ success strategies or strategy exhaustion failures). CWE knowledge tracks per-language technique success rates — `format_for_prompt` boosts techniques verified for the target language and annotates them with `[verified for <language>]`.

## Cost Controls

- **Per-CVE budget**: `cfg.budget.max_cost_per_cve`. Checked after every phase via `_is_over_budget()`. Returns `COST_CAP_REACHED` status.
- **BudgetTracker** (`pipeline/budget.py`): Single source of truth for pipeline-wide cost. Shared across all agents via `set_budget_tracker()`. Each LLM call records tokens to the tracker in real-time. The agent turn loop checks `tracker.is_exhausted` instead of per-agent accumulators. When active, `PipelineContext.tokens` reads from the tracker; `add_tokens()` becomes a no-op to prevent double-counting.
- **Per-agent budgets**: Retained for backward compatibility in tests that don't use a tracker.
- **Generator budget check**: `generate()` checks `tracker.is_exhausted` before each retry attempt — prevents the blowout bug where retries continued after budget was exhausted.
- **Oracle critic tokens**: `LLMOracleCritic` records to the shared tracker — previously invisible to all budget checks.
- **GENIE-first intel**: Skips the most expensive phase (Intel Agent) when GENIE data is available.
- **Intel caching**: Reuses compiled reports from prior runs.
- **Early termination**: Non-web CVEs filtered before spending tokens. Grace period prevents runaway exploitation.
- **Model selection**: Configurable per-agent via `forge.yaml`. Multiple provider configs exist: `forge.yaml` (GitHub Copilot), `forge-bedrock.yaml` (AWS Bedrock — Claude Sonnet), `forge-bedrock-fallback.yaml` (AWS Bedrock — Llama 4 Maverick). All use LiteLLM's `provider/model_name` routing. Critic uses a cheap model.
- **Token tracking**: `TokenUsage` accumulated across all phases, including partial tokens from crashed agents.
- **Truncation detection**: `LLMClient` warns on `finish_reason=length` — signals that the API truncated the response. `ToolCall.from_openai()` warns on `null` or empty `function.arguments`. Together these catch truncation before it causes silent downstream failures.
- **Per-agent max_tokens**: Configurable via `forge.yaml` → `AgentSettings.max_tokens`. Generator uses 16384 to accommodate large `write_app_files` payloads.

## Per-CVE Output Artifacts

Each CVE produces a directory under `data/results/CVE-XXXX-XXXX/`:

| File | Contents | Producer |
|------|----------|----------|
| `result.json` | Full `PipelineResult` — status, levels, tokens, agent results, `ToolSpan` list | `cli._save_per_cve_artifact()` |
| `otel_spans.json` | LLM-level OTEL telemetry — per-call model, tokens, latency, cost attributes | `llm_client.export_and_clear_otel_spans()` |
| `forge/` | Generated app source, Dockerfile, build logs | Generator + Sandbox |
| `conversations/` | Per-agent LLM conversation transcripts | Agent base class |
| `rules/` | Sigma/Snort detection rules | Detector agent |

**OTEL span lifecycle**: LiteLLM auto-creates OTEL spans for each LLM call via the `"otel"` callback. Spans accumulate in an `InMemorySpanExporter` (module-level singleton). After each CVE completes, `export_and_clear_otel_spans()` serializes all spans to `otel_spans.json` and clears the exporter for the next CVE.

**Trace ID linkage**: `PipelineResult.otel_trace_id` stores the `SpanCollector.trace_id` (UUID), propagated to `results.csv` via `ExploitAttempt.otel_trace_id`.

## Key Files

| Component | Source File |
|-----------|------------|
| CLI entry point | `src/forge2/cli.py` |
| Orchestrator | `src/forge2/agents/orchestrator.py` |
| Orchestrator Helpers | `src/forge2/agents/orch_helper.py` |
| Orchestrator Recording | `src/forge2/agents/orch_recording.py` |
| Intel Agent | `src/forge2/agents/intel.py` |
| Generator Agent | `src/forge2/agents/generator.py` |
| Planner Agent | `src/forge2/agents/planner.py` |
| Exploit Agent | `src/forge2/agents/exploit.py` |
| Detector Agent | `src/forge2/agents/detector.py` |
| Base Agent | `src/forge2/agents/base.py` |
| Coaching | `src/forge2/agents/coaching.py` |
| Inline Oracle | `src/forge2/oracle/inline_oracle.py` |
| Oracle Evidence | `src/forge2/oracle/evidence.py` |
| LLM Critic | `src/forge2/oracle/llm_critic.py` |
| Oracle core | `src/forge2/oracle/oracle.py` |
| Data Models | `src/forge2/models.py` |
| Config | `src/forge2/config.py` + `data/config/forge.yaml` + `data/config/forge-bedrock*.yaml` |
| CVE Loader | `src/forge2/cve/loader.py` |
| CWE Module Factory | `src/forge2/cve/cwe_module_factory.py` |
| App Verifier | `src/forge2/generator/verification.py` |
| CWE Enricher | `src/forge2/cve/enricher.py` |
| Sandbox (Podman) | `src/forge2/sandbox/podman.py` |
| Span Collector | `src/forge2/signals/collector.py` |
| Results Store | `src/forge2/pipeline/results_store.py` |
| Artifact Store | `src/forge2/pipeline/artifact_store.py` |
| LLM Client | `src/forge2/pipeline/llm_client.py` |
| Budget Tracker | `src/forge2/pipeline/budget.py` |
| Prompt Engine | `src/forge2/pipeline/prompt_engine.py` |
| Intel Hooks | `src/forge2/intel/hooks.py` |
| Learning Store | `src/forge2/learnings.py` |
| Cookbook Store | `src/forge2/cookbook.py` |
| Package Experience Store | `src/forge2/experience.py` |
| Package Resolver | `src/forge2/cve/package_resolver.py` |
| Registry Checker | `src/forge2/cve/registry_checker.py` |
| Detection KB | `src/forge2/detection/kb_updater.py` |
| OSV Enricher | `src/forge2/pipeline/osv_enricher.py` |
| Storage Manager | `src/forge2/storage.py` |
| Web Search | `src/forge2/generator/web_search.py` |
| Sandbox Base (Dockerfile qualification) | `src/forge2/sandbox/_base.py` |
| Monitoring Dashboard | `dashboard/app.py` |
