# FORGE

| ⚠️ This product is not officially supported by Dynatrace. |
| --------------------------------------------------------- |

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Proprietary](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

FORGE is a multi-agent framework for automated vulnerability exploitability assessment. Given a CVE, FORGE generates a synthetic vulnerable application, deploys it in a Podman sandbox, and autonomously attempts exploitation through a 5-agent pipeline. It produces three outputs: a graduated exploitation depth (L0-L3), EPSS/CVSS validation data, and exploitation-grounded detection rules (Sigma/Snort).

**Security notice:** FORGE creates intentionally vulnerable applications. Never expose generated containers to untrusted networks or use in production.

## Results

Evaluated on 603 CVEs from the CVE-GENIE dataset: 67.8% end-to-end L1+ exploitation (409/603), 70.3% generation+deployment success, 96.5% exploitation rate among generated apps, at $1.50 mean cost per CVE across eight languages and 187 CWE types. Full evaluation data, knowledge base, and results artifacts are available at [dynatrace-oss/forge-artifacts](https://github.com/dynatrace-oss/forge-artifacts).

## Pipeline

```
Intel → Generator → [Build & Deploy] → Planner → Exploit → Detector
```

| Agent | Role |
|-------|------|
| Intel | Gathers vulnerability intelligence (NVD, GitHub Advisory, patch diffs, OSV) into a structured dossier |
| Generator | Creates a synthetic vulnerable application embodying the CVE with CWE-enriched recipes; actor-critic retry |
| Planner | Produces a ranked attack plan from the intel report and app manifest |
| Exploit | Script-centric exploitation (20 turns, 5 tools); tool gating enforces recon-first; per-turn coaching |
| Detector | Generates and validates Sigma/Snort rules from exploitation traces and a curated detection knowledge base |

## Graduated Exploitation Taxonomy

| Level | Name | Evidence |
|-------|------|----------|
| L0 | No Evidence | No exploitation evidence observed |
| L1 | Triggered | Targeted payload activates the specific vulnerable functionality (e.g., path traversal returns file contents, XSS payload reflected without encoding) |
| L2 | Exploited | Significant attacker-controlled impact: data exfiltration, code execution evidence, arbitrary file access |
| L3 | Compromised | Full compromise: RCE with output, complete data dump, persistence, or privilege escalation |

## LLM-Primary Oracle

The oracle evaluates every exploit tool call — never just the final state. It receives CWE criteria (from `oracle_patterns.yaml`), app source code, a server-side snapshot, and sandbox context. Structural caps (code-level guardrails per CWE and tool type) enforce conservative bounds on what the LLM can claim.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Podman
- LLM API access via LiteLLM (GitHub Copilot, AWS Bedrock, or any supported provider)

## Setup

```bash
git clone https://github.com/dynatrace-oss/forge.git
cd forge
uv sync
cp .env.example .env   # set LLM credentials (see .env.example)
```

For AWS Bedrock:
```bash
export AWS_BEARER_TOKEN_BEDROCK="<your-key>"
export AWS_REGION_NAME="us-east-1"
```

## Usage

```bash
# Single CVE
forge run CVE-2024-12345

# Single CVE with Bedrock provider
forge run CVE-2024-12345 --config data/config/forge-bedrock.yaml

# CVEs from file
forge run --cve-list data/test/validation_25.txt

# Results summary
forge stats
```

## Configuration

Runtime configs in `data/config/`:

| Config | Provider | Model |
|--------|----------|-------|
| `forge.yaml` | GitHub Copilot | Claude Sonnet 4.5 |
| `forge-bedrock.yaml` | AWS Bedrock | Claude Sonnet 4.5 |
| `forge-bedrock-fallback.yaml` | AWS Bedrock | Llama 4 Maverick |

Config controls per-agent model, turn limits, temperature, sandbox resource limits, budget cap ($2.50/CVE), oracle patterns, and model pricing.

## Project Structure

```
src/forge/
├── agents/          # 5 agents + orchestrator + coaching
├── oracle/          # LLM-primary oracle, structural caps, evidence scoring
├── tools/           # Tool modules: sandbox, HTTP, observation, generator, detection
├── cve/             # CVE-GENIE loader, stratified selector, CWE enrichment
├── generator/       # Generation knowledge base, CWE recipes, app verification
├── intel/           # 4-tier intelligence store
├── signals/         # OTEL span collection and query
├── sandbox/         # Podman container execution
├── detection/       # Sigma/Snort rule models and validators
├── pipeline/        # LLM client, prompt engine, BudgetTracker
├── analysis/        # RQ analysis pipeline
├── config.py        # ForgeConfig (Pydantic), YAML loader
└── models.py        # Shared data models
```

Evaluation data, prompt templates, knowledge base, and results are in the companion [forge-artifacts](https://github.com/dynatrace-oss/forge-artifacts) repository.

## Development

```bash
uv run ruff check src/forge/ tests/ scripts/
uv run python -m mypy src/forge/ --strict
uv run pytest tests/ -x -q
```

## Citation

```bibtex
@inproceedings{forge-ares2026,
  title     = {{FORGE}: Multi-Agent Graduated Exploitation and Detection Engineering},
  booktitle = {Proceedings of the 21st International Conference on Availability,
               Reliability and Security (ARES 2026), Workshop on Agentic AI
               in Cybersecurity (Agentcy)},
  year      = {2026},
  publisher = {ACM},
  url       = {https://www.ares-conference.eu/agentcy}
}
```

## License

See [LICENSE](LICENSE).
