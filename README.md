# Forge

| ⚠️ This product is not officially supported by Dynatrace. |
| --------------------------------------------------------- |

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

Forge is an automated vulnerability research framework that generates vulnerable Java applications, deploys them in containers, produces exploit scripts, and validates exploitability for real-world CVEs.

Vulnerable applications targeting the same framework share significant structural regularity (~70% identical infrastructure code). Forge generates this deterministically through templates, confining LLM inference to vulnerability-specific logic and significantly reducing the amount of LLM-generated code per CVE. This achieves 92% cost reduction compared to pure-LLM approaches.

**Security notice:** Forge creates intentionally vulnerable applications. Never expose generated containers to untrusted networks or use in production.

## Results

Evaluated on 90 CVEs across 32+ Java packages: 88.9% exploitation success at $0.22 per CVE (avg 14.1 minutes). Full evaluation data and artifacts are available at [dynatrace-oss/forge-artifacts](https://github.com/dynatrace-oss/forge-artifacts).

## Architecture

Six specialized agents coordinated by a workflow service:

| Agent | Role |
| ----- | ---- |
| Blueprint Management | Framework detection, template selection, code generation |
| Vulnerability Generation | CVE-specific vulnerable Java code (the core LLM usage) |
| Deployment | Container build, lifecycle management |
| Exploit Generation | GitHub context extraction (fix commits, issues, PRs), payload generation |
| Exploit Validation | Multi-tier validation with vulnerability-specific LLM analysis |
| ReAct Error Recovery | Iterative debugging using API reference files (95% recovery rate) |

These agents delegate to 19 services across 10 functional domains (LLM interaction, blueprint management, exploit generation, validation, container lifecycle, dependency resolution, configuration, prompt templating, and monitoring).

### Templates

Four template categories (28 templates total) eliminate LLM generation of boilerplate:

- **Core** (9 POM templates): `spring_boot_web`, `servlet_container`, `standalone_jar`, `http2_server`, `websocket_server`, `kafka_client`, `remoting_protocol_server`, `spring_framework_native`, `microservice_native`
- **Framework**: Code scaffolding (controllers, servlets, protocol handlers) per framework
- **Maven**: Repository declarations for non-Central artifacts
- **Container**: Universal Containerfile with JAR/WAR packaging and Java 8-21 selection

### Framework Intelligence

Version compatibility matrices and API reference files prevent hallucinated API calls:

- Spring Boot/Framework version mapping (8 version bands)
- Struts 6.0-6.3 vs 6.4+ API migration guidance
- Maven Central version validation before POM generation

### Validation

Context-aware validation using 18 vulnerability-specific contexts that distinguish triggering from full exploitation. For example, a path traversal blocked by OS permissions is still classified as vulnerable (the application failed to validate), reducing false negatives.

For the full architecture, see [docs/architecture.md](docs/architecture.md).

## Requirements

- Python 3.12+
- [Poetry](https://python-poetry.org/)
- Docker or Podman
- Azure OpenAI API access
- Maven 3.6+, Java 8+

## Setup

```bash
git clone https://github.com/dynatrace-oss/forge.git
cd forge

poetry install
poetry shell

export AZURE_OPENAI_API_KEY="your-api-key"
export AZURE_OPENAI_ENDPOINT="your-endpoint"
export AZURE_OPENAI_DEPLOYMENT="your-deployment"
```

## Usage

```bash
# End-to-end: blueprint, container, exploit, validation
poetry run python src/main.py process \
  --packages org.apache.struts:struts2-core \
  --cve-ids org.apache.struts:struts2-core:GHSA-43mq-6xmg-29vm \
  --framework-type struts \
  --auto-run --ports 8080 --validate

# Process multiple CVEs for a package
poetry run python src/main.py process --packages org.yaml:snakeyaml --limit 5

# Full workflow with background containers
poetry run python src/main.py workflow \
  --packages org.apache.tomcat.embed:tomcat-embed-core \
  --auto-run --validate --background

# Validate a specific exploit
poetry run python src/main.py validate-exploit --id <blueprint-id>

# List blueprints / view details
poetry run python src/main.py list
poetry run python src/main.py details --id <blueprint-id>
```

## Documentation

- [Architecture](docs/architecture.md) — Multi-agent system design, service layer, template system
- [Getting Started](docs/getting-started.md) — First-time setup and configuration
- [Examples](docs/examples.md) — Usage examples for common vulnerability types
- [Troubleshooting](docs/troubleshooting.md) — Common issues and solutions

## License

See [LICENSE](LICENSE).
