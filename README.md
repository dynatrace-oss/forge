# FORGE: Vulnerability Research Framework

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

FORGE is a **multi-agent framework** for automated vulnerability research that generates realistic vulnerable applications, deploys them in containers, and validates exploits by generating Proof-of-Concept(PoC) code. The system combines **configuration-driven architecture**, **LLM intelligence**, and **robust reliability** for security research.

## 🌟 Key Features

### **PoC-Enhanced Research**

- **PoC Integration**: Extracts and analyzes real-world Proof-of-Concept code from CVE references
- **LLM-Enhanced Generation**: Creates realistic vulnerable applications using PoC data and CVE descriptions
- **Multi-Source Analysis**: Combines OSV database, CVE references, and GitHub PoCs for vulnerability modeling

### **Configurable Architecture**

- **Configuration-Driven Design**: All framework detection patterns, prompts, and templates externalized to config files
- **Service Consolidation**: Streamlined architecture with cleanup, template customization, and error recovery
- **Microservice Reliability**: Circuit breakers, atomic operations, health monitoring, and graceful degradation
- **Automatic Data Management**: Comprehensive directory structure with monitoring, IoC collection, and persistence

### **Multi-Agent Framework**

- **Blueprint Management Agent**: Handles vulnerability blueprint creation with framework intelligence
- **Deployment Agent**: Manages containerization and deployment with error recovery
- **ReAct Agent**: Provides intelligent reasoning and action capabilities for complex scenarios
- **Framework Intelligence**: Dynamic framework detection using configurable patterns

### **Automated Validation & Cleanup**

- **HTTP-Based Validation**: All vulnerabilities accessible via RESTful endpoints for automated testing
- **Framework Support**: Spring Boot, Apache Struts, Micronaut, Quarkus with intelligent selection
- **Persistent Monitoring**: Container logs, validation results, exploit reports, and IoC collection
- **Automated Cleanup**: System maintenance with retention policies and redundant file removal

## 📋 Requirements

- Python 3.12+
- Docker or Podman
- LLM API access
- 4GB+ RAM for container builds

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://bitbucket.lab.dynatrace.org/projects/CASP/repos/gyros/browse
cd forge

# Install Poetry package manager
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies and activate environment
poetry install
poetry shell

# Configure LLM service (Azure OpenAI)
export AZURE_OPENAI_API_KEY="your-api-key"
export AZURE_OPENAI_ENDPOINT="your-endpoint"
export AZURE_OPENAI_DEPLOYMENT="your-deployment"
```

### Template Setup (Required)

See the [Template Guide](docs/template_guide.md) for complete template setup requirements.

### Basic Usage

```bash
# Create vulnerability blueprints
python src/main.py process --packages org.yaml:snakeyaml --limit 2

# Complete workflow with containers and validation
poetry run python src/main.py process --packages org.apache.struts:struts2-core --cve-ids org.apache.struts:struts2-core:GHSA-43mq-6xmg-29vm --framework-type struts --auto-run --ports 8080 --validate

# Test HTTP endpoints after container deployment
curl http://localhost:8080/
curl -X POST http://localhost:8080/api/vulnerable -H "Content-Type: application/json" -d '{"test":"payload"}'

# Validate specific exploits
python src/main.py validate-exploit --id <blueprint-id>

# View stored validation data
python src/main.py validation-results
python src/main.py container-logs
python src/main.py exploit-reports
```

For comprehensive usage examples, see the individual guides in the [docs](docs/) folder.

## 🏗️ Architecture

FORGE uses a multi-agent architecture with three main layers:

- **Agent Layer**: Blueprint management, deployment, and vulnerability generation agents
- **Service Layer**: Blueprint repository, container service, exploit validation, LLM service, and reliability management
- **Template System**: Vulnerability, framework, import, container, and prompt templates

## ✨ Dynamic Prompt Template System

FORGE features a prompt template system with automatic context enrichment:

### Template Types

**Simple Templates (v1.0.0)** - Fast string replacement for basic prompts:

```python
prompt = prompt_manager.format_prompt(
    "blueprint_creation",
    cve_id="CVE-2024-1234",
    package_name="org.example:lib"
)
```

**Advanced Templates** - Jinja2 with automatic enrichers for complex prompts:

```python
prompt = prompt_manager.format_prompt(
    "vulnerability_generation",
    cve_id="CVE-2024-1234",
    package_name="org.apache.struts:struts2-core",
    package_version="2.0.11"
    # Enrichers automatically add:
    # - version_warnings (API breaking changes)
    # - github_context (CVE fix commits, PoC code)
    # - cwe_descriptions (vulnerability classifications)
    # - application_endpoints (extracted from code)
)
```

### Context Enrichers

Enrichers automatically populate context before rendering:

- **VersionCheckerEnricher**: Version-specific API warnings (Struts 6.x, Spring 6.x)
- **GitHubContextEnricher**: Security advisories, fix commits, PoC code extraction
- **CWEClassifierEnricher**: Human-readable CWE descriptions
- **ProtocolDetectorEnricher**: HTTP/2, WebSocket, gRPC, Kafka protocol detection
- **EndpointExtractorEnricher**: HTTP endpoint metadata extraction (@RequestMapping, etc.)
- **FrameworkDetectorEnricher**: Framework-specific adaptation guidance

### Template Composition

### Benefits

✅ **Automatic Context**: Enrichers populate complex data (GitHub PoC, CWE info, version warnings)
✅ **Consistency**: Fragments ensure uniform instructions across all templates
✅ **Zero Breaking Changes**: Backward-compatible bridge pattern - existing code works unchanged
✅ **Performance**: Simple templates use fast string replacement; advanced templates cached (1hr TTL)

For detailed documentation, see:

- **Guide**: [docs/prompt_system_guide.md](docs/prompt_system_guide.md)
- **API Reference**: [docs/api-reference.md](docs/api-reference.md#prompt-template-system)

## 🛠️ Configuration

Basic configuration example:

```yaml
# config/llm_config.yaml
provider: azure
model: gpt-4
azure_endpoint: https://your-endpoint.openai.azure.com/
temperature: 0.1
```

Key environment variables:

```bash
export AZURE_OPENAI_API_KEY="your-api-key"
export AZURE_OPENAI_ENDPOINT="your-endpoint"
export AZURE_OPENAI_DEPLOYMENT="your-deployment"
```

## 🧩 Extensibility

FORGE is designed to be highly extensible. For details on extending framework support, custom templates, and reliability features, see the

- **Spring Framework Support**: Supports Spring Framework core packages (spring-web, spring-core, etc.)
- **GitHub API Integration**: GitHub API for issue descriptions, maintainer comments, and fix commits
- **Maven Central Validation**: All package versions validated against Maven Central before builds
- **WAR Framework Support**: Complete support for WAR-based frameworks (Apache Struts, servlet containers)
- **MavenVersionResolver**: Validates and resolves package versions from Maven Central
- **GitHubContextService**: Extracts comprehensive vulnerability context from GitHub
- **Package Classification**: Automatic detection of framework types and version requirements
- **Dynamic Java Versioning**: Auto-detects Java 8/11/17/21 requirements per package

## 📚 Documentation

- **[Getting Started](docs/getting-started.md)**: Step-by-step guide for first-time users
- **[Architecture](docs/architecture.md)**: Multi-agent system design and data flow
- **[API Reference](docs/api-reference.md)**: Component documentation and configuration
- **[Framework Intelligence](docs/framework-intelligence.md)**: Framework detection and adaptation
- **[PoC Integration](docs/poc-integration.md)**: GitHub context extraction and analysis
- **[Troubleshooting](docs/troubleshooting.md)**: Common issues and solutions

## ⚠️ Security Warning

**For security research only.** FORGE creates vulnerable applications for controlled testing environments. Never expose to the internet or use in production.
