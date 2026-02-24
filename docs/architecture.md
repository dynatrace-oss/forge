# FORGE Architecture Documentation

This document provides a comprehensive overview of the FORGE vulnerability research framework architecture, including the multi-agent system, service layers, and data flow patterns.

## System Overview

FORGE implements a multi-agent architecture designed for automated vulnerability research. The system combines AI-powered code generation, real-world PoC integration, and robust reliability patterns.

```mermaid
graph TB
    subgraph "Cloud Services"
        LLM[Azure OpenAI LLM]
        OSV[OSV Database]
        GitHub[GitHub API]
    end

    subgraph "Multi-Agent Layer"
        BMA[Blueprint Management Agent]
        DA[Deployment Agent]
        EVA[Exploit Validation Agent]
        EGA[Exploit Generation Agent]
        VGA[Vulnerability Generation Agent]
        RA[ReAct Agent]
    end

    subgraph "Service Layer"
        LLMS[LLM Service]
        FIS[Framework Intelligence Service]
        CS[Container Service]
        EVS[Exploit Validation Service]
        RS[Reliability Service]
    end

    subgraph "Data Layer"
        BS[Blueprint Storage]
        MD[Monitoring Data]
        GC[GitHub Context Cache]
    end

    BMA --> FIS
    BMA --> LLMS
    BMA --> OSV
    DA --> CS
    EVA --> EVS
    EGA --> LLMS
    VGA --> LLMS
    VGA --> OSV
    RA --> CS

    LLMS --> LLM
    FIS --> LLM
    EVS --> LLM
    EGA --> GitHub

    BMA --> BS
    EVA --> MD
    EGA --> GC

    style LLM fill:#fff3e0
    style BMA fill:#e1f5fe
    style DA fill:#f3e5f5
    style EVA fill:#e8f5e8
    style VGA fill:#f1f8e9
    style RA fill:#ffebee
```

## Multi-Agent Architecture

### Blueprint Management Agent

**Purpose**: Orchestrates vulnerability blueprint creation with intelligent framework detection.

**Key Responsibilities**:

- Package analysis using OSV database integration
- Framework detection via AI-powered pattern matching
- Template selection and customization
- LLM-driven vulnerability code generation

**Data Flow**:

```mermaid
sequenceDiagram
    participant U as User
    participant BMA as Blueprint Agent
    participant OSV as OSV Database
    participant FIS as Framework Intelligence Service
    participant LLM as LLM Service
    participant TM as Template Manager
    participant BR as Blueprint Repository

    U->>BMA: Package specification
    BMA->>OSV: Query vulnerabilities
    OSV-->>BMA: CVE data + metadata
    BMA->>FIS: Analyze package structure
    FIS-->>BMA: Framework recommendations
    BMA->>TM: Select template
    TM-->>BMA: Template configuration
    BMA->>LLM: Generate vulnerability code
    LLM-->>BMA: Code snippets + metadata
    BMA->>BR: Store blueprint
    BR-->>BMA: Blueprint ID
    BMA-->>U: Created blueprint
```

### Deployment Agent

**Purpose**: Manages container lifecycle from build to deployment with error recovery.

**Container Lifecycle Management**:

```mermaid
stateDiagram-v2
    [*] --> Blueprint_Ready
    Blueprint_Ready --> Building : Build Request
    Building --> Build_Success : Success
    Building --> Build_Failed : Error
    Build_Failed --> Error_Recovery
    Error_Recovery --> Building : Retry
    Build_Success --> Deploying
    Deploying --> Running : Success
    Deploying --> Deploy_Failed : Error
    Deploy_Failed --> Error_Recovery
    Running --> Health_Check
    Health_Check --> Validated : HTTP OK
    Health_Check --> Health_Failed : HTTP Error
    Health_Failed --> Error_Recovery
    Validated --> [*]
```

### Exploit Validation Agent

**Purpose**: Strategic coordinator for exploit validation workflows, making decisions about validation approaches and orchestrating multiple services.

**Key Responsibilities**:

- Strategic validation strategy determination
- Container management decision making
- Service coordination and orchestration
- Result enhancement and analysis
- Error recovery coordination

**Validation Strategy Flow**:

```mermaid
graph LR
    A[Blueprint Input] --> B[Strategy Decision]
    B --> C[Container Decision]
    C --> D[Orchestration]
    D --> E[Validation Execution]
    E --> F[Result Enhancement]
    F --> G[Cleanup Coordination]
    
    style B fill:#ffecb3
    style C fill:#c8e6c9
    style D fill:#e1f5fe
    style F fill:#ffcdd2
```

### Exploit Generation Agent

**Purpose**: Strategic coordinator for exploit script generation workflows using  LLM-driven generation with GitHub context.

**Key Responsibilities**:

- GitHub metadata extraction and context formatting
- LLM-driven script generation with comprehensive context
- Fix commit analysis and reverse engineering guidance
- Quality enhancement and validation of generated scripts
- Vulnerability mechanism understanding from GitHub discussions

### Vulnerability Generation Agent

**Purpose**: Generates vulnerability-specific code and payloads using LLM-driven techniques.

**Key Responsibilities**:

- CVE-specific vulnerability code generation
- Payload creation and adaptation
- Integration with PoC extraction results
- Context-aware code synthesis

### ReAct Agent

**Purpose**: Specialized agent for intelligent error recovery using iterative reasoning and action cycles.

**Key Responsibilities**:

- Error analysis and recovery strategy planning
- Iterative problem-solving with LLM reasoning
- Container and build error resolution
- Adaptive responses based on observed results

**Reasoning Cycle**:

```mermaid
graph LR
    A[Error Context] --> B[Reason: Analyze Error]
    B --> C[Act: Execute Recovery]
    C --> D[Observe: Evaluate Results]
    D --> E{Success?}
    E -->|No| B
    E -->|Yes| F[Recovery Complete]

    style B fill:#ffecb3
    style C fill:#c8e6c9
    style D fill:#e1f5fe
    style E fill:#ffcdd2
```

**Integration**: The ReAct Agent works closely with the [Error Recovery Service](../src/services/exploit_validation/error_recovery_service.py) to provide validation failure analysis and corrective action recommendations.

## Prompt Management System

### PromptManager Overview

**Location**: `src/utils/core/prompt_manager.py`

The `PromptManager` provides a centralized, YAML-based prompt management system that replaced 9 different custom prompt loading implementations across the codebase.

**Key Features**:

- **Single Source of Truth**: All prompts loaded from `src/config/prompts/*.yaml`
- **Rich Metadata**: Version tracking, descriptions, categories, examples
- **Variable Validation**: Automatic checking of required vs optional variables
- **Dual Syntax Support**: Handles both `{var}` and `${var}` placeholders
- **Error Handling**: Clear error messages for missing variables or prompts

### YAML Prompt Structure

```yaml
metadata:
  name: prompt_name
  version: 1.0.0
  description: What this prompt does
  category: prompt_category
  tags:
    - tag1
    - tag2

placeholders:
  required:
    - variable1
    - variable2
  optional:
    - optional_var1

template: |
  Your prompt template here with {variable1} and {variable2}.
  Optional variables: {optional_var1}

examples:
  - description: Example usage
    variables:
      variable1: "value1"
      variable2: "value2"
```

### Available Prompts (22 Total)

| Category | Prompts |
| ---------- | --------- |
| **Blueprint Management** | blueprint_creation, similar_blueprints_analysis, package_description, package_tags |
| **Container Generation** | container_generation, template_customization, dependency_optimization |
| **Exploit Generation** | llm_poc_generation, exploitation_guidance, poc_analysis |
| **Framework Detection** | framework_detection, framework_selection, framework_internal_doc, code_adaptation, version_determination |
| **Validation** | vulnerability_validation, vulnerability_classification, vulnerability_generation, protocol_vulnerability_generation |
| **Error Recovery** | react_reasoning, react_observation, file_regeneration |

---

## Service Layer Architecture

### Service Dependencies

```mermaid
graph TB
    subgraph "System Integration"
        SI[CVEEmulatorSystem]
    end

    subgraph "Agent Layer"
        BMA[Blueprint Management Agent]
        DA[Deployment Agent]
        EVA[Exploit Validation Agent]
        EGA[Exploit Generation Agent]
        VGA[Vulnerability Generation Agent]
        RA[ReAct Agent]
    end

    subgraph "System Services"
        LLM[LLM Service]
        WS[Workflow Service]
        RS[Reliability Service]
        LVS[LLM Validation Service]
    end

    subgraph "Configuration Services"
        CMS[Config Manifest Service]
        FMS[Framework Metadata Service]
        PTS[Prompt Template Service]
    end

    subgraph "Container Services"
        CS[Container Service]
        CF[Containerfile Factory]
    end

    subgraph "Agent-Specific Services"
        subgraph "Blueprint Management"
            BR[Blueprint Repository Service]
            FIS[Framework Intelligence Service]
            FAS[Framework Adaptation Service]
        end

        subgraph "Exploit Validation"
            EVS[Exploit Validation Service]
            VOS[Validation Orchestration Service]
            ERS[Error Recovery Service]
        end

        subgraph "Exploit Generation"
            ESGS[Exploit Script Generation Service]
            GCS[GitHub Context Service]
        end

        subgraph "Dependency Management"
            MVR[Maven Version Resolver]
        end
    end

    subgraph "Utilities"
        ARL[API Reference Loader]
        TM[Template Manager]
    end

    SI --> BMA
    SI --> DA
    SI --> EVA
    SI --> EGA
    SI --> VGA

    BMA --> BR
    BMA --> FIS
    BMA --> FAS
    BMA --> LLM
    BMA --> TM
    DA --> CS
    DA --> ERS
    EVA --> EVS
    EVA --> VOS
    EVA --> ERS
    EVA --> CS
    EGA --> ESGS
    EGA --> GCS
    EGA --> LLM
    VGA --> LLM
    RA --> CS
    RA --> LLM

    TM --> CF
    VOS --> CS
    EVS --> ESGS
    EVS --> LVS
    ESGS --> GCS
    ESGS --> LLM

    FIS --> LLM
    FIS --> PTS
    FAS --> LLM
    ERS --> ARL
    LLM --> ARL

    TM --> FMS
    TM --> CMS
    CF --> FMS

    style SI fill:#fff3e0
    style EVA fill:#e8f5e8
    style VOS fill:#e1f5fe
    style FIS fill:#e3f2fd
    style LLM fill:#fff9c4
```

## Service Organization Structure

The services are organized into agent-based folders to improve maintainability and clearly separate responsibilities:

### Service Naming Conventions

All services follow the `*_service.py` naming pattern for consistency. Historical renames include:

- `system_integration.py` → `system_integration_service.py`
- `exploit_script_generator.py` → `exploit_script_generation_service.py`
- Factories use `*_factory.py` pattern (e.g., `containerfile_factory.py`)

### Agent-Service Relationships

Each agent coordinates specific services within its domain:

**Blueprint Management Agent** coordinates:

- Framework intelligence and adaptation decisions
- Blueprint repository operations
- Template selection and customization

**Exploit Validation Agent** coordinates:

- Validation strategy decisions
- Container discovery and orchestration
- Error recovery workflows

**Exploit Generation Agent** coordinates:

- GitHub metadata extraction (issues, fix commits, advisories)
- LLM-driven script generation with comprehensive context
- Script generation and enhancement with fix commit analysis

**Deployment Agent** coordinates:

- Container lifecycle management
- Build and deployment operations

## Key Service Components

### APIReferenceLoader

**Purpose**: Provides version-specific API guidance to LLM during code generation and error recovery.

**Key Features**:

- **Version Range Matching**: Automatically selects correct API patterns based on package version ranges (e.g., "6.0-6.3" matches 6.0.x through 6.3.x)
- **Import Format Handling**: Supports both string and list import formats in YAML configuration
- **Intelligent Caching**: Caches loaded API references in memory for improved performance
- **Framework Detection**: Automatically detects framework (Struts, Spring) from package name
- **LLM Integration**: Injects targeted version-specific guidance into LLM prompts for accurate code generation

**Location**: [src/utils/api_references/api_reference_loader.py](../src/utils/api_references/api_reference_loader.py)

**Configuration Files**:

- [src/config/api_references/struts_version_apis.yaml](../src/config/api_references/struts_version_apis.yaml) - Struts version-specific API guidance
- [src/config/api_references/spring_version_apis.yaml](../src/config/api_references/spring_version_apis.yaml) - Spring version-specific API guidance

**Version Range Configuration Example**:

```yaml
# struts_version_apis.yaml
"6.0-6.3":  # Matches 6.0.x, 6.1.x, 6.2.x, 6.3.x
  imports:
    - "org.apache.struts2.dispatcher.multipart.UploadedFile"
  example_code: |
    // File upload handling for Struts 6.0-6.3
    private UploadedFile uploadedFile;

"6.4+":     # Matches 6.4.0 and above
  imports:
    - "org.apache.struts2.action.UploadedFilesAware"
  example_code: |
    // File upload handling for Struts 6.4+
    implements UploadedFilesAware
```

### GitHubContextService

**Purpose**: Extracts comprehensive vulnerability context from GitHub using API integration.

**Key Features**:

- Full GitHub API integration (replaces HTML scraping)
- Issue descriptions (3000 chars) with maintainer comments
- Smart diff extraction from fix commits
- Commit classification (fix vs exploit)
- Reference filtering and prioritization

**Location**: [src/services/exploit_generation/github_context_service.py](../src/services/exploit_generation/github_context_service.py)

### MavenVersionResolver

**Purpose**: Validates and resolves Maven package versions against Maven Central.

**Key Features**:

- Version existence validation before builds
- Fallback strategies for invalid OSV versions
- Version range resolution (latest, match_major, etc.)
- Maven Central API integration
- Prevents build failures from non-existent versions

**Location**: [src/services/dependency/maven_version_resolver.py](../src/services/dependency/maven_version_resolver.py)

### Template Manager Enhancements

**Purpose**: Intelligent template selection based on package classification.

**Key Features**:

- Package classification (Spring Framework core, Struts core, application libraries)
- Spring Boot version mapping for framework packages
- Dynamic Java version detection (8/11/17/21)
- Framework-specific template routing (WAR vs JAR)
- POM template generation with dependencyManagement overrides

**Location**: [src/templates/manager.py](../src/templates/manager.py)

### Utilities

**New Utility Modules** (v0.4.3):

- `src/utils/analysis/github_utils.py`: GitHub classification and filtering
- `src/utils/analysis/github_context_utils.py`: DRY context formatting
- `src/utils/analysis/endpoint_utils.py`: HTTP endpoint metadata extraction

**Configuration Files**:

- `src/config/framework_packages.yaml`: Package classification
- `src/config/spring_boot_version_mapping.yaml`: Version compatibility mapping
- `src/config/github_classification.yaml`: Commit classification patterns

### Circuit Breaker Pattern Implementation

```mermaid
stateDiagram-v2
    [*] --> Closed
    Closed --> Open : Failure Threshold Exceeded
    Open --> Half_Open : Timeout Elapsed
    Half_Open --> Closed : Success
    Half_Open --> Open : Failure
    
    note right of Closed
        Normal Operation
        Calls pass through
    end note
    
    note right of Open
        Fail Fast
        Immediate rejection
    end note
    
    note right of Half_Open
        Testing Recovery
        Limited calls allowed
    end note
```

## CWE-to-Vulnerability-Type Mapping System

### Overview

FORGE uses a sophisticated CWE-based classification system to automatically categorize vulnerabilities and select appropriate validation patterns. This system bridges OSV vulnerability data with the framework's validation and exploitation capabilities. Currently, the mapping is done manually but this will be moved to an automated system in the future.

### Classification Flow

```mermaid
graph LR
    A[OSV Vulnerability Data] --> B[Extract CWE IDs]
    B --> C[extract_vulnerability_type_from_blueprint]
    C --> D[CWE-to-Type Mapping]
    D --> E[Vulnerability Type]
    E --> F[Pattern Selection]
    F --> G[Validation Context]
    F --> H[Exploitation Strategy]

    style C fill:#e1f5fe
    style D fill:#fff3e0
    style E fill:#e8f5e8
```

### Supported CWE Mappings

The system maps CWE identifiers to internal vulnerability types for pattern-based validation:

| CWE ID | Vulnerability Type | Description |
| -------- | ------------------- | ------------- |
| CWE-502 | deserialization / yaml_deserialization | Deserialization of Untrusted Data |
| CWE-89 | sql_injection | SQL Injection |
| CWE-78 | command_injection | OS Command Injection |
| CWE-79 | xss | Cross-site Scripting |
| CWE-113 | http_response_splitting | HTTP Response Splitting / Header Injection |
| CWE-611 | xxe | XML External Entity |
| CWE-22 | path_traversal | Path Traversal |
| CWE-400 | dos_attack | Resource Exhaustion |
| CWE-770 | dos_serialization | Serialization-based DoS |
| CWE-94 | code_injection | Code Injection |
| CWE-20 | input_validation | Improper Input Validation |

**Note:** CWE-502 uses package-specific refinement - YAML libraries (e.g., org.yaml:snakeyaml) are classified as `yaml_deserialization` rather than generic `deserialization`.

Classification happens in [src/utils/core/common.py:42-74](../src/utils/core/common.py#L42-L74):

### Pattern Selection Integration

Once classified, the vulnerability type drives pattern selection from [src/config/vulnerability_patterns.yaml](../src/config/vulnerability_patterns.yaml):

```yaml
osv_patterns:
  http_response_splitting:
    - "HTTP response splitting"
    - "CRLF injection"
    - "Header injection"
    - "Content-Disposition"
    - "Reflected File Download"

exploitation_indicators:
  http_response_splitting:
    - "attachment; filename="
    - "Content-Disposition header"
    - "\\r\\n in response"
    - "CRLF sequence detected"

log_patterns:
  http_response_splitting:
    - "header.*injection"
    - "response.*splitting"
    - "filename.*reflected"
```

### Unknown Vulnerability Type Handling

When no CWE mapping exists, the system:

1. Returns `"unknown"` as the vulnerability type
2. Logs a warning: `"No patterns available for vulnerability type: unknown"`
3. Uses generic validation context with lower confidence scores
4. Suggests adding custom CWE mapping in [src/utils/core/common.py](../src/utils/core/common.py)

**Troubleshooting:** See [troubleshooting.md](troubleshooting.md#issue-unknown-vulnerability-type) for handling unmapped CWE IDs.

## GitHub Context-Enhanced Exploitation Pipeline

### GitHub Metadata Integration

The framework uses GitHub metadata to understand vulnerabilities through:

- **GitHub Context Service**: Extracts metadata from issues, fix commits, and advisories
- **Config-Driven Classification**: Uses `github_classification.yaml` for commit classification
- **Fix Commit Analysis**: Reverse engineering guidance based on what was fixed
- **LLM Context Formatting**: Comprehensive context with fix commits as primary source
- **Generation**: Single LLM-driven path with rich GitHub context

### GitHub Context Extraction Flow

```mermaid
graph LR
    subgraph "Vulnerability References"
        A[GitHub URLs]
    end

    subgraph "Classification Layer"
        B[Config-Driven Patterns]
        C[Commit Type Detection]
        D[Reference Filtering]
    end

    subgraph "Metadata Extraction"
        E[Fix Commits]
        F[GitHub Issues]
        G[Security Advisories]
    end

    subgraph "Context Formatting"
        H[Fix Analysis with Reverse Engineering]
        I[Issue Discussions]
        J[Advisory Details]
    end

    subgraph "LLM Generation"
        K[Comprehensive Context]
        L[ Generation]
        M[Exploit Script]
    end

    A --> B
    B --> C
    C --> D
    D --> E
    D --> F
    D --> G
    E --> H
    F --> I
    G --> J
    H --> K
    I --> K
    J --> K
    K --> L
    L --> M

    style B fill:#e1f5fe
    style H fill:#ffecb3
    style K fill:#c8e6c9
```

### Config-Driven Classification

```mermaid
graph TD
    A[Commit Metadata] --> B[GitHub Classifier]
    B --> C{Load Config}
    C --> D[github_classification.yaml]
    D --> E[Fix Indicators]
    D --> F[Exploit Indicators]
    D --> G[Confidence Thresholds]

    E --> H[Keyword Matching]
    E --> I[Code Pattern Analysis]
    F --> H

    H --> J{Classification}
    I --> J
    G --> J

    J --> K[fix_commit]
    J --> L[exploit_poc]
    J --> M[reference]

    style B fill:#e1f5fe
    style D fill:#fff3e0
    style J fill:#c8e6c9
```

## 🌐 HTTP-Based Validation Architecture

### Universal Web Template System

```mermaid
graph TD
    A[Any Vulnerability Type] --> B[Universal Web Template]
    B --> C[Spring Boot Application]
    C --> D[HTTP Endpoints]
    D --> E[Port 8080 Deployment]
    E --> F[HTTP Validation]

    subgraph "Standard Endpoints"
        G["api/vulnerable"]
        H["api/health"]
        I["Root endpoint"]
    end

    D --> G
    D --> H
    D --> I

    style B fill:#e8f5e8
    style C fill:#e1f5fe
    style F fill:#fff3e0
```

### LLM-Based Validation Contexts

FORGE uses vulnerability-specific validation contexts to provide intelligent, LLM-driven validation instead of hardcoded pattern matching. Each vulnerability type has tailored analysis guidance that helps the LLM understand what constitutes successful demonstration.

#### Context-Driven Validation Flow

```mermaid
graph LR
    A[Vulnerability Type] --> B[Select Context]
    B --> C[LLM Validation Service]
    C --> D[Context-Specific Guidance]
    D --> E[Analyze Execution Results]
    E --> F[Validation Decision]

    style B fill:#fff3e0
    style C fill:#e1f5fe
    style D fill:#e8f5e8
```

#### Supported Validation Contexts (⚠️ Needs further evaluation)

The system provides specialized contexts for 12+ vulnerability types defined in [src/services/system/llm_validation_service.py:33-135](../src/services/system/llm_validation_service.py#L33-L135):

| Context Type | Key Focus | Example Evidence |
| ------------- | ----------- | ------------------ |
| **path_traversal** | Path processing without validation | OS permission errors on /etc/passwd |
| **deserialization** | Object instantiation and class loading | ScriptEngineManager creation |
| **yaml_deserialization** | YAML parsing and object instantiation | Constructor invocation messages |
| **injection** | Command/query execution attempts | SQL/shell syntax errors |
| **rce** | Code execution or process creation | Command output, process spawning |
| **dos_attack** | Resource consumption | OutOfMemoryError, timeout errors |
| **dos_serialization** | Serialization resource exhaustion | Heap exhaustion during processing |
| **http_response_splitting** | Header manipulation | Content-Disposition reflection |
| **xss** | Script injection in responses | `<script>` tag reflection |
| **sql_injection** | SQL query execution | Database syntax errors |
| **command_injection** | OS command execution | Shell error messages |
| **input_validation** | Input processing failures | Validation bypass evidence |

#### Example: HTTP Response Splitting Context

```python
{
    "description": "HTTP response splitting, header injection, and Reflected File Download (RFD) vulnerabilities allow attackers to manipulate HTTP response headers through CRLF injection or unsanitized input reflection in headers like Content-Disposition",

    "analysis_guidance": [
        "CRITICAL: This vulnerability manifests in HTTP RESPONSE HEADERS, not the response body",
        "Check if user-controlled input appears in HTTP response headers (Content-Disposition, Set-Cookie, Location, etc.)",
        "For RFD: Verify if malicious filename is reflected in Content-Disposition header without sanitization",
        "For CRLF injection: Look for carriage return/line feed sequences (\\r\\n or %0d%0a) in response headers",
        "HTTP 200 status with benign body content is expected - focus on header manipulation",
        "Evidence of header injection (e.g., 'attachment; filename=\"malicious.exe\"') indicates successful vulnerability trigger",
        "The vulnerability is triggered if the application reflects user input into headers without proper encoding/sanitization"
    ],

    "key_question": "Did the application reflect user-controlled input into HTTP response headers without proper sanitization, allowing header manipulation?"
}
```

#### Context Benefits

**Intelligent Analysis**: LLM understands the difference between:

- Application-level vulnerability demonstration (✅ Success)
- OS-level exploitation blocking (✅ Still success - vuln triggered)
- Application-level input rejection (❌ Failure - vuln not triggered)

**Header vs Body Distinction**: For HTTP-based vulnerabilities like RFD, the context explicitly guides the LLM to check response headers rather than just the body content.

**Triggered vs Exploited**: The system understands that a vulnerability can be "triggered" (demonstrated) even if full exploitation is blocked by external factors like OS permissions or security controls. **_It is important to note that this methodology is rather rudimentary and a more sophisticated solution needs to be explored_**.

#### Implementation Location

All validation contexts are defined in [src/services/system/llm_validation_service.py](../src/services/system/llm_validation_service.py) within the `vulnerability_contexts` dictionary, which maps each vulnerability type to its description, analysis guidance, and key validation question.

### Container Lifecycle with Validation Orchestration

```mermaid
sequenceDiagram
    participant DA as Deployment Agent
    participant CS as Container Service
    participant C as Container
    participant EVA as Exploit Validation Agent
    participant VOS as Validation Orchestration Service
    participant ESGS as Exploit Script Generation Service
    participant GCS as GitHub Context Service
    participant LVS as LLM Validation Service
    participant ERS as Error Recovery Service

    DA->>CS: Deploy container request
    CS->>C: Start container on port 8080
    C-->>CS: Container running
    CS->>C: HTTP health check
    C-->>CS: HTTP 200 OK
    CS-->>DA: Deployment successful

    DA->>EVA: Validate vulnerability
    EVA->>VOS: Discover & coordinate containers
    VOS-->>EVA: Container coordination results

    EVA->>ESGS: Generate exploit script
    ESGS->>GCS: Fetch GitHub context
    GCS-->>ESGS: Fix commits, issues, advisories
    ESGS-->>EVA: LLM-generated script with GitHub context

    EVA->>C: Execute validation script
    C-->>EVA: HTTP response + logs

    EVA->>LVS: Analyze results with vulnerability context
    LVS-->>EVA: Validation analysis

    alt Validation Failed
        EVA->>ERS: Initiate error recovery
        ERS-->>EVA: Recovery recommendations
    end

    EVA->>VOS: Monitor container for indicators
    VOS-->>EVA: IoC collection results

    EVA-->>DA: Enhanced validation results
```

## Data Flow Patterns

### Template-Driven Architecture

```mermaid
graph TB
    subgraph "Template Structure"
        A[src/templates/core/]
        B[src/templates/framework/]
        C[src/templates/maven/]
        D[src/templates/containerfiles/]
        E[src/templates/readme/]
    end

    subgraph "Configuration Sources"
        F[src/config/framework_adaptation.yaml]
        G[src/config/prompts/]
        H[src/config/framework_metadata.yaml]
        I[src/config/framework_config_manifests.yaml]
    end

    subgraph "Template Management"
        J[Template Manager]
        K[Framework Intelligence Service]
        L[Containerfile Factory]
        M[Config Manifest Service]
        N[Framework Metadata Service]
    end

    subgraph "Runtime Generation"
        O[Framework Detection]
        P[Template Selection]
        Q[LLM Customization]
        R[Code Generation]
    end

    A --> J
    B --> J
    C --> J
    D --> L
    E --> J

    F --> K
    G --> J
    H --> N
    I --> M

    J --> P
    K --> O
    L --> P
    M --> Q
    N --> L

    O --> P
    P --> Q
    Q --> R

    style A fill:#e8f5e8
    style C fill:#fff3e0
    style J fill:#e1f5fe
    style K fill:#e3f2fd
```

### Error Recovery and Reliability Flow

```mermaid
graph TD
    A[Service Operation] --> B{Success?}
    B -->|Yes| C[Normal Flow]
    B -->|No| D[Error Detection]
    
    D --> E[Error Classification]
    E --> F{Error Type}
    
    F -->|Transient| G[Retry Logic]
    F -->|Configuration| H[Fallback Config]
    F -->|Resource| I[Resource Recovery]
    F -->|Critical| J[Circuit Breaker]
    
    G --> K[Exponential Backoff]
    H --> L[Default Values]
    I --> M[Cleanup + Restart]
    J --> N[Fail Fast Mode]
    
    K --> A
    L --> A
    M --> A
    N --> O[Manual Intervention]
    
    style D fill:#ffcdd2
    style J fill:#ffebee
```

## Architectural Characteristics

### System Scalability

- **Multi-Agent Coordination**: Agents operate with clear separation of concerns
- **Container Isolation**: Each vulnerability demonstration runs in isolated containers
- **Port Management**: Dynamic port allocation prevents conflicts
- **Intelligent Caching**: Framework patterns, GitHub metadata (7-day retention), and LLM responses cached
- **Error Recovery**: ReAct agent provides intelligent error resolution
- **Config-Driven Patterns**: Classification patterns externalized to YAML configs for easy updates

### Reliability Patterns

- **Circuit Breaker**: LLM and external service calls protected by circuit breakers
- **Retry Logic**: Exponential backoff for transient failures
- **Graceful Degradation**: System continues with reduced functionality when services fail
- **Resource Monitoring**: Container and system resource tracking
- **Validation Layers**: Multiple validation stages ensure quality

## Extensibility

### Plugin Architecture

The system supports extensible components:

- **GitHub Metadata Sources**: Easy addition of new metadata extraction sources
- **Classification Patterns**: Config-driven commit classification via `github_classification.yaml`
- **Generation Methods**:  LLM-driven generation with extensible context formatting
- **Execution Environments**: Extensible sandboxing and monitoring
- **Analysis Techniques**: Configurable indicator collection patterns
- **Utility Functions**: Centralized utilities in `utils/analysis/github_utils.py` for reusability

### Framework Addition

Adding new frameworks requires only:

1. Pattern definitions in configuration files
2. Template variants for framework-specific features
3. LLM prompt adaptations for framework characteristics
