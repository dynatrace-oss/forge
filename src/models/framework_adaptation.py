import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from shared.types import FrameworkType

logger = logging.getLogger(__name__)


class AdaptationStrategy(Enum):
    """Strategies for adapting vulnerability code to different web frameworks."""
    
    CONVERT_TO_WEB = "convert_to_web"             # Convert to web application pattern
    CONVERT_FRAMEWORK = "convert_framework"       # Convert between framework types
    ENHANCE_NATIVE = "enhance_native"             # Enhance with native framework features
    MICROSERVICE_PATTERN = "microservice_pattern" # Apply microservice patterns
    WEB_ENDPOINT_PATTERN = "web_endpoint_pattern" # Create HTTP endpoints for vulnerability triggering


class AdaptationComplexity(Enum):
    """Complexity levels for framework adaptation tasks."""
    
    SIMPLE = "simple"         # Basic wrapper or configuration changes
    MODERATE = "moderate"     # Code structure changes, new dependencies
    COMPLEX = "complex"       # Significant architectural changes
    ADVANCED = "advanced"     # Deep framework integration required


class FrameworkSuitability(Enum):
    """Framework suitability levels for specific vulnerability types."""
    
    EXCELLENT = "excellent"   # Perfect match for vulnerability demonstration
    GOOD = "good"             # Well-suited with minor adaptations
    FAIR = "fair"             # Suitable with moderate adaptations
    POOR = "poor"             # Requires significant adaptation
    INCOMPATIBLE = "incompatible"  # Cannot effectively demonstrate vulnerability


@dataclass
class FrameworkCapability:
    """Represents a framework's capability for handling specific vulnerability types."""
    
    framework_type: FrameworkType
    vulnerability_type: str
    suitability: FrameworkSuitability
    adaptation_complexity: AdaptationComplexity
    required_dependencies: list[str] = field(default_factory=list)
    configuration_requirements: list[str] = field(default_factory=list)
    performance_impact: str = "low"  # low, medium, high
    security_considerations: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class FrameworkChoice:
    """Represents an LLM-driven framework selection decision."""
    
    selected_framework: FrameworkType
    confidence_score: float  # 0.0 - 1.0
    rationale: str
    alternative_frameworks: list[FrameworkType] = field(default_factory=list)
    vulnerability_analysis: dict[str, any] = field(default_factory=dict)
    package_analysis: dict[str, any] = field(default_factory=dict)
    adaptation_strategy: AdaptationStrategy = AdaptationStrategy.CONVERT_TO_WEB
    estimated_complexity: AdaptationComplexity = AdaptationComplexity.SIMPLE
    required_changes: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    llm_metadata: dict[str, any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate framework choice data."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")
        
        if not self.rationale.strip():
            raise ValueError("Rationale is required for framework choice")


@dataclass
class CodeAdaptation:
    """Represents the result of adapting code to a specific framework."""

    original_code: str
    adapted_code: str
    source_framework: FrameworkType
    target_framework: FrameworkType
    adaptation_strategy: AdaptationStrategy
    changes_made: list[str] = field(default_factory=list)
    dependencies_added: list[dict[str, str]] = field(default_factory=list)
    configuration_files: dict[str, str] = field(default_factory=dict)
    endpoint_metadata: list[dict[str, any]] = field(default_factory=list)
    imports_modified: bool = False
    package_structure_changed: bool = False
    framework_specific_features: list[str] = field(default_factory=list)
    adaptation_notes: str = ""
    validation_status: str = "pending"  # pending, success, failed
    validation_errors: list[str] = field(default_factory=list)
    performance_considerations: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AdaptationContext:
    """Context information for framework adaptation decisions."""
    
    package_name: str
    package_version: str
    vulnerability_type: str
    vulnerability_description: str
    cve_ids: list[str] = field(default_factory=list)
    osv_metadata: dict[str, any] = field(default_factory=dict)
    existing_dependencies: list[dict[str, str]] = field(default_factory=list)
    target_environment: str = "container"  # container, standalone, cloud
    performance_requirements: str = "standard"  # minimal, standard, optimized
    security_requirements: str = "demonstration"  # demonstration, production, hardened
    framework_preferences: list[FrameworkType] = field(default_factory=list)
    framework_exclusions: list[FrameworkType] = field(default_factory=list)
    additional_context: dict[str, any] = field(default_factory=dict)


@dataclass
class AdaptationResult:
    """Comprehensive result of framework adaptation process."""
    
    context: AdaptationContext
    framework_choice: FrameworkChoice | None = None
    code_adaptation: CodeAdaptation | None = None
    template_customizations: dict[str, str] = field(default_factory=dict)
    deployment_configuration: dict[str, any] = field(default_factory=dict)
    validation_results: dict[str, any] = field(default_factory=dict)
    performance_metrics: dict[str, float] = field(default_factory=dict)
    success: bool = False
    error_details: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    adaptation_time_seconds: float = 0.0
    llm_usage_stats: dict[str, any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def add_error(self, error: str) -> None:
        """Add an error to the result."""
        self.error_details.append(error)
        self.success = False
        logger.error(f"Framework adaptation error: {error}")
    
    def add_warning(self, warning: str) -> None:
        """Add a warning to the result."""
        self.warnings.append(warning)
        logger.warning(f"Framework adaptation warning: {warning}")
    
    def mark_success(self) -> None:
        """Mark the adaptation as successful."""
        if not self.error_details:
            self.success = True
            framework_name = self.framework_choice.selected_framework.value if self.framework_choice else "unknown"
            logger.info(f"Framework adaptation successful: {framework_name}")


@dataclass
class FrameworkPattern:
    """Represents a framework-specific pattern for vulnerability demonstration."""
    
    framework_type: FrameworkType
    pattern_name: str
    pattern_description: str
    code_template: str
    required_dependencies: list[dict[str, str]] = field(default_factory=list)
    configuration_template: str = ""
    entry_point_template: str = ""
    vulnerability_trigger: str = ""
    expected_behavior: str = ""
    ioc_patterns: list[str] = field(default_factory=list)
    usage_examples: list[str] = field(default_factory=list)
    complexity_level: AdaptationComplexity = AdaptationComplexity.SIMPLE
    maintenance_notes: str = ""


@dataclass
class FrameworkAdaptationMetrics:
    """Metrics for tracking framework adaptation performance."""
    
    framework_type: FrameworkType
    total_adaptations: int = 0
    successful_adaptations: int = 0
    failed_adaptations: int = 0
    average_adaptation_time: float = 0.0
    average_confidence_score: float = 0.0
    common_adaptation_strategies: dict[AdaptationStrategy, int] = field(default_factory=dict)
    common_failure_reasons: dict[str, int] = field(default_factory=dict)
    vulnerability_type_success_rates: dict[str, float] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        """Calculate the overall success rate."""
        if self.total_adaptations == 0:
            return 0.0
        return self.successful_adaptations / self.total_adaptations
    
    def record_adaptation(self, result: AdaptationResult) -> None:
        """Record an adaptation attempt."""
        self.total_adaptations += 1
        
        if result.success:
            self.successful_adaptations += 1
            if result.framework_choice:
                self.average_confidence_score = (
                    (self.average_confidence_score * (self.successful_adaptations - 1) + 
                     result.framework_choice.confidence_score) / self.successful_adaptations
                )
        else:
            self.failed_adaptations += 1
            # Record failure reasons
            for error in result.error_details:
                self.common_failure_reasons[error] = self.common_failure_reasons.get(error, 0) + 1
        
        # Update adaptation strategy usage
        if result.framework_choice:
            strategy = result.framework_choice.adaptation_strategy
            self.common_adaptation_strategies[strategy] = self.common_adaptation_strategies.get(strategy, 0) + 1
        
        # Update average adaptation time
        self.average_adaptation_time = (
            (self.average_adaptation_time * (self.total_adaptations - 1) + 
             result.adaptation_time_seconds) / self.total_adaptations
        )
        
        # Update vulnerability type success rates
        vuln_type = result.context.vulnerability_type
        if vuln_type not in self.vulnerability_type_success_rates:
            self.vulnerability_type_success_rates[vuln_type] = 0.0
        
        # Calculate new success rate for this vulnerability type
        vuln_successes = sum(1 for _ in range(self.total_adaptations) if result.success)
        vuln_total = sum(1 for _ in range(self.total_adaptations))
        if vuln_total > 0:
            self.vulnerability_type_success_rates[vuln_type] = vuln_successes / vuln_total
        
        self.last_updated = datetime.now()


# Framework-specific configuration schemas
FRAMEWORK_CONFIGURATIONS = {
    FrameworkType.SPRING_BOOT: {
        "required_dependencies": [
            {"group_id": "org.springframework.boot", "artifact_id": "spring-boot-starter"},
            {"group_id": "org.springframework.boot", "artifact_id": "spring-boot-starter-web"},
        ],
        "main_class_pattern": "VulnApplication",
        "annotation_requirements": ["@SpringBootApplication"],
        "package_structure": "src/main/java/com/vuln/demo",
        "configuration_files": ["application.properties", "application.yml"],
        "default_port": 8080,
        "framework_features": ["auto-configuration", "embedded-server", "actuator"],
    },
    FrameworkType.APACHE_STRUTS: {
        "required_dependencies": [
            {"group_id": "org.apache.struts", "artifact_id": "struts2-core"},
            {"group_id": "org.apache.struts", "artifact_id": "struts2-convention-plugin"},
        ],
        "main_class_pattern": "VulnerableAction",
        "annotation_requirements": ["@Action"],
        "package_structure": "src/main/java/com/vuln/action",
        # NOTE: configuration_files listed here are INJECTED BY TEMPLATES, not generated by LLM
        # The LLM should NEVER create these files - template system handles all configuration
        "configuration_files": [],  # Empty - templates inject struts.xml and web.xml during deployment
        "template_injected_configs": ["struts.xml", "web.xml"],  # Documentation of what templates provide
        "default_port": 8080,
        "framework_features": ["action-based", "interceptors", "result-types", "war-packaging"],
    },
    FrameworkType.MICRONAUT: {
        "required_dependencies": [
            {"group_id": "io.micronaut", "artifact_id": "micronaut-http"},
            {"group_id": "io.micronaut", "artifact_id": "micronaut-http-server-netty"},
        ],
        "main_class_pattern": "VulnApplication",
        "annotation_requirements": ["@Application"],
        "package_structure": "src/main/java/com/vuln/demo",
        "configuration_files": ["application.yml", "application.properties"],
        "default_port": 8080,
        "framework_features": ["reactive", "compile-time-di", "native-image"],
    },
    FrameworkType.QUARKUS: {
        "required_dependencies": [
            {"group_id": "io.quarkus", "artifact_id": "quarkus-resteasy"},
            {"group_id": "io.quarkus", "artifact_id": "quarkus-arc"},
        ],
        "main_class_pattern": "VulnResource",
        "annotation_requirements": ["@Path"],
        "package_structure": "src/main/java/com/vuln/resource",
        "configuration_files": ["application.properties"],
        "default_port": 8080,
        "framework_features": ["native-compilation", "fast-startup", "low-memory"],
    },
}


# Common vulnerability type to framework suitability mapping for web-based demonstrations
VULNERABILITY_FRAMEWORK_SUITABILITY = {
    "deserialization": {
        FrameworkType.SPRING_BOOT: FrameworkSuitability.EXCELLENT,
        FrameworkType.APACHE_STRUTS: FrameworkSuitability.EXCELLENT,
        FrameworkType.MICRONAUT: FrameworkSuitability.GOOD,
        FrameworkType.QUARKUS: FrameworkSuitability.GOOD,
        FrameworkType.WEB_APPLICATION: FrameworkSuitability.GOOD,
    },
    "web_vulnerability": {
        FrameworkType.SPRING_BOOT: FrameworkSuitability.EXCELLENT,
        FrameworkType.APACHE_STRUTS: FrameworkSuitability.EXCELLENT,
        FrameworkType.MICRONAUT: FrameworkSuitability.GOOD,
        FrameworkType.QUARKUS: FrameworkSuitability.GOOD,
        FrameworkType.WEB_APPLICATION: FrameworkSuitability.EXCELLENT,
    },
    "injection": {
        FrameworkType.SPRING_BOOT: FrameworkSuitability.EXCELLENT,
        FrameworkType.APACHE_STRUTS: FrameworkSuitability.EXCELLENT,
        FrameworkType.MICRONAUT: FrameworkSuitability.GOOD,
        FrameworkType.QUARKUS: FrameworkSuitability.GOOD,
        FrameworkType.WEB_APPLICATION: FrameworkSuitability.GOOD,
    },
    "library_vulnerability": {
        FrameworkType.SPRING_BOOT: FrameworkSuitability.EXCELLENT,
        FrameworkType.APACHE_STRUTS: FrameworkSuitability.GOOD,
        FrameworkType.MICRONAUT: FrameworkSuitability.GOOD,
        FrameworkType.QUARKUS: FrameworkSuitability.GOOD,
        FrameworkType.WEB_APPLICATION: FrameworkSuitability.GOOD,
    },
}