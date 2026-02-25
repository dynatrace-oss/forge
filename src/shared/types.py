from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class TemplateType(Enum):
    """Types of templates supported by the system."""

    JAVA = "java"
    PYTHON = "python"
    RUBY = "ruby"
    GENERIC = "generic"


class TemplateSection(Enum):
    """Template sections."""

    METADATA = "metadata"
    IMPORTS = "imports"
    DEMO_CODE = "demo_code"
    RESOURCES = "resources"
    EXPLOITATION = "exploitation"
    MITIGATION = "mitigation"
    DEPENDENCIES = "dependencies"
    CONTAINER_CONFIG = "container_config"


class FrameworkType(Enum):
    """Supported framework types for web-based vulnerability demonstrations."""

    SPRING_BOOT = "spring_boot"
    APACHE_STRUTS = "apache_struts"
    JENKINS_PLUGIN = "jenkins_plugin"
    MICRONAUT = "micronaut"
    QUARKUS = "quarkus"
    WEB_APPLICATION = "web_application"


class IoCType(Enum):
    """Types of Indicators of Compromise (IoCs) collected during vulnerability testing."""

    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    APPLICATION = "application"
    TIMING = "timing"
    BEHAVIORAL = "behavioral"


class IoCCategory(Enum):
    """Specific categories within IoC types for detailed classification."""

    # Network IoCs
    HTTP_REQUEST = "http_request"
    DNS_LOOKUP = "dns_lookup"
    NETWORK_CONNECTION = "network_connection"
    URL_ACCESS = "url_access"
    PORT_SCAN = "port_scan"

    # Filesystem IoCs
    FILE_CREATION = "file_creation"
    FILE_DELETION = "file_deletion"
    FILE_MODIFICATION = "file_modification"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    PERMISSION_CHANGE = "permission_change"
    TEMP_FILE_USAGE = "temp_file_usage"

    # Process IoCs
    COMMAND_EXECUTION = "command_execution"
    PROCESS_CREATION = "process_creation"
    ENVIRONMENT_MODIFICATION = "environment_modification"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_CALL = "system_call"

    # Application IoCs
    FRAMEWORK_ERROR = "framework_error"
    LIBRARY_LOADING = "library_loading"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_EXCEPTION = "security_exception"
    DESERIALIZATION_ATTEMPT = "deserialization_attempt"
    INJECTION_PATTERN = "injection_pattern"
    VULNERABILITY_INDICATOR = "vulnerability_indicator"

    # Timing IoCs
    EXECUTION_DELAY = "execution_delay"
    TIMEOUT_PATTERN = "timeout_pattern"
    RESPONSE_TIME_ANOMALY = "response_time_anomaly"
    TIMING_ATTACK_INDICATOR = "timing_attack_indicator"

    # Behavioral IoCs
    RESOURCE_CONSUMPTION = "resource_consumption"
    NETWORK_PATTERN = "network_pattern"
    ERROR_FREQUENCY = "error_frequency"
    LOG_PATTERN_ANOMALY = "log_pattern_anomaly"


class IoCConfidenceLevel(Enum):
    """Confidence levels for IoC detection accuracy."""

    LOW = "low"           # 0.0 - 0.3
    MEDIUM = "medium"     # 0.3 - 0.7
    HIGH = "high"         # 0.7 - 0.9
    CRITICAL = "critical" # 0.9 - 1.0


@dataclass
class IoC:
    """Individual Indicator of Compromise with metadata."""

    ioc_type: IoCType
    category: IoCCategory
    value: str
    description: str
    confidence: float
    confidence_level: IoCConfidenceLevel
    timestamp: datetime
    source_line: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Validate confidence score and set confidence level."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")
        
        # Auto-set confidence level based on score
        if self.confidence < 0.3:
            self.confidence_level = IoCConfidenceLevel.LOW
        elif self.confidence < 0.7:
            self.confidence_level = IoCConfidenceLevel.MEDIUM
        elif self.confidence < 0.9:
            self.confidence_level = IoCConfidenceLevel.HIGH
        else:
            self.confidence_level = IoCConfidenceLevel.CRITICAL


@dataclass
class IoCCollection:
    """Collection of IoCs organized by type and category."""

    blueprint_id: str
    container_id: str
    vulnerability_type: str
    collection_timestamp: datetime
    total_iocs: int
    iocs_by_type: Dict[IoCType, List[IoC]]
    iocs_by_category: Dict[IoCCategory, List[IoC]]
    confidence_summary: Dict[IoCConfidenceLevel, int]
    collection_metadata: Dict[str, Any]

    def get_ioc_count_by_type(self) -> Dict[str, int]:
        """Get count of IoCs by type."""
        return {ioc_type.value: len(iocs) for ioc_type, iocs in self.iocs_by_type.items()}

    def get_ioc_count_by_category(self) -> Dict[str, int]:
        """Get count of IoCs by category."""
        return {category.value: len(iocs) for category, iocs in self.iocs_by_category.items()}

    def get_high_confidence_iocs(self) -> List[IoC]:
        """Get all IoCs with high or critical confidence levels."""
        high_confidence_iocs = []
        for iocs in self.iocs_by_type.values():
            for ioc in iocs:
                if ioc.confidence_level in [IoCConfidenceLevel.HIGH, IoCConfidenceLevel.CRITICAL]:
                    high_confidence_iocs.append(ioc)
        return high_confidence_iocs


@dataclass
class IoCExtractionResult:
    """Result of IoC extraction from logs or container analysis."""

    success: bool
    total_iocs_extracted: int
    iocs: List[IoC]
    extraction_time_seconds: float
    error_message: Optional[str] = None
    source_data_size: int = 0
    
    def get_iocs_by_type(self, ioc_type: IoCType) -> List[IoC]:
        """Get IoCs filtered by type."""
        return [ioc for ioc in self.iocs if ioc.ioc_type == ioc_type]
    
    def get_iocs_by_category(self, category: IoCCategory) -> List[IoC]:
        """Get IoCs filtered by category."""
        return [ioc for ioc in self.iocs if ioc.category == category]


# ===== Error Recovery Types =====

class ErrorRecoveryPhase(Enum):
    """Phases of the error recovery process."""
    
    DETECTION = "detection"
    ANALYSIS = "analysis"
    PATTERN_MATCHING = "pattern_matching"
    FIX_GENERATION = "fix_generation"
    FIX_APPLICATION = "fix_application"
    VALIDATION = "validation"
    ROLLBACK = "rollback"
    LEARNING = "learning"


class ReactPhase(Enum):
    """Phases of the ReAct (Reason-Act-Observe) loop."""
    
    REASON = "reason"  # Analyze error and plan action
    ACT = "act"        # Apply fix action
    OBSERVE = "observe" # Evaluate results
    RETRY = "retry"    # Retry with new approach if needed


class ErrorRecoveryStrategy(Enum):
    """Different strategies for error recovery."""
    
    IMMEDIATE_RETRY = "immediate_retry"
    PATTERN_BASED = "pattern_based"
    LLM_GUIDED = "llm_guided"
    OSV_REFERENCE = "osv_reference"
    TEMPLATE_FALLBACK = "template_fallback"
    INCREMENTAL_FIX = "incremental_fix"
    ROLLBACK_AND_RETRY = "rollback_and_retry"


class FixValidationMethod(Enum):
    """Methods for validating that a fix was successful."""
    
    BUILD_SUCCESS = "build_success"
    CONTAINER_RUN = "container_run"
    VALIDATION_TEST = "validation_test"
    LOG_ANALYSIS = "log_analysis"
    MANUAL_VERIFICATION = "manual_verification"
    AUTOMATED_TESTING = "automated_testing"


class ErrorRecoveryTrigger(Enum):
    """Events that can trigger error recovery."""
    
    CONTAINER_BUILD_FAILURE = "container_build_failure"
    CONTAINER_RUN_FAILURE = "container_run_failure"
    VALIDATION_FAILURE = "validation_failure"
    LLM_GENERATION_FAILURE = "llm_generation_failure"
    TEMPLATE_PROCESSING_FAILURE = "template_processing_failure"
    DEPENDENCY_RESOLUTION_FAILURE = "dependency_resolution_failure"
    MANUAL_TRIGGER = "manual_trigger"
