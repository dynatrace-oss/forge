from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ErrorType(Enum):
    """Types of errors that can be recovered."""
    
    CONTAINER_BUILD_FAILURE = "container_build_failure"
    VALIDATION_FAILURE = "validation_failure"
    DEPENDENCY_RESOLUTION = "dependency_resolution"
    JAVA_COMPILATION = "java_compilation"
    RESOURCE_NOT_FOUND = "resource_not_found"
    NETWORK_TIMEOUT = "network_timeout"
    PERMISSION_DENIED = "permission_denied"
    MEMORY_ERROR = "memory_error"
    CONFIGURATION_ERROR = "configuration_error"
    TEMPLATE_ERROR = "template_error"
    LLM_GENERATION_ERROR = "llm_generation_error"
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    CRITICAL = "critical"


class FixType(Enum):
    """Types of fixes that can be applied."""
    
    DEPENDENCY_UPDATE = "dependency_update"
    CODE_MODIFICATION = "code_modification"
    CONFIGURATION_CHANGE = "configuration_change"
    TEMPLATE_SUBSTITUTION = "template_substitution"
    RESOURCE_ADDITION = "resource_addition"
    IMPORT_ADDITION = "import_addition"
    CLASS_RENAME = "class_rename"
    METHOD_SIGNATURE_FIX = "method_signature_fix"
    PACKAGE_DECLARATION_FIX = "package_declaration_fix"
    CONTAINERFILE_UPDATE = "containerfile_update"
    POM_XML_FIX = "pom_xml_fix"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    FALLBACK_STRATEGY = "fallback_strategy"


class RecoveryStatus(Enum):
    """Status of recovery attempts."""
    
    NOT_ATTEMPTED = "not_attempted"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL_SUCCESS = "partial_success"
    MAX_ATTEMPTS_REACHED = "max_attempts_reached"
    SKIPPED = "skipped"



@dataclass 
class ErrorContext:
    """Context information about an error that occurred."""
    
    error_id: str
    timestamp: datetime
    error_type: ErrorType
    severity: ErrorSeverity
    
    # Error details
    error_message: str
    stack_trace: str | None = None
    exit_code: int | None = None
    
    # Context information
    blueprint_id: str | None = None
    container_name: str | None = None
    operation: str | None = None  # e.g., "build", "run", "validate"
    
    # Log data
    stdout_logs: str = ""
    stderr_logs: str = ""
    container_logs: str = ""
    
    # File context
    affected_files: list[str] = field(default_factory=list)
    file_contents: dict[str, str] = field(default_factory=dict)
    
    # Environment context
    environment_vars: dict[str, str] = field(default_factory=dict)
    system_info: dict[str, any] = field(default_factory=dict)
    
    # Pattern matching results
    matched_patterns: list[str] = field(default_factory=list)
    confidence_scores: dict[str, float] = field(default_factory=dict)


@dataclass
class FixAction:
    """Represents a specific fix action to be applied."""
    
    action_id: str
    fix_type: FixType
    description: str
    
    # Fix details
    target_file: str | None = None
    content_changes: dict[str, str] = field(default_factory=dict)  # old_content -> new_content
    file_additions: dict[str, str] = field(default_factory=dict)  # file_path -> content
    file_deletions: list[str] = field(default_factory=list)
    
    # Command-based fixes
    commands: list[str] = field(default_factory=list)
    
    # Validation
    validation_commands: list[str] = field(default_factory=list)
    expected_outcomes: list[str] = field(default_factory=list)
    
    # Metadata
    priority: int = 5  # 1-10, higher is more important
    confidence: float = 0.5
    estimated_duration_seconds: int = 60
    requires_rollback: bool = True
    rollback_actions: list["FixAction"] = field(default_factory=list)


@dataclass
class FixResult:
    """Result of applying a fix action."""
    
    action_id: str
    status: RecoveryStatus
    applied_at: datetime
    completed_at: datetime | None = None
    
    # Results
    success: bool = False
    error_message: str | None = None
    output_logs: str = ""
    
    # Changes made
    files_modified: list[str] = field(default_factory=list)
    files_created: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)
    commands_executed: list[str] = field(default_factory=list)
    
    # Validation results
    validation_passed: bool = False
    validation_output: str = ""
    
    # Performance metrics
    execution_time_seconds: float = 0.0
    
    def mark_completed(self, success: bool, error_message: str | None = None) -> None:
        """Mark the fix as completed with the given result."""
        self.completed_at = datetime.now()
        self.success = success
        self.error_message = error_message
        self.status = RecoveryStatus.SUCCESS if success else RecoveryStatus.FAILED
        
        if self.applied_at and self.completed_at:
            self.execution_time_seconds = (self.completed_at - self.applied_at).total_seconds()


@dataclass
class RecoveryAttempt:
    """Represents a complete recovery attempt for an error."""
    
    attempt_id: str
    error_context: ErrorContext
    started_at: datetime
    completed_at: datetime | None = None
    
    # Recovery strategy
    strategy_name: str = "react_loop"
    max_iterations: int = 3
    current_iteration: int = 0
    
    # Recovery actions
    planned_actions: list[FixAction] = field(default_factory=list)
    executed_actions: list[FixResult] = field(default_factory=list)
    
    # Results
    final_status: RecoveryStatus = RecoveryStatus.NOT_ATTEMPTED
    recovery_successful: bool = False
    final_error_message: str | None = None
    
    # Metrics
    total_execution_time_seconds: float = 0.0
    actions_attempted: int = 0
    actions_successful: int = 0
    
    # Learning data
    llm_analysis: dict[str, any] = field(default_factory=dict)
    pattern_matches: list[str] = field(default_factory=list)
    osv_references_used: list[str] = field(default_factory=list)
    
    def add_action_result(self, result: FixResult) -> None:
        """Add a fix result to this recovery attempt."""
        self.executed_actions.append(result)
        self.actions_attempted += 1
        if result.success:
            self.actions_successful += 1
    
    def mark_completed(self, success: bool, error_message: str | None = None) -> None:
        """Mark the recovery attempt as completed."""
        self.completed_at = datetime.now()
        self.recovery_successful = success
        self.final_error_message = error_message
        self.final_status = RecoveryStatus.SUCCESS if success else RecoveryStatus.FAILED
        
        if self.started_at and self.completed_at:
            self.total_execution_time_seconds = (self.completed_at - self.started_at).total_seconds()
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate of actions in this attempt."""
        return self.actions_successful / self.actions_attempted if self.actions_attempted > 0 else 0.0




@dataclass
class ErrorRecoveryMetrics:
    """Metrics for error recovery system performance."""
    
    # Overall statistics
    total_errors_encountered: int = 0
    total_recovery_attempts: int = 0
    successful_recoveries: int = 0
    failed_recoveries: int = 0
    
    # Performance metrics
    average_recovery_time_seconds: float = 0.0
    fastest_recovery_time_seconds: float = float('inf')
    slowest_recovery_time_seconds: float = 0.0
    
    # Pattern statistics
    patterns_learned: int = 0
    patterns_applied: int = 0
    pattern_success_rate: float = 0.0
    
    # Error type breakdown
    error_type_counts: dict[ErrorType, int] = field(default_factory=dict)
    error_type_success_rates: dict[ErrorType, float] = field(default_factory=dict)
    
    # Time-based metrics
    last_updated: datetime = field(default_factory=datetime.now)
    metrics_period_start: datetime = field(default_factory=datetime.now)
    
    def update_recovery_result(self, attempt: RecoveryAttempt) -> None:
        """Update metrics with a completed recovery attempt."""
        self.total_recovery_attempts += 1
        
        if attempt.recovery_successful:
            self.successful_recoveries += 1
        else:
            self.failed_recoveries += 1
        
        # Update timing metrics
        if attempt.total_execution_time_seconds > 0:
            self.average_recovery_time_seconds = (
                (self.average_recovery_time_seconds * (self.total_recovery_attempts - 1) + 
                 attempt.total_execution_time_seconds) / self.total_recovery_attempts
            )
            
            self.fastest_recovery_time_seconds = min(
                self.fastest_recovery_time_seconds, 
                attempt.total_execution_time_seconds
            )
            
            self.slowest_recovery_time_seconds = max(
                self.slowest_recovery_time_seconds,
                attempt.total_execution_time_seconds
            )
        
        # Update error type statistics
        error_type = attempt.error_context.error_type
        if error_type not in self.error_type_counts:
            self.error_type_counts[error_type] = 0
        self.error_type_counts[error_type] += 1
        
        # Update success rates by error type
        type_total = self.error_type_counts[error_type]
        current_successes = self.error_type_success_rates.get(error_type, 0) * (type_total - 1)
        if attempt.recovery_successful:
            current_successes += 1
        self.error_type_success_rates[error_type] = current_successes / type_total
        
        self.last_updated = datetime.now()
    
    @property
    def total_attempts(self) -> int:
        """Alias for total_recovery_attempts for compatibility."""
        return self.total_recovery_attempts
    
    @property
    def overall_success_rate(self) -> float:
        """Calculate overall recovery success rate."""
        return (self.successful_recoveries / self.total_recovery_attempts 
                if self.total_recovery_attempts > 0 else 0.0)