import logging
import sys
import traceback
from dataclasses import dataclass, field
from enum import Enum

from shared.constants import (
    CODE_GENERATION_ERROR,
    CONFIGURATION_ERROR,
    CONTAINER_BUILD_ERROR,
    CRITICAL,
    DEPENDENCY_ERROR,
    ERROR,
    INFO,
    LLM_ERROR,
    NETWORK_ERROR,
    PERMISSION_ERROR,
    RESOURCE_ERROR,
    TEMPLATE_ERROR,
    UNKNOWN_ERROR,
    VALIDATION_ERROR,
    WARNING,
)

logger = logging.getLogger(__name__)
logger.propagate = True


class ErrorSeverity(Enum):
    """Severity levels for errors."""

    INFO = INFO
    WARNING = WARNING
    ERROR = ERROR
    CRITICAL = CRITICAL


class ErrorCategory(Enum):
    """Categories of errors for better classification."""

    CONFIGURATION = CONFIGURATION_ERROR
    TEMPLATE = TEMPLATE_ERROR
    CODE_GENERATION = CODE_GENERATION_ERROR
    CONTAINER_BUILD = CONTAINER_BUILD_ERROR
    DEPENDENCY = DEPENDENCY_ERROR
    NETWORK = NETWORK_ERROR
    PERMISSION = PERMISSION_ERROR
    LLM = LLM_ERROR
    VALIDATION = VALIDATION_ERROR
    RESOURCE = RESOURCE_ERROR
    UNKNOWN = UNKNOWN_ERROR


@dataclass
class VulnerabilityError(Exception):
    """
    Base class for all vulnerability-related errors.
    Provides standardized error information and formatting.
    """

    message: str
    category: ErrorCategory = ErrorCategory.UNKNOWN
    severity: ErrorSeverity = ErrorSeverity.ERROR
    details: dict = field(default_factory=dict)
    cause: Exception | None = None
    remedy: str | None = None

    def __post_init__(self):
        """Initialize the exception with proper message."""
        # Construct a comprehensive error message
        full_message = f"{self.severity.name}: {self.message}"
        if self.cause:
            full_message += f" | Caused by: {str(self.cause)}"

        super().__init__(full_message)

    def to_dict(self) -> dict:
        """Convert error to a dictionary representation."""
        result = {
            "message": self.message,
            "category": self.category.name,
            "severity": self.severity.name,
            "details": {},
        }

        if self.details:
            result["details"] = self.details

        if self.cause:
            result["cause"] = str(self.cause)

        if self.remedy:
            result["remedy"] = self.remedy

        return result

    def log(self) -> None:
        """Log the error with appropriate severity level."""
        log_message = f"{self.category.name}: {self.message}"

        if self.remedy:
            log_message += f" | Remedy: {self.remedy}"

        # Get the root logger to ensure consistent handler usage
        root_logger = logging.getLogger()

        if self.severity == ErrorSeverity.CRITICAL:
            root_logger.critical(log_message, exc_info=self.cause or True)
        elif self.severity == ErrorSeverity.ERROR:
            root_logger.error(log_message, exc_info=self.cause or True)
        elif self.severity == ErrorSeverity.WARNING:
            root_logger.warning(log_message, exc_info=self.cause)
        else:
            root_logger.info(log_message)


class TemplateError(VulnerabilityError):
    """Error related to template loading or parsing."""

    def __init__(
        self,
        message: str,
        details: dict | None = None,
        cause: Exception | None = None,
        remedy: str | None = None,
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.TEMPLATE,
            severity=ErrorSeverity.ERROR,
            details=details or {},
            cause=cause,
            remedy=remedy,
        )


class CodeGenerationError(VulnerabilityError):
    """Error related to code generation."""

    def __init__(
        self,
        message: str,
        details: dict | None = None,
        cause: Exception | None = None,
        remedy: str | None = None,
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.CODE_GENERATION,
            severity=ErrorSeverity.ERROR,
            details=details or {},
            cause=cause,
            remedy=remedy,
        )


class ContainerBuildError(VulnerabilityError):
    """Error related to container building."""

    def __init__(
        self,
        message: str,
        details: dict | None = None,
        cause: Exception | None = None,
        remedy: str | None = None,
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.CONTAINER_BUILD,
            severity=ErrorSeverity.ERROR,
            details=details or {},
            cause=cause,
            remedy=remedy,
        )


class DependencyError(VulnerabilityError):
    """Error related to dependency resolution."""

    def __init__(
        self,
        message: str,
        details: dict | None = None,
        cause: Exception | None = None,
        remedy: str | None = None,
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.DEPENDENCY,
            severity=ErrorSeverity.ERROR,
            details=details or {},
            cause=cause,
            remedy=remedy,
        )


class LLMError(VulnerabilityError):
    """Error related to LLM operations."""

    def __init__(
        self,
        message: str,
        details: dict | None = None,
        cause: Exception | None = None,
        remedy: str | None = None,
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.LLM,
            severity=ErrorSeverity.ERROR,
            details=details or {},
            cause=cause,
            remedy=remedy,
        )


class ValidationError(VulnerabilityError):
    """Error related to data validation."""

    def __init__(
        self,
        message: str,
        details: dict | None = None,
        cause: Exception | None = None,
        remedy: str | None = None,
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.ERROR,
            details=details or {},
            cause=cause,
            remedy=remedy,
        )


def handle_error(
    error: Exception,
    exit_on_error: bool = False,
    default_category: ErrorCategory = ErrorCategory.UNKNOWN,
    default_severity: ErrorSeverity = ErrorSeverity.ERROR,
) -> VulnerabilityError:
    """
    Handle an exception, converting it to a VulnerabilityError.

    Args:
        error: The exception to handle
        exit_on_error: Whether to exit the program after handling
        default_category: Default category if not a VulnerabilityError
        default_severity: Default severity if not a VulnerabilityError

    Returns:
        VulnerabilityError instance
    """
    # If already a VulnerabilityError, use it directly
    if isinstance(error, VulnerabilityError):
        vuln_error = error
    else:
        # Convert to VulnerabilityError
        vuln_error = VulnerabilityError(
            message=str(error),
            category=default_category,
            severity=default_severity,
            cause=error,
            details={"traceback": traceback.format_exc()},
        )

    # Log the error
    vuln_error.log()

    # Exit if required
    if exit_on_error:
        print(f"FATAL: {vuln_error.message}", file=sys.stderr)
        if vuln_error.remedy:
            print(f"REMEDY: {vuln_error.remedy}", file=sys.stderr)
        sys.exit(1)

    return vuln_error
