from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List, Any

@dataclass
class ValidationResult:
    """
    Result of vulnerability validation testing.

    Contains information about whether a vulnerability was successfully
    demonstrated and supporting evidence.
    """

    vulnerability_demonstrated: bool
    indicators_found: list[str]
    confidence_score: float
    details: str | None = None

    def __post_init__(self):
        """Validate the confidence score is within valid range."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")


@dataclass
class ExploitValidationResult:
    """
    Validation of exploit against a specific blueprint.
    """

    blueprint_id: str
    success: bool
    validation_results: list[ValidationResult]
    total_payloads_tested: int
    successful_payloads: int
    execution_time_seconds: float
    error_message: str | None = None

    @property
    def success_rate(self) -> float:
        """Calculate the success rate of payload testing."""
        if self.total_payloads_tested == 0:
            return 0.0
        return self.successful_payloads / self.total_payloads_tested

    @property
    def overall_confidence(self) -> float:
        """Calculate overall confidence based on all validation results."""
        if not self.validation_results:
            return 0.0

        total_confidence = sum(result.confidence_score for result in self.validation_results)
        return total_confidence / len(self.validation_results)

    @property
    def vulnerability_demonstrated(self) -> bool:
        """Check if any validation result demonstrates a vulnerability."""
        return any(result.vulnerability_demonstrated for result in self.validation_results)

    @property
    def exploitation_indicators(self) -> list[str]:
        """Get all indicators found across validation results."""
        indicators = []
        for result in self.validation_results:
            indicators.extend(result.indicators_found)
        return indicators


@dataclass
class ComprehensiveValidationResult:
    """
    Comprehensive validation result matching manual testing format.

    This format includes all information needed for tracking, analysis,
    and reproduction of validation tests.
    """

    # Core identifiers
    validation_id: str
    blueprint_id: str
    cve_id: str
    ghsa_id: Optional[str] = None

    # Container information
    container_name: str = ""
    container_port: int = 0

    # Exploit information
    exploit_script: str = ""
    exploit_exit_code: int = -1
    exploit_output_snippet: str = ""

    # Validation results
    exploitation_confirmed: bool = False
    validation_score: float = 0.0
    validation_result: str = "NOT_TESTED"  # EXPLOITABLE, NOT_EXPLOITABLE, ERROR
    exploitation_indicators: List[str] = field(default_factory=list)

    # Container logs
    container_logs_snippet: str = ""

    # Timing and metadata
    test_duration_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    validation_method: str = "automated"
    notes: str = ""

    # Vulnerability details
    vulnerability_details: Dict[str, Any] = field(default_factory=dict)

    # Test metadata
    test_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate fields after initialization."""
        if not 0.0 <= self.validation_score <= 1.0:
            raise ValueError("Validation score must be between 0.0 and 1.0")

        # Set validation result based on score if not explicitly set
        if self.validation_result == "NOT_TESTED" and self.validation_score > 0:
            if self.validation_score >= 0.7:
                self.validation_result = "EXPLOITABLE"
            elif self.validation_score >= 0.4:
                self.validation_result = "PARTIALLY_EXPLOITABLE"
            else:
                self.validation_result = "NOT_EXPLOITABLE"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "validation_id": self.validation_id,
            "blueprint_id": self.blueprint_id,
            "cve_id": self.cve_id,
            "ghsa_id": self.ghsa_id,
            "container_name": self.container_name,
            "container_port": self.container_port,
            "exploit_script": self.exploit_script,
            "exploitation_confirmed": self.exploitation_confirmed,
            "validation_score": self.validation_score,
            "validation_result": self.validation_result,
            "exploitation_indicators": self.exploitation_indicators,
            "exploit_exit_code": self.exploit_exit_code,
            "exploit_output_snippet": self.exploit_output_snippet,
            "container_logs_snippet": self.container_logs_snippet,
            "test_duration_seconds": self.test_duration_seconds,
            "timestamp": self.timestamp,
            "validation_method": self.validation_method,
            "notes": self.notes,
            "vulnerability_details": self.vulnerability_details,
            "test_metadata": self.test_metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ComprehensiveValidationResult':
        """Create instance from dictionary."""
        return cls(**data)
