from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from jinja2 import Template


@dataclass
class PlaceholderDef:
    """
    Definition of a template placeholder variable.

    Attributes:
        name: Variable name (e.g., "cve_id", "package_name")
        type: Expected type ("string", "list", "dict", "int", "bool")
        description: Human-readable description of the placeholder
        default: Default value if not provided (None = required)
        enricher: Name of enricher to automatically populate this placeholder
        validator: Optional custom validation function
    """
    name: str
    type: str = "string"
    description: str = ""
    default: Any = None
    enricher: Optional[str] = None
    validator: Optional[Callable] = None

    def validate_value(self, value: Any) -> tuple[bool, str]:
        """
        Validate a value against this placeholder definition.

        Args:
            value: The value to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check type
        if self.type == "string" and not isinstance(value, str):
            return False, f"{self.name} must be a string, got {type(value).__name__}"
        elif self.type == "list" and not isinstance(value, list):
            return False, f"{self.name} must be a list, got {type(value).__name__}"
        elif self.type == "dict" and not isinstance(value, dict):
            return False, f"{self.name} must be a dict, got {type(value).__name__}"
        elif self.type == "int" and not isinstance(value, int):
            return False, f"{self.name} must be an int, got {type(value).__name__}"
        elif self.type == "bool" and not isinstance(value, bool):
            return False, f"{self.name} must be a bool, got {type(value).__name__}"

        # Custom validator
        if self.validator:
            try:
                if not self.validator(value):
                    return False, f"{self.name} failed custom validation"
            except Exception as e:
                return False, f"{self.name} validation error: {e}"

        return True, ""


@dataclass
class TemplateMetadata:
    """
    Metadata about a prompt template.

    Attributes:
        name: Template identifier
        version: Semantic version (e.g., "1.0.0")
        description: Human-readable description
        category: Category for organization (e.g., "vulnerability", "framework")
        author: Author or team name
        last_updated: Last modification date
        tags: List of tags for filtering/search
        classification_level: Optional vulnerability classification level
        framework_hints: Optional list of framework types this template works with
        vulnerability_types: Optional list of vulnerability types
    """
    name: str
    version: str = "1.0.0"
    description: str = ""
    category: str = "general"
    author: str = "FORGE Framework"
    last_updated: Optional[datetime] = None
    tags: list[str] = field(default_factory=list)
    classification_level: Optional[str] = None
    framework_hints: list[str] = field(default_factory=list)
    vulnerability_types: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "TemplateMetadata":
        """Create TemplateMetadata from dictionary."""
        # Handle datetime parsing
        last_updated = data.get("last_updated")
        if last_updated and isinstance(last_updated, str):
            try:
                last_updated = datetime.fromisoformat(last_updated)
            except ValueError:
                last_updated = None

        return cls(
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            category=data.get("category", "general"),
            author=data.get("author", "FORGE Framework"),
            last_updated=last_updated,
            tags=data.get("tags", []),
            classification_level=data.get("classification_level"),
            framework_hints=data.get("framework_hints", []),
            vulnerability_types=data.get("vulnerability_types", [])
        )


@dataclass
class ComposablePromptTemplate:
    """
    A prompt template with composition capabilities.

    Supports template inheritance (extends), fragment inclusion (includes),
    Jinja2 rendering, and placeholder validation.

    Attributes:
        name: Template identifier
        content: Raw template content (Jinja2 syntax)
        metadata: Template metadata
        extends: Base template name to extend (inheritance)
        includes: List of fragment names to include
        required_placeholders: List of required placeholder definitions
        optional_placeholders: List of optional placeholder definitions
        compiled_template: Cached Jinja2 compiled template
    """
    name: str
    content: str
    metadata: TemplateMetadata
    extends: Optional[str] = None
    includes: list[str] = field(default_factory=list)
    required_placeholders: list[PlaceholderDef] = field(default_factory=list)
    optional_placeholders: list[PlaceholderDef] = field(default_factory=list)
    compiled_template: Optional[Template] = None

    def get_all_placeholders(self) -> dict[str, PlaceholderDef]:
        """Get all placeholders (required + optional) as a dict."""
        result = {}
        for placeholder in self.required_placeholders:
            result[placeholder.name] = placeholder
        for placeholder in self.optional_placeholders:
            result[placeholder.name] = placeholder
        return result

    def validate_context(self, context: dict) -> "ValidationResult":
        """
        Validate that context contains all required placeholders.

        Args:
            context: Context dictionary to validate

        Returns:
            ValidationResult with errors and warnings
        """
        errors = []
        warnings = []

        # Check required placeholders
        for placeholder in self.required_placeholders:
            if placeholder.name not in context:
                errors.append(f"Missing required placeholder: {placeholder.name}")
            else:
                # Validate value type
                is_valid, error_msg = placeholder.validate_value(context[placeholder.name])
                if not is_valid:
                    errors.append(error_msg)

        # Check optional placeholders that are present
        for placeholder in self.optional_placeholders:
            if placeholder.name in context:
                is_valid, error_msg = placeholder.validate_value(context[placeholder.name])
                if not is_valid:
                    warnings.append(error_msg)

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def render(self, context: dict) -> str:
        """
        Render template with context using Jinja2.

        Args:
            context: Context dictionary with variable values

        Returns:
            Rendered template string

        Raises:
            ValueError: If template not compiled or context invalid
        """
        if not self.compiled_template:
            raise ValueError(f"Template '{self.name}' not compiled. Call compile() first.")

        # Validate context
        validation = self.validate_context(context)
        if not validation.is_valid:
            raise ValueError(f"Invalid context for template '{self.name}': {validation.errors}")

        # Add defaults for optional placeholders
        full_context = context.copy()
        for placeholder in self.optional_placeholders:
            if placeholder.name not in full_context and placeholder.default is not None:
                full_context[placeholder.name] = placeholder.default

        # Render with Jinja2
        return self.compiled_template.render(**full_context)


@dataclass
class ValidationResult:
    """
    Result of template or context validation.

    Attributes:
        is_valid: Whether validation passed
        errors: List of error messages (prevent execution)
        warnings: List of warning messages (allow execution)
    """
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        """String representation for logging."""
        if self.is_valid:
            msg = "Validation passed"
            if self.warnings:
                msg += f" with {len(self.warnings)} warning(s)"
        else:
            msg = f"Validation failed with {len(self.errors)} error(s)"

        if self.errors:
            msg += "\nErrors:\n  - " + "\n  - ".join(self.errors)
        if self.warnings:
            msg += "\nWarnings:\n  - " + "\n  - ".join(self.warnings)

        return msg


@dataclass
class PromptFragment:
    """
    A reusable prompt fragment that can be included in templates.

    Fragments are small, reusable pieces of prompt text that appear
    across multiple templates (e.g., version guidance instructions,
    JSON output format specifications).

    Attributes:
        name: Fragment identifier
        content: Fragment content (Jinja2 syntax)
        description: Human-readable description
        required_variables: Variables this fragment expects
    """
    name: str
    content: str
    description: str = ""
    required_variables: list[str] = field(default_factory=list)


@dataclass
class EnricherConfig:
    """
    Configuration for a context enricher.

    Attributes:
        name: Enricher identifier
        enricher_class: Class name of the enricher
        enabled: Whether this enricher is active
        config: Additional configuration for the enricher
        priority: Execution priority (lower = earlier)
    """
    name: str
    enricher_class: str
    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)
    priority: int = 100
