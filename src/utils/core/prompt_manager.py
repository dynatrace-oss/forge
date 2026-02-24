import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# Get project root (same pattern as llm_service.py)
PROJECT_ROOT = Path(__file__).resolve().parents[3]

_prompt_template_service_instance: Optional['PromptTemplateService'] = None


@dataclass
class PromptTemplate:
    """
    Represents a prompt template with metadata.

    Attributes:
        name: Unique identifier for the prompt
        template: The actual prompt text with placeholders
        version: Semantic version of the prompt
        description: Human-readable description of what the prompt does
        category: Category for organization (e.g., "blueprint_management", "exploit_generation")
        required_placeholders: List of required variable names
        optional_placeholders: List of optional variable names
        examples: List of example usage dictionaries
        metadata: Full metadata dictionary from YAML
    """

    name: str
    template: str
    version: str = "1.0.0"
    description: str = ""
    category: str = "general"
    required_placeholders: list[str] = field(default_factory=list)
    optional_placeholders: list[str] = field(default_factory=list)
    examples: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class PromptManager:
    """
    Centralized prompt management system with PromptTemplateService integration.

    All templates use v2.0.0 Jinja2 format with enrichers and composition support.
    The manager delegates rendering to PromptTemplateService for full Jinja2 capabilities,
    with fallback to simple string replacement if advanced features are disabled.
    """

    def __init__(self, prompts_dir: Path | None = None, enable_advanced_features: bool = True):
        """
        Initialize the PromptManager.

        Args:
            prompts_dir: Directory containing YAML prompt files.
                        Defaults to PROJECT_ROOT/src/config/prompts
            enable_advanced_features: Whether to use PromptTemplateService (True) or fallback to simple string replacement (False)
        """
        self.prompts_dir = prompts_dir or (PROJECT_ROOT / "src" / "config" / "prompts")
        self.prompts: dict[str, PromptTemplate] = {}
        self.enable_advanced_features = enable_advanced_features
        self._load_prompts()

    def _load_prompts(self) -> None:
        """Load all YAML prompts from the prompts directory."""
        if not self.prompts_dir.exists():
            logger.warning(f"Prompts directory not found: {self.prompts_dir}")
            return

        # Load all .yaml and .yml files
        yaml_files = list(self.prompts_dir.glob("*.yaml")) + list(self.prompts_dir.glob("*.yml"))

        if not yaml_files:
            logger.warning(f"No YAML prompt files found in {self.prompts_dir}")
            return

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data:
                    logger.warning(f"Empty YAML file: {yaml_file.name}")
                    continue

                # Extract metadata
                metadata = data.get("metadata", {})
                placeholders = data.get("placeholders", {})
                template = data.get("template", "")
                examples = data.get("examples", [])

                # Create PromptTemplate
                prompt_template = PromptTemplate(
                    name=metadata.get("name", yaml_file.stem),
                    template=template,
                    version=metadata.get("version", "1.0.0"),
                    description=metadata.get("description", ""),
                    category=metadata.get("category", "general"),
                    required_placeholders=placeholders.get("required", []),
                    optional_placeholders=placeholders.get("optional", []),
                    examples=examples,
                    metadata=metadata,
                )

                self.prompts[prompt_template.name] = prompt_template
                logger.debug(f"Loaded prompt: {prompt_template.name} v{prompt_template.version}")

            except yaml.YAMLError as e:
                logger.error(f"YAML parsing error in {yaml_file.name}: {e}")
            except Exception as e:
                logger.error(f"Error loading prompt {yaml_file.name}: {e}")

        logger.info(f"Successfully loaded {len(self.prompts)} prompts (all v2.0.0 Jinja2) from {self.prompts_dir}")

    def _get_prompt_template_service(self):
        """Lazy-load PromptTemplateService to avoid circular imports."""
        global _prompt_template_service_instance
        if _prompt_template_service_instance is None:
            try:
                from services.prompts.prompt_template_service import PromptTemplateService
                from services.prompts.enrichers.enricher_registry import enricher_registry

                _prompt_template_service_instance = PromptTemplateService(
                    prompts_dir=self.prompts_dir,
                    enable_caching=True,
                    enable_validation=True
                )
                logger.info("PromptTemplateService initialized for advanced template support")
            except ImportError as e:
                logger.warning(f"Could not import PromptTemplateService: {e}")
                _prompt_template_service_instance = None
            except Exception as e:
                logger.error(f"Failed to initialize PromptTemplateService: {e}")
                _prompt_template_service_instance = None

        return _prompt_template_service_instance

    def get_prompt(self, name: str) -> PromptTemplate | None:
        """
        Get a prompt template by name.

        Args:
            name: Name of the prompt (without file extension)

        Returns:
            PromptTemplate object or None if not found
        """
        return self.prompts.get(name)

    def format_prompt(self, name: str, **kwargs) -> str:
        """
        Format a prompt template with variable substitution using PromptTemplateService.

        All templates are now v2.0.0 and use Jinja2 with enrichers and composition support.

        Args:
            name: Name of the prompt template
            **kwargs: Variables to substitute in the template

        Returns:
            Formatted prompt string

        Raises:
            ValueError: If prompt not found or required variables missing
        """
        template_obj = self.get_prompt(name)
        if not template_obj:
            available = list(self.prompts.keys())
            raise ValueError(
                f"Prompt template '{name}' not found. "
                f"Available prompts: {available}. "
                f"Please ensure the YAML file exists in {self.prompts_dir}"
            )

        # All templates now use PromptTemplateService (v2.0.0 with Jinja2)
        if self.enable_advanced_features:
            return self._format_advanced_template(name, **kwargs)

        # Fallback to simple formatting if advanced features disabled
        return self._format_simple_template(template_obj, **kwargs)

    def _format_advanced_template(self, name: str, **kwargs) -> str:
        """
        Format a v2.0.0 Jinja2 template using PromptTemplateService.

        Supports full Jinja2 syntax, enrichers, and template composition.

        Args:
            name: Template name
            **kwargs: Context variables

        Returns:
            Rendered template string with all enrichments applied
        """
        service = self._get_prompt_template_service()
        if service is None:
            logger.warning(f"PromptTemplateService not available, falling back to simple formatting for '{name}'")
            template_obj = self.get_prompt(name)
            return self._format_simple_template(template_obj, **kwargs)

        try:
            # PromptTemplateService.render_template may be async, but for backward compatibility
            # we need a synchronous interface. Check if it's async.
            import inspect
            import asyncio

            render_method = service.render_template
            if inspect.iscoroutinefunction(render_method):
                # Run async method synchronously
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # We're already in an async context, can't use run_until_complete
                        logger.warning(f"Cannot render async template '{name}' in async context synchronously")
                        # Fall back to simple formatting
                        template_obj = self.get_prompt(name)
                        return self._format_simple_template(template_obj, **kwargs)
                    else:
                        rendered = loop.run_until_complete(render_method(name, context=kwargs))
                except RuntimeError:
                    # No event loop
                    rendered = asyncio.run(render_method(name, context=kwargs))
            else:
                # Synchronous method
                rendered = render_method(name, context=kwargs)

            logger.debug(f"Advanced template '{name}' rendered successfully via PromptTemplateService")
            return rendered

        except Exception as e:
            logger.error(f"Error rendering advanced template '{name}' via PromptTemplateService: {e}")
            logger.warning(f"Falling back to simple formatting for '{name}'")
            template_obj = self.get_prompt(name)
            return self._format_simple_template(template_obj, **kwargs)

    def _format_simple_template(self, template_obj: PromptTemplate, **kwargs) -> str:
        """
        Fallback template formatter using basic string replacement.

        Used when PromptTemplateService is unavailable or disabled.
        Note: This won't process Jinja2 syntax, enrichers, or composition features.

        Args:
            template_obj: PromptTemplate object
            **kwargs: Variables to substitute

        Returns:
            Formatted string with basic variable substitution

        Raises:
            ValueError: If required variables are missing
        """
        template = template_obj.template
        provided_keys = set(kwargs.keys())
        required = set(template_obj.required_placeholders)
        optional = set(template_obj.optional_placeholders)

        logger.debug(f"Formatting simple prompt '{template_obj.name}' with keys: {provided_keys}")

        # Check for missing required placeholders
        missing_keys = required - provided_keys
        if missing_keys:
            raise ValueError(
                f"Missing required variables for template '{template_obj.name}': {', '.join(missing_keys)}. "
                f"Required: {required}. Provided: {provided_keys}"
            )

        # Fill in optional placeholders with empty string if not provided
        for key in optional:
            kwargs.setdefault(key, "")

        # Replace variables - support both {var} and ${var} syntax
        formatted = template
        for key, value in kwargs.items():
            # Replace both {key} and ${key} patterns
            formatted = formatted.replace(f"{{{key}}}", str(value))
            formatted = formatted.replace(f"${{{key}}}", str(value))

        return formatted

    def validate_variables(self, name: str, **kwargs) -> tuple[bool, list[str]]:
        """
        Validate that all required variables are provided.

        Args:
            name: Name of the prompt template
            **kwargs: Variables to validate

        Returns:
            Tuple of (is_valid, list_of_missing_variables)
        """
        template_obj = self.get_prompt(name)
        if not template_obj:
            return False, [f"Prompt '{name}' not found"]

        provided_keys = set(kwargs.keys())
        required = set(template_obj.required_placeholders)

        missing = required - provided_keys
        return len(missing) == 0, list(missing)

    def reload_prompts(self) -> None:
        """
        Reload all prompts from disk, including PromptTemplateService.

        Useful for development and testing when prompts are modified.
        """
        logger.info("Reloading prompts from disk...")
        old_count = len(self.prompts)
        self.prompts.clear()
        self._load_prompts()
        new_count = len(self.prompts)

        # Also reload PromptTemplateService if it's initialized
        global _prompt_template_service_instance
        if _prompt_template_service_instance is not None:
            try:
                _prompt_template_service_instance._load_templates()
                _prompt_template_service_instance._load_fragments()
                logger.info("PromptTemplateService reloaded")
            except Exception as e:
                logger.error(f"Failed to reload PromptTemplateService: {e}")

        logger.info(f"Prompt reload complete: {old_count} -> {new_count} prompts loaded")

    def list_prompts(self) -> list[str]:
        """
        Get a list of all available prompt names.

        Returns:
            Sorted list of prompt names
        """
        return sorted(self.prompts.keys())

    def get_prompts_by_category(self, category: str) -> list[PromptTemplate]:
        """
        Get all prompts in a specific category.

        Args:
            category: Category name (e.g., "blueprint_management", "exploit_generation")

        Returns:
            List of PromptTemplate objects in the category
        """
        return [p for p in self.prompts.values() if p.category == category]

    def list_categories(self) -> list[str]:
        """
        Get a list of all unique categories.

        Returns:
            Sorted list of category names
        """
        categories = {p.category for p in self.prompts.values()}
        return sorted(categories)


# Singleton instance for global use
_prompt_manager_instance: PromptManager | None = None


def get_prompt_manager() -> PromptManager:
    """
    Singleton PromptManager instance.

    Returns:
        Global PromptManager instance
    """
    global _prompt_manager_instance
    if _prompt_manager_instance is None:
        prompts_dir = PROJECT_ROOT / "src" / "config" / "prompts"
        _prompt_manager_instance = PromptManager(prompts_dir)
    return _prompt_manager_instance


# Convenience module-level instance
prompt_manager = get_prompt_manager()
