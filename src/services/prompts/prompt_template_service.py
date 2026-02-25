import logging
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, DictLoader, ChoiceLoader
from jinja2 import Template as Jinja2Template

from services.prompts.models import (
    ComposablePromptTemplate,
    PlaceholderDef,
    PromptFragment,
    TemplateMetadata,
    ValidationResult,
)
from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


class PromptTemplateService:
    """
    Advanced prompt template service with composition, validation, and caching.

    This service manages a library of prompt templates, supports template
    composition (inheritance + fragments), validates contexts, and caches
    both compiled templates and rendered prompts for performance.

    Usage:
        service = PromptTemplateService()
        rendered = await service.render_template(
            "vulnerability_generation",
            context={"cve_id": "CVE-2024-1234", ...}
        )
    """

    def __init__(
        self,
        prompts_dir: Path | None = None,
        fragments_dir: Path | None = None,
        config_dir: Path | None = None,
        enable_caching: bool = True,
        enable_validation: bool = True,
        prompt_manager=None  # Backward compatibility with existing PromptManager
    ):
        """
        Initialize the PromptTemplateService.

        Args:
            prompts_dir: Directory containing prompt YAML files
            fragments_dir: Directory containing fragment templates
            config_dir: Directory containing configuration files
            enable_caching: Whether to cache compiled/rendered templates
            enable_validation: Whether to validate contexts before rendering
            prompt_manager: Optional existing PromptManager for backward compatibility
        """
        # Default directories
        if prompts_dir is None:
            prompts_dir = PROJECT_ROOT / "src" / "config" / "prompts"
        if fragments_dir is None:
            fragments_dir = prompts_dir / "fragments"
        if config_dir is None:
            config_dir = PROJECT_ROOT / "src" / "config"

        self.prompts_dir = prompts_dir
        self.fragments_dir = fragments_dir
        self.config_dir = config_dir
        self.enable_caching = enable_caching
        self.enable_validation = enable_validation
        self.prompt_manager = prompt_manager  # Backward compatibility

        # Storage
        self.templates: dict[str, ComposablePromptTemplate] = {}
        self.fragments: dict[str, PromptFragment] = {}
        self.configs: dict[str, dict] = {}  # Loaded configuration files
        self._fragment_templates: dict[str, str] = {}  # For Jinja2 DictLoader
        self._base_templates: dict[str, str] = {}  # Base templates for inheritance

        # Caching
        self._compiled_cache: dict[str, Jinja2Template] = {}  # Template name -> compiled template
        self._rendered_cache: dict[str, tuple[str, datetime]] = {}  # Cache key -> (rendered, expiry)
        self._cache_ttl = timedelta(hours=1)  # Default TTL

        # Load fragments first (needed for Jinja2 environment setup)
        self._load_fragments()

        # Load base templates for inheritance
        self._load_base_templates()

        # Jinja2 environment - include base/ subdirectory and fragments
        template_search_paths = [
            str(self.prompts_dir),
            str(self.prompts_dir / "base")
        ]
        file_loader = FileSystemLoader(template_search_paths)
        fragment_loader = DictLoader(self._fragment_templates)
        base_template_loader = DictLoader(self._base_templates)

        self.jinja_env = Environment(
            loader=ChoiceLoader([fragment_loader, base_template_loader, file_loader]),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True
        )

        self._load_templates()

        logger.info(f"PromptTemplateService initialized with {len(self.templates)} templates, {len(self.fragments)} fragments")

    def _load_templates(self) -> None:
        """Load all prompt templates from YAML files."""
        if not self.prompts_dir.exists():
            logger.error(f"Prompts directory not found: {self.prompts_dir}")
            return

        yaml_files = list(self.prompts_dir.glob("*.yaml")) + list(self.prompts_dir.glob("*.yml"))
        loaded_count = 0

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                if not data:
                    logger.warning(f"Empty template file: {yaml_file.name}")
                    continue

                # Extract template components
                metadata_dict = data.get("metadata", {})
                metadata = TemplateMetadata.from_dict(metadata_dict)

                # Parse placeholders
                placeholders_section = data.get("placeholders", {})
                required_placeholders = self._parse_placeholders(placeholders_section.get("required", []))
                optional_placeholders = self._parse_placeholders(placeholders_section.get("optional", []))

                template_content = data.get("template", "")
                if not template_content:
                    logger.warning(f"No template content in {yaml_file.name}")
                    continue

                # Composition fields
                extends = data.get("extends")
                includes = data.get("includes", [])

                template = ComposablePromptTemplate(
                    name=metadata.name or yaml_file.stem,
                    content=template_content,
                    metadata=metadata,
                    extends=extends,
                    includes=includes,
                    required_placeholders=required_placeholders,
                    optional_placeholders=optional_placeholders
                )

                template.compiled_template = self._compile_template(template.name, template_content)

                self.templates[template.name] = template
                loaded_count += 1

            except Exception as e:
                logger.error(f"Failed to load template {yaml_file.name}: {e}")

        logger.info(f"Loaded {loaded_count} prompt templates from {self.prompts_dir}")

    def _parse_placeholders(self, placeholder_list: list) -> list[PlaceholderDef]:
        """
        Parse placeholder definitions from YAML.

        Args:
            placeholder_list: List of placeholder names or dicts

        Returns:
            List of PlaceholderDef objects
        """
        placeholders = []

        for item in placeholder_list:
            if isinstance(item, str):
                # Simple string name
                placeholders.append(PlaceholderDef(name=item))
            elif isinstance(item, dict):
                # Detailed definition
                placeholders.append(PlaceholderDef(
                    name=item.get("name", ""),
                    type=item.get("type", "string"),
                    description=item.get("description", ""),
                    default=item.get("default"),
                    enricher=item.get("enricher")
                ))

        return placeholders

    def _compile_template(self, name: str, content: str) -> Jinja2Template | None:
        """
        Compile a Jinja2 template from string content.

        Args:
            name: Template name (for error messages)
            content: Template content string

        Returns:
            Compiled Jinja2 template or None if compilation fails
        """
        try:
            return self.jinja_env.from_string(content)
        except Exception as e:
            logger.error(f"Failed to compile template '{name}': {e}")
            return None

    def _load_fragments(self) -> None:
        """Load reusable fragments from fragments directory."""
        if not self.fragments_dir.exists():
            logger.debug(f"Fragments directory not found: {self.fragments_dir}")
            return

        # Check for fragments YAML file
        fragments_file = self.fragments_dir / "fragments.yaml"
        if fragments_file.exists():
            try:
                with open(fragments_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                fragments_dict = data.get("fragments", {})
                for name, content in fragments_dict.items():
                    fragment_content = content if isinstance(content, str) else content.get("content", "")
                    self.fragments[name] = PromptFragment(
                        name=name,
                        content=fragment_content,
                        description=content.get("description", "") if isinstance(content, dict) else "",
                        required_variables=content.get("variables", []) if isinstance(content, dict) else []
                    )
                    # Store for DictLoader
                    self._fragment_templates[name] = fragment_content

                logger.info(f"Loaded {len(self.fragments)} fragments from {fragments_file}")

            except Exception as e:
                logger.error(f"Failed to load fragments file: {e}")

    def _load_base_templates(self) -> None:
        """Load base templates from base/ directory for Jinja2 inheritance."""
        base_dir = self.prompts_dir / "base"
        if not base_dir.exists():
            logger.debug(f"Base templates directory not found: {base_dir}")
            return

        yaml_files = list(base_dir.glob("*.yaml")) + list(base_dir.glob("*.yml"))
        loaded_count = 0

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                if not data:
                    logger.warning(f"Empty base template file: {yaml_file.name}")
                    continue

                # Extract template content only (not the YAML metadata)
                template_content = data.get("template", "")
                if template_content:
                    # Store with filename as key for Jinja2 {% extends 'filename.yaml' %}
                    self._base_templates[yaml_file.name] = template_content
                    loaded_count += 1
                    logger.debug(f"Loaded base template: {yaml_file.name} ({len(template_content)} chars)")
                else:
                    logger.warning(f"No template content in base template: {yaml_file.name}")

            except Exception as e:
                logger.error(f"Failed to load base template {yaml_file.name}: {e}")

        logger.info(f"Loaded {loaded_count} base templates from {base_dir}")

    def get_template(self, name: str) -> ComposablePromptTemplate | None:
        """
        Get a template by name.

        Args:
            name: Template name

        Returns:
            ComposablePromptTemplate or None if not found
        """
        template = self.templates.get(name)
        if not template:
            logger.warning(f"Template not found: {name}")
            # Fallback to prompt_manager if available (backward compatibility)
            if self.prompt_manager:
                logger.debug(f"Falling back to PromptManager for template: {name}")

        return template

    def render_template(
        self,
        name: str,
        context: dict[str, object],
        validate: bool = True,
        use_cache: bool = True
    ) -> str:
        """
        Render a template with the provided context.

        Args:
            name: Template name
            context: Context dictionary with variable values
            validate: Whether to validate context before rendering
            use_cache: Whether to use/update rendered cache

        Returns:
            Rendered template string

        Raises:
            ValueError: If template not found or context invalid
        """
        # Check cache first
        if use_cache and self.enable_caching:
            cache_key = self._make_cache_key(name, context)
            cached = self._get_from_cache(cache_key)
            if cached:
                logger.debug(f"Cache hit for template '{name}'")
                return cached

        # Get template
        template = self.get_template(name)
        if not template:
            # Fallback to prompt_manager
            if self.prompt_manager:
                logger.debug(f"Using PromptManager to format prompt: {name}")
                try:
                    return self.prompt_manager.format_prompt(name, **context)
                except Exception as e:
                    raise ValueError(f"Template '{name}' not found and PromptManager fallback failed: {e}")
            raise ValueError(f"Template '{name}' not found")

        # Validate context if enabled
        if validate and self.enable_validation:
            validation = template.validate_context(context)
            if not validation.is_valid:
                raise ValueError(f"Invalid context for template '{name}':\n{validation}")

        # Add defaults for optional placeholders
        full_context = context.copy()
        for placeholder in template.optional_placeholders:
            if placeholder.name not in full_context:
                if placeholder.default is not None:
                    full_context[placeholder.name] = placeholder.default
                else:
                    full_context[placeholder.name] = ""  # Default to empty string

        # Render template
        try:
            rendered = template.render(full_context)

            # Cache if enabled
            if use_cache and self.enable_caching:
                cache_key = self._make_cache_key(name, context)
                self._add_to_cache(cache_key, rendered)

            return rendered

        except Exception as e:
            logger.error(f"Failed to render template '{name}': {e}")
            raise

    def compose_template(
        self,
        base_template: str,
        extensions: list[str] | None = None,
        fragments: list[str] | None = None
    ) -> ComposablePromptTemplate:
        """
        Dynamically compose a template from base + extensions + fragments.

        Args:
            base_template: Name of base template
            extensions: Optional list of extension template names
            fragments: Optional list of fragment names to include

        Returns:
            Composed ComposablePromptTemplate

        Raises:
            ValueError: If base template or components not found
        """
        base = self.get_template(base_template)
        if not base:
            raise ValueError(f"Base template not found: {base_template}")

        # Start with base content
        composed_content = base.content
        composed_placeholders = base.get_all_placeholders().copy()

        # Add fragments
        if fragments:
            for fragment_name in fragments:
                fragment = self.fragments.get(fragment_name)
                if fragment:
                    # Inject fragment content (simple concatenation for now)
                    composed_content += f"\n\n{{# Fragment: {fragment_name} #}}\n{fragment.content}"
                else:
                    logger.warning(f"Fragment not found: {fragment_name}")

        # Create composed template
        composed = ComposablePromptTemplate(
            name=f"{base_template}_composed",
            content=composed_content,
            metadata=base.metadata,
            extends=base.extends,
            includes=base.includes + (fragments or []),
            required_placeholders=list(composed_placeholders.values()),
            optional_placeholders=base.optional_placeholders
        )

        # Compile composed template
        composed.compiled_template = self._compile_template(composed.name, composed_content)

        return composed

    def validate_template(self, template: ComposablePromptTemplate) -> ValidationResult:
        """
        Validate template structure and syntax.

        Args:
            template: Template to validate

        Returns:
            ValidationResult with errors/warnings
        """
        errors = []
        warnings = []

        # Check required fields
        if not template.name:
            errors.append("Template name is required")
        if not template.content:
            errors.append("Template content is required")

        # Check template compilation
        if not template.compiled_template:
            errors.append(f"Template '{template.name}' not compiled")

        # Check for duplicate placeholders
        all_names = [p.name for p in template.required_placeholders] + \
                    [p.name for p in template.optional_placeholders]
        if len(all_names) != len(set(all_names)):
            duplicates = [name for name in all_names if all_names.count(name) > 1]
            errors.append(f"Duplicate placeholders: {duplicates}")

        # Warnings for missing metadata
        if not template.metadata.description:
            warnings.append(f"Template '{template.name}' missing description")
        if not template.metadata.tags:
            warnings.append(f"Template '{template.name}' missing tags")

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def validate_context(self, template_name: str, context: dict) -> ValidationResult:
        """
        Validate context against template requirements.

        Args:
            template_name: Name of template
            context: Context dictionary to validate

        Returns:
            ValidationResult
        """
        template = self.templates.get(template_name)
        if not template:
            return ValidationResult(
                is_valid=False,
                errors=[f"Template '{template_name}' not found"]
            )

        return template.validate_context(context)

    async def load_context_config(self, config_name: str) -> dict:
        """
        Load a context configuration file (e.g., protocol_detection.yaml).

        Args:
            config_name: Configuration file name (without .yaml extension)

        Returns:
            Configuration dictionary

        Raises:
            FileNotFoundError: If config file not found
        """
        # Check cache
        if config_name in self.configs:
            return self.configs[config_name]

        # Load from file
        config_path = self.config_dir / "prompts" / f"{config_name}.yaml"
        if not config_path.exists():
            # Try top-level config dir
            config_path = self.config_dir / f"{config_name}.yaml"

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_name}.yaml")

        try:
            import aiofiles
            async with aiofiles.open(config_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                config = yaml.safe_load(content)

            # Cache configuration
            self.configs[config_name] = config
            logger.debug(f"Loaded configuration: {config_name}")

            return config

        except Exception as e:
            logger.error(f"Failed to load configuration {config_name}: {e}")
            raise

    def clear_cache(self, pattern: str | None = None) -> int:
        """
        Clear rendered template cache.

        Args:
            pattern: Optional pattern to match cache keys (None = clear all)

        Returns:
            Number of cache entries cleared
        """
        if pattern is None:
            # Clear all
            count = len(self._rendered_cache)
            self._rendered_cache.clear()
            logger.info(f"Cleared all cache entries ({count})")
            return count

        # Clear matching pattern
        keys_to_remove = [k for k in self._rendered_cache.keys() if pattern in k]
        for key in keys_to_remove:
            del self._rendered_cache[key]

        logger.info(f"Cleared {len(keys_to_remove)} cache entries matching '{pattern}'")
        return len(keys_to_remove)

    def list_templates(self, category: str | None = None) -> list[str]:
        """
        List available template names.

        Args:
            category: Optional category filter

        Returns:
            List of template names
        """
        if category:
            return [
                name for name, template in self.templates.items()
                if template.metadata.category == category
            ]
        return sorted(self.templates.keys())

    def list_categories(self) -> list[str]:
        """Get list of unique template categories."""
        categories = {template.metadata.category for template in self.templates.values()}
        return sorted(categories)

    def get_template_info(self, name: str) -> dict | None:
        """
        Get template metadata and information.

        Args:
            name: Template name

        Returns:
            Dictionary with template info or None if not found
        """
        template = self.templates.get(name)
        if not template:
            return None

        return {
            "name": template.name,
            "description": template.metadata.description,
            "category": template.metadata.category,
            "version": template.metadata.version,
            "author": template.metadata.author,
            "tags": template.metadata.tags,
            "required_placeholders": [p.name for p in template.required_placeholders],
            "optional_placeholders": [p.name for p in template.optional_placeholders],
            "extends": template.extends,
            "includes": template.includes
        }

    # Cache helper methods

    def _make_cache_key(self, template_name: str, context: dict) -> str:
        """Generate cache key from template name and context."""
        # Create deterministic key from sorted context items
        context_str = "_".join(f"{k}={str(v)[:20]}" for k, v in sorted(context.items()))
        return f"{template_name}_{hash(context_str)}"

    def _get_from_cache(self, cache_key: str) -> str | None:
        """Get rendered template from cache if not expired."""
        if cache_key in self._rendered_cache:
            rendered, expiry = self._rendered_cache[cache_key]
            if datetime.now() < expiry:
                return rendered
            else:
                # Expired, remove from cache
                del self._rendered_cache[cache_key]
        return None

    def _add_to_cache(self, cache_key: str, rendered: str) -> None:
        """Add rendered template to cache with TTL."""
        expiry = datetime.now() + self._cache_ttl
        self._rendered_cache[cache_key] = (rendered, expiry)

        # Limit cache size (simple LRU-like behavior)
        if len(self._rendered_cache) > 1000:
            # Remove oldest 100 entries
            oldest_keys = sorted(
                self._rendered_cache.keys(),
                key=lambda k: self._rendered_cache[k][1]
            )[:100]
            for key in oldest_keys:
                del self._rendered_cache[key]


_prompt_template_service_instance: PromptTemplateService | None = None


def get_prompt_template_service() -> PromptTemplateService:
    """Get PromptTemplateService instance."""
    global _prompt_template_service_instance
    if _prompt_template_service_instance is None:
        _prompt_template_service_instance = PromptTemplateService()
    return _prompt_template_service_instance
