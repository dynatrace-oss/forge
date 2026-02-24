import logging
import platform
from jinja2 import Environment, TemplateSyntaxError, UndefinedError

logger = logging.getLogger(__name__)


class TemplateRenderer:
    """
    Handles rendering templates with Jinja2 template engine.

    Supports:
    - Variable substitution: {{ variable_name }}
    - Conditionals: {% if condition %}...{% endif %}
    - Loops: {% for item in list %}...{% endfor %}
    - Filters: {{ value|default('default') }}
    """

    def __init__(self):
        """Initialize the Jinja2 template renderer."""
        # Create Jinja2 environment with strict undefined handling
        self.env = Environment(
            autoescape=False,  # Don't escape for Containerfiles/XML
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True
        )

        # Add custom filters
        self.env.filters['int'] = int
        self.env.filters['str'] = str

    def render_template(self, template_content: str, context: dict[str, any]) -> str:
        """
        Render a Jinja2 template with the provided context.

        Args:
            template_content: Jinja2 template content
            context: Dictionary of variable names and values

        Returns:
            Rendered template content

        Raises:
            TemplateSyntaxError: If template syntax is invalid
            UndefinedError: If required variable is missing from context
        """
        if not template_content:
            return ""

        logger.debug(f"Rendering Jinja2 template with context keys: {list(context.keys())}")

        try:
            # Create Jinja2 template from content
            template = self.env.from_string(template_content)

            # Render with context
            rendered = template.render(**context)

            return rendered

        except TemplateSyntaxError as e:
            logger.error(f"Jinja2 template syntax error at line {e.lineno}: {e.message}")
            raise
        except UndefinedError as e:
            logger.error(f"Jinja2 undefined variable error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error rendering Jinja2 template: {e}")
            raise

    def detect_architecture(self) -> str:
        """
        Detect the system architecture.

        Returns:
            Architecture string ('arm64', 'amd64', or 'generic')
        """
        # Check if running on macOS with Apple Silicon
        if platform.system() == "Darwin" and platform.machine() == "arm64":
            return "arm64"

        # Check if running on Linux with ARM architecture
        if platform.system() == "Linux" and ("arm" in platform.machine() or "aarch" in platform.machine()):
            return "arm64"

        # Specific check for ARM on Windows
        if platform.system() == "Windows" and ("arm" in platform.machine() or "aarch" in platform.machine()):
            return "arm64"

        # Default to generic x86_64/amd64
        return "generic"

    def format_dependencies(self, dependencies: list[dict[str, any]]) -> str:
        """
        Format a list of dependencies as XML.

        Args:
            dependencies: list of dependency dictionaries

        Returns:
            XML string for dependencies
        """
        if not dependencies:
            return ""

        dependency_strings = []

        for dep in dependencies:
            group_id = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")
            version = dep.get("version", "")

            if not group_id or not artifact_id:
                logger.warning(f"Skipping incomplete dependency: {dep}")
                continue

            dependency_strings.append(
                f"""        <dependency>
            <groupId>{group_id}</groupId>
            <artifactId>{artifact_id}</artifactId>
            <version>{version}</version>
        </dependency>"""
            )

        return "\n".join(dependency_strings)
