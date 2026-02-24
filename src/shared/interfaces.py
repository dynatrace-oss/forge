from pathlib import Path
from typing import Protocol


class TemplateLoaderInterface(Protocol):
    """Interface for template loaders."""

    def load_template_content(self, template_path: Path, required: bool = False) -> str:
        """Load template content."""
        ...

    def parse_template_file(self, template_file: Path, language: str, package_name: str) -> any:
        """Parse a template file."""
        ...


class LLMServiceInterface(Protocol):
    """Interface for LLM services."""

    async def generate(self, prompt: str, retries: int = 2) -> str | None:
        """Generate text from prompt."""
        ...

    async def generate_blueprint_metadata(self, vulnerability_data: dict[str, any]) -> dict[str, any]:
        """Generate blueprint metadata."""
        ...

    async def generate_vulnerability_code(self, vulnerability_data: dict[str, any]) -> dict[str, str]:
        """Generate vulnerable code."""
        ...


class TemplateManagerInterface(Protocol):
    """Interface for template managers."""

    def generate_pom_xml(
        self, blueprint: any, main_class_name: str, additional_dependencies: list[dict[str, any]] | None = None
    ) -> str:
        """Generate POM XML."""
        ...

    def generate_containerfile(self, blueprint: any, main_class_name: str) -> str:
        """Generate Containerfile."""
        ...

    def generate_readme(
        self, blueprint: any, container_name: str, is_detailed: bool = False, context: dict | None = None
    ) -> str:
        """Generate README."""
        ...
