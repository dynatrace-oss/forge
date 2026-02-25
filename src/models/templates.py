import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from shared.constants import VULNERABILITY_CATEGORIES
from shared.types import FrameworkType, TemplateSection, TemplateType
from utils.core.common import parse_maven_dependency

logger = logging.getLogger(__name__)


class VulnerabilityCategory(Enum):
    """Categories of vulnerabilities."""

    XXE = VULNERABILITY_CATEGORIES[0]
    XSS = VULNERABILITY_CATEGORIES[1]
    INSECURE_DESERIALIZATION = VULNERABILITY_CATEGORIES[2]
    SQL_INJECTION = VULNERABILITY_CATEGORIES[3]
    COMMAND_INJECTION = VULNERABILITY_CATEGORIES[4]
    OTHER = VULNERABILITY_CATEGORIES[5]


@dataclass
class VulnerabilityTemplate:
    """
    Represents a structured vulnerability template.
    Provides methods for accessing and manipulating template sections.
    """

    name: str
    template_type: TemplateType
    sections: dict[str, any] = field(default_factory=dict)
    metadata: dict[str, any] = field(default_factory=dict)

    def get_framework_type(self) -> FrameworkType:
        """Determine framework type from metadata or template structure (web-based only)."""
        if self.framework_template:
            return self.framework_template.framework_type
        else:
            # Default to web application for HTTP-based vulnerability demonstrations
            return FrameworkType.WEB_APPLICATION

    def get_all_files(self) -> dict[str, str]:
        """Get all files including framework-specific configurations."""
        files = {}

        # Base template files
        if self.has_section(TemplateSection.DEMO_CODE):
            main_class = self.get_section(TemplateSection.DEMO_CODE)
            if main_class:
                files["src/main/java/VulnerableDemo.java"] = main_class

        # Framework-specific files
        if self.framework_template:
            framework_files = self.framework_template.get_configuration_files()
            files.update(framework_files)

        # Resource files
        resources = self.get_resources()
        if isinstance(resources, dict):
            for name, resource in resources.items():
                if isinstance(resource, dict) and "content" in resource:
                    files[f"src/main/resources/{name}"] = resource["content"]
                else:
                    files[f"src/main/resources/{name}"] = str(resource)

        return files

    def get_framework_dependencies(self) -> list[dict[str, str]]:
        """Get framework-specific dependencies."""
        if self.framework_template:
            return self.framework_template.get_framework_dependencies()
        return []

    @property
    def package_name(self) -> str:
        """Get the package name from metadata."""
        return self.metadata.get("package", "")

    @property
    def cve_id(self) -> str:
        """Get the CVE ID from metadata."""
        return self.metadata.get("cve", "")

    @property
    def vulnerability_type(self) -> str:
        """Get the vulnerability type from metadata."""
        return self.metadata.get("vulnerability_type", "")

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        """Get the vulnerability category from metadata."""
        category_str = self.metadata.get("vulnerability_category", "OTHER")
        try:
            return VulnerabilityCategory(category_str.lower())
        except ValueError:
            return VulnerabilityCategory.OTHER

    @property
    def severity(self) -> str:
        """Get the severity from metadata."""
        return self.metadata.get("severity", "UNKNOWN")

    @property
    def description(self) -> str:
        """Get the description from metadata."""
        return self.metadata.get("description", "")

    def get_section(self, section: TemplateSection) -> str | None:
        """
        Get a section from the template.

        Args:
            section: Section enum value

        Returns:
            Section content or None if not found
        """
        if section.value in self.sections:
            return self.sections[section.value]

        # For backward compatibility, try lowercase
        if section.value.lower() in self.sections:
            return self.sections[section.value.lower()]

        return None

    def set_section(self, section: TemplateSection, content: dict) -> None:
        """
        Set a section in the template.

        Args:
            section: Section enum value
            content: Section content
        """
        self.sections[section.value] = content

    def has_section(self, section: TemplateSection) -> bool:
        """
        Check if a section exists in the template.

        Args:
            section: Section enum value

        Returns:
            True if the section exists
        """
        return section.value in self.sections or section.value.lower() in self.sections

    def get_imports(self) -> str:
        """Get the imports section."""
        return self.get_section(TemplateSection.IMPORTS) or ""

    def get_demo_code(self) -> str:
        """Get the demo code section."""
        return self.get_section(TemplateSection.DEMO_CODE) or ""

    def get_resources(self) -> dict | str:
        """Get the resources section."""
        return self.get_section(TemplateSection.RESOURCES) or {}

    def get_dependencies(self) -> list[dict]:
        """Get the dependencies section."""
        deps = self.get_section(TemplateSection.DEPENDENCIES)
        if deps is None:
            return []

        # Handle string format (for backward compatibility)
        if isinstance(deps, str):
            return self._parse_dependency_string(deps)

        # Handle list format
        if isinstance(deps, list):
            return deps

        # Handle unknown format
        logger.warning(f"Unknown dependencies format in template {self.name}")
        return []

    def _parse_dependency_string(self, deps_str: str) -> list[dict]:
        """
        Parse a dependency string into a list of dependency dictionaries.
        For backward compatibility with older template formats.
        """
        result = []

        # Simple format: groupId:artifactId:version
        for line in deps_str.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            dependency = parse_maven_dependency(line)
            if dependency:
                result.append(dependency)

        return result

    def add_resource(self, name: str, content: str, description: str | None = None) -> None:
        """
        Add a resource to the template.

        Args:
            name: Resource name
            content: Resource content
            description: Optional resource description
        """
        resources = self.get_resources()

        # Create resources section if it doesn't exist
        if not resources:
            resources = {}
            self.set_section(TemplateSection.RESOURCES, resources)

        # Add the resource
        resources[name] = {
            "content": content,
            "description": description or f"Resource file: {name}",
        }

    def get_resource_content(self, name: str) -> str | None:
        """
        Get content of a specific resource.

        Args:
            name: Resource name

        Returns:
            Resource content or None if not found
        """
        resources = self.get_resources()
        if name in resources:
            return resources[name].get("content")
        return None

    def to_dict(self) -> dict:
        """Convert template to dictionary representation."""
        return {
            "name": self.name,
            "template_type": self.template_type.value,
            "metadata": self.metadata,
            "sections": self.sections,
        }

    def to_json(self) -> str:
        """Convert template to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class FrameworkTemplate:
    """
    Template for framework-specific vulnerability applications.
    All configurations loaded from template files.
    """

    name: str
    framework_type: FrameworkType
    base_template: VulnerabilityTemplate
    framework_sections: dict[str, any] = field(default_factory=dict)
    build_configuration: dict[str, any] = field(default_factory=dict)
    deployment_configuration: dict[str, any] = field(default_factory=dict)
    template_loader: any = field(default=None)

    def __post_init__(self):
        # Initialize template_loader if not provided
        if not hasattr(self, 'template_loader') or self.template_loader is None:
            from utils.core.loader import TemplateLoader
            self.template_loader = TemplateLoader(Path("templates"))

    def get_framework_dependencies(self) -> list[dict[str, str]]:
        """Load framework dependencies from template files."""
        try:
            template_name = f"{self.framework_type.value}_dependencies.txt"
            template_path = f"framework/{template_name}"

            dependency_content = self.template_loader.load_template_content(template_path, required=True)

            dependencies = []
            for line in dependency_content.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        dependencies.append(
                            {"group_id": parts[0].strip(), "artifact_id": parts[1].strip(), "version": parts[2].strip()}
                        )

            return dependencies

        except Exception as e:
            logging.error(f"Error when trying to acquire dependencies from template: {e}")
            raise FileNotFoundError(
                f"Failed to load framework dependencies for {self.framework_type.value}. "
                f"Please ensure template file exists at src/templates/framework/{self.framework_type.value}_dependencies.txt"
            )

    def get_configuration_files(self) -> dict[str, str]:
        """Load framework configuration files from templates."""
        try:
            template_name = f"{self.framework_type.value}_config.txt"
            template_path = f"framework/{template_name}"

            config_content = self.template_loader.load_template_content(template_path, required=True)

            configs = {}
            current_file = None
            current_content = []

            for line in config_content.split("\n"):
                if line.startswith("FILE:"):
                    # Save previous file if exists
                    if current_file:
                        configs[current_file] = "\n".join(current_content)

                    # Start new file
                    current_file = line[5:].strip()
                    current_content = []
                elif current_file:
                    current_content.append(line)

            # Save last file
            if current_file:
                configs[current_file] = "\n".join(current_content)

            if not configs:
                raise ValueError("No configuration files found in template")

            return configs

        except Exception as e:
            logger.error(f"Error when loading configuration files for package/framework: {e}")
            raise FileNotFoundError(
                f"Failed to load framework configuration for {self.framework_type.value}. "
                f"Please ensure template file exists at src/templates/framework/{self.framework_type.value}_config.txt"
            )
