import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from models.error_handling import TemplateError
from models.templates import TemplateSection, TemplateType, VulnerabilityTemplate
from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


class TemplateLoader:
    """
    Handles loading templates from the filesystem.
    """

    def __init__(self, base_dir: Union[str, Path]):
        """
        Initialize the template loader.

        Args:
            base_dir: Base directory for templates
        """
        self.base_dir = Path(base_dir)
        self.template_cache: Dict[Path, str] = {}

    def _ensure_base_dir_exists(self) -> None:
        """Ensure the base directory exists, creating it if necessary."""
        if not self.base_dir.exists():
            try:
                self.base_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created template directory: {self.base_dir}")
            except Exception as e:
                logger.warning(f"Failed to create template directory {self.base_dir}: {e}")

    def load_template_content(self, template_path: Union[str, Path], required: bool = False) -> str:
        """
        Load template content with enhanced error reporting.

        Args:
            template_path: Path to template file
            required: Whether template is required

        Returns:
            Template content

        Raises:
            FileNotFoundError: If required template not found
        """
        template_path = Path(template_path)

        if not template_path.is_absolute():
            full_path = self.base_dir / template_path
        else:
            full_path = template_path

        if full_path in self.template_cache:
            return self.template_cache[full_path]

        if not full_path.exists():
            if required:
                # Provide helpful suggestions for missing templates
                suggestions = self._get_template_suggestions(full_path)
                error_msg = f"Required template not found: {template_path}"
                if suggestions:
                    error_msg += "\n\nSuggestions:\n" + "\n".join(f"- {s}" for s in suggestions)

                raise FileNotFoundError(error_msg)
            else:
                logger.warning(f"Optional template not found: {full_path}")
                return ""

        try:
            content = full_path.read_text(encoding="utf-8").strip()
            if not content and required:
                raise ValueError(f"Required template {template_path} is empty")

            self.template_cache[full_path] = content
            return content

        except Exception as e:
            if required:
                raise ValueError(f"Error loading required template {template_path}: {str(e)}")
            logger.warning(f"Error loading optional template {template_path}: {str(e)}")
            return ""

    def _get_template_suggestions(self, missing_path: Path) -> list[str]:
        """Provide helpful suggestions for missing templates."""
        suggestions = []

        # Check if directory exists
        if not missing_path.parent.exists():
            suggestions.append(f"Create directory: {missing_path.parent}")

        # Suggest similar existing files
        if missing_path.parent.exists():
            similar_files = []
            for file in missing_path.parent.glob("*.txt"):
                if file.stem.lower() in missing_path.stem.lower() or missing_path.stem.lower() in file.stem.lower():
                    similar_files.append(file.name)

            if similar_files:
                suggestions.append(f"Similar files found: {', '.join(similar_files)}")

        # Provide template creation guidance
        if "framework" in str(missing_path):
            suggestions.append("Framework templates should contain dependency and configuration information")
        elif "imports" in str(missing_path):
            suggestions.append("Import templates should contain Java import statements")
        elif "prompts" in str(missing_path):
            suggestions.append("Prompt templates should contain LLM prompts with placeholders")

        return suggestions

    def find_template_file(self, directory: Union[str, Path], name: str, extensions: Optional[List[str]] = None) -> str:
        """
        Find a template file in the specified directory.

        Args:
            directory: Directory to search in (relative to base_dir)
            name: Template name
            extensions: list of possible extensions (defaults to ['.txt', '.template'])

        Returns:
            Path to the template file or empty string if not found
        """
        if extensions is None:
            extensions = [".txt", ".template"]

        # Resolve directory path
        dir_path = self.base_dir / directory

        # Ensure the directory exists
        if not dir_path.exists():
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created template directory: {dir_path}")
            except Exception as e:
                logger.warning(f"Template directory not found and could not be created: {dir_path}, {e}")
                return ""

        # Try each extension
        for ext in extensions:
            # Try exact name with extension
            file_path = dir_path / f"{name}{ext}"
            if file_path.exists():
                return str(file_path)

        # If no exact match, try looking for files that contain the name
        try:
            for filename in dir_path.iterdir():
                if not filename.is_file():
                    continue

                for ext in extensions:
                    if filename.name.endswith(ext) and name.lower() in filename.name.lower():
                        return str(filename)
        except Exception as e:
            logger.error(f"Error searching for template {name} in {dir_path}: {str(e)}")

        # Nothing found
        return ""

    def extract_section(self, content: str, section_name: str, prefix: str = "") -> str:
        """
        Extract a section from template content.

        Args:
            content: Full template content
            section_name: Name of the section to extract
            prefix: Optional prefix to remove from lines (default: '')

        Returns:
            Extracted section content or empty string if not found
        """
        pattern = rf"#\s*{re.escape(section_name)}\s*\n((?:.+\n)*?)(?:#\s*(?:[A-Z_]+)|$)"
        match = re.search(pattern, content, re.MULTILINE)

        if match:
            section_content = match.group(1).strip()

            # Remove prefix from each line if specified
            if prefix and section_content:
                lines = []
                for line in section_content.split("\n"):
                    if line.startswith(prefix):
                        lines.append(line[len(prefix) :])
                    else:
                        lines.append(line)
                section_content = "\n".join(lines)

            return section_content

        return ""

    def extract_resources(self, content: str) -> Dict[str, Any]:
        """
        Extract resources section from template content.

        Args:
            content: Full template content

        Returns:
            dictionary of resources or empty dict if not found
        """
        # First check if there's a resources section
        resources_section = self.extract_section(content, "RESOURCES")
        if not resources_section:
            return {}

        # Parse resources
        resources = {}
        resource_pattern = r"#\s*Resource:\s*([^\n]+)\n((?:.+\n)*)(?=#\s*Resource:|$)"

        for match in re.finditer(resource_pattern, resources_section, re.MULTILINE):
            resource_name = match.group(1).strip()
            resource_content = match.group(2).strip()

            # Extract description if available
            description = None
            desc_match = re.search(r"#\s*Description:\s*([^\n]+)", resource_content)
            if desc_match:
                description = desc_match.group(1).strip()
                # Remove description line from content
                resource_content = re.sub(r"#\s*Description:\s*[^\n]+\n", "", resource_content)

            # Remove any remaining comment lines
            resource_content = re.sub(r"#.*\n", "", resource_content).strip()

            resources[resource_name] = {
                "content": resource_content,
                "description": description or f"Resource file: {resource_name}",
            }

        return resources

    def parse_template_file(
        self, template_file: Union[str, Path], language: str, package_name: str
    ) -> VulnerabilityTemplate:
        """
        Parse a template file into a VulnerabilityTemplate.

        Args:
            template_file: Path to template file
            language: Programming language
            package_name: Package name

        Returns:
            VulnerabilityTemplate instance

        Raises:
            TemplateError: If there's an error parsing the template
        """
        try:
            # Load template content
            template_path = Path(template_file)
            content = self.load_template_content(template_path, required=True)

            # Extract the base name of the template
            template_name = template_path.stem

            # Initialize template sections
            template_type = self._get_template_type(language)
            sections = {}
            metadata = {"package": package_name}

            # Extract metadata
            metadata_section = self.extract_section(content, "METADATA", "# ")
            if metadata_section:
                for line in metadata_section.strip().split("\n"):
                    if line.startswith("# "):
                        parts = line[2:].split(":", 1)
                        if len(parts) == 2:
                            key, value = parts
                            metadata[key.strip()] = value.strip()

            # Extract imports section
            imports_section = self.extract_section(content, "IMPORTS")
            if imports_section:
                sections[TemplateSection.IMPORTS.value] = imports_section

            # Extract demo code section
            demo_code_section = self.extract_section(content, "DEMO_CODE")
            if demo_code_section:
                sections[TemplateSection.DEMO_CODE.value] = demo_code_section

            # Extract resources section
            resources = self.extract_resources(content)
            if resources:
                sections[TemplateSection.RESOURCES.value] = resources

            # Extract exploitation section
            exploitation_section = self.extract_section(content, "EXPLOITATION")
            if exploitation_section:
                sections[TemplateSection.EXPLOITATION.value] = exploitation_section

            # Extract mitigation section
            mitigation_section = self.extract_section(content, "MITIGATION")
            if mitigation_section:
                sections[TemplateSection.MITIGATION.value] = mitigation_section

            # Extract dependencies section
            dependencies_section = self.extract_section(content, "DEPENDENCIES", "# ")
            if dependencies_section:
                dependencies = []
                for line in dependencies_section.strip().split("\n"):
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) >= 3:
                        dependencies.append(
                            {
                                "group_id": parts[0],
                                "artifact_id": parts[1],
                                "version": parts[2],
                            }
                        )

                if dependencies:
                    sections[TemplateSection.DEPENDENCIES.value] = dependencies

            # Create template
            return VulnerabilityTemplate(
                name=template_name,
                template_type=template_type,
                sections=sections,
                metadata=metadata,
            )

        except Exception as e:
            logger.error(f"Error parsing template file {template_file}: {str(e)}")
            raise TemplateError(
                message=f"Error parsing template file {template_file}",
                cause=e,
                remedy=f"Check that the template file {template_file} is properly formatted",
            )

    def _get_template_type(self, language: str) -> TemplateType:
        """
        Convert language string to TemplateType.

        Args:
            language: Language string

        Returns:
            TemplateType enum value
        """
        try:
            return TemplateType(language.lower())
        except ValueError:
            return TemplateType.GENERIC


class ConfigLoader:
    """
    Configuration loader for YAML and JSON files.
    Provides centralized configuration loading for the FORGE system.
    """

    @staticmethod
    def load_config(config_name: str, config_dir: Optional[Path] = None) -> Dict[str, Any]:
        """
        Load configuration from a YAML or JSON file.

        Args:
            config_name: Name of the config file (without extension)
            config_dir: Directory containing config files (defaults to src/config)

        Returns:
            Dictionary containing configuration data

        Raises:
            FileNotFoundError: If config file is not found
            yaml.YAMLError: If YAML parsing fails
        """
        if config_dir is None:
            config_dir = PROJECT_ROOT / "src" / "config"

        # Try YAML first, then JSON
        for extension in [".yaml", ".yml", ".json"]:
            config_path = config_dir / f"{config_name}{extension}"
            if config_path.exists():
                try:
                    with open(config_path, "r", encoding="utf-8") as f:
                        if extension == ".json":
                            return json.load(f)
                        else:
                            return yaml.safe_load(f) or {}
                except Exception as e:
                    logger.error(f"Failed to parse config file {config_path}: {e}")
                    raise

        raise FileNotFoundError(f"Configuration file '{config_name}' not found in {config_dir}")

    @staticmethod
    def load_config_safe(
        config_name: str, default: Dict[str, Any] = None, config_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Load configuration with safe fallback to default values.

        Args:
            config_name: Name of the config file (without extension)
            default: Default configuration to return if loading fails
            config_dir: Directory containing config files

        Returns:
            Configuration dictionary or default values
        """
        if default is None:
            default = {}

        try:
            return ConfigLoader.load_config(config_name, config_dir)
        except Exception as e:
            logger.warning(f"Failed to load config '{config_name}': {e}. Using defaults.")
            return default


# Convenience functions for common configurations
def load_supported_packages() -> Dict[str, Any]:
    """Load supported packages configuration."""
    return ConfigLoader.load_config_safe(
        "supported_packages",
        default={"supported_packages": {}, "transitive_vulnerable_packages": [], "package_fallbacks": {}},
    )
