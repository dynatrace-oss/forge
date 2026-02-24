import logging
import traceback
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Get project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class LLMContextBuilder:
    """
    Centralized context builder for LLM prompts.

    This class consolidates 7+ different context formatting methods that were
    previously scattered across llm_service.py.

    All methods are static for easy importing without instantiation.
    """

    # Cache for framework requirements
    _framework_requirements_cache = None

    @staticmethod
    def format_dependencies(vulnerability_data: dict) -> str:
        """
        Format dependencies section for LLM prompt.

        Args:
            vulnerability_data: Vulnerability data containing dependency information

        Returns:
            Formatted dependencies section string (empty if no dependencies)
        """
        additional_dependencies = vulnerability_data.get("additional_dependencies", [])

        if not additional_dependencies:
            return ""

        deps_text = "Additional Dependencies:\n"
        for dep in additional_dependencies:
            group_id = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")
            version = dep.get("version", "")
            deps_text += f"- {group_id}:{artifact_id}:{version}\n"

        return deps_text.strip()

    @staticmethod
    def format_references(references: list | str) -> str:
        """
        Format references list for prompt inclusion.

        Args:
            references: List of reference URLs/dicts or string

        Returns:
            Formatted references string
        """
        if not references:
            return "No references provided"

        if isinstance(references, str):
            return references

        try:
            # Handle different reference formats
            formatted_refs = []
            for ref in references:
                if isinstance(ref, dict):
                    if "url" in ref:
                        formatted_refs.append(ref["url"])
                    elif "link" in ref:
                        formatted_refs.append(ref["link"])
                    else:
                        formatted_refs.append(str(ref))
                else:
                    formatted_refs.append(str(ref))

            return "\n".join(f"- {ref}" for ref in formatted_refs[:5])  # Limit to 5 references
        except Exception as e:
            logger.error(f"Error formatting references: {e}")
            return str(references)

    @staticmethod
    def format_dependency_examples(similar_blueprints: list) -> str:
        """
        Format dependency examples from similar blueprints.

        Args:
            similar_blueprints: List of similar blueprint objects

        Returns:
            Formatted dependency examples string
        """
        dependencies = []

        for blueprint in similar_blueprints:
            if "dependency_info" in blueprint.metadata:
                dep_info = blueprint.metadata["dependency_info"]
                if "additional_dependencies" in dep_info:
                    dependencies.extend(dep_info["additional_dependencies"])

        if not dependencies:
            return "No dependency examples found"

        formatted = "Dependency examples from similar blueprints:\n"
        unique_deps = []
        seen = set()

        for dep in dependencies:
            key = f"{dep.get('group_id', '')}:{dep.get('artifact_id', '')}"
            if key not in seen:
                seen.add(key)
                unique_deps.append(dep)

        for dep in unique_deps[:5]:  # Limit to 5 examples
            formatted += f"- {dep.get('group_id', '')}:{dep.get('artifact_id', '')}:{dep.get('version', '')}\n"

        return formatted

    @staticmethod
    def generate_available_libraries(package_name: str, package_available_libraries: dict) -> str:
        """
        Generate dynamic available libraries context based on the target package.

        Args:
            package_name: The target package name (e.g., "com.google.guava:guava")
            package_available_libraries: Dictionary mapping package patterns to library lists

        Returns:
            Formatted available libraries section as bulleted list
        """
        # Start with base libraries
        available_libs = package_available_libraries.get("_base", []).copy()

        # Add package-specific libraries
        for pkg_pattern, libs in package_available_libraries.items():
            if pkg_pattern == "_base":
                continue
            if pkg_pattern in package_name or package_name.split(":")[-1] in pkg_pattern:
                available_libs.extend(libs)
                break

        # Format as a bulleted list
        formatted_libs = "\n".join(f"- {lib}" for lib in available_libs)
        return formatted_libs

    @staticmethod
    def get_version_guidance(package_name: str, package_version: str, version_guidance_func=None) -> str:
        """
        Get targeted version-specific API guidance from reference system.

        Args:
            package_name: Package name (e.g., "org.apache.struts:struts2-core")
            package_version: Package version (e.g., "6.2.0")
            version_guidance_func: Function to call for getting version guidance
                                  (default: uses utils.api_references.api_reference_loader.get_version_guidance)

        Returns:
            Formatted guidance string with version-specific APIs, or empty string
        """
        try:
            # Import here to avoid circular dependencies
            if version_guidance_func is None:
                from utils.api_references.api_reference_loader import get_version_guidance as default_func

                version_guidance_func = default_func

            guidance = version_guidance_func(package_name, package_version)
            if guidance:
                logger.info(f"Loaded version guidance for {package_name} {package_version}")
                logger.info(f"VERSION GUIDANCE CONTENT (first 500 chars):\n{guidance[:500]}")
                logger.info(f"VERSION GUIDANCE LENGTH: {len(guidance)} characters")
                return guidance
            else:
                logger.debug(f"No version guidance available for {package_name} {package_version}")
                return ""
        except Exception as e:
            logger.warning(f"Error loading version guidance for {package_name}: {e}")
            logger.warning(f"Traceback: {traceback.format_exc()}")
            return ""

    @staticmethod
    def get_framework_requirements(framework_type: str) -> str:
        """
        Get framework-specific requirements for code adaptation.

        Loads requirements from framework_requirements.yaml config file.
        Falls back to hardcoded defaults if YAML not found.

        Args:
            framework_type: Target framework type (e.g., "SPRING_BOOT", "APACHE_STRUTS")

        Returns:
            Formatted framework requirements string
        """
        # Try to load from YAML first
        try:
            if LLMContextBuilder._framework_requirements_cache is None:
                yaml_path = PROJECT_ROOT / "src" / "config" / "framework_requirements.yaml"
                if yaml_path.exists():
                    with open(yaml_path, "r", encoding="utf-8") as f:
                        LLMContextBuilder._framework_requirements_cache = yaml.safe_load(f)
                    logger.info(f"Loaded framework requirements from {yaml_path}")

            # Get from cache if available
            if LLMContextBuilder._framework_requirements_cache:
                frameworks = LLMContextBuilder._framework_requirements_cache.get("frameworks", {})
                if framework_type in frameworks:
                    req = frameworks[framework_type]
                    formatted = f"**{req.get('name', framework_type)} Requirements:**\n"
                    formatted += req.get("requirements", "")
                    if "critical_warnings" in req:
                        formatted += f"\n\n{req['critical_warnings']}"
                    return formatted
        except Exception as e:
            logger.warning(f"Error loading framework requirements from YAML: {e}")

        # Fallback to hardcoded requirements
        logger.debug(f"Using hardcoded framework requirements for {framework_type}")
        return LLMContextBuilder._get_hardcoded_framework_requirements(framework_type)

    @staticmethod
    def _get_hardcoded_framework_requirements(framework_type: str) -> str:
        """
        Get hardcoded framework requirements (fallback).

        Args:
            framework_type: Target framework type

        Returns:
            Formatted framework requirements string
        """
        framework_specs = {
            "SPRING_BOOT": """
                **Spring Boot Requirements:**
                - Use @SpringBootApplication annotation for main class
                - Create @RestController for web endpoints
                - Use @PostMapping/@GetMapping for HTTP endpoints
                - Add spring-boot-starter-web dependency
                - Configure application.properties for server settings
                - Use dependency injection with @Autowired
                - Main class should extend SpringBootApplication pattern
                """,
            "APACHE_STRUTS": """
                **Apache Struts Requirements:**
                - Create Action classes extending ActionSupport
                - Use @Action annotation for action methods
                - Configure struts.xml for action mappings
                - Add struts2-core and struts2-convention-plugin dependencies
                - Use Result types for view rendering
                - Configure web.xml for Struts filter
                - Follow convention-based configuration

                **CRITICAL - DO NOT create configuration files:**
                - DO NOT create struts.xml - it will be injected automatically from templates
                - DO NOT create web.xml - it will be injected automatically from templates
                - The template system handles all framework configuration files
                """,
            "MICRONAUT": """
                **Micronaut Requirements:**
                - Use @Application annotation for main class
                - Create @Controller for web endpoints
                - Use @Get/@Post annotations for HTTP endpoints
                - Add micronaut-http and micronaut-http-server-netty dependencies
                - Configure application.yml for server settings
                - Use compile-time dependency injection
                - Main class should be an Application
                """,
            "QUARKUS": """
                **Quarkus Requirements:**
                - Use @Path annotation for REST endpoints
                - Create JAX-RS resource classes
                - Use @GET/@POST annotations for HTTP methods
                - Add quarkus-resteasy and quarkus-arc dependencies
                - Configure application.properties for settings
                - Use CDI for dependency injection
                - Main class can be a standard main method
                """,
            "WEB_APPLICATION": """
                **Web Application Requirements:**
                - Create Spring Boot web application with @SpringBootApplication
                - Add @RestController for HTTP endpoints
                - Include endpoints like /api/vulnerable, /api/parse, /api/exploit
                - Run on port 8080 for HTTP accessibility
                - Focus on HTTP-based vulnerability demonstration
                """,
        }

        return framework_specs.get(framework_type, framework_specs["WEB_APPLICATION"])
