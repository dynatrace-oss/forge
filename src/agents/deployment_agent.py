import logging
import re

from models.blueprint import Blueprint
from models.error_handling import ErrorCategory, ErrorSeverity, handle_error
from models.error_recovery import ErrorSeverity as RecoveryErrorSeverity
from models.error_recovery import ErrorType
from services.blueprint_management.blueprint_repository_service import BlueprintRepositoryService
from services.blueprint_management.framework_adaptation_service import FrameworkAdaptationService
from services.blueprint_management.framework_intelligence_service import FrameworkIntelligenceService
from services.deployment.container_service import ContainerService
from services.exploit_validation.error_recovery_service import ErrorRecoveryService
from services.system.llm_service import LLMService
from templates.manager import TemplateManager, VulnerabilityTemplate
from utils.container.deployment_utils import (
    ensure_consistent_package_declarations,
    ensure_required_imports,
    fix_resource_access_patterns,
    get_main_class_name,
    normalize_file_paths,
    validate_and_fix_java_imports,
    validate_java_syntax_enhanced,
)
from utils.core.common import (
    extract_files_from_llm_response,
    get_class_name_for_package,
)
from utils.core.prompt_manager import prompt_manager

logger = logging.getLogger(__name__)


class DeploymentAgent:
    """
    Agent responsible for deploying vulnerable applications in containers.
    Makes strategic decisions about deployment strategies and container configurations.

    DYNAMIC PROMPT TEMPLATE SYSTEM INTEGRATION:

    This agent uses simple prompt templates via PromptManager for container generation:

    - container_generation
      * Used in: _generate_container_prompt()
      * Purpose: Generate LLM prompt for container file creation
      * Context provided: package_name, package_version, cve_ids, description,
        metadata_section, code_snippets_section, template_section, framework_context
      * No enrichers - just straightforward {var} replacement

    USAGE PATTERN:

    prompt = prompt_manager.format_prompt(
        "container_generation",
        package_name=blueprint.package_name,
        package_version=blueprint.package_version,
        # ... other context variables
    )

    Since container_generation is a simple template (v1.0.0), PromptManager:
    1. Detects it's not an advanced template (no extends, no Jinja2 syntax)
    2. Uses fast string replacement via _format_simple_template()
    3. Returns formatted prompt immediately (no enricher invocation)
    """

    def __init__(
        self,
        blueprint_service: BlueprintRepositoryService | None = None,
        container_service: ContainerService | None = None,
        llm_service: LLMService | None = None,
        template_manager: TemplateManager | None = None,
        error_recovery_service: ErrorRecoveryService | None = None,
        framework_adaptation_service: FrameworkAdaptationService | None = None,
        framework_intelligence_service: FrameworkIntelligenceService | None = None,
        use_llm: bool = True,
        enable_error_recovery: bool = True,
        enable_framework_adaptation: bool = True,
    ):
        """
        Initialize the Deployment Agent.

        Args:
            blueprint_service: Service for retrieving blueprints
            container_service: Service for container operations
            llm_service: Service for LLM interaction
            template_manager: Service for template management
            error_recovery_service: Service for error recovery
            framework_adaptation_service: Service for framework adaptation
            framework_intelligence_service: Service for framework intelligence
            use_llm: Whether to use LLM for container generation
            enable_error_recovery: Whether to enable automatic error recovery
            enable_framework_adaptation: Whether to enable framework adaptation
        """
        self.blueprint_service = blueprint_service or BlueprintRepositoryService()
        self.container_service = container_service or ContainerService()
        self.llm_service = llm_service or LLMService()
        self.template_manager = template_manager or TemplateManager()
        self.error_recovery_service = error_recovery_service or ErrorRecoveryService(
            llm_service=self.llm_service
        )
        self.use_llm = use_llm
        self.enable_error_recovery = enable_error_recovery
        self.enable_framework_adaptation = enable_framework_adaptation
        
        # Initialize framework adaptation services (single initialization)
        if self.enable_framework_adaptation:
            self.framework_adaptation_service = framework_adaptation_service or FrameworkAdaptationService(
                llm_service=self.llm_service
            )
            self.framework_intelligence_service = framework_intelligence_service or FrameworkIntelligenceService(
                llm_service=self.llm_service
            )
        else:
            self.framework_adaptation_service = None
            self.framework_intelligence_service = None

    async def deploy_blueprint(self, blueprint_id: str) -> dict[str, any]:
        """
        Deploy a blueprint as a containerized application.
        Makes decisions about deployment strategy based on blueprint properties.

        Args:
            blueprint_id: ID of the blueprint to deploy

        Returns:
            dictionary with deployment result
        """
        try:
            logger.info(f"Deploying blueprint {blueprint_id}")

            # Get the blueprint
            blueprint = await self.blueprint_service.get_blueprint(blueprint_id)
            if not blueprint:
                return {
                    "status": "error",
                    "blueprint_id": blueprint_id,
                    "error": f"Blueprint {blueprint_id} not found",
                }

            # Decide on deployment strategy
            if self.use_llm:
                # Use LLM-based container generation
                logger.info(f"Using LLM-based container generation for blueprint {blueprint_id}")
                result = await self._generate_container_with_llm(blueprint)
            else:
                # Use template-based container generation
                logger.info(f"Using template-based container generation for blueprint {blueprint_id}")
                result = await self._generate_container_with_template(blueprint)

            if result["status"] != "success":
                return result

            # Build the container with error recovery
            build_result = await self._build_container_with_recovery(
                blueprint, result["container_dir"], result["container_name"]
            )

            # Add blueprint information to the result
            build_result["blueprint_id"] = blueprint_id
            build_result["blueprint_name"] = blueprint.name
            build_result["cve_ids"] = blueprint.cve_ids

            return build_result

        except Exception as e:
            logger.error(f"Error deploying blueprint {blueprint_id}: {e}")
            return {"status": "error", "blueprint_id": blueprint_id, "error": str(e)}

    async def _generate_container_with_llm(self, blueprint: Blueprint) -> dict[str, any]:
        """Generate container files using LLM with enhanced file processing."""
        try:
            # Create a container directory
            container_info = self.container_service.create_container_dir(blueprint.package_name)
            container_dir = container_info["container_dir"]
            container_name = container_info["container_name"]

            # Check if blueprint already has code snippets from vulnerability generation
            if blueprint.code_snippets:
                logger.info("Using existing code snippets from blueprint for container generation")
                files = {}

                for filename, content in blueprint.code_snippets.items():
                    # Skip non-code files
                    if filename.endswith((".txt", ".md")) and "code_block" in filename:
                        continue

                    # Use the existing files directly
                    if filename.endswith((".java", ".yaml", ".yml", ".json", ".properties", ".xml")):
                        files[filename] = content

                files = normalize_file_paths(files)

                files = fix_resource_access_patterns(files)
                files = ensure_consistent_package_declarations(files)
                files = ensure_required_imports(files)
                files = validate_and_fix_java_imports(files)

                if files and self._validate_container_files(files, blueprint):
                    logger.info(f"Using {len(files)} files from blueprint code snippets")

                    main_class_name = get_main_class_name(files) or get_class_name_for_package(blueprint.package_name)
                    files = await self._add_template_generated_files(blueprint, files, main_class_name, container_name)
                    await self.container_service.write_container_files(container_dir, files)

                    return {
                        "status": "success",
                        "blueprint_id": blueprint.blueprint_id,
                        "container_dir": container_dir,
                        "container_name": container_name,
                        "generation_method": "blueprint_snippets_enhanced",
                    }
            # If no valid code snippets, continue with LLM generation
            logger.info("No valid code snippets in blueprint, generating with LLM")

            # Generate prompt for the LLM (template parameter is optional and can be None)
            prompt = self._generate_container_prompt(blueprint, None)

            # Generate container files using LLM
            try:
                logger.info(f"Generating container files using LLM for blueprint {blueprint.blueprint_id}")
                response = await self.llm_service.generate(prompt)

                # Store the raw LLM response for debugging
                self.llm_response = response
                logger.debug(f"LLM response preview: {response[:500]}...")

            except Exception as e:
                # Log error and fall back to template-based generation
                logger.warning(f"LLM container generation failed: {e}. Falling back to template-based generation")
                return await self._generate_container_with_template(blueprint)

            # Parse LLM response into files using the common utility
            files = extract_files_from_llm_response(response)

            # If no files were extracted, try simple parsing approach
            if not files:
                logger.warning("Failed to extract files with advanced parser, trying fallback method")
                raise FileNotFoundError("No files found in LLM response")

            files = normalize_file_paths(files)
            files = fix_resource_access_patterns(files)
            files = ensure_consistent_package_declarations(files)
            files = ensure_required_imports(files)
            files = validate_and_fix_java_imports(files)

            # Validate after all fixes
            if not files or not self._validate_container_files(files, blueprint):
                logger.warning("Invalid or missing files in LLM response after fixes")
                # Fall back to template-based generation
                return await self._generate_container_with_template(blueprint)

            # Add template-generated files
            main_class_name = get_main_class_name(files) or get_class_name_for_package(blueprint.package_name)
            files = await self._add_template_generated_files(blueprint, files, main_class_name, container_name)

            # Write files to container directory
            logger.info(f"Writing {len(files)} container files to {container_dir}")
            await self.container_service.write_container_files(container_dir, files)

            return {
                "status": "success",
                "blueprint_id": blueprint.blueprint_id,
                "container_dir": container_dir,
                "container_name": container_name,
                "generation_method": "llm_enhanced",
            }

        except Exception as e:
            # Log error and fall back to template-based generation
            logger.warning(f"Error in LLM container generation: {e}. Falling back to template-based generation")
            return await self._generate_container_with_template(blueprint)

    async def _generate_container_with_template(self, blueprint: Blueprint) -> dict[str, any]:
        """This method serves as a reliable fallback when LLM-based generation
        fails or is disabled, using blueprint code snippets as the source of truth."""
        try:
            logger.info(f"Generating container using blueprint code snippets for blueprint {blueprint.blueprint_id}")

            # Create a container directory
            container_info = self.container_service.create_container_dir(blueprint.package_name)
            container_dir = container_info["container_dir"]
            container_name = container_info["container_name"]

            # Use blueprint code snippets instead of vulnerability templates
            if not blueprint.code_snippets:
                logger.error(f"No code snippets available in blueprint {blueprint.blueprint_id}")
                return {
                    "status": "error",
                    "blueprint_id": blueprint.blueprint_id,
                    "error": f"No code snippets available for {blueprint.package_name}. Blueprint code snippets are required.",
                }

            logger.info(f"Using {len(blueprint.code_snippets)} code snippets from blueprint as fallback")

            # Normalize and prepare code snippets for container
            files = normalize_file_paths(blueprint.code_snippets)
            logger.info(f"Normalized {len(files)} files from blueprint code snippets")

            # Find main class name from Java files
            main_class_name = None
            for file_path, content in files.items():
                if file_path.endswith('.java') and 'public static void main' in content:
                    # Extract class name from content
                    class_match = re.search(r'(?:public\s+)?class\s+(\w+)', content)
                    if class_match:
                        main_class_name = class_match.group(1)
                        logger.info(f"Found main class: {main_class_name} in {file_path}")
                        break

            if not main_class_name:
                main_class_name = get_class_name_for_package(blueprint.package_name)
                # WAR-based apps (Struts, servlet containers) don't need main class - this is expected
                # JAR-based apps (Spring Boot, Micronaut, Quarkus) DO need main class - this is a problem
                is_war_based = self._is_war_based_framework(blueprint)
                if is_war_based:
                    logger.debug(f"No main class needed for WAR-based app, using generated name for POM: {main_class_name}")
                else:
                    logger.warning(f"No main class found for JAR-based app, using generated name: {main_class_name}")

            files = normalize_file_paths(files)
            files = fix_resource_access_patterns(files)
            files = ensure_consistent_package_declarations(files)
            files = ensure_required_imports(files)
            files = validate_and_fix_java_imports(files)

            if not self._validate_container_files(files, blueprint):
                logger.error("Template-generated files failed validation")
                return {
                    "status": "error",
                    "blueprint_id": blueprint.blueprint_id,
                    "error": "Generated files failed validation - missing main class or invalid Java syntax",
                }

            # Add template-generated files (POM, Containerfile, README)
            try:
                files = await self._add_template_generated_files(blueprint, files, main_class_name, container_name)
            except Exception as e:
                logger.error(f"Failed to add template-generated files: {e}")
                return {
                    "status": "error",
                    "blueprint_id": blueprint.blueprint_id,
                    "error": f"Template file generation failed: {str(e)}",
                }

            # Write files to container directory
            logger.info(f"Writing {len(files)} template-generated files to {container_dir}")
            try:
                await self.container_service.write_container_files(container_dir, files)
            except Exception as e:
                logger.error(f"Failed to write container files: {e}")
                return {
                    "status": "error",
                    "blueprint_id": blueprint.blueprint_id,
                    "error": f"File writing failed: {str(e)}",
                }

            logger.info(f"Successfully generated container using blueprint code snippets for blueprint {blueprint.blueprint_id}")

            return {
                "status": "success",
                "blueprint_id": blueprint.blueprint_id,
                "container_dir": container_dir,
                "container_name": container_name,
                "generation_method": "blueprint_based",
            }

        except Exception as e:
            logger.error(f"Error in blueprint-based container generation: {e}", exc_info=True)
            return {
                "status": "error",
                "blueprint_id": blueprint.blueprint_id,
                "error": f"Blueprint-based generation failed: {str(e)}",
            }

    def _extract_action_class_name_from_files(self, files: dict[str, str]) -> str:
        """
        Extract the actual Action class name from generated Java files.

        This prevents the 404 loop where struts.xml references a hardcoded class name
        that doesn't match the LLM-generated Action class name.

        Args:
            files: Dictionary of file paths to content

        Returns:
            Fully qualified class name (e.g., "com.vuln.VulnerableFileUploadAction")
            or fallback "com.vuln.VulnerableAction"
        """
        for file_path, content in files.items():
            if file_path.endswith(".java") and ("extends ActionSupport" in content or "ActionSupport" in content):
                # Extract package name
                package_match = re.search(r"^\s*package\s+([a-zA-Z_][\w.]*)\s*;", content, re.MULTILINE)
                # Extract class name
                class_match = re.search(r"^\s*(?:public\s+)?class\s+(\w+)", content, re.MULTILINE)

                if package_match and class_match:
                    package_name = package_match.group(1)
                    class_name = class_match.group(1)
                    fqcn = f"{package_name}.{class_name}"
                    logger.info(f"Extracted Action class name: {fqcn} from {file_path}")
                    return fqcn

        # Fallback to default
        logger.warning("Could not extract Action class name from files, using fallback: com.vuln.VulnerableAction")
        return "com.vuln.VulnerableAction"

    async def _add_template_generated_files(
        self,
        blueprint: Blueprint,
        files: dict[str, str],
        main_class_name: str,
        container_name: str,
    ) -> dict[str, str]:
        """Add template-generated files (pom.xml, Containerfile, README.md) to the files dictionary."""
        # Extract framework adaptation dependencies from blueprint metadata
        framework_deps = None
        framework_type = None
        if blueprint.metadata and "framework_adaptation" in blueprint.metadata:
            framework_deps = blueprint.metadata["framework_adaptation"].get("dependencies_added")
            if framework_deps:
                logger.info(f"Using {len(framework_deps)} framework adaptation dependencies from blueprint")

            # Extract framework type for framework-specific config file generation
            framework_type = blueprint.metadata["framework_adaptation"].get("selected_framework")
            if framework_type:
                logger.info(f"Framework type detected from adaptation: {framework_type}")

                # Only extract action class name for Apache Struts
                action_class_name = None
                if "struts" in framework_type.lower():
                    action_class_name = self._extract_action_class_name_from_files(files)
                    logger.info(f"Will inject Action class name into struts.xml: {action_class_name}")

                # Extract config values from blueprint for protocol servers
                config_values = None
                if "__config_values__" in blueprint.code_snippets:
                    config_values = blueprint.code_snippets["__config_values__"]
                    logger.info(f"Found {len(config_values)} config values for protocol server")

                config_files = self.template_manager.get_framework_config_files(
                    framework_type=framework_type,
                    package_version=blueprint.package_version,
                    action_class_name=action_class_name,
                    config_values=config_values,
                )

                if config_files:
                    logger.info(f"Adding {len(config_files)} framework config files for {framework_type}")
                    for config_path in config_files.keys():
                        logger.debug(f"   - {config_path}")
                    files.update(config_files)

                    # Endpoint extraction (extract_struts_xml_actions, extract_spring_mvc_endpoints)
                    # looks in blueprint.code_snippets for config files like struts.xml
                    for config_path, config_content in config_files.items():
                        blueprint.add_code_snippet(config_path, config_content)
                    logger.info(f"Added {len(config_files)} config files to blueprint code snippets for endpoint extraction")

                    # Without this, config files are only in memory and validation can't extract endpoints
                    await self.blueprint_service.store_blueprint(blueprint)
                    logger.info(f"Re-saved blueprint {blueprint.blueprint_id} with {len(config_files)} config files persisted")
                else:
                    logger.debug(f"No config files needed for framework: {framework_type}")

        # Generate pom.xml using template manager
        files["pom.xml"] = self.template_manager.generate_pom_xml(
            blueprint=blueprint,
            main_class_name=main_class_name,
            framework_adaptation_dependencies=framework_deps
        )

        # Generate Containerfile using template manager
        files["Containerfile"] = self.template_manager.generate_containerfile(
            blueprint=blueprint, main_class_name=main_class_name
        )

        # Extract exploitation and mitigation information from LLM response
        context = {}

        if hasattr(self, "llm_response"):
            # Extract exploitation information
            exploitation_info = self._extract_section_from_llm_response("Exploitation", "exploit")
            if exploitation_info:
                context["exploitation"] = exploitation_info
            else:
                context["exploitation"] = "No specific exploitation information available."

            # Extract mitigation information
            mitigation_info = self._extract_section_from_llm_response("Mitigation", "fix")
            if mitigation_info:
                context["mitigation"] = mitigation_info
            else:
                context["mitigation"] = "No specific mitigation information available."

            # Try to determine vulnerability type and severity from metadata or CVE
            vulnerability_type = self._determine_vulnerability_type(blueprint)
            severity = self._determine_severity(blueprint)

            if vulnerability_type:
                context["vulnerability_type"] = vulnerability_type

            if severity:
                context["severity"] = severity

        # Generate README.md using template manager with context
        files["README.md"] = self.template_manager.generate_readme(
            blueprint=blueprint,
            container_name=container_name,
            context=context,
        )

        return files

    def _determine_vulnerability_type(self, blueprint: Blueprint) -> str:
        """Determine vulnerability type from blueprint metadata or description."""
        # Check the description
        description = blueprint.description.lower()
        if "deserialization" in description:
            return "Deserialization Vulnerability"
        elif "remote code execution" in description or "rce" in description:
            return "Remote Code Execution"

        # Check metadata
        if "osv_data" in blueprint.metadata:
            osv_data = blueprint.metadata["osv_data"]
            if "database_specific" in osv_data and "cwe_ids" in osv_data["database_specific"]:
                cwe_ids = osv_data["database_specific"]["cwe_ids"]
                if "CWE-502" in cwe_ids:
                    return "Deserialization of Untrusted Data"
                elif "CWE-20" in cwe_ids:
                    return "Improper Input Validation"

        return ""

    def _determine_severity(self, blueprint: Blueprint) -> str:
        """Determine severity from blueprint metadata."""
        # Check metadata
        if "osv_data" in blueprint.metadata:
            osv_data = blueprint.metadata["osv_data"]
            if "database_specific" in osv_data and "severity" in osv_data["database_specific"]:
                return osv_data["database_specific"]["severity"]

        return ""

    def _extract_section_from_llm_response(self, section_name: str, alternative_name: str = None) -> str:
        """Extract a specific section from the LLM response using a simpler approach."""
        if not hasattr(self, "llm_response"):
            return ""

        # Use a simple pattern that looks for the section name followed by a colon and newline
        section_pattern = rf"{section_name}:\s*\n([\s\S]+?)(?:\n\w+:\s*\n|\Z)"

        # Check for alternative name if provided
        if alternative_name:
            alt_pattern = rf"{alternative_name}:\s*\n([\s\S]+?)(?:\n\w+:\s*\n|\Z)"
            alt_match = re.search(alt_pattern, self.llm_response, re.IGNORECASE)
            if alt_match:
                return alt_match.group(1).strip()

        # Search main section name
        match = re.search(section_pattern, self.llm_response, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # If we reach here, we couldn't find the section
        return ""

    def _generate_container_prompt(self, blueprint: Blueprint, template: VulnerabilityTemplate | None) -> str:
        """
        Generate prompt for container generation using PromptManager.

        TEMPLATE USAGE:
        - Template: container_generation (SIMPLE v1.0.0)
        - Routing: prompt_manager.format_prompt() → _format_simple_template()
        - No enrichers invoked (simple string replacement only)
        - Context: All variables manually prepared by this method

        Args:
            blueprint: Blueprint with vulnerability details
            template: Optional vulnerability template for additional context

        Returns:
            Formatted container generation prompt for LLM
        """
        try:
            # Determine if this is actually a framework-specific vulnerability
            framework_type = (
                blueprint.get_framework_type() if hasattr(blueprint, "get_framework_type") else "standalone"
            )

            # Add framework context to the prompt only if it's truly framework-specific
            framework_context = ""
            if framework_type != "standalone":
                framework_context = f"Framework Type: {framework_type}\n"
            else:
                framework_context = "Framework Type: standalone - Generate a simple Java application without Spring Boot or other frameworks\n"

            # Create context for prompt formatting and use PromptManager
            prompt = prompt_manager.format_prompt(
                "container_generation",
                package_name=blueprint.package_name,
                package_version=blueprint.package_version,
                cve_ids=", ".join(blueprint.cve_ids),
                description=blueprint.description,
                metadata_section=self._format_metadata_section(blueprint),
                code_snippets_section=self._format_code_snippets_section(blueprint),
                template_section=self._format_template_section(template) if template else "",
                framework_context=framework_context,
            )

            return prompt

        except Exception as e:
            raise ValueError(f"Failed to generate container prompt: {str(e)}")

    def _format_metadata_section(self, blueprint: Blueprint) -> str:
        """Format metadata section for prompt."""
        if not blueprint.metadata:
            return "No metadata available"

        metadata_section = "VULNERABILITY METADATA:\n"
        enhanced_metadata = blueprint.metadata.get("enhanced_metadata", {})

        for key, value in enhanced_metadata.items():
            if isinstance(value, str):
                metadata_section += f"{key}: {value}\n"
            elif isinstance(value, (list, tuple)):
                metadata_section += f"{key}: {', '.join(map(str, value))}\n"

        return metadata_section

    def _format_code_snippets_section(self, blueprint: Blueprint) -> str:
        """Format code snippets section for prompt."""
        if not blueprint.code_snippets:
            return "No code snippets available"

        code_snippets_section = "CODE SNIPPETS:\n"
        for name, code in blueprint.code_snippets.items():
            code_snippets_section += f"--- {name} ---\n{code[:500]}...\n\n"

        return code_snippets_section

    def _format_template_section(self, template: VulnerabilityTemplate) -> str:
        """Format template section for prompt."""
        if not template:
            return "No template information available"

        template_section = "TEMPLATE INFORMATION:\n"
        template_section += f"Imports:\n{template.get_imports()}\n\n"
        template_section += f"Demo Code:\n{template.get_demo_code()}\n\n"

        resources = template.get_resources()
        if isinstance(resources, dict) and resources:
            template_section += "Resources:\n"
            for name, resource in resources.items():
                if isinstance(resource, dict) and "content" in resource:
                    content = (
                        resource["content"][:200] + "..." if len(resource["content"]) > 200 else resource["content"]
                    )
                    template_section += f"--- {name} ---\n{content}\n\n"

        return template_section

    def _is_war_based_framework(self, blueprint: Blueprint) -> bool:
        """
        Detect if blueprint requires WAR packaging (servlet-based, no main method needed).

        WAR-based frameworks:
        - Apache Struts (struts2-core, struts-core, etc.)
        - Traditional Spring MVC (servlet containers)
        - Any servlet-based application

        JAR-based frameworks (require main method):
        - Spring Boot
        - Micronaut
        - Quarkus
        - Standalone libraries

        Args:
            blueprint: Blueprint to check

        Returns:
            True if WAR-based (servlet container), False if JAR-based (needs main method)
        """
        try:
            # Check package name for Struts patterns
            package_name = blueprint.package_name.lower()

            # Struts packages are always WAR-based
            if "struts" in package_name:
                logger.info(f"Detected Struts package (WAR-based): {blueprint.package_name}")
                return True

            # Check framework metadata from framework adaptation
            framework_metadata = blueprint.metadata.get("framework_adaptation", {})
            selected_framework = framework_metadata.get("selected_framework", "").lower()

            if "struts" in selected_framework or "servlet" in selected_framework:
                logger.info(f"Detected WAR-based framework from metadata: {selected_framework}")
                return True

            # Check deployment configuration
            deployment_config = framework_metadata.get("deployment_config", {})
            packaging_type = deployment_config.get("packaging_type", "").lower()

            if packaging_type == "war":
                logger.info("Detected WAR packaging from deployment config")
                return True

            # Default to JAR-based (requires main method)
            logger.debug(f"Package {blueprint.package_name} is JAR-based (requires main method)")
            return False

        except Exception as e:
            logger.warning(f"Error detecting framework packaging type: {e}, defaulting to JAR-based")
            return False

    def _validate_container_files(self, files: dict[str, str], blueprint: Blueprint) -> bool:
        """
        Comprehensive validation of generated container files.

        Framework-aware validation:
        - WAR-based frameworks (Struts, servlet containers): No main method required
        - JAR-based frameworks (Spring Boot, Micronaut, Quarkus): Main method required

        Args:
            files: Generated container files
            blueprint: Blueprint being deployed (for framework detection)

        Returns:
            True if validation passes, False otherwise
        """
        try:
            # Detect framework packaging type
            is_war_based = self._is_war_based_framework(blueprint)

            # Check for at least one Java source file
            has_java_file = False
            has_main_method = False
            java_files = []

            for filename, content in files.items():
                if filename.endswith(".java"):
                    has_java_file = True
                    java_files.append(filename)

                    # Only match actual class declarations (not in comments)
                    class_match = re.search(r"^\s*(?:public\s+)?class\s+(\w+)", content, re.MULTILINE)
                    if class_match:
                        class_name = class_match.group(1)
                        expected_filename = f"{class_name}.java"

                        if not filename.endswith(expected_filename):
                            logger.warning(
                                f"Class {class_name} should be in file {expected_filename}, found in {filename}"
                            )
                            # This should have been fixed by normalization
                            return False

                    # Check if it has a main method
                    if "public static void main" in content:
                        has_main_method = True
                        logger.info(f"Found main method in Java file {filename}")

                    if not validate_java_syntax_enhanced(filename, content):
                        logger.warning(f"Java syntax validation failed for {filename}")
                        return False

            if not has_java_file:
                logger.warning("No Java source file found in generated files")
                logger.debug(f"Files found: {list(files.keys())}")
                return False

            # Only require main method for JAR-based applications (Spring Boot, Micronaut, Quarkus, standalone)
            # WAR-based applications (Struts, servlet containers) are loaded by web container, no main needed
            if not is_war_based and not has_main_method:
                logger.warning(f"No main method found in JAR-based application. Java files: {java_files}")
                return False
            elif is_war_based and not has_main_method:
                logger.info("WAR-based application detected - main method not required. Validation passed.")

            logger.info(f"Container files validation passed. Found {len(java_files)} Java files")
            return True

        except Exception as e:
            logger.error(f"Error validating container files: {e}")
            return False

    async def deploy_all_blueprints(self, package_filter: str = None, limit: int = 10) -> list[dict[str, any]]:
        """
        Deploy all blueprints matching a filter.

        Args:
            package_filter: Optional package name filter
            limit: Maximum number of blueprints to deploy

        Returns:
            list of deployment results
        """
        try:
            # Get all blueprints
            blueprints = await self.blueprint_service.get_blueprints(package_filter=package_filter, limit=limit)

            if not blueprints:
                logger.warning(f"No blueprints found matching filter: {package_filter}")
                return []

            # Deploy each blueprint
            results = []
            for blueprint in blueprints:
                result = await self.deploy_blueprint(blueprint.blueprint_id)
                results.append(result)

            return results

        except Exception as e:
            logger.error(f"Error deploying all blueprints: {e}")
            return [{"status": "error", "error": str(e)}]

    async def undeploy_container(self, container_name: str) -> dict[str, any]:
        """
        Undeploy a container.

        Args:
            container_name: Name of the container to undeploy

        Returns:
            dictionary with undeploy result
        """
        try:
            # Remove the container
            result = await self.container_service.remove_container(container_name)
            return result

        except Exception as e:
            logger.error(f"Error undeploying container {container_name}: {e}")
            return {
                "status": "error",
                "container_name": container_name,
                "error": str(e),
            }

    async def deploy_multiple_blueprints(self, package_filter: str = None, limit: int = 10) -> list[dict[str, any]]:
        """
        Deploy multiple blueprints matching a filter.

        Args:
            package_filter: Optional package name filter
            limit: Maximum number of blueprints to deploy

        Returns:
            list of deployment results
        """
        # This is an alias for deploy_all_blueprints for compatibility with system_integration.py
        return await self.deploy_all_blueprints(package_filter, limit)

    async def run_container(self, container_name: str, ports: list[str] = None, blueprint_id: str = None) -> dict[str, any]:
        """
        Run a container.
        Makes decisions about resource constraints and security settings.

        Args:
            container_name: Name of the container to run
            ports: Optional list of port mappings in format "host:container"
            blueprint_id: Optional blueprint ID to add as container label for discovery

        Returns:
            dictionary with run result
        """
        try:
            logger.info(f"Running container {container_name} with ports {ports}")

            # Prepare labels if blueprint_id is provided
            labels = {}
            if blueprint_id:
                labels["blueprint_id"] = blueprint_id
                logger.info(f"Adding blueprint_id label: {blueprint_id}")

            # Run the container
            result = await self.container_service.run_container(container_name, ports, labels)

            # Verify container is running
            if result["status"] == "success":
                logger.info(f"Container {container_name} is now running with ID {result.get('container_id')}")
            else:
                logger.warning(f"Container {container_name} failed to start: {result.get('error')}")

                # Try to get logs if container ID is available
                if "container_id" in result:
                    logs = await self.container_service.get_container_logs(result["container_id"])
                    result["logs"] = logs

            return result

        except Exception as e:
            # Log and categorize error
            handle_error(
                e,
                default_category=ErrorCategory.CONTAINER_BUILD,
                default_severity=ErrorSeverity.ERROR,
                exit_on_error=True,
            )

            return {
                "status": "error",
                "container_name": container_name,
                "error": str(e),
            }

    async def stop_container(self, container_id: str) -> dict[str, any]:
        """
        Stop a running container.

        Args:
            container_id: ID of the container to stop

        Returns:
            dictionary with stop result
        """
        try:
            # Stop the container
            result = await self.container_service.stop_container(container_id)
            return result

        except Exception as e:
            logger.error(f"Error stopping container {container_id}: {e}")
            return {"status": "error", "container_id": container_id, "error": str(e)}


    async def _build_container_with_recovery(
        self, 
        blueprint: Blueprint, 
        container_dir: str, 
        container_name: str
    ) -> dict[str, any]:
        """
        Build container with automatic error recovery if build fails.
        
        Args:
            blueprint: Blueprint being deployed
            container_dir: Directory containing container files
            container_name: Name of the container
            
        Returns:
            Build result dictionary
        """
        max_recovery_attempts = 3
        
        for attempt in range(max_recovery_attempts):
            try:
                logger.info(f"Container build attempt {attempt + 1}/{max_recovery_attempts} for {container_name}")
                
                # Attempt to build the container
                build_result = await self.container_service.build_container(container_dir, container_name)
                
                if build_result.get("status") == "success":
                    logger.info(f"Container {container_name} built successfully")
                    return build_result
                else:
                    error_msg = build_result.get('error', 'Unknown error')
                    logger.warning(f"CONTAINER BUILD FAILED on attempt {attempt + 1}")
                    logger.info(f"Error: {error_msg}")
                    logger.info(f"Container Name: {container_name}")
                    logger.info(f"Container Dir: {build_result.get('container_dir', 'Unknown')}")

                    # Log build output details for debugging (INFO level - file only)
                    if 'output' in build_result:
                        stdout_preview = build_result['output'][:1000]
                        logger.info("BUILD STDOUT (first 1000 chars):")
                        for line in stdout_preview.split('\n')[:20]:  # First 20 lines
                            logger.info(f"   STDOUT: {line}")

                    if 'error_output' in build_result:
                        stderr_preview = build_result['error_output'][:1000]
                        logger.info("BUILD STDERR (first 1000 chars):")
                        for line in stderr_preview.split('\n')[:20]:  # First 20 lines
                            logger.info(f"   STDERR: {line}")
                    
                    # If error recovery is disabled or this is the last attempt, return failure
                    if not self.enable_error_recovery or attempt == max_recovery_attempts - 1:
                        return build_result
                    
                    # Attempt error recovery
                    recovery_successful = await self._attempt_build_recovery(
                        blueprint, container_dir, container_name, build_result, attempt
                    )

                    if not recovery_successful:
                        logger.warning(f"Error recovery failed for attempt {attempt + 1}")
                        # Continue to next attempt
                        continue
                    
                    logger.info(f"Error recovery completed for attempt {attempt + 1}, retrying build...")
                    
            except Exception as e:
                logger.error(f"Build attempt {attempt + 1} failed with exception: {e}")
                
                if not self.enable_error_recovery or attempt == max_recovery_attempts - 1:
                    return {"status": "error", "error": str(e)}
                
                # Attempt recovery for exception
                try:
                    recovery_successful = await self._attempt_exception_recovery(
                        blueprint, container_dir, container_name, e, attempt
                    )

                    if not recovery_successful:
                        logger.warning(f"Exception recovery failed for attempt {attempt + 1}")
                        continue
                        
                except Exception as recovery_error:
                    logger.error(f"Error during recovery: {recovery_error}")
                    continue
        
        # If we get here, all attempts failed
        return {
            "status": "error", 
            "error": f"Container build failed after {max_recovery_attempts} attempts with recovery"
        }

    async def _attempt_build_recovery(
        self,
        blueprint: Blueprint,
        container_dir: str,
        container_name: str,
        build_result: dict,
        attempt: int
    ) -> bool:
        """
        Attempt to recover from a container build failure.
        
        Args:
            blueprint: Blueprint being deployed
            container_dir: Container directory path
            container_name: Container name
            build_result: Failed build result
            attempt: Current attempt number
            
        Returns:
            True if recovery was successful, False otherwise
        """
        try:
            logger.info(f"Attempting error recovery for build failure (attempt {attempt + 1})")
            
            # Extract specific Maven error from logs
            maven_error = self._extract_maven_error_from_logs(
                stdout_logs=build_result.get("stdout", ""),
                stderr_logs=build_result.get("stderr", "")
            )
            
            # Create error context with enhanced build output
            stdout_logs = build_result.get("stdout", "") or build_result.get("output", "")
            stderr_logs = build_result.get("stderr", "") or build_result.get("error_output", "")
            
            logger.info("ERROR CONTEXT CREATION:")
            logger.info(f"Maven Error: {maven_error}")
            logger.info(f"Build Error: {build_result.get('error', 'None')}")
            logger.info(f"STDOUT Length: {len(stdout_logs)} chars")
            logger.info(f"STDERR Length: {len(stderr_logs)} chars")
            
            # Build environment vars with framework adaptation context
            env_vars = {
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "cve_ids": ", ".join(blueprint.cve_ids),
                "framework_type": "spring_boot",  # Default, could be enhanced
                "framework_adaptation_used": "false",
                "source_framework": "none",
                "adaptation_notes": "",
                "protocol_type": "",
                "vuln_level": "",
            }

            # Add classification metadata if present (for protocol-level vulnerabilities)
            if blueprint.metadata and "classification" in blueprint.metadata:
                classification = blueprint.metadata["classification"]
                env_vars["protocol_type"] = classification.get("protocol_type", "")
                env_vars["vuln_level"] = classification.get("level", "")

            # Add framework adaptation context if present
            if blueprint.metadata and "framework_metadata" in blueprint.metadata:
                fm = blueprint.metadata["framework_metadata"]
                if fm.get("has_adaptation"):
                    env_vars["framework_adaptation_used"] = "true"
                    env_vars["source_framework"] = fm.get("source_framework", "WEB_APPLICATION")
                    env_vars["framework_type"] = fm.get("target_framework", "unknown")
                    env_vars["adaptation_notes"] = "\n".join(fm.get("changes_made", []))

            error_context = self.error_recovery_service.create_error_context(
                error_message=maven_error or build_result.get("error", "Container build failed"),
                error_type=ErrorType.CONTAINER_BUILD_FAILURE,
                severity=RecoveryErrorSeverity.HIGH,
                blueprint_id=blueprint.blueprint_id,
                container_name=container_name,
                operation="container_build",
                stdout_logs=stdout_logs,
                stderr_logs=stderr_logs,
                affected_files=[container_dir],
                environment_vars=env_vars
            )
            
            # Attempt recovery
            recovery_attempt = await self.error_recovery_service.analyze_and_recover(error_context)

            if recovery_attempt.recovery_successful:
                logger.info(f"Error recovery successful for {container_name}")
                return True
            else:
                logger.warning(f"Error recovery failed: {recovery_attempt.final_error_message}")
                return False
                
        except Exception as e:
            logger.error(f"Error during build recovery: {e}")
            return False

    async def _attempt_exception_recovery(
        self,
        blueprint: Blueprint,
        container_dir: str,
        container_name: str,
        exception: Exception,
        attempt: int
    ) -> bool:
        """
        Attempt to recover from an exception during container build.
        
        Args:
            blueprint: Blueprint being deployed
            container_dir: Container directory path
            container_name: Container name
            exception: Exception that occurred
            attempt: Current attempt number
            
        Returns:
            True if recovery was successful, False otherwise
        """
        try:
            logger.info(f"Attempting exception recovery for {type(exception).__name__} (attempt {attempt + 1})")
            
            # Determine error type from exception
            error_type = self._classify_build_exception(exception)
            
            # Build environment vars with framework adaptation context
            env_vars = {
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "cve_ids": ", ".join(blueprint.cve_ids),
                "exception_type": type(exception).__name__,
                "framework_adaptation_used": "false",
                "source_framework": "none",
                "adaptation_notes": "",
            }

            # Add framework adaptation context if present
            if blueprint.metadata and "framework_metadata" in blueprint.metadata:
                fm = blueprint.metadata["framework_metadata"]
                if fm.get("has_adaptation"):
                    env_vars["framework_adaptation_used"] = "true"
                    env_vars["source_framework"] = fm.get("source_framework", "WEB_APPLICATION")
                    env_vars["framework_type"] = fm.get("target_framework", "unknown")
                    env_vars["adaptation_notes"] = "\n".join(fm.get("changes_made", []))

            # Create error context
            error_context = self.error_recovery_service.create_error_context(
                error_message=str(exception),
                error_type=error_type,
                severity=RecoveryErrorSeverity.HIGH,
                blueprint_id=blueprint.blueprint_id,
                container_name=container_name,
                operation="container_build",
                stack_trace=str(exception),
                affected_files=[container_dir],
                environment_vars=env_vars
            )
            
            # Attempt recovery
            recovery_attempt = await self.error_recovery_service.analyze_and_recover(error_context)

            return recovery_attempt.recovery_successful
            
        except Exception as e:
            logger.error(f"Error during exception recovery: {e}")
            return False

    def _classify_build_exception(self, exception: Exception) -> ErrorType:
        """
        Classify an exception into an appropriate error type.
        
        Args:
            exception: Exception to classify
            
        Returns:
            Appropriate ErrorType
        """
        exception_str = str(exception).lower()
        
        if "permission" in exception_str or "access" in exception_str:
            return ErrorType.PERMISSION_DENIED
        elif "network" in exception_str or "connection" in exception_str or "timeout" in exception_str:
            return ErrorType.NETWORK_TIMEOUT
        elif "memory" in exception_str or "oom" in exception_str:
            return ErrorType.MEMORY_ERROR
        elif "file" in exception_str or "directory" in exception_str:
            return ErrorType.RESOURCE_NOT_FOUND
        elif "dependency" in exception_str or "resolve" in exception_str:
            return ErrorType.DEPENDENCY_RESOLUTION
        else:
            return ErrorType.CONTAINER_BUILD_FAILURE

    async def get_error_recovery_status(self) -> dict[str, any]:
        """
        Get the current status of the error recovery system.
        
        Returns:
            Dictionary containing recovery status information
        """
        if not self.error_recovery_service:
            return {"enabled": False, "status": "not_available"}
        
        try:
            metrics = self.error_recovery_service.get_recovery_metrics()
            capability = await self.error_recovery_service.test_recovery_capability()
            
            return {
                "enabled": self.enable_error_recovery,
                "service_available": True,
                "total_recoveries": metrics.total_recovery_attempts,
                "successful_recoveries": metrics.successful_recoveries,
                "success_rate": metrics.overall_success_rate,
                "capability_test": capability
            }
            
        except Exception as e:
            return {
                "enabled": self.enable_error_recovery,
                "service_available": False,
                "error": str(e)
            }

    def _extract_maven_error_from_logs(self, stdout_logs: str, stderr_logs: str) -> str | None:
        """
        Extract specific Maven compilation errors from build logs.
        
        Args:
            stdout_logs: Maven stdout output
            stderr_logs: Maven stderr output
            
        Returns:
            Specific Maven error message or None if no specific error found
        """
        # Combine logs for analysis
        combined_logs = f"{stdout_logs}\n{stderr_logs}"
        
        # Generic Maven compilation error patterns
        error_patterns = [
            # Java compilation errors
            r"cannot find symbol.*?symbol:\s*(.+?).*?location:\s*(.+?)(?=\n|\[ERROR\]|$)",
            r"package (.+?) does not exist",
            r"(.+?) cannot be resolved to a type",
            r"The method (.+?) is undefined for the type (.+?)",
            r"Syntax error on token.+?expected",
            r"The import (.+?) cannot be resolved",
            # Maven-specific errors
            r"Failed to execute goal.*?Compilation failure",
            r"COMPILATION ERROR.*?(.+?)(?=\[INFO\]|\[ERROR\]|$)",
        ]
        
        for pattern in error_patterns:
            matches = re.search(pattern, combined_logs, re.DOTALL | re.IGNORECASE)
            if matches:
                # Return the full match, cleaned up
                error_text = matches.group(0).strip()
                # Clean up formatting
                error_text = re.sub(r'\[ERROR\]|\[INFO\]', '', error_text).strip()
                error_text = re.sub(r'\s+', ' ', error_text)
                return error_text[:500]  # Limit length
        
        # Fallback: look for any line with "ERROR" in Maven context
        error_lines = []
        for line in combined_logs.split('\n'):
            if 'ERROR' in line and any(keyword in line.lower() for keyword in ['compilation', 'symbol', 'method', 'package']):
                error_lines.append(line.strip())
        
        if error_lines:
            return ' | '.join(error_lines[:3])  # Max 3 error lines
        
        return None

