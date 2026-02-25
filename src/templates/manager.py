import asyncio
import logging
from pathlib import Path

from services.blueprint_management.framework_intelligence_service import FrameworkIntelligenceService
from services.config.config_manifest_service import ConfigManifestService
from services.config.framework_metadata_service import FrameworkMetadataService
from services.container.containerfile_factory import ContainerfileFactory
from shared.constants import (
    ENABLE_LLM_EXPLOITATION_GUIDANCE,
    LLM_EXPLOITATION_TIMEOUT,
    PROJECT_ROOT,
    TEMPLATES_BASE_DIR,
)
from shared.interfaces import LLMServiceInterface
from shared.types import FrameworkType
from utils.core.loader import TemplateLoader
from utils.support.renderer import TemplateRenderer

# Import new utility modules (Phase 1 refactoring)
from utils.core import version_utils

logger = logging.getLogger(__name__)


class TemplateManager:
    """
    Manager for vulnerability templates.
    Provides a single interface for working with different types of templates.
    """

    """Unified template manager combining all template functionality."""

    def __init__(
        self,
        templates_dir: str |  Path = None,
        llm_service: LLMServiceInterface | None= None,
        enable_framework_adaptation: bool = True
    ):
        """
        Initialize template manager with framework adaptation capabilities.

        Args:
            templates_dir: Base directory for templates
            llm_service: Optional LLM service for enhanced features
            enable_framework_adaptation: Whether to enable framework adaptation features
        """
        self.templates_dir = Path(templates_dir) if templates_dir else Path(TEMPLATES_BASE_DIR)
        if not self.templates_dir.is_absolute():
            self.templates_dir = PROJECT_ROOT / self.templates_dir

        # Initialize components
        self.loader = TemplateLoader(self.templates_dir)
        self.renderer = TemplateRenderer()

        # LLM service is optional and injected
        self.llm_service = llm_service
        self.enable_framework_adaptation = enable_framework_adaptation

        # Initialize framework adaptation services
        if self.enable_framework_adaptation and self.llm_service:
            self.framework_intelligence_service = FrameworkIntelligenceService(
                llm_service=self.llm_service
            )
        else:
            self.framework_intelligence_service = None

        # Initialize config manifest service for multi-config file support
        self.config_manifest_service = ConfigManifestService()
        logger.info("Config manifest service initialized")

        # Initialize framework metadata service (Stage 2: Externalize Hardcoded Logic)
        self.framework_metadata_service = FrameworkMetadataService()
        logger.info("Framework metadata service initialized")

        # Initialize Containerfile factory (Stage 2: Externalize Hardcoded Logic)
        self.containerfile_factory = ContainerfileFactory(self.framework_metadata_service)
        logger.info("Containerfile factory initialized")

        # Setup directory structure
        self._setup_directories()

        # Cache logic removed for simplification - direct template loading is more reliable

        # Load framework patterns
        try:
            self.framework_patterns = self._load_framework_patterns()
        except FileNotFoundError as e:
            logger.error(f"Failed to load framework patterns: {e}")
            raise

        # Instantiate specialised generators (delegate POM / Containerfile work)
        from templates.pom_generator import PomGenerator
        from templates.containerfile_generator import ContainerfileGenerator

        self._pom_generator = PomGenerator(self)
        self._containerfile_generator = ContainerfileGenerator(self)

    def _get_vulnerability_type_from_blueprint(self, blueprint) -> str:
        """
        Extract vulnerability type from blueprint using config-driven approach.

        Args:
            blueprint: Blueprint object

        Returns:
            Vulnerability type string
        """
        # Try enhanced metadata first
        vuln_type = (blueprint.metadata or {}).get("enhanced_metadata", {}).get("vulnerability_type")
        if vuln_type and vuln_type != "unknown":
            return vuln_type

        # Fallback to CWE mapping from config
        osv_data = (blueprint.metadata or {}).get("osv_data", {})
        cwe_ids = osv_data.get("database_specific", {}).get("cwe_ids", [])

        if cwe_ids:
            import yaml
            config_path = PROJECT_ROOT / "src" / "config" / "vulnerability_patterns.yaml"
            try:
                with open(config_path, 'r') as f:
                    patterns = yaml.safe_load(f)
                    cwe_map = patterns.get("cwe_mappings", {})

                # Return first matching CWE type
                for cwe_id in cwe_ids:
                    if cwe_id in cwe_map:
                        return cwe_map[cwe_id]
            except Exception as e:
                logger.warning(f"Failed to load CWE mapping: {e}")

        return "unknown"

    def _setup_directories(self):
        """Setup directory structure."""
        # Note: vulnerability directory was removed per changelog - blueprint code snippets are now the single source of truth
        self.resources_dir = self.templates_dir / "resources"
        self.framework_dir = self.templates_dir / "framework"

        # Core template directories for framework adaptation
        self.core_templates_dir = self.templates_dir / "core"

        # Container-specific directories
        self.container_dir = self.templates_dir / "container"
        self.container_java_dir = self.container_dir / "java"
        self.pom_dir = self.container_java_dir / "pom"
        self.repos_dir = self.container_java_dir / "repos"
        self.containerfile_dir = self.container_java_dir / "containerfile"
        self.readme_dir = self.container_java_dir / "readme"

    def _load_framework_patterns(self) -> dict[FrameworkType, list[str]]:
        """Load framework detection patterns from template files."""
        patterns_file = self.templates_dir / "framework" / "detection_patterns.txt"
        if not patterns_file.exists():
            raise FileNotFoundError(
                f"Framework detection patterns file not found at {patterns_file}. "
                f"Please create this file with framework detection patterns in format:\n"
                f"[SPRING_BOOT]\nspring\nspringboot\n\n[APACHE_STRUTS]\nstruts\nstruts2"
            )

        patterns = {}
        current_framework = None

        try:
            with open(patterns_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("[") and line.endswith("]"):
                        framework_name = line[1:-1].upper()
                        try:
                            current_framework = FrameworkType(framework_name.lower())
                            patterns[current_framework] = []
                        except ValueError:
                            logger.warning(f"Unknown framework type: {framework_name}")
                            current_framework = None
                    elif current_framework and line:
                        patterns[current_framework].append(line.lower())

            if not patterns:
                raise ValueError("No framework patterns loaded")

            return patterns

        except Exception as e:
            raise FileNotFoundError(f"Failed to load framework patterns: {str(e)}")

    async def detect_framework_type(self, vulnerability_data: dict[str, any]) -> FrameworkType:
        """Enhanced framework detection with framework intelligence service."""
        try:
            # First try template-based detection (existing logic)
            template_result = self._detect_framework_from_patterns(vulnerability_data)

            # If template detection found a specific framework, use it
            if template_result != FrameworkType.WEB_APPLICATION:
                logger.info(f"Framework detected by patterns: {template_result.value}")
                return template_result

            # Use framework intelligence service if available
            if self.enable_framework_adaptation and self.framework_intelligence_service:
                try:
                    intelligence_result = self._detect_framework_with_intelligence_sync(vulnerability_data)
                    if intelligence_result and intelligence_result != FrameworkType.WEB_APPLICATION:
                        logger.info(f"Framework detected by intelligence service: {intelligence_result.value}")
                        return intelligence_result
                except Exception as e:
                    logger.warning(f"Framework intelligence detection failed: {e}")

            # For ambiguous cases, try LLM enhancement (OPTIONAL fallback)
            llm_result = await self._detect_framework_with_llm_safe(vulnerability_data)
            if llm_result:
                logger.info(f"Framework detection enhanced by LLM: {llm_result}")
                try:
                    return FrameworkType(llm_result.lower())
                except ValueError:
                    logger.warning(f"LLM returned unknown framework type: {llm_result}")

            # Fall back to template result
            return template_result

        except Exception as e:
            logger.error(f"Error in framework detection: {e}")
            return FrameworkType.SPRING_BOOT

    def _load_framework_packages_config(self) -> dict:
        """Load framework package classification from config file."""
        import yaml

        config_path = PROJECT_ROOT / "src" / "config" / "framework_packages.yaml"
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load framework packages config: {e}")
            return {}

    def _load_spring_boot_version_mapping(self) -> dict:
        """Load Spring Boot to Spring Framework version mapping from config file."""
        import yaml

        config_path = PROJECT_ROOT / "src" / "config" / "spring_boot_version_mapping.yaml"
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load Spring Boot version mapping: {e}")
            return {}

    def _detect_framework_from_patterns(self, vulnerability_data: dict[str, any]) -> FrameworkType:
        """Original pattern-based detection (existing logic)."""
        if not self.framework_patterns:
            raise ValueError("Framework detection patterns not loaded")

        package_name = vulnerability_data.get("package_name", "").lower()
        description = vulnerability_data.get("description", "").lower()
        summary = vulnerability_data.get("summary", "").lower()
        cve_id = vulnerability_data.get("cve_id", "").lower()

        search_text = f"{package_name} {description} {summary} {cve_id}"

        for framework_type, patterns in self.framework_patterns.items():
            if any(pattern in search_text for pattern in patterns):
                return framework_type

        return FrameworkType.WEB_APPLICATION

    def _detect_framework_with_llm_safe(self, vulnerability_data: dict[str, any]) -> str:
        """Safely use LLM for framework detection without breaking existing flow."""
        try:
            if not self.llm_service or not hasattr(self.llm_service, "detect_framework_with_llm"):
                return ""

            result = asyncio.run(
                asyncio.wait_for(self.llm_service.detect_framework_with_llm(vulnerability_data), timeout=20.0)
            )

            if isinstance(result, dict) and "framework_type" in result:
                return result["framework_type"]

            return ""

        except asyncio.TimeoutError:
            logger.warning("LLM framework detection timed out")
            return ""
        except Exception as e:
            logger.debug(f"Error in safe LLM framework detection: {e}")
            return ""

    def _detect_framework_with_intelligence_sync(self, vulnerability_data: dict[str, any]) -> FrameworkType | None:
        """Synchronous wrapper for framework intelligence detection."""
        try:
            try:
                _ = asyncio.get_running_loop()
                # We're in an async context, use thread pool
                import concurrent.futures

                def run_detection_task():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(
                            self._detect_framework_with_intelligence(vulnerability_data)
                        )
                    finally:
                        new_loop.close()

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_detection_task)
                    return future.result(timeout=10.0)

            except RuntimeError:
                # No running loop
                return asyncio.run(self._detect_framework_with_intelligence(vulnerability_data))

        except Exception as e:
            logger.warning(f"Synchronous framework intelligence detection failed: {e}")
            return None

    async def _detect_framework_with_intelligence(self, vulnerability_data: dict[str, any]) -> FrameworkType | None:
        """Use framework intelligence service for advanced framework detection."""
        try:
            package_name = vulnerability_data.get("package_name", "")

            # Create package info for intelligence service
            package_info = {
                "name": package_name,
                "version": vulnerability_data.get("package_version", ""),
                "description": vulnerability_data.get("description", ""),
                "dependencies": [package_name] if package_name else []
            }

            # Use framework intelligence service for detection
            detection_results = await self.framework_intelligence_service.detect_framework_from_dependencies(
                package_info["dependencies"]
            )

            # Find the highest confidence framework
            best_framework = None
            best_score = 0.0

            for framework_name, score in detection_results.items():
                if score > best_score and score > 0.5:  # Confidence threshold
                    # Map framework name to FrameworkType
                    framework_type = self._map_framework_name_to_type(framework_name)
                    if framework_type:
                        best_framework = framework_type
                        best_score = score

            if best_framework:
                logger.info(f"Framework intelligence detected {best_framework.value} with confidence {best_score:.2f}")
                return best_framework

            return None

        except Exception as e:
            logger.warning(f"Framework intelligence detection error: {e}")
            return None

    def _map_framework_name_to_type(self, framework_name: str) -> FrameworkType | None:
        """Map framework intelligence service framework names to FrameworkType enum."""
        mapping = {
            "spring_boot": FrameworkType.SPRING_BOOT,
            "apache_struts": FrameworkType.APACHE_STRUTS,
            "micronaut": FrameworkType.MICRONAUT,
            "quarkus": FrameworkType.QUARKUS,
            "web_application": FrameworkType.WEB_APPLICATION,
        }

        return mapping.get(framework_name.lower())

    def get_readme_template(self) -> str:
        """
        Get README template by loading from file.

        Returns:
            Universal README template content
        """
        readme_template_path = self.templates_dir / "readme" / "universal_readme.md"

        if readme_template_path.exists():
            return readme_template_path.read_text()
        else:
            logger.error(f"README template not found: {readme_template_path}")
            raise FileNotFoundError(f"README template not found at {readme_template_path}")

    def get_framework_config_files(
        self,
        framework_type: str,
        package_version: str | None = None,
        action_class_name: str | None = None,
        config_values: dict | None = None,
    ) -> dict[str, str]:
        """
        Get framework configuration files using manifest system.

        REFACTORED (Stage 1): Now uses config manifests for all frameworks.
        Maintains backward compatibility while enabling multi-file configs.

        Design Philosophy (FORGE):
            - LLM generates ONLY Java code (vulnerability logic)
            - Templates provide ALL framework boilerplate (configs, views)
            - Injected during container generation, NOT during blueprint creation
            - This separation of concerns minimizes token usage and maximizes reliability

        Args:
            framework_type: Framework type (apache_struts, spring_boot, micronaut, etc.)
            package_version: Optional package version for version-aware config rendering
            action_class_name: Optional Struts Action class name for dynamic struts.xml rendering
            config_values: Optional config values dict for protocol servers (application.yml rendering)

        Returns:
            Dictionary mapping file paths to content
            Empty dict if framework doesn't need config files (uses defaults)
        """
        config_files = {}
        framework_lower = framework_type.lower()

        try:
            # Get config specs from manifest
            config_specs = self.config_manifest_service.get_config_specs(framework_lower)

            if not config_specs:
                logger.debug(f"No config manifest for framework '{framework_type}', using defaults")
                return config_files

            # Build context for conditional evaluation and rendering
            context = {
                "package_version": package_version,
                "action_class_name": action_class_name,
                **(config_values or {})
            }

            # Extract protocol_type from config_values if present
            if config_values and "protocol_type" in config_values:
                context["protocol_type"] = config_values["protocol_type"]

            # Extract kafka_role from config_values if present
            if config_values and "kafka_role" in config_values:
                context["kafka_role"] = config_values["kafka_role"]

            # Filter specs by conditions
            applicable_specs = self.config_manifest_service.filter_by_condition(
                config_specs,
                context
            )

            logger.info(f"Loading {len(applicable_specs)} config file(s) for {framework_type}")

            # Process each config file spec
            for spec in applicable_specs:
                config_path = self.templates_dir / "framework" / "configs" / spec.template

                if not config_path.exists():
                    logger.warning(f"Config template not found: {config_path}")
                    continue

                # Read template content
                template_content = config_path.read_text(encoding='utf-8')

                # Render or use as-is
                if spec.render:
                    # Build template variables
                    template_vars = {}

                    # Add framework-specific variables
                    if framework_lower in ["apache_struts", "struts"]:
                        template_vars["struts_filter_class"] = version_utils.get_struts_filter_class(
                            package_version or "6.0.0"
                        )
                        template_vars["action_class_name"] = action_class_name or "com.vuln.VulnerableAction"

                    # Add all context values
                    template_vars.update(context)

                    # Render with Jinja2
                    rendered_content = self.renderer.render_template(template_content, template_vars)
                    config_files[spec.destination] = rendered_content
                    logger.debug(f"Rendered {spec.template} -> {spec.destination}")
                else:
                    # Use static content
                    config_files[spec.destination] = template_content
                    logger.debug(f"Loaded static {spec.template} -> {spec.destination}")

            logger.info(f"Loaded {len(config_files)} config file(s) for {framework_type}")

        except Exception as e:
            logger.error(f"Error loading framework config files for {framework_type}: {e}")
            return {}

        return config_files

    def generate_pom_xml(
        self,
        blueprint,
        main_class_name: str,
        additional_dependencies: list[dict[str, any]] = None,
        framework_adaptation_dependencies: list[dict[str, any]] = None,
    ) -> str:
        """
        Generate a complete POM XML file for a blueprint.

        Delegates to PomGenerator.

        Args:
            blueprint: Blueprint with vulnerability information
            main_class_name: Name of the main class
            additional_dependencies: Additional dependencies to include
            framework_adaptation_dependencies: Dependencies from framework adaptation

        Returns:
            Complete POM XML content
        """
        return self._pom_generator.generate_pom_xml(
            blueprint,
            main_class_name,
            additional_dependencies,
            framework_adaptation_dependencies,
        )

    def generate_containerfile(self, blueprint, main_class_name: str) -> str:
        """
        Generate a complete Containerfile for a blueprint.

        Delegates to ContainerfileGenerator.

        Args:
            blueprint: Blueprint with vulnerability information
            main_class_name: Name of the main class

        Returns:
            Complete Containerfile content
        """
        return self._containerfile_generator.generate_containerfile(blueprint, main_class_name)

    def get_containerfile_template(self, architecture: str = None) -> str:
        """
        Get Containerfile template using universal approach.

        Delegates to ContainerfileGenerator.

        Args:
            architecture: Target architecture (ignored - universal template works for all)

        Returns:
            Universal Containerfile template content
        """
        return self._containerfile_generator.get_containerfile_template(architecture)

    # ------------------------------------------------------------------
    # README generation
    # ------------------------------------------------------------------

    def generate_readme(
        self,
        blueprint,
        container_name: str,
        context: dict = None,
    ) -> str:
        """Generate README with optional exploitation guidance."""
        try:
            # Existing README generation logic
            readme_template = self.get_readme_template()

            # Context with optional LLM-generated exploitation guidance
            template_context = {
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "cve_ids": ", ".join(blueprint.cve_ids),
                "description": blueprint.description,
                "container_name": container_name,
                "vulnerability_type": self._get_vulnerability_type_from_blueprint(blueprint),
                "severity": self._extract_severity(blueprint),
                "exploitation": context.get("exploitation", "") if context else "",
                "mitigation": context.get("mitigation", "") if context else "",
            }

            # Try to enhance with LLM-generated exploitation guidance (OPTIONAL)
            try:
                enhanced_exploitation = self._generate_exploitation_guidance_safe(blueprint, container_name)
                if enhanced_exploitation:
                    template_context["exploitation"] = enhanced_exploitation
                    logger.info("README with LLM-generated exploitation guidance")
            except Exception as e:
                logger.debug(f"Could not generate exploitation guidance (using template fallback): {e}")

            rendered_readme = self.renderer.render_template(readme_template, template_context)
            return rendered_readme

        except Exception as e:
            logger.error(f"Error generating README: {e}")
            raise

    def _generate_exploitation_guidance_safe(self, blueprint, container_name: str) -> str:
        """Safely generate exploitation guidance without breaking existing flow."""
        if not ENABLE_LLM_EXPLOITATION_GUIDANCE:
            return ""
        try:
            # Check if LLM service is available and prompt exists
            if not hasattr(self, "llm_service") or not self.llm_service:
                return ""

            # Check if exploitation guidance prompt exists
            if not self.llm_service.get_prompt_template("exploitation_guidance"):
                logger.debug("Exploitation guidance prompt not available")
                return ""

            # Prepare vulnerability data for exploitation guidance
            vulnerability_data = {
                "cve_id": ", ".join(blueprint.cve_ids),
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "summary": (blueprint.metadata or {}).get("enhanced_metadata", {}).get("summary", ""),
                "description": blueprint.description,
                "vulnerability_type": self._get_vulnerability_type_from_blueprint(blueprint),
                "attack_vector": (blueprint.metadata or {}).get("enhanced_metadata", {}).get("attack_vector", ""),
                "impact": (blueprint.metadata or {}).get("enhanced_metadata", {}).get("impact", ""),
                "framework_type": blueprint.get_framework_type()
                if hasattr(blueprint, "get_framework_type")
                else "standalone",
                "container_name": container_name,
                "access_url": "http://localhost:8080",  # Default
                "exposed_ports": "8080",  # Default
                "code_snippets_summary": self._summarize_code_snippets(blueprint.code_snippets),
            }

            # Progressive timeout handling - try with increasing timeouts
            max_attempts = 2
            for attempt in range(max_attempts):
                timeout = LLM_EXPLOITATION_TIMEOUT * (attempt + 1)  # 60s, then 120s

                try:
                    # Use a thread pool to run async code from sync context
                    import concurrent.futures

                    def run_async_with_timeout(timeout_value):
                        # Create new event loop in thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            return loop.run_until_complete(
                                asyncio.wait_for(
                                    self.llm_service.generate_exploitation_guidance(vulnerability_data),
                                    timeout=timeout_value,
                                )
                            )
                        finally:
                            loop.close()

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(run_async_with_timeout, timeout)
                        guidance = future.result(timeout=timeout + 10)

                    logger.info(f"Exploitation guidance generated successfully in {timeout}s timeout window")
                    return guidance or ""

                except (asyncio.TimeoutError, concurrent.futures.TimeoutError):
                    if attempt == max_attempts - 1:
                        logger.warning(f"Exploitation guidance generation timed out after {timeout}s")
                        return ""
                    logger.info(f"Attempt {attempt + 1} timed out after {timeout}s, retrying with longer timeout")
                    continue
                except Exception as e:
                    logger.debug(f"Error generating exploitation guidance: {e}")
                    return ""

        except Exception as e:
            logger.debug(f"Error in safe exploitation guidance generation: {e}")
            return ""

    def _extract_severity(self, blueprint) -> str:
        """
        Extract severity from blueprint metadata.

        Args:
            blueprint: Blueprint object

        Returns:
            Severity string
        """
        # Check enhanced metadata first
        enhanced_metadata = (blueprint.metadata or {}).get("enhanced_metadata", {})
        if "severity" in enhanced_metadata:
            return enhanced_metadata["severity"]

        # Check OSV data for severity information
        if "osv_data" in blueprint.metadata:
            osv_data = blueprint.metadata["osv_data"]

            # Check database_specific severity
            if "database_specific" in osv_data and "severity" in osv_data["database_specific"]:
                return osv_data["database_specific"]["severity"]

            # Check severity array
            if "severity" in osv_data and isinstance(osv_data["severity"], list):
                for severity_info in osv_data["severity"]:
                    if isinstance(severity_info, dict):
                        if "score" in severity_info:
                            return severity_info["score"]
                        elif "type" in severity_info:
                            return severity_info["type"]

        return "UNKNOWN"

    def _summarize_code_snippets(self, code_snippets: dict) -> str:
        """Create a summary of code snippets for LLM context."""
        if not code_snippets:
            return "No code snippets available"

        summary = f"Generated {len(code_snippets)} code files:\n"
        for name, code in code_snippets.items():
            lines = len(code.split("\n"))
            summary += f"- {name}: {lines} lines\n"

        return summary
