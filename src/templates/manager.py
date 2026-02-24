import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from models.templates import FrameworkTemplate, VulnerabilityTemplate
from models.error_handling import TemplateError
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
from shared.types import FrameworkType, TemplateSection
from utils.core.common import (
    extract_package_parts,
)
from utils.core.loader import TemplateLoader
from utils.core.prompt_manager import prompt_manager
from utils.support.renderer import TemplateRenderer

# Import new utility modules (Phase 1 refactoring)
from utils.core import version_utils, package_utils, pom_utils

logger = logging.getLogger(__name__)


class TemplateManager:
    """
    Manager for vulnerability templates.
    Provides a single interface for working with different types of templates.
    """

    """Unified template manager combining all template functionality."""

    def __init__(
        self, 
        templates_dir: Union[str, Path] = None, 
        llm_service: Optional[LLMServiceInterface] = None,
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

        # Template customization stats (moved from separate service)
        self.customization_stats = {
            "total_customizations": 0,
            "llm_customizations": 0,
            "average_customization_time": 0.0,
        }

        # Setup directory structure
        self._setup_directories()

        # Cache logic removed for simplification - direct template loading is more reliable

        # Load framework patterns
        try:
            self.framework_patterns = self._load_framework_patterns()
        except FileNotFoundError as e:
            logger.error(f"Failed to load framework patterns: {e}")
            raise

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

    def _load_framework_patterns(self) -> Dict[FrameworkType, list[str]]:
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

    def load_template(self, package_name: str) -> VulnerabilityTemplate:
        """Load template with proper error handling."""
        # Direct template loading without caching

        # Note: Vulnerability templates were removed per changelog
        # Blueprint code snippets are now the single source of truth
        logger.error(f"load_template called for {package_name} but vulnerability templates were removed")
        raise FileNotFoundError(
            f"No template found for {package_name}. "
            f"Vulnerability templates were removed per architectural decision. "
            f"Blueprint code snippets are now the single source of truth for vulnerability demonstrations."
        )

    async def detect_framework_type(self, vulnerability_data: Dict[str, Any]) -> FrameworkType:
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

    def _detect_framework_from_patterns(self, vulnerability_data: Dict[str, Any]) -> FrameworkType:
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

    def _detect_framework_with_llm_safe(self, vulnerability_data: Dict[str, Any]) -> str:
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

    def _detect_framework_with_intelligence_sync(self, vulnerability_data: Dict[str, Any]) -> Optional[FrameworkType]:
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

    async def _detect_framework_with_intelligence(self, vulnerability_data: Dict[str, Any]) -> Optional[FrameworkType]:
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

    def _map_framework_name_to_type(self, framework_name: str) -> Optional[FrameworkType]:
        """Map framework intelligence service framework names to FrameworkType enum."""
        mapping = {
            "spring_boot": FrameworkType.SPRING_BOOT,
            "apache_struts": FrameworkType.APACHE_STRUTS,
            "micronaut": FrameworkType.MICRONAUT,
            "quarkus": FrameworkType.QUARKUS,
            "web_application": FrameworkType.WEB_APPLICATION,
        }
        
        return mapping.get(framework_name.lower())

    def load_framework_template(
        self, framework_type: FrameworkType, vulnerability_data: Dict[str, Any]
    ) -> FrameworkTemplate:
        """
        Load or create a framework template.

        Args:
            framework_type: Type of framework
            vulnerability_data: Vulnerability information

        Returns:
            Framework template instance
        """
        # Direct framework template loading without caching

        # Load base vulnerability template
        base_template = self.load_template(vulnerability_data.get("package_name", ""))

        # Create framework-specific template
        framework_template = FrameworkTemplate(
            name=f"{framework_type.value}_template",
            framework_type=framework_type,
            base_template=base_template,
        )

        return framework_template

    def generate_framework_container_files(self, blueprint, framework_type: FrameworkType) -> Dict[str, str]:
        """
        Generate complete container files for a framework-based application.

        Args:
            blueprint: Blueprint with vulnerability information
            framework_type: Type of framework

        Returns:
            Dictionary of file paths to content
        """
        files = {}

        # Load framework template
        vulnerability_data = {
            "package_name": blueprint.package_name,
            "cve_id": blueprint.cve_ids[0] if blueprint.cve_ids else "",
            "description": blueprint.description,
        }

        framework_template = self.load_framework_template(framework_type, vulnerability_data)

        # Get all framework files
        framework_files = framework_template.get_configuration_files()
        files.update(framework_files)

        # Generate framework-specific POM
        framework_dependencies = framework_template.get_framework_dependencies()
        pom_content = self.generate_pom_xml(
            blueprint, self._get_main_class_name(framework_type), framework_dependencies
        )
        files["pom.xml"] = pom_content

        # Generate framework-specific Containerfile
        containerfile_content = self._generate_framework_containerfile(blueprint, framework_type)
        files["Containerfile"] = containerfile_content

        # Generate enhanced README
        readme_content = self._generate_framework_readme(blueprint, framework_type)
        files["README.md"] = readme_content

        return files

    def generate_framework_aware_files(self, blueprint, vulnerability_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate files with framework awareness.

        Args:
            blueprint: Blueprint object
            vulnerability_data: Original vulnerability data with framework hints

        Returns:
            Dictionary of generated files
        """
        # Detect framework type from vulnerability data
        framework_type = self.detect_framework_type(vulnerability_data)

        # Generate framework-specific files (all frameworks are web-based now)
        return self.generate_framework_container_files(blueprint, framework_type)

    def _get_main_class_name(self, framework_type: FrameworkType) -> str:
        """
        Get main class name for framework type.

        REFACTORED (Stage 2): Now uses framework_metadata_service instead of hardcoded logic.
        """
        # Use metadata service to get main class name
        main_class = self.framework_metadata_service.get_main_class_name(framework_type.value)
        logger.debug(f"Main class for {framework_type.value}: {main_class}")
        return main_class

    def _generate_framework_containerfile(self, blueprint, framework_type: FrameworkType) -> str:
        """Generate framework-specific Containerfile."""
        if framework_type == FrameworkType.SPRING_BOOT:
            return self._generate_spring_boot_containerfile(blueprint)
        elif framework_type == FrameworkType.APACHE_STRUTS:
            return self._generate_struts_containerfile()
        else:
            return self.generate_containerfile(blueprint, self._get_main_class_name(framework_type))

    def _generate_spring_boot_containerfile(self, blueprint) -> str:
        """
        Generate Spring Boot specific Containerfile.

        REFACTORED (Stage 2): Now uses ContainerfileFactory with metadata-driven approach.

        Args:
            blueprint: Blueprint with vulnerability information

        Returns:
            Rendered Containerfile content for Spring Boot applications
        """
        # Determine Java version from blueprint or package version
        is_spring_core = package_utils.is_spring_framework_core_package(blueprint.package_name)
        _, java_version = version_utils.determine_spring_boot_version(
            blueprint.package_version,
            blueprint.package_name,
            is_spring_core=is_spring_core
        )

        # Use ContainerfileFactory to generate Containerfile
        try:
            containerfile = self.containerfile_factory.generate_containerfile(
                framework_type="spring_boot",
                java_version=java_version,
                additional_context={
                    'cve_ids': ", ".join(blueprint.cve_ids) if blueprint.cve_ids else "N/A"
                }
            )
            logger.info(f"Generated Spring Boot Containerfile using factory (Java {java_version})")
            return containerfile
        except Exception as e:
            logger.error(f"Failed to generate Spring Boot Containerfile: {e}")
            raise

    def _generate_struts_containerfile(self, java_version: str = "8") -> str:
        """
        Generate Apache Struts specific Containerfile.

        REFACTORED (Stage 2): Now uses ContainerfileFactory with metadata-driven approach.

        Args:
            java_version: Java version to use (e.g., "8", "11", "17")

        Returns:
            Containerfile content for WAR-based applications with Tomcat
        """
        # Use ContainerfileFactory to generate Containerfile
        try:
            containerfile = self.containerfile_factory.generate_containerfile(
                framework_type="apache_struts",
                java_version=java_version
            )
            logger.info(f"Generated Struts Containerfile using factory (Java {java_version})")
            return containerfile
        except Exception as e:
            logger.error(f"Failed to generate Struts Containerfile: {e}")
            raise

    def _generate_protocol_server_containerfile(self, blueprint, main_class_name: str, protocol_type: str) -> str:
        """
        Generate Containerfile for protocol-level vulnerabilities.

        Protocol servers use Maven Shade plugin (not Spring Boot), so use
        ContainerfileFactory with protocol_server framework type.

        Args:
            blueprint: Blueprint with vulnerability information
            main_class_name: Name of the main class
            protocol_type: Protocol type (e.g., "http2", "websocket", "kafka")

        Returns:
            Containerfile content for protocol servers
        """
        # Determine Java version for the package
        is_spring_core = package_utils.is_spring_framework_core_package(blueprint.package_name)
        _, java_version = version_utils.determine_spring_boot_version(
            blueprint.package_version, blueprint.package_name, is_spring_core=is_spring_core
        )
        logger.info(f"Using Java {java_version} for protocol server Containerfile (package: {blueprint.package_name} v{blueprint.package_version})")

        # Use ContainerfileFactory to generate Containerfile for protocol servers
        # Protocol servers are treated as a framework type "protocol_server"
        try:
            containerfile = self.containerfile_factory.generate_containerfile(
                framework_type="protocol_server",
                java_version=java_version
            )
            logger.info(f"Generated protocol server Containerfile using factory for {protocol_type} (Java {java_version})")
            return containerfile
        except Exception as e:
            # Fallback: if protocol_server not in metadata, just use the universal containerfile
            # which works for JAR-based applications (protocol servers use Maven Shade to create fat JARs)
            logger.warning(f"ContainerfileFactory failed for protocol_server: {e}, falling back to universal containerfile")

            # Get appropriate Containerfile template
            architecture = self.renderer.detect_architecture()
            containerfile_template = self.get_containerfile_template(architecture)

            # Extract artifact_id from package name
            _, artifact_id = extract_package_parts(blueprint.package_name)

            # Build the context for template rendering
            context = {
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "cve_ids": ", ".join(blueprint.cve_ids),
                "artifact_id": artifact_id.lower(),
                "main_class": main_class_name,
                "java_version": java_version,
            }

            # Render the template
            rendered_containerfile = self.renderer.render_template(containerfile_template, context)
            logger.info(f"Generated protocol server Containerfile using fallback for {protocol_type} (Java {java_version})")

            return rendered_containerfile

    def get_pom_template(self, package_name: str, framework_type: str = None, protocol_type: str = None) -> str:
        """
        Get POM template based on framework type and package requirements.

        REFACTORED (Stage 2): Now uses framework_metadata_service for template selection.

        Args:
            package_name: Name of the vulnerable package
            framework_type: Optional framework type hint (e.g., 'standalone_jar', 'spring_boot', 'struts')
            protocol_type: Optional protocol type for protocol servers (e.g., 'HTTP/2', 'WebSocket')

        Returns:
            POM template content as string
        """
        template_name = None

        # If framework_type is provided, try metadata-driven template selection
        if framework_type:
            framework_type_normalized = framework_type.lower().replace("-", "_")

            # Try to get template from metadata service
            template_name = self.framework_metadata_service.get_template_for_package(
                framework_type=framework_type_normalized,
                package_name=package_name,
                protocol_type=protocol_type
            )

            # If framework was explicitly adapted but no specific template matched,
            # use the framework's default template instead of falling back to other frameworks.

            if not template_name:
                default_templates = {
                    "spring_boot": "spring_boot_web.xml",
                    "apache_struts": "servlet_container.xml",
                    "standalone_jar": "standalone_jar.xml",
                    "micronaut": "microservice_native.xml",
                    "quarkus": "microservice_native.xml",
                    "protocol_server": "standalone_jar.xml",  # Safe default for protocol servers
                    "kafka_client": "kafka_client.xml",
                }
                if framework_type_normalized in default_templates:
                    template_name = default_templates[framework_type_normalized]
                    logger.info(
                        f"Using default template for adapted framework '{framework_type_normalized}': {template_name} "
                        f"(no specific pattern matched for {package_name})"
                    )

        # Fallback: Try to detect framework from package name patterns
        # Only used when NO framework_type was explicitly provided
        if not template_name and not framework_type:
            # Check package-specific patterns for each framework
            for fw_type in ["spring_boot", "apache_struts", "micronaut", "quarkus", "standalone_jar", "protocol_server"]:
                template_name = self.framework_metadata_service.get_template_for_package(
                    framework_type=fw_type,
                    package_name=package_name,
                    protocol_type=protocol_type
                )
                if template_name:
                    logger.info(f"Template selected by pattern matching: {template_name} (framework: {fw_type})")
                    break

        # If we found a template name, construct path and load it
        if template_name:
            template_path = self.core_templates_dir / template_name
            logger.info(f"Using template: {template_name} for package: {package_name}")

            if template_path.exists():
                return self.loader.load_template_content(template_path, required=True)
            else:
                logger.warning(f"Template {template_name} not found at {template_path}, trying fallback")

        # Final fallback: Use standalone JAR template (most generic)
        fallback_template = "standalone_jar.xml"
        fallback_path = self.core_templates_dir / fallback_template

        if fallback_path.exists():
            logger.info(f"Using fallback template: {fallback_template} for package: {package_name}")
            return self.loader.load_template_content(fallback_path, required=True)

        # Last resort: Try universal web template
        universal_fallback = self.templates_dir / "universal_web.xml"
        if universal_fallback.exists():
            logger.warning(f"Using universal fallback template for package: {package_name}")
            return self.loader.load_template_content(universal_fallback, required=True)

        # No template found at all
        raise FileNotFoundError(
            f"No POM template found for package '{package_name}' with framework type '{framework_type}'. "
            f"Checked: metadata-driven selection, pattern matching, and fallback templates.\n"
            f"Please ensure templates exist in templates/core/ directory."
        )

    def get_repository_templates(self, package_name: str) -> str:
        """
        Generate repository configurations dynamically based on the package name.
        Loads repository templates from files instead of hardcoding XML.

        Args:
            package_name: Package name

        Returns:
            XML content for Maven repositories
        """
        repositories = []
        repos_dir = self.templates_dir / "maven" / "repositories"

        # Always include Maven Central repository
        maven_central_path = repos_dir / "maven_central.xml"
        if maven_central_path.exists():
            repositories.append(maven_central_path.read_text().strip())
        else:
            logger.warning(f"Maven Central template not found: {maven_central_path}")

        # Add package-specific repositories dynamically
        package_lower = package_name.lower()

        if "snakeyaml" in package_lower or "javax.script" in package_lower:
            # XWiki repository for specialized packages
            xwiki_path = repos_dir / "xwiki.xml"
            if xwiki_path.exists():
                repositories.append(xwiki_path.read_text().strip())
            else:
                logger.warning(f"XWiki repository template not found: {xwiki_path}")

        if "jboss" in package_lower or "hibernate" in package_lower:
            # JBoss repository for JBoss/Hibernate packages
            jboss_path = repos_dir / "jboss.xml"
            if jboss_path.exists():
                repositories.append(jboss_path.read_text().strip())
            else:
                logger.warning(f"JBoss repository template not found: {jboss_path}")

        # Wrap in repositories tag and return
        repositories_xml = f"""<repositories>
{chr(10).join(repositories)}
    </repositories>"""

        return repositories_xml

    def get_containerfile_template(self, architecture: str = None) -> str:
        """
        Get Containerfile template using universal approach.

        Args:
            architecture: Target architecture (ignored - universal template works for all)

        Returns:
            Universal Containerfile template content
        """
        # Use universal containerfile that auto-adapts to different application types
        universal_containerfile = self.templates_dir / "universal_containerfile.txt"
        
        if universal_containerfile.exists():
            logger.info("Using universal containerfile template")
            content = self.loader.load_template_content(universal_containerfile)
            if content:
                return content
        
        # Fallback to old generic template if universal doesn't exist
        generic_file = self.containerfile_dir / "generic.txt"
        content = self.loader.load_template_content(generic_file)
        
        if content:
            logger.warning("Universal containerfile not found, using fallback generic template")
            return content
        
        logger.error("No Containerfile template found!")
        raise FileNotFoundError(
            f"No Containerfile template found. Expected:\n"
            f"- {universal_containerfile} (universal template)\n"
            f"- {generic_file} (fallback template)"
        )

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
        package_version: Optional[str] = None,
        action_class_name: Optional[str] = None,
        config_values: Optional[dict] = None,
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

        Args:
            blueprint: Blueprint with vulnerability information
            main_class_name: Name of the main class
            additional_dependencies: Additional dependencies to include
            framework_adaptation_dependencies: Dependencies from framework adaptation (e.g., Struts plugins)

        Returns:
            Complete POM XML content
        """
        try:
            # Extract group and artifact info from package name
            group_id, artifact_id = extract_package_parts(blueprint.package_name)
            logger.info(f"Extracted group_id={group_id}, artifact_id={artifact_id} from {blueprint.package_name}")

            # Ensure package version is set (should already be set from OSV data extraction)
            if not blueprint.package_version or blueprint.package_version.strip() == "":
                logger.error(f"Package version not set for {blueprint.package_name}. OSV version extraction failed.")
                suggested_version = self._determine_version_with_llm(blueprint)
                if suggested_version:
                    blueprint.package_version = suggested_version
                    logger.info(f"LLM suggested version {suggested_version} for {blueprint.package_name}")
                else:
                    logger.error(
                        f"Failed to determine version for {blueprint.package_name}. Cannot proceed with POM generation."
                    )
                    raise ValueError(
                        f"No valid version found for package {blueprint.package_name}. Both OSV extraction and LLM determination failed."
                    )

            # First check if framework was selected during adaptation
            framework_metadata = (blueprint.metadata or {}).get('framework_adaptation', {})
            if framework_metadata.get('selected_framework'):
                selected_framework = framework_metadata['selected_framework']
                logger.info(f"Using framework from adaptation: {selected_framework}")
                # Map framework adaptation name to template framework type
                framework_type_str = selected_framework
            else:
                # Fall back to pattern-based detection
                vulnerability_data = {
                    "package_name": blueprint.package_name,
                    "cve_id": blueprint.cve_ids[0] if blueprint.cve_ids else "",
                    "description": blueprint.description,
                    "summary": "",  # Blueprint doesn't have summary, use empty string
                }
                framework_type = self._detect_framework_from_patterns(vulnerability_data)
                framework_type_str = framework_type.value
                logger.info(f"Detected framework type from patterns: {framework_type_str} for {blueprint.package_name}")

            # Extract protocol_type from classification metadata (for protocol servers)
            protocol_type = (blueprint.metadata or {}).get('classification', {}).get('protocol_type')
            if protocol_type:
                logger.info(f"Protocol type detected: {protocol_type}")

            # This will select WAR packaging for Struts, JAR for Spring Boot, etc.
            # Stage 2: Now passes protocol_type for protocol server template selection
            pom_template = self.get_pom_template(
                blueprint.package_name,
                framework_type=framework_type_str,
                protocol_type=protocol_type
            )
            logger.debug(f"POM template content length: {len(pom_template)}")

            # Get repository configuration
            repositories = self.get_repository_templates(blueprint.package_name)
            logger.debug(f"Repository template content length: {len(repositories)}")

            # Format dependencies
            # Convert framework_type_str back to FrameworkType enum for _get_all_dependencies
            from shared.types import FrameworkType
            try:
                framework_type_enum = FrameworkType(framework_type_str)
            except ValueError:
                # If framework_type_str is not a valid enum value, try to map it
                framework_type_enum = self._map_framework_name_to_type(framework_type_str) or FrameworkType.SPRING_BOOT
                logger.warning(f"Could not convert {framework_type_str} to FrameworkType, using {framework_type_enum.value}")

            all_dependencies = self._get_all_dependencies(
                blueprint,
                additional_dependencies,
                framework_type_enum,
                framework_adaptation_dependencies
            )
            dependencies_xml = self.renderer.format_dependencies(all_dependencies)
            logger.debug(f"Dependencies XML length: {len(dependencies_xml)}")

            # Determine Spring Boot and Java versions based on package version
            is_spring_core = package_utils.is_spring_framework_core_package(blueprint.package_name)
            spring_boot_version, java_version = version_utils.determine_spring_boot_version(
                blueprint.package_version,
                blueprint.package_name,
                is_spring_core=is_spring_core
            )
            logger.info(f"Selected versions: Spring Boot {spring_boot_version} + Java {java_version} for {blueprint.package_name} v{blueprint.package_version}")

            # Detect servlet container packages for proper container selection
            is_servlet_container = package_utils.is_servlet_container_package(blueprint.package_name)
            servlet_container_type = None
            if is_servlet_container:
                servlet_container_type = package_utils.detect_servlet_container_type(blueprint.package_name)
                logger.info(f"Testing servlet container: {servlet_container_type} (package is the container itself)")
            else:
                servlet_container_type = "tomcat"  # Default for non-servlet-container packages
                logger.debug("Using default servlet container: tomcat (package is not a container)")

            # Validate version compatibility to catch issues early
            try:
                version_utils.validate_spring_compatibility(
                    blueprint.package_name,
                    blueprint.package_version,
                    spring_boot_version,
                    java_version
                )
            except ValueError as e:
                # Re-raise with context about where the error occurred
                raise TemplateError(
                    message=f"Version compatibility check failed for {blueprint.package_name}",
                    cause=e,
                    remedy="Check the _determine_spring_boot_version() logic to ensure correct version selection"
                )

            # Generate project name from artifact_id (convert hyphens to spaces and capitalize)
            project_name = artifact_id.replace("-", " ").title() + " Web Demo"

            context = {
                "group_id": group_id,
                "artifact_id": artifact_id,
                "package_version": blueprint.package_version,
                "package_name": blueprint.package_name,
                "main_class": main_class_name,
                "repositories": repositories,
                "dependencies": dependencies_xml,
                "spring_boot_version": spring_boot_version,
                "java_version": java_version,
                "servlet_container": servlet_container_type,
                # Additional variables for Maven property placeholders
                "project.version": "1.0-SNAPSHOT",
                "project.name": project_name,
                "project.build.sourceEncoding": "UTF-8",
                # Alternative names (used in some templates)
                "spring-boot.version": spring_boot_version,
                "java.version": java_version,
                # Servlet container / WAR project variables (for Struts, servlet templates)
                "servlet.api.version": "4.0.1",
                "jsp.api.version": "2.3.3",
                "jstl.version": "1.2",
                "tomcat.version": "9.0.80",
                "maven.compiler.version": "3.11.0",
                "maven.compiler.source": java_version,
                "maven.compiler.target": java_version,
                "maven.war.version": "3.4.0",
                "maven.surefire.version": "3.0.0",
            }
            logger.info(f"Template context keys: {list(context.keys())}")
            logger.info(f"Using package version: {blueprint.package_version} for {blueprint.package_name}")

            # Render the template
            rendered_pom = self.renderer.render_template(pom_template, context)
            logger.debug(f"Rendered POM XML length: {len(rendered_pom)}")

            # Verify that all variables have been replaced
            for key in context.keys():
                placeholder = f"${{{key}}}"
                if placeholder in rendered_pom:
                    logger.warning(f"Unreplaced variable in POM XML: {placeholder}")

            # Make sure the POM is valid by fixing common issues
            rendered_pom = pom_utils.ensure_valid_pom_xml(rendered_pom)

            return rendered_pom
        except Exception as e:
            logger.error(f"Error generating POM XML: {str(e)}", exc_info=True)
            raise TemplateError(
                message=f"Error generating POM XML for {blueprint.package_name}",
                cause=e,
                remedy="Check the template format and blueprint information",
            )

    def _get_all_dependencies(
        self, blueprint, additional_dependencies: list[dict[str, any]] = None, framework_type=None,
        framework_adaptation_dependencies: list[dict[str, any]] = None
    ) -> list[dict[str, any]]:
        """
        Get all dependencies for a blueprint.

        Args:
            blueprint: Blueprint with vulnerability information
            additional_dependencies: Additional dependencies to include
            framework_type: Framework type to determine dependency handling
            framework_adaptation_dependencies: Dependencies from framework adaptation (e.g., Struts plugins)

        Returns:
            list of dependency dictionaries
        """
        from utils.core.common import extract_package_parts

        group_id, artifact_id = extract_package_parts(blueprint.package_name)

        dependencies = []

        # CRITICAL: Check if this is a Spring Framework CORE package
        # Spring Framework core packages should NOT be added as explicit dependencies
        # They are managed by Spring Boot via dependencyManagement override
        if package_utils.is_spring_framework_core_package(blueprint.package_name):
            logger.info(f"SKIPPING explicit dependency for Spring Framework CORE package: {blueprint.package_name}")
            logger.info("This package will be managed by Spring Boot with version override via dependencyManagement")
            logger.info(f"Target version: {blueprint.package_version}")
        # CRITICAL: Check if this is a SERVLET CONTAINER package
        # Servlet containers should NOT be added as explicit dependencies
        # They are provided by Spring Boot starters (spring-boot-starter-undertow/jetty/webflux)
        elif package_utils.is_servlet_container_package(blueprint.package_name):
            logger.info(f"SKIPPING explicit dependency for SERVLET CONTAINER package: {blueprint.package_name}")
            logger.info("This package will be included by Spring Boot starter (spring-boot-starter-undertow/jetty/webflux)")
            logger.info(f"Target version: {blueprint.package_version}")
        else:
            # This ensures we test the ACTUAL CVE, not a patched version
            logger.info(f"Adding main vulnerability dependency: {blueprint.package_name} @ {blueprint.package_version}")
            dependencies.append(
                {
                    "group_id": group_id,
                    "artifact_id": artifact_id,
                    "version": blueprint.package_version,  # Use EXACT vulnerable version from CVE
                }
            )

        # Add common dependencies
        # Only add slf4j-simple for standalone applications or non-Spring frameworks
        if framework_type and framework_type not in [FrameworkType.SPRING_BOOT]:
            logger.info(f"Adding slf4j-simple for non-Spring Boot framework: {framework_type}")
            dependencies.append(
                {
                    "group_id": "org.slf4j",
                    "artifact_id": "slf4j-simple",
                    "version": "1.7.32",
                }
            )
            dependencies.append({"group_id": "org.slf4j", "artifact_id": "slf4j-api", "version": "1.7.32"})
        else:
            logger.info("Skipping slf4j-simple for Spring Boot (uses logback by default)")

        # Add explicitly provided additional dependencies
        if additional_dependencies:
            dependencies.extend(additional_dependencies)

        # Add framework adaptation dependencies (e.g., Struts plugins for adapted code)
        if framework_adaptation_dependencies:
            logger.info(f"Merging {len(framework_adaptation_dependencies)} framework adaptation dependencies into POM")

            # Initialize Maven version resolver
            from services.dependency.maven_version_resolver import MavenVersionResolver
            version_resolver = MavenVersionResolver()

            # Deduplicate: Only add if not already present
            existing_keys = {f"{d['group_id']}:{d['artifact_id']}" for d in dependencies}

            for dep in framework_adaptation_dependencies:
                # Validate basic dependency structure
                if not all(k in dep for k in ['group_id', 'artifact_id']):
                    logger.warning(f"Skipping invalid framework dependency (missing group_id or artifact_id): {dep}")
                    continue

                dep_key = f"{dep.get('group_id')}:{dep.get('artifact_id')}"

                # Skip if already exists
                if dep_key in existing_keys:
                    logger.warning(f"Skipping duplicate dependency: {dep_key}")
                    continue

                # Resolve version if missing or invalid
                if 'version' not in dep or not dep['version'] or not dep['version'].strip():
                    try:
                        version_info = version_resolver.resolve_version(
                            group_id=dep['group_id'],
                            artifact_id=dep['artifact_id'],
                            target_version=blueprint.package_version,
                            strategy="match_major"
                        )
                        dep['version'] = version_info.version
                        logger.info(f"Resolved version for {dep_key} → {version_info.version} (via {version_info.resolved_via})")
                    except ValueError as e:
                        # Plugin is incompatible with framework version (e.g., struts2-convention-plugin with Struts 2.0.x)
                        logger.warning(f"Skipping incompatible dependency {dep_key}: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Failed to resolve version for {dep_key}: {e}")
                        continue
                else:
                    # Version provided by LLM - verify it exists in Maven Central
                    logger.debug(f"Verifying LLM-provided version: {dep_key}:{dep['version']}")
                    if not version_resolver.version_exists(dep['group_id'], dep['artifact_id'], dep['version']):
                        logger.warning(f"LLM-provided version {dep['version']} not found in Maven Central for {dep_key}, resolving alternative...")
                        try:
                            version_info = version_resolver.resolve_version(
                                dep['group_id'],
                                dep['artifact_id'],
                                target_version=blueprint.package_version,
                                strategy="match_major"
                            )
                            old_version = dep['version']
                            dep['version'] = version_info.version
                            logger.info(f"Replaced invalid version {old_version} → {version_info.version} for {dep_key}")
                        except ValueError as e:
                            # Plugin is incompatible with framework version
                            logger.warning(f"Skipping incompatible dependency {dep_key}: {e}")
                            continue
                        except Exception as e:
                            logger.error(f"Could not resolve alternative version for {dep_key}: {e}")
                            continue

                # Add validated dependency with resolved version
                dependencies.append(dep)
                logger.info(f"Added framework dependency: {dep_key}:{dep.get('version')}")
                existing_keys.add(dep_key)

        return dependencies

    def generate_containerfile(self, blueprint, main_class_name: str) -> str:
        """
        Generate a complete Containerfile for a blueprint.

        Detects packaging type (JAR vs WAR) from framework metadata and generates
        appropriate Containerfile (universal for JARs, Tomcat-based for WARs).
        For protocol-level vulnerabilities, uses simpler protocol server containerfile.

        Args:
            blueprint: Blueprint with vulnerability information
            main_class_name: Name of the main class

        Returns:
            Complete Containerfile content
        """
        try:
            # PRIORITY 1: Check for protocol-level vulnerabilities first
            # Protocol servers use Maven Shade plugin (not Spring Boot), so need simpler containerfile
            classification_metadata = (blueprint.metadata or {}).get('classification', {})
            protocol_type = classification_metadata.get('protocol_type')

            if protocol_type:
                logger.info(f"Detected protocol-level vulnerability (protocol: {protocol_type}), using protocol server containerfile")
                return self._generate_protocol_server_containerfile(blueprint, main_class_name, protocol_type)

            # PRIORITY 2: Detect framework type from blueprint metadata OR from package name patterns
            # This ensures containerfile is correct even if framework adaptation failed
            framework_metadata = (blueprint.metadata or {}).get('framework_adaptation', {})
            framework_type = framework_metadata.get('selected_framework')

            # If no framework in metadata, detect from package name (same as POM generation)
            if not framework_type:
                vulnerability_data = {
                    "package_name": blueprint.package_name,
                    "package_version": blueprint.package_version,
                    "cve_ids": blueprint.cve_ids,
                    "description": blueprint.description,
                }
                framework_enum = self._detect_framework_from_patterns(vulnerability_data)
                framework_type = framework_enum.value
                logger.info(f"No framework in metadata, detected from package: {framework_type}")

            # Normalize framework type to lowercase for comparison
            framework_type_lower = framework_type.lower() if framework_type else 'spring_boot'

            logger.info(f"Generating Containerfile for framework: {framework_type} (normalized: {framework_type_lower})")

            # WAR-based frameworks need Tomcat/servlet container
            if framework_type_lower in ['struts', 'apache_struts', 'servlet', 'servlet_container']:
                # Determine Java version for the package
                is_spring_core = package_utils.is_spring_framework_core_package(blueprint.package_name)
                _, java_version = version_utils.determine_spring_boot_version(
                    blueprint.package_version, blueprint.package_name, is_spring_core=is_spring_core
                )
                logger.info(f"Detected WAR-based framework ({framework_type}) with Java {java_version}, using Tomcat Containerfile")
                return self._generate_struts_containerfile(java_version)

            # JAR-based frameworks use universal Spring Boot template
            logger.info(f"Using JAR-based universal Containerfile for {framework_type}")

            # Determine Java version for the package
            is_spring_core = package_utils.is_spring_framework_core_package(blueprint.package_name)
            _, java_version = version_utils.determine_spring_boot_version(
                blueprint.package_version, blueprint.package_name, is_spring_core=is_spring_core
            )
            logger.info(f"Using Java {java_version} for Containerfile (package: {blueprint.package_name} v{blueprint.package_version})")

            # Get appropriate Containerfile template
            architecture = self.renderer.detect_architecture()
            containerfile_template = self.get_containerfile_template(architecture)

            # Extract artifact_id from package name
            _, artifact_id = extract_package_parts(blueprint.package_name)

            # Build the context for template rendering
            context = {
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "cve_ids": ", ".join(blueprint.cve_ids),
                "artifact_id": artifact_id.lower(),
                "version": "1.0-SNAPSHOT",  # Maven default version for vulnerability demos
                "main_class": main_class_name,
                "java_version": java_version,  # Java version for base image selection
            }

            # Render the template
            rendered_containerfile = self.renderer.render_template(containerfile_template, context)

            # Verify that all variables have been replaced
            for key in context.keys():
                placeholder = f"${{{key}}}"
                if placeholder in rendered_containerfile:
                    logger.warning(f"Unreplaced variable in Containerfile: {placeholder}")

            # Ensure the Containerfile handles missing resources directory gracefully
            if "COPY --from=build --chown=vulnapp:vulnapp /app/src/main/resources" in rendered_containerfile:
                rendered_containerfile = rendered_containerfile.replace(
                    "COPY --from=build --chown=vulnapp:vulnapp /app/src/main/resources /app/resources",
                    "# Create resources directory\n"
                    + "RUN mkdir -p /app/resources && chown -R vulnapp:vulnapp /app/resources\n\n"
                    + "# Conditionally copy resources if they exist\n"
                    + "COPY --from=build --chown=vulnapp:vulnapp /app/src/main/resources/* /app/resources/ 2>/dev/null || true",
                )

            return rendered_containerfile
        except Exception as e:
            logger.error(f"Error generating Containerfile: {str(e)}", exc_info=True)
            raise TemplateError(
                message=f"Error generating Containerfile for {blueprint.package_name}",
                cause=e,
                remedy="Check the template format and blueprint information",
            )

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

    def _determine_version_with_llm(self, blueprint) -> str | None:
        """
        Use LLM to determine an appropriate version when OSV extraction fails.

        Args:
            blueprint: Blueprint object with package information

        Returns:
            Suggested version string or None if determination fails
        """
        try:
            if not self.llm_service:
                logger.warning("No LLM service available for version determination")
                return None

            # Prepare OSV metadata for prompt
            osv_metadata = ""
            if hasattr(blueprint, "metadata") and (blueprint.metadata or {}).get("osv_data"):
                osv_data = (blueprint.metadata or {})["osv_data"]
                # Extract relevant OSV information for version determination
                if "affected" in osv_data:
                    osv_metadata = f"OSV Affected Packages: {osv_data['affected'][:2]}"  # Limit to avoid token overflow

            # Use PromptManager to format the prompt
            rendered_prompt = prompt_manager.format_prompt(
                "version_determination",
                package_name=blueprint.package_name,
                cve_ids=", ".join(blueprint.cve_ids) if blueprint.cve_ids else "None",
                description=blueprint.description or "No description available",
                osv_metadata=osv_metadata or "No OSV metadata available",
            )

            # Call LLM with timeout
            import asyncio

            try:
                # Try to get existing loop or create new one
                try:
                    _ = asyncio.get_running_loop()
                    # We're in an async context, use thread pool
                    import concurrent.futures

                    def run_llm_task():
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        try:
                            return new_loop.run_until_complete(
                                asyncio.wait_for(
                                    self.llm_service.generate(rendered_prompt),
                                    timeout=15.0,  # Reasonable timeout for version determination
                                )
                            )
                        finally:
                            new_loop.close()

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(run_llm_task)
                        result = future.result(timeout=18.0)

                except RuntimeError:
                    # No running loop
                    result = asyncio.run(asyncio.wait_for(self.llm_service.generate(rendered_prompt), timeout=15.0))

                # Extract and validate version from LLM response
                if result and isinstance(result, str):
                    suggested_version = version_utils.extract_and_validate_version(result.strip())
                    if suggested_version:
                        logger.info(
                            f"LLM successfully determined version {suggested_version} for {blueprint.package_name}"
                        )
                        return suggested_version
                    else:
                        logger.warning(
                            f"LLM response '{result.strip()}' did not contain a valid version for {blueprint.package_name}"
                        )
                else:
                    logger.warning(
                        f"LLM returned empty or invalid response for version determination of {blueprint.package_name}"
                    )

            except (asyncio.TimeoutError, concurrent.futures.TimeoutError):
                logger.error(f"LLM version determination timed out for {blueprint.package_name}")
            except Exception as e:
                logger.error(f"LLM version determination failed for {blueprint.package_name}: {e}")

        except Exception as e:
            logger.error(f"Error in LLM version determination for {blueprint.package_name}: {e}", exc_info=True)

        return None

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

    def get_dynamic_template(
        self, 
        framework_type: FrameworkType, 
        vulnerability_data: Dict[str, Any],
        use_customization: bool = True
    ) -> Dict[str, str]:
        """
        Get dynamically selected and customized templates based on framework and vulnerability context.
        
        Args:
            framework_type: Detected framework type
            vulnerability_data: Vulnerability context information
            use_customization: Whether to use LLM-driven template customization
            
        Returns:
            Dictionary of customized template files
        """
        try:
            package_info = {
                "name": vulnerability_data.get("package_name", ""),
                "version": vulnerability_data.get("package_version", ""),
                "dependencies": vulnerability_data.get("additional_dependencies", [])
            }
            
            # Prepare vulnerability context
            vulnerability_context = {
                "vulnerability_type": vulnerability_data.get("vulnerability_type", "unknown"),
                "description": vulnerability_data.get("description", ""),
                "cve_ids": vulnerability_data.get("cve_ids", []),
                "severity": vulnerability_data.get("severity", "unknown")
            }
            
            # Use integrated template customization if LLM service is available
            if use_customization and self.llm_service:
                logger.info(f"Using LLM-driven template customization for {framework_type.value}")
                customized_templates = self._customize_template_internal(
                    framework_type=framework_type,
                    package_info=package_info,
                    vulnerability_context=vulnerability_context
                )
                
                if customized_templates:
                    logger.info(f"Generated {len(customized_templates)} customized templates")
                    return customized_templates
            
        except Exception as e:
            logger.error(f"Dynamic template generation failed: {e}")
            # Ultimate fallback - return basic template
            return self._get_fallback_templates(framework_type)

    def _get_fallback_templates(self, framework_type: FrameworkType) -> Dict[str, str]:
        """Handle template generation failure with proper error logging."""
        logger.error(f"All template generation methods failed for framework: {framework_type}")
        logger.error("No fallback templates available - template generation requires valid configuration")
        raise RuntimeError(f"Template generation failed for framework {framework_type} - check template configuration and connectivity")


    def get_framework_adaptation_stats(self) -> Dict[str, Any]:
        """Get statistics about framework adaptation usage."""
        stats = {
            "framework_adaptation_enabled": self.enable_framework_adaptation,
            "services_available": {
                "framework_intelligence": self.framework_intelligence_service is not None,
                "template_customization": self.llm_service is not None,
            },
            "cache_stats": {
                "caching_disabled": "Cache logic removed for simplification and reliability",
            }
        }
        
        # Get template customization stats
        stats["template_customization_stats"] = self.customization_stats
        
        return stats

    def _customize_template_internal(
        self,
        framework_type: FrameworkType,
        package_info: Dict[str, Any],
        vulnerability_context: Dict[str, Any],
    ) -> Dict[str, str]:
        """
        Internal template customization using LLM service.
        
        Args:
            framework_type: Target framework type
            package_info: Package information (name, version, dependencies)
            vulnerability_context: Vulnerability context and requirements
            
        Returns:
            Dictionary of customized template files
        """
        start_time = time.time()
        
        try:
            # Get base template for framework
            base_template = self._get_base_template_for_framework(framework_type)
            if not base_template:
                logger.warning(f"No base template found for framework: {framework_type.value}")
                return {}
            
            # Prepare customization context
            customization_context = {
                "framework_type": framework_type.value,
                "package_name": package_info.get("name", ""),
                "package_version": package_info.get("version", ""),
                "vulnerability_type": vulnerability_context.get("vulnerability_type", ""),
                "vulnerability_description": vulnerability_context.get("description", ""),
                "base_template": base_template,
                "existing_dependencies": package_info.get("dependencies", []),
            }
            
            # Get LLM customization if available
            try:
                if hasattr(self.llm_service, 'load_prompt'):
                    prompt_template = self.llm_service.load_prompt("template_customization")
                    customization_prompt = prompt_template.format(**customization_context)
                    response = self.llm_service.generate_response(customization_prompt)
                    
                    self.customization_stats["llm_customizations"] += 1
                    customized_templates = self._parse_customization_response(response, base_template)
                    
                    if customized_templates:
                        return customized_templates
                        
            except Exception as e:
                logger.warning(f"LLM template customization failed: {e}")
            
            # Fallback to basic customizations
            return self._apply_basic_customizations(base_template, package_info)
            
        except Exception as e:
            logger.error(f"Template customization failed: {e}")
            return {}
        finally:
            # Update statistics
            customization_time = time.time() - start_time
            self._update_customization_stats(customization_time)

    def _get_base_template_for_framework(self, framework_type: FrameworkType) -> Optional[str]:
        """Get base template for framework type."""
        template_mapping = {
            FrameworkType.SPRING_BOOT: "spring_boot_web",
            FrameworkType.APACHE_STRUTS: "servlet_container",
            FrameworkType.MICRONAUT: "microservice_native",
            FrameworkType.QUARKUS: "microservice_native",
        }
        
        template_name = template_mapping.get(framework_type)
        if template_name:
            template_path = self.templates_dir / "core" / f"{template_name}.xml"
            if template_path.exists():
                return template_path.read_text()
        
        return None

    def _parse_customization_response(self, response: str, base_template: str) -> Dict[str, str]:
        """Parse LLM customization response."""
        # Simple parsing - look for XML-like content
        if "<" in response and ">" in response:
            return {"web.xml": response}
        else:
            return {"web.xml": base_template}

    def _apply_basic_customizations(self, base_template: str, package_info: Dict[str, Any]) -> Dict[str, str]:
        """Apply basic customizations to template."""
        customized = base_template.replace("${package_name}", package_info.get("name", "vulnerable-app"))
        customized = customized.replace("${package_version}", package_info.get("version", "1.0.0"))
        
        return {"web.xml": customized}

    def _update_customization_stats(self, customization_time: float):
        """Update customization statistics."""
        self.customization_stats["total_customizations"] += 1
        
        # Update average time
        total = self.customization_stats["total_customizations"]
        current_avg = self.customization_stats["average_customization_time"]
        self.customization_stats["average_customization_time"] = (
            (current_avg * (total - 1) + customization_time) / total
        )
