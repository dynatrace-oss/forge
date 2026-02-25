import logging

from models.error_handling import TemplateError
from shared.types import FrameworkType
from utils.core import package_utils, version_utils
from utils.core.common import extract_package_parts

logger = logging.getLogger(__name__)


class ContainerfileGenerator:
    """
    Extracts Containerfile-related methods from TemplateManager to keep concerns
    separated.  Depends on TemplateManager for shared helpers, ContainerfileFactory,
    and renderer.

    Args:
        template_manager: Parent TemplateManager instance (provides shared helpers,
            renderer, containerfile_factory, and framework_metadata_service).
    """

    def __init__(self, template_manager: any) -> None:
        self._tm = template_manager

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_containerfile(self, blueprint: any, main_class_name: str) -> str:
        """
        Detects packaging type (JAR vs WAR) from framework metadata and generates
        an appropriate Containerfile (universal for JARs, Tomcat-based for WARs).
        For protocol-level vulnerabilities, uses a simpler protocol-server
        Containerfile.

        Args:
            blueprint: Blueprint with vulnerability information.
            main_class_name: Name of the main class.

        Returns:
            Complete Containerfile content as a string.

        Raises:
            TemplateError: If Containerfile generation fails.
        """
        try:
            # PRIORITY 1: Protocol-level vulnerabilities
            classification_metadata = (blueprint.metadata or {}).get("classification", {})
            protocol_type = classification_metadata.get("protocol_type")

            if protocol_type:
                logger.info(
                    f"Detected protocol-level vulnerability (protocol: {protocol_type}), "
                    "using protocol server containerfile"
                )
                return self._generate_protocol_server_containerfile(
                    blueprint, main_class_name, protocol_type
                )

            # PRIORITY 2: Detect framework type
            framework_metadata = (blueprint.metadata or {}).get("framework_adaptation", {})
            framework_type = framework_metadata.get("selected_framework")

            if not framework_type:
                vulnerability_data = {
                    "package_name": blueprint.package_name,
                    "package_version": blueprint.package_version,
                    "cve_ids": blueprint.cve_ids,
                    "description": blueprint.description,
                }
                framework_enum = self._tm._detect_framework_from_patterns(vulnerability_data)
                framework_type = framework_enum.value
                logger.info(
                    f"No framework in metadata, detected from package: {framework_type}"
                )

            framework_type_lower = framework_type.lower() if framework_type else "spring_boot"
            logger.info(
                f"Generating Containerfile for framework: {framework_type} "
                f"(normalized: {framework_type_lower})"
            )

            # WAR-based frameworks need Tomcat/servlet container
            if framework_type_lower in [
                "struts",
                "apache_struts",
                "servlet",
                "servlet_container",
            ]:
                is_spring_core = package_utils.is_spring_framework_core_package(
                    blueprint.package_name
                )
                _, java_version = version_utils.determine_spring_boot_version(
                    blueprint.package_version,
                    blueprint.package_name,
                    is_spring_core=is_spring_core,
                )
                logger.info(
                    f"Detected WAR-based framework ({framework_type}) with Java "
                    f"{java_version}, using Tomcat Containerfile"
                )
                return self._generate_struts_containerfile(java_version)

            # JAR-based frameworks use universal Spring Boot template
            logger.info(
                f"Using JAR-based universal Containerfile for {framework_type}"
            )

            is_spring_core = package_utils.is_spring_framework_core_package(
                blueprint.package_name
            )
            _, java_version = version_utils.determine_spring_boot_version(
                blueprint.package_version,
                blueprint.package_name,
                is_spring_core=is_spring_core,
            )
            logger.info(
                f"Using Java {java_version} for Containerfile "
                f"(package: {blueprint.package_name} v{blueprint.package_version})"
            )

            architecture = self._tm.renderer.detect_architecture()
            containerfile_template = self.get_containerfile_template(architecture)

            _, artifact_id = extract_package_parts(blueprint.package_name)

            context = {
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "cve_ids": ", ".join(blueprint.cve_ids),
                "artifact_id": artifact_id.lower(),
                "version": "1.0-SNAPSHOT",
                "main_class": main_class_name,
                "java_version": java_version,
            }

            rendered_containerfile = self._tm.renderer.render_template(
                containerfile_template, context
            )

            for key in context.keys():
                placeholder = f"${{{key}}}"
                if placeholder in rendered_containerfile:
                    logger.warning(
                        f"Unreplaced variable in Containerfile: {placeholder}"
                    )

            if (
                "COPY --from=build --chown=vulnapp:vulnapp /app/src/main/resources"
                in rendered_containerfile
            ):
                rendered_containerfile = rendered_containerfile.replace(
                    "COPY --from=build --chown=vulnapp:vulnapp "
                    "/app/src/main/resources /app/resources",
                    "# Create resources directory\n"
                    + "RUN mkdir -p /app/resources && chown -R vulnapp:vulnapp /app/resources\n\n"
                    + "# Conditionally copy resources if they exist\n"
                    + "COPY --from=build --chown=vulnapp:vulnapp "
                    "/app/src/main/resources/* /app/resources/ 2>/dev/null || true",
                )

            return rendered_containerfile

        except Exception as e:
            logger.error(f"Error generating Containerfile: {str(e)}", exc_info=True)
            raise TemplateError(
                message=f"Error generating Containerfile for {blueprint.package_name}",
                cause=e,
                remedy="Check the template format and blueprint information",
            )

    def get_containerfile_template(self, architecture: str = None) -> str:
        """
        Get Containerfile template using universal approach.

        Args:
            architecture: Target architecture (ignored — universal template works
                for all architectures).

        Returns:
            Universal Containerfile template content.

        Raises:
            FileNotFoundError: If no Containerfile template is found.
        """
        universal_containerfile = self._tm.templates_dir / "universal_containerfile.txt"

        if universal_containerfile.exists():
            logger.info("Using universal containerfile template")
            content = self._tm.loader.load_template_content(universal_containerfile)
            if content:
                return content

        generic_file = self._tm.containerfile_dir / "generic.txt"
        content = self._tm.loader.load_template_content(generic_file)

        if content:
            logger.warning(
                "Universal containerfile not found, using fallback generic template"
            )
            return content

        logger.error("No Containerfile template found!")
        raise FileNotFoundError(
            f"No Containerfile template found. Expected:\n"
            f"- {universal_containerfile} (universal template)\n"
            f"- {generic_file} (fallback template)"
        )

    def _get_main_class_name(self, framework_type: FrameworkType) -> str:
        """
        Get main class name for a framework type via metadata service.

        Args:
            framework_type: FrameworkType enum value.

        Returns:
            Fully-qualified main class name string.
        """
        main_class = self._tm.framework_metadata_service.get_main_class_name(
            framework_type.value
        )
        logger.debug(f"Main class for {framework_type.value}: {main_class}")
        return main_class

    def _generate_framework_containerfile(
        self, blueprint: any, framework_type: FrameworkType
    ) -> str:
        """
        Dispatch to the correct framework-specific Containerfile generator.

        Args:
            blueprint: Blueprint with vulnerability information.
            framework_type: FrameworkType enum value.

        Returns:
            Containerfile content string.
        """
        if framework_type == FrameworkType.SPRING_BOOT:
            return self._generate_spring_boot_containerfile(blueprint)
        elif framework_type == FrameworkType.APACHE_STRUTS:
            return self._generate_struts_containerfile()
        else:
            return self.generate_containerfile(
                blueprint, self._get_main_class_name(framework_type)
            )

    def _generate_spring_boot_containerfile(self, blueprint: any) -> str:
        """
        Generate a Spring Boot specific Containerfile via ContainerfileFactory.

        Args:
            blueprint: Blueprint with vulnerability information.

        Returns:
            Rendered Containerfile content for Spring Boot applications.
        """
        is_spring_core = package_utils.is_spring_framework_core_package(
            blueprint.package_name
        )
        _, java_version = version_utils.determine_spring_boot_version(
            blueprint.package_version,
            blueprint.package_name,
            is_spring_core=is_spring_core,
        )

        try:
            containerfile = self._tm.containerfile_factory.generate_containerfile(
                framework_type="spring_boot",
                java_version=java_version,
                additional_context={
                    "cve_ids": ", ".join(blueprint.cve_ids) if blueprint.cve_ids else "N/A"
                },
            )
            logger.info(
                f"Generated Spring Boot Containerfile using factory (Java {java_version})"
            )
            return containerfile
        except Exception as e:
            logger.error(f"Failed to generate Spring Boot Containerfile: {e}")
            raise

    def _generate_struts_containerfile(self, java_version: str = "8") -> str:
        """
        Generate an Apache Struts specific Containerfile via ContainerfileFactory.

        Args:
            java_version: Java version to use (e.g., '8', '11', '17').

        Returns:
            Containerfile content for WAR-based applications with Tomcat.
        """
        try:
            containerfile = self._tm.containerfile_factory.generate_containerfile(
                framework_type="apache_struts",
                java_version=java_version,
            )
            logger.info(
                f"Generated Struts Containerfile using factory (Java {java_version})"
            )
            return containerfile
        except Exception as e:
            logger.error(f"Failed to generate Struts Containerfile: {e}")
            raise

    def _generate_protocol_server_containerfile(
        self, blueprint: any, main_class_name: str, protocol_type: str
    ) -> str:
        """
        Generate a Containerfile for protocol-level vulnerabilities.

        Protocol servers use Maven Shade plugin (not Spring Boot), so
        ContainerfileFactory is invoked with framework type 'protocol_server'.
        Falls back to the universal Containerfile if the factory does not recognise
        the type.

        Args:
            blueprint: Blueprint with vulnerability information.
            main_class_name: Name of the main class.
            protocol_type: Protocol type (e.g., 'http2', 'websocket', 'kafka').

        Returns:
            Containerfile content for protocol servers.
        """
        is_spring_core = package_utils.is_spring_framework_core_package(
            blueprint.package_name
        )
        _, java_version = version_utils.determine_spring_boot_version(
            blueprint.package_version,
            blueprint.package_name,
            is_spring_core=is_spring_core,
        )
        logger.info(
            f"Using Java {java_version} for protocol server Containerfile "
            f"(package: {blueprint.package_name} v{blueprint.package_version})"
        )

        try:
            containerfile = self._tm.containerfile_factory.generate_containerfile(
                framework_type="protocol_server",
                java_version=java_version,
            )
            logger.info(
                f"Generated protocol server Containerfile using factory for "
                f"{protocol_type} (Java {java_version})"
            )
            return containerfile
        except Exception as e:
            logger.warning(
                f"ContainerfileFactory failed for protocol_server: {e}, "
                "falling back to universal containerfile"
            )

            architecture = self._tm.renderer.detect_architecture()
            containerfile_template = self.get_containerfile_template(architecture)

            _, artifact_id = extract_package_parts(blueprint.package_name)

            context = {
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "cve_ids": ", ".join(blueprint.cve_ids),
                "artifact_id": artifact_id.lower(),
                "main_class": main_class_name,
                "java_version": java_version,
            }

            rendered_containerfile = self._tm.renderer.render_template(
                containerfile_template, context
            )
            logger.info(
                f"Generated protocol server Containerfile using fallback for "
                f"{protocol_type} (Java {java_version})"
            )
            return rendered_containerfile
