import logging
from jinja2 import Template

from services.config.framework_metadata_service import FrameworkMetadataService

logger = logging.getLogger(__name__)


class ContainerfileFactory:
    """
    Factory for generating Containerfiles from framework metadata.

    This class eliminates hardcoded Containerfile generation logic by using
    configuration-driven templates and metadata.
    """

    # Universal Containerfile template (supports JAR and WAR packaging)
    UNIVERSAL_TEMPLATE = """# Containerfile for {{ framework_display_name }}
                            # Auto-generated using metadata-driven approach

                            {% if war_pattern %}
                            # Build stage for WAR packaging
                            FROM maven:3.9-eclipse-temurin-{{ java_version }} AS build
                            WORKDIR /app

                            COPY pom.xml .
                            RUN mvn dependency:go-offline -B || true

                            COPY src ./src
                            RUN mvn clean package -DskipTests

                            # Runtime stage
                            FROM {{ base_image }}
                            WORKDIR /app

                            # Copy built WAR from build stage
                            COPY --from=build /app/{{ war_pattern }} {{ deploy_path }}

                            {% elif maven_build %}
                            # Build stage for JAR packaging (Maven Shade)
                            FROM maven:3.9-eclipse-temurin-{{ java_version }} AS build
                            WORKDIR /app

                            COPY pom.xml .
                            RUN mvn dependency:go-offline -B || true

                            COPY src ./src
                            RUN mvn clean package -DskipTests

                            # Runtime stage
                            FROM {{ base_image }}
                            WORKDIR /app

                            # Copy built JAR from build stage
                            COPY --from=build /app/{{ jar_pattern }} application.jar

                            {% else %}
                            # Single stage for JAR packaging
                            FROM {{ base_image }}
                            WORKDIR /app

                            # JAR packaging - standalone executable
                            COPY {{ jar_pattern }} application.jar
                            {% endif %}

                            # Expose application port
                            EXPOSE {{ expose_port }}

                            {% if health_check %}
                            # Health check
                            HEALTHCHECK CMD {{ health_check }}
                            {% endif %}

                            # Run application
                            {% if cmd %}
                            CMD {{ cmd | tojson }}
                            {% endif %}
                            """

    def __init__(self, metadata_service: FrameworkMetadataService | None = None):
        """
        Initialize the ContainerfileFactory.

        Args:
            metadata_service: Optional FrameworkMetadataService instance.
                            If not provided, a new one will be created.
        """
        self.metadata_service = metadata_service or FrameworkMetadataService()
        self.template = Template(self.UNIVERSAL_TEMPLATE)
        logger.info("ContainerfileFactory initialized")

    def generate_containerfile(
        self,
        framework_type: str,
        java_version: str = "17",
        additional_context: dict[str, any] | None = None
    ) -> str:
        """
        Generate Containerfile for a given framework.

        Args:
            framework_type: Framework type identifier (e.g., "spring_boot", "apache_struts")
            java_version: Java version to use (e.g., "8", "11", "17")
            additional_context: Optional additional template variables

        Returns:
            Rendered Containerfile content

        Raises:
            ValueError: If framework configuration not found
        """
        # Get framework metadata
        metadata = self.metadata_service.get_metadata(framework_type)
        if not metadata:
            raise ValueError(
                f"No metadata found for framework: {framework_type}. "
                f"Available frameworks: {self.metadata_service.list_frameworks()}"
            )

        # Get Containerfile configuration
        containerfile_config = metadata.containerfile
        if not containerfile_config:
            raise ValueError(f"No Containerfile configuration found for framework: {framework_type}")

        # Prepare template context
        context = {
            "framework_display_name": metadata.display_name,
            "framework_type": framework_type,
            "java_version": java_version,
            "expose_port": containerfile_config.get("expose_port", 8080),
        }

        # Process base image (substitute Java version placeholder)
        base_image_template = containerfile_config.get("base_image", "eclipse-temurin:{{java_version}}-jre")
        context["base_image"] = base_image_template.replace("{{java_version}}", java_version)

        # Handle JAR vs WAR packaging
        if "war_pattern" in containerfile_config:
            # WAR packaging (e.g., Struts, servlet containers)
            context["war_pattern"] = containerfile_config["war_pattern"]
            context["deploy_path"] = containerfile_config.get("deploy_path", "/app/application.war")
            context["jar_pattern"] = None
            context["maven_build"] = False
        else:
            # JAR packaging (default)
            context["jar_pattern"] = containerfile_config.get("jar_pattern", "target/*.jar")
            context["war_pattern"] = None
            context["deploy_path"] = None
            # Check if Maven build is required for JAR packaging (e.g., protocol servers using Maven Shade)
            context["maven_build"] = containerfile_config.get("maven_build", False)

        # CMD instruction
        cmd = containerfile_config.get("cmd")
        if cmd:
            context["cmd"] = cmd
        else:
            context["cmd"] = None

        # Health check
        health_check = containerfile_config.get("health_check")
        if health_check:
            context["health_check"] = health_check
        else:
            context["health_check"] = None

        # Merge additional context
        if additional_context:
            context.update(additional_context)

        # Render template
        try:
            containerfile = self.template.render(context)
            logger.info(f"Generated Containerfile for {framework_type} (Java {java_version})")
            logger.debug(f"Containerfile length: {len(containerfile)} bytes")
            return containerfile

        except Exception as e:
            logger.error(f"Failed to render Containerfile template for {framework_type}: {e}")
            raise

    def get_framework_info(self, framework_type: str) -> dict[str, any] | None:
        """
        Get framework information including Containerfile config.

        Args:
            framework_type: Framework type identifier

        Returns:
            Dictionary with framework information or None if not found
        """
        metadata = self.metadata_service.get_metadata(framework_type)
        if not metadata:
            return None

        return {
            "display_name": metadata.display_name,
            "main_class": metadata.main_class_name,
            "base_package": metadata.base_package,
            "containerfile_config": metadata.containerfile,
        }

    def list_available_frameworks(self) -> list[str]:
        """
        Get list of frameworks that have Containerfile configurations.

        Returns:
            List of framework identifiers
        """
        return self.metadata_service.list_frameworks()


def create_containerfile(
    framework_type: str,
    java_version: str = "17",
    **kwargs
) -> str:
    """
    Convenience function to generate a Containerfile.

    Args:
        framework_type: Framework type identifier
        java_version: Java version to use
        **kwargs: Additional context variables

    Returns:
        Rendered Containerfile content
    """
    factory = ContainerfileFactory()
    return factory.generate_containerfile(framework_type, java_version, kwargs)
