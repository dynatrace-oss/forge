import logging
from pathlib import Path
from typing import Optional
import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


def load_framework_packages_config() -> dict:
    """
    Load framework package classification from config file.

    Returns:
        Dictionary containing framework package classifications
    """
    config_path = PROJECT_ROOT / "src" / "config" / "framework_packages.yaml"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning(f"Framework packages config not found: {config_path}")
        return {}
    except Exception as e:
        logger.error(f"Failed to load framework packages config: {e}")
        return {}


def is_spring_framework_core_package(package_name: str) -> bool:
    """
    Check if package is a Spring Framework core package.

    Spring Framework core packages ARE the framework itself and cannot be added
    as explicit dependencies to Spring Boot applications. They must be managed
    via Spring Boot's dependency management.

    Args:
        package_name: Package name in format "groupId:artifactId"

    Returns:
        True if this is a Spring Framework core package
    """
    config = load_framework_packages_config()
    spring_core_packages = config.get("spring_framework_core_packages", [])

    is_core = package_name in spring_core_packages
    if is_core:
        logger.info(f"Detected Spring Framework CORE package: {package_name}")
        logger.info("Will use spring_framework_native.xml template with dependencyManagement override")

    return is_core


def is_servlet_container_package(package_name: str) -> bool:
    """
    Check if package is a servlet container that should be tested.

    Args:
        package_name: Package name in format "groupId:artifactId"

    Returns:
        True if this is a servlet container package
    """
    config = load_framework_packages_config()
    servlet_packages = config.get("servlet_container_packages", [])

    is_servlet = package_name in servlet_packages
    if is_servlet:
        logger.info(f"Detected SERVLET CONTAINER package: {package_name}")
        logger.info("Will use Spring Boot with appropriate servlet container template")

    return is_servlet


def detect_servlet_container_type(package_name: str) -> Optional[str]:
    """
    Detect which servlet container type from package name.

    Args:
        package_name: Package name in format "groupId:artifactId"

    Returns:
        Container type: "undertow", "jetty", "tomcat", "netty", or None

    Examples:
        detect_servlet_container_type("io.undertow:undertow-core") → "undertow"
        detect_servlet_container_type("org.eclipse.jetty:jetty-server") → "jetty"
        detect_servlet_container_type("com.fasterxml.jackson.core:jackson-databind") → None
    """
    config = load_framework_packages_config()
    detection_rules = config.get("servlet_container_detection", {})

    for container_type, patterns in detection_rules.items():
        for pattern in patterns:
            if pattern in package_name:
                logger.info(f"Detected servlet container type: {container_type} from {package_name}")
                return container_type

    return None


def extract_group_id(package_name: str) -> str:
    """
    Extract Maven groupId from package name.

    Args:
        package_name: Package name (e.g., "org.springframework:spring-core" or "org.springframework.spring-core")

    Returns:
        Group ID string (e.g., "org.springframework")
    """
    if ":" in package_name:
        return package_name.split(":")[0]
    elif "." in package_name:
        parts = package_name.split(".")
        return ".".join(parts[:-1]) if len(parts) > 1 else "com.vuln"
    else:
        return "com.vuln"


def extract_artifact_id(package_name: str) -> str:
    """
    Extract Maven artifactId from package name.

    Args:
        package_name: Package name (e.g., "org.springframework:spring-core" or "org.springframework.spring-core")

    Returns:
        Artifact ID string (e.g., "spring-core")
    """
    if ":" in package_name:
        return package_name.split(":")[1]
    elif "." in package_name:
        return package_name.split(".")[-1]
    else:
        return package_name or "vulnerable-demo"


def extract_package_parts(package_name: str) -> tuple[str, str]:
    """
    Extract both groupId and artifactId from package name.

    Args:
        package_name: Package name in various formats

    Returns:
        Tuple of (group_id, artifact_id)
    """
    return (extract_group_id(package_name), extract_artifact_id(package_name))
