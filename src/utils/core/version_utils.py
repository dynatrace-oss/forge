import logging
import re
import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)

from services.config.framework_metadata_service import FrameworkMetadataService
_metadata_service = FrameworkMetadataService()


def get_struts_filter_class(package_version: str) -> str:
    """
    Determine correct Struts filter class based on package version.

    REFACTORED (Stage 2): Now uses framework_metadata.yaml version rules instead of hardcoded logic.

    Version history (maintained for reference):
    - 2.0.x-2.1.2: FilterDispatcher (deprecated)
    - 2.1.3-2.4.x: ng.filter.StrutsPrepareAndExecuteFilter
    - 2.5+, 6.x: filter.StrutsPrepareAndExecuteFilter

    Args:
        package_version: Struts version (e.g., "6.2.0", "2.5.31")

    Returns:
        Fully qualified filter class name
    """
    try:
        # Use metadata service to get filter class based on version
        filter_class = _metadata_service.get_filter_class("apache_struts", package_version)

        if filter_class:
            logger.debug(f"Filter class for Struts {package_version}: {filter_class}")
            return filter_class

        # Fallback to latest version if no match found
        logger.warning(f"No filter class match for Struts version '{package_version}', using modern default")
        return "org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter"

    except Exception as e:
        logger.error(f"Error determining Struts filter class for version '{package_version}': {e}")
        # Default to modern filter (works for 2.5+, 6.x)
        return "org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter"


def load_spring_boot_version_mapping() -> dict:
    """Load Spring Boot version mapping from config file."""
    mapping_file = PROJECT_ROOT / "src" / "config" / "spring_boot_version_mapping.yaml"
    try:
        with open(mapping_file, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning(f"Spring Boot version mapping file not found: {mapping_file}")
        return {
            "fallback": {
                "spring_6_and_above": {"spring_boot": "3.4.0", "java": "17"},
                "spring_5_and_below": {"spring_boot": "2.7.18", "java": "11"}
            }
        }
    except Exception as e:
        logger.error(f"Error loading Spring Boot version mapping: {e}")
        return {}


def get_spring_boot_for_framework_version(package_version: str) -> tuple[str, str]:
    """
    Map Spring Framework version to compatible Spring Boot version.

    This is CRITICAL for Spring Framework core packages. We cannot add Spring Framework
    packages as explicit dependencies to Spring Boot apps. Instead, we must select a
    Spring Boot version that naturally includes the target Spring Framework version.

    Args:
        package_version: Spring Framework version (e.g., "6.2.0", "5.3.10")

    Returns:
        tuple of (spring_boot_version, java_version)

    Example:
        "6.2.0" → ("3.4.0", "17")
        "6.1.6" → ("3.2.5", "17")
        "5.3.10" → ("2.7.18", "11")
    """
    # Parse major.minor from package version
    version_match = re.match(r"(\d+)\.(\d+)", package_version)
    if not version_match:
        logger.warning(f"Could not parse Spring Framework version from '{package_version}', using fallback")
        # Fallback to Spring Boot 3.x for modern versions
        return ("3.2.5", "17")

    major = int(version_match.group(1))
    minor = int(version_match.group(2))
    framework_version_key = f"{major}.{minor}"

    # Load mapping
    mapping_config = load_spring_boot_version_mapping()
    version_mapping = mapping_config.get("spring_framework_to_boot", {})

    # Look up compatible Spring Boot version
    if framework_version_key in version_mapping:
        config = version_mapping[framework_version_key]
        spring_boot_version = config["spring_boot"]
        java_version = config["java"]
        notes = config.get("notes", "")

        logger.info(f"Spring Framework {framework_version_key} → Spring Boot {spring_boot_version} + Java {java_version}")
        if notes:
            logger.info(f"   Note: {notes}")

        return (spring_boot_version, java_version)

    # Fallback strategy
    fallback = mapping_config.get("fallback", {})
    if major >= 6:
        config = fallback.get("spring_6_and_above", {"spring_boot": "3.4.0", "java": "17"})
        logger.warning(f"Spring Framework {framework_version_key} not in mapping, using fallback for 6.x+: Spring Boot {config['spring_boot']} + Java {config['java']}")
    else:
        config = fallback.get("spring_5_and_below", {"spring_boot": "2.7.18", "java": "11"})
        logger.warning(f"Spring Framework {framework_version_key} not in mapping, using fallback for 5.x: Spring Boot {config['spring_boot']} + Java {config['java']}")

    return (config["spring_boot"], config["java"])


def determine_spring_boot_version(package_version: str, package_name: str, is_spring_core: bool = False) -> tuple[str, str]:
    """
    Determine compatible Spring Boot version and Java version based on package version.

    Args:
        package_version: Version of the vulnerable package (e.g., "6.2.0", "5.3.10")
        package_name: Name of the package (e.g., "org.springframework:spring-web")
        is_spring_core: Whether this is a Spring Framework core package

    Returns:
        tuple of (spring_boot_version, java_version)
    """
    # CRITICAL: Check if this is a Spring Framework CORE package
    # Core packages need special handling - use version mapping
    if is_spring_core:
        return get_spring_boot_for_framework_version(package_version)

    # Extract major version from package version
    version_match = re.match(r"(\d+)\.(\d+)", package_version)
    if not version_match:
        # Default fallback
        logger.warning(f"Could not parse version from '{package_version}', using default Spring Boot 2.7.18 + Java 11")
        return ("2.7.18", "11")

    major = int(version_match.group(1))
    minor = int(version_match.group(2))

    # Version compatibility matrix for Spring Framework / Spring Boot
    # Spring 6.x → Spring Boot 3.x → Java 17+
    # Spring 5.x → Spring Boot 2.x → Java 11+
    # Spring 4.x → Spring Boot 1.5.x → Java 8+

    if "spring" in package_name.lower():
        if major >= 6:
            # Spring 6.x requires Spring Boot 3.x and Java 17
            logger.info(f"Spring Framework {major}.x detected → Spring Boot 3.x + Java 17 (REQUIRED for Spring 6.x)")
            return ("3.2.5", "17")
        elif major == 5:
            # Spring 5.x requires Spring Boot 2.x and Java 11
            logger.info(f"Spring Framework {major}.x detected → Spring Boot 2.x + Java 11")
            if minor >= 3:
                return ("2.7.18", "11")
            else:
                return ("2.6.15", "11")
        elif major == 4:
            # Spring 4.x requires Spring Boot 1.5.x and Java 8
            logger.info(f"Spring Framework {major}.x detected → Spring Boot 1.5.x + Java 8")
            return ("1.5.22.RELEASE", "8")

    # Apache Struts version compatibility
    if "struts" in package_name.lower():
        if major == 2:
            if minor < 5:  # Struts 2.0-2.4 (includes CVE-2017-5638 @ 2.3.1)
                # Requires Java 5-8, use Java 8 for best compatibility
                logger.info(f"Struts {major}.{minor} detected → Java 8 (Struts 2.0-2.4 compatibility)")
                return ("N/A", "8")
            else:  # Struts 2.5+
                # Requires Java 7+, use Java 11 for modern support
                logger.info(f"Struts {major}.{minor} detected → Java 11 (Struts 2.5+ compatibility)")
                return ("N/A", "11")
        elif major >= 6:  # Struts 6.x
            # Requires Java 8+, use Java 17 for latest versions
            logger.info(f"Struts {major}.x detected → Java 17 (Struts 6.x compatibility)")
            return ("N/A", "17")
        else:
            # Very old Struts 1.x, use Java 8
            logger.info(f"Struts {major}.x detected → Java 8 (Struts 1.x compatibility)")
            return ("N/A", "8")

    # For non-Spring packages, use conservative defaults
    logger.info("Non-Spring/Struts package detected → Default Spring Boot 2.7.18 + Java 11")
    return ("2.7.18", "11")


def validate_spring_compatibility(package_name: str, package_version: str, spring_boot_version: str, java_version: str) -> None:
    """
    Validate Spring Boot and Spring Framework version compatibility.

    Raises ValueError if incompatible combination is detected.

    Args:
        package_name: Package name (e.g., "org.springframework:spring-web")
        package_version: Package version (e.g., "6.2.0")
        spring_boot_version: Selected Spring Boot version
        java_version: Selected Java version
    """
    # Only validate for Spring packages
    if "spring" not in package_name.lower():
        return

    # Extract major version
    version_match = re.match(r"(\d+)\.", package_version)
    if not version_match:
        return

    major = int(version_match.group(1))

    # Validation rules
    if major >= 6:
        # Spring Framework 6.x REQUIRES Spring Boot 3.x and Java 17+
        if not spring_boot_version.startswith("3."):
            error_msg = (
                f"INCOMPATIBLE VERSIONS DETECTED!\n"
                f"   Package: {package_name} {package_version} (Spring Framework {major}.x)\n"
                f"   Spring Boot: {spring_boot_version}\n"
                f"   Java: {java_version}\n"
                f"\n"
                f"   Spring Framework 6.x REQUIRES Spring Boot 3.x + Java 17+\n"
                f"   Current configuration will cause runtime failures!\n"
                f"   Container will build but exit immediately."
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

        if int(java_version) < 17:
            error_msg = (
                f"INCOMPATIBLE JAVA VERSION!\n"
                f"   Package: {package_name} {package_version} (Spring Framework {major}.x)\n"
                f"   Java: {java_version}\n"
                f"\n"
                f"   Spring Framework 6.x REQUIRES Java 17 or higher\n"
                f"   Current Java {java_version} will cause compilation or runtime failures!"
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

    elif major == 5:
        # Spring Framework 5.x should use Spring Boot 2.x
        if spring_boot_version.startswith("3."):
            logger.warning(
                f"Spring Framework {major}.x with Spring Boot 3.x may have compatibility issues. "
                f"Consider using Spring Boot 2.x for Spring Framework 5.x packages."
            )

    logger.info(f"Version compatibility validated: Spring Framework {major}.x + Spring Boot {spring_boot_version} + Java {java_version}")


def is_valid_maven_version(version: str) -> bool:
    """
    Validate that a version follows Maven conventions.

    Args:
        version: Version string to validate

    Returns:
        True if valid Maven version format
    """
    if not version or not isinstance(version, str):
        return False

    # Maven version patterns
    patterns = [
        r"^\d+\.\d+\.\d+$",  # Standard semantic: 1.2.3
        r"^\d+\.\d+$",  # Two-part: 1.2
        r"^\d+\.\d+\.\d+-\w+$",  # With classifier: 32.1.3-jre
        r"^\d{8}$",  # Date-based: 20230618
    ]

    return any(re.match(pattern, version.strip()) for pattern in patterns)


def extract_and_validate_version(response: str) -> str | None:
    """
    Extract and validate version number from LLM response.

    Args:
        response: LLM response text containing a version

    Returns:
        Extracted version string if valid, None otherwise
    """
    # Clean the response
    cleaned_response = response.strip().strip('"').strip("'")

    # Look for version patterns in the response
    version_patterns = [
        r"^(\d+\.\d+\.\d+)$",  # x.y.z (exact match)
        r"^(\d+\.\d+)$",  # x.y (exact match)
        r"^(\d{8})$",  # date format like 20230618 (exact match)
        r"^(\d+\.\d+\.\d+-\w+)$",  # x.y.z-suffix (like 32.1.3-jre)
        r"\b(\d+\.\d+\.\d+)\b",  # x.y.z (anywhere in response)
        r"\b(\d+\.\d+)\b",  # x.y (anywhere in response)
        r"\b(\d{8})\b",  # date format (anywhere in response)
    ]

    for pattern in version_patterns:
        match = re.search(pattern, cleaned_response)
        if match:
            version = match.group(1)
            # Additional validation
            if is_valid_maven_version(version):
                logger.debug(f"Extracted and validated version {version} from LLM response: {response}")
                return version
            else:
                logger.debug(f"Extracted version {version} from LLM response but failed validation")

    logger.warning(f"Could not extract valid version from LLM response: {response}")
    return None
