import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


@dataclass
class FrameworkMetadata:
    """Encapsulates framework-specific metadata."""
    display_name: str
    main_class_name: str
    base_package: str
    dependencies: Dict[str, List[Dict[str, Any]]]
    containerfile: Dict[str, Any]
    template_selection: Dict[str, List[Dict[str, str]]]
    version_rules: Optional[Dict[str, List[Dict[str, str]]]] = None


class FrameworkMetadataService:
    """
    Service for loading and accessing framework metadata.

    This service eliminates hardcoded framework logic by providing a centralized,
    configuration-driven approach to framework-specific behavior.
    """

    def __init__(self, metadata_file: Optional[Path] = None):
        """
        Initialize the FrameworkMetadataService.

        Args:
            metadata_file: Optional path to framework_metadata.yaml.
                          Defaults to src/config/framework_metadata.yaml
        """
        self.metadata_file = metadata_file or (PROJECT_ROOT / "src" / "config" / "framework_metadata.yaml")
        self._metadata: Optional[Dict] = None
        self._load_metadata()

    def _load_metadata(self) -> None:
        """Load framework metadata from YAML file."""
        try:
            if not self.metadata_file.exists():
                logger.error(f"Framework metadata file not found: {self.metadata_file}")
                raise FileNotFoundError(f"Framework metadata file not found: {self.metadata_file}")

            with open(self.metadata_file, 'r') as f:
                self._metadata = yaml.safe_load(f)

            if not self._metadata:
                logger.error("Framework metadata file is empty")
                raise ValueError("Framework metadata file is empty")

            logger.info(f"Loaded framework metadata from {self.metadata_file}")
            logger.debug(f"Available frameworks: {list(self._metadata.get('frameworks', {}).keys())}")

        except Exception as e:
            logger.error(f"Failed to load framework metadata: {e}")
            raise

    def get_metadata(self, framework_type: str) -> Optional[FrameworkMetadata]:
        """
        Get complete metadata for a framework.

        Args:
            framework_type: Framework type identifier (e.g., "spring_boot", "apache_struts")

        Returns:
            FrameworkMetadata object or None if framework not found
        """
        frameworks = self._metadata.get('frameworks', {})
        framework_data = frameworks.get(framework_type)

        if not framework_data:
            logger.warning(f"No metadata found for framework: {framework_type}")
            return None

        try:
            return FrameworkMetadata(
                display_name=framework_data.get('display_name', framework_type),
                main_class_name=framework_data.get('main_class_name', 'VulnerableDemo'),
                base_package=framework_data.get('base_package', 'com.vuln'),
                dependencies=framework_data.get('dependencies', {}),
                containerfile=framework_data.get('containerfile', {}),
                template_selection=framework_data.get('template_selection', {'rules': []}),
                version_rules=framework_data.get('version_rules')
            )
        except Exception as e:
            logger.error(f"Failed to parse metadata for framework {framework_type}: {e}")
            return None

    def get_main_class_name(self, framework_type: str) -> str:
        """
        Get main class name for a framework.

        Args:
            framework_type: Framework type identifier

        Returns:
            Main class name (e.g., "VulnApplication" for Spring Boot)
            Falls back to "VulnerableDemo" if framework not found
        """
        metadata = self.get_metadata(framework_type)
        if metadata:
            logger.debug(f"Main class for {framework_type}: {metadata.main_class_name}")
            return metadata.main_class_name

        # Fallback to default
        fallback = self._metadata.get('fallback', {}).get('main_class_name', 'VulnerableDemo')
        logger.warning(f"No metadata for {framework_type}, using fallback main class: {fallback}")
        return fallback

    def get_filter_class(self, framework_type: str, version: str) -> Optional[str]:
        """
        Get version-specific filter class (primarily for Struts).

        Args:
            framework_type: Framework type identifier (e.g., "apache_struts")
            version: Package version (e.g., "2.5.30", "6.2.0")

        Returns:
            Fully qualified filter class name or None if not found
        """
        metadata = self.get_metadata(framework_type)
        if not metadata or not metadata.version_rules:
            logger.debug(f"No version rules for framework: {framework_type}")
            return None

        filter_rules = metadata.version_rules.get('filter_class', [])

        for rule in filter_rules:
            version_range = rule.get('version_range')
            filter_class = rule.get('class')

            if not version_range or not filter_class:
                continue

            if self._version_in_range(version, version_range):
                logger.info(f"Matched filter class for {framework_type} {version}: {filter_class}")
                logger.debug(f"  Matched rule: {version_range}")
                return filter_class

        logger.warning(f"No filter class match for {framework_type} version {version}")
        return None

    def get_template_for_package(
        self,
        framework_type: str,
        package_name: str,
        protocol_type: Optional[str] = None
    ) -> Optional[str]:
        """
        Get template name based on package name or protocol type.

        Template selection priority:
        1. protocol_type match (highest priority)
        2. package_pattern match
        3. None (caller should use fallback)

        Args:
            framework_type: Framework type identifier
            package_name: Package name to match against patterns
            protocol_type: Optional protocol type (e.g., "HTTP/2", "WebSocket")

        Returns:
            Template filename (e.g., "spring_boot_web.xml") or None
        """
        metadata = self.get_metadata(framework_type)
        if not metadata:
            logger.debug(f"No metadata for framework: {framework_type}")
            return None

        rules = metadata.template_selection.get('rules', [])

        # Priority 1: Check protocol_type matches first
        if protocol_type:
            for rule in rules:
                rule_protocol = rule.get('protocol_type')
                if rule_protocol and rule_protocol.lower() == protocol_type.lower():
                    template = rule.get('template')
                    logger.info(f"Template selected by protocol_type: {template}")
                    logger.debug(f"  Matched protocol: {protocol_type}")
                    return template

        # Priority 2: Check package_pattern matches
        package_lower = package_name.lower()
        for rule in rules:
            pattern = rule.get('package_pattern')
            if pattern and pattern.lower() in package_lower:
                template = rule.get('template')
                logger.info(f"Template selected by package_pattern: {template}")
                logger.debug(f"  Matched pattern: {pattern} in {package_name}")
                return template

        logger.debug(f"No template rule matched for {framework_type} / {package_name}")
        return None

    def get_common_dependencies(self, category: str) -> List[Dict[str, Any]]:
        """
        Get common dependencies by category.

        Args:
            category: Dependency category (e.g., "logging", "testing")

        Returns:
            List of dependency dictionaries
        """
        common_deps = self._metadata.get('common_dependencies', {})
        deps = common_deps.get(category, [])

        if deps:
            logger.debug(f"Retrieved {len(deps)} common dependencies for category: {category}")
        else:
            logger.debug(f"No common dependencies found for category: {category}")

        return deps

    def get_containerfile_config(self, framework_type: str) -> Optional[Dict[str, Any]]:
        """
        Get Containerfile configuration for a framework.

        Args:
            framework_type: Framework type identifier

        Returns:
            Containerfile configuration dictionary or None
        """
        metadata = self.get_metadata(framework_type)
        if metadata:
            return metadata.containerfile
        return None

    def _version_in_range(self, version: str, version_range: str) -> bool:
        """
        Check if a version falls within a specified range.

        Supports three range formats:
        - "X.Y.Z+": Minimum version (e.g., "6.0.0+" matches 6.0.0, 6.1.0, 7.0.0)
        - "X.Y.Z-A.B.C": Range (e.g., "2.5.0-2.99.99" matches 2.5.0 through 2.99.99)
        - "X.Y.Z": Exact match (e.g., "2.1.2" matches only 2.1.2)

        Args:
            version: Version to check (e.g., "2.5.30")
            version_range: Range specification (e.g., "6.0.0+", "2.5.0-2.99.99")

        Returns:
            True if version is in range, False otherwise
        """
        try:
            # Parse the version being checked
            version_parts = self._parse_version(version)
            if not version_parts:
                logger.warning(f"Could not parse version: {version}")
                return False

            # Handle "X.Y.Z+" format (minimum version)
            if version_range.endswith('+'):
                min_version_str = version_range[:-1]
                min_version_parts = self._parse_version(min_version_str)
                if not min_version_parts:
                    logger.warning(f"Could not parse minimum version: {min_version_str}")
                    return False

                result = self._compare_versions(version_parts, min_version_parts) >= 0
                logger.debug(f"Version {version} {'is' if result else 'is not'} >= {min_version_str}")
                return result

            # Handle "X.Y.Z-A.B.C" format (range)
            elif '-' in version_range:
                range_parts = version_range.split('-')
                if len(range_parts) != 2:
                    logger.warning(f"Invalid range format: {version_range}")
                    return False

                min_version_str, max_version_str = range_parts
                min_version_parts = self._parse_version(min_version_str)
                max_version_parts = self._parse_version(max_version_str)

                if not min_version_parts or not max_version_parts:
                    logger.warning(f"Could not parse range: {version_range}")
                    return False

                in_range = (
                    self._compare_versions(version_parts, min_version_parts) >= 0 and
                    self._compare_versions(version_parts, max_version_parts) <= 0
                )
                logger.debug(f"Version {version} {'is' if in_range else 'is not'} in range {version_range}")
                return in_range

            # Handle exact match "X.Y.Z" format
            else:
                exact_version_parts = self._parse_version(version_range)
                if not exact_version_parts:
                    logger.warning(f"Could not parse exact version: {version_range}")
                    return False

                match = self._compare_versions(version_parts, exact_version_parts) == 0
                logger.debug(f"Version {version} {'matches' if match else 'does not match'} exact {version_range}")
                return match

        except Exception as e:
            logger.error(f"Error checking version range: {e}")
            return False

    def _parse_version(self, version: str) -> Optional[tuple]:
        """
        Parse a version string into a tuple of integers.

        Args:
            version: Version string (e.g., "2.5.30", "6.2.0")

        Returns:
            Tuple of (major, minor, patch) or None if parsing fails
        """
        try:
            # Remove any trailing qualifiers (e.g., "-RELEASE", "-jre")
            version_clean = re.split(r'[-_]', version)[0]
            parts = version_clean.split('.')

            # Parse major, minor, patch (default to 0 if not present)
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0

            return (major, minor, patch)
        except (ValueError, IndexError) as e:
            logger.debug(f"Failed to parse version '{version}': {e}")
            return None

    def _compare_versions(self, v1: tuple, v2: tuple) -> int:
        """
        Compare two version tuples.

        Args:
            v1: First version tuple (major, minor, patch)
            v2: Second version tuple (major, minor, patch)

        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        else:
            return 0

    def list_frameworks(self) -> List[str]:
        """
        Get list of all available framework identifiers.

        Returns:
            List of framework type identifiers
        """
        frameworks = self._metadata.get('frameworks', {})
        return list(frameworks.keys())

    def reload_metadata(self) -> None:
        """Reload metadata from disk (useful for testing or config updates)."""
        self._metadata = None
        self._load_metadata()
        logger.info("Framework metadata reloaded")
