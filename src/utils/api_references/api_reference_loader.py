import logging
import re
from typing import Optional, Dict, Any

import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


class APIReferenceLoader:
    """Loads and provides version-specific API references for code generation."""

    def __init__(self):
        """Initialize API reference loader."""
        self.api_references_dir = PROJECT_ROOT / "src" / "config" / "api_references"
        self._cache = {}  # Cache loaded YAML files

    def get_version_guidance(self, package_name: str, package_version: str) -> Optional[str]:
        """
        Get targeted version-specific API guidance for a package.

        Args:
            package_name: Package name (e.g., "org.apache.struts:struts2-core")
            package_version: Package version (e.g., "6.2.0")

        Returns:
            String with targeted API guidance for this version, or None if not found
        """
        # Determine framework from package name
        framework = self._detect_framework(package_name)
        if not framework:
            logger.debug(f"No API reference framework detected for {package_name}")
            return None

        # Load API reference for this framework
        api_ref = self._load_api_reference(framework)
        if not api_ref:
            return None

        # Extract major version
        major_version = self._extract_major_version(package_version)
        if not major_version:
            logger.warning(f"Could not extract major version from {package_version}")
            return None

        # Find matching version section
        version_data = self._find_version_data(api_ref, framework, major_version, package_version)
        if not version_data:
            logger.warning(f"No API reference found for {framework} version {major_version}")
            return None

        # Build guidance string
        guidance = self._format_guidance(framework, package_version, version_data)
        return guidance

    def _detect_framework(self, package_name: str) -> Optional[str]:
        """Detect framework from package name."""
        package_lower = package_name.lower()

        if "struts" in package_lower:
            return "struts"
        elif "spring" in package_lower:
            return "spring"

        return None

    def _load_api_reference(self, framework: str) -> Optional[Dict[str, Any]]:
        """Load API reference YAML for a framework (with caching)."""
        if framework in self._cache:
            return self._cache[framework]

        yaml_file = self.api_references_dir / f"{framework}_version_apis.yaml"
        if not yaml_file.exists():
            logger.warning(f"API reference file not found: {yaml_file}")
            return None

        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
            self._cache[framework] = data
            logger.debug(f"Loaded API reference for {framework} from {yaml_file}")
            return data
        except Exception as e:
            logger.error(f"Error loading API reference {yaml_file}: {e}")
            return None

    def _extract_major_version(self, version: str) -> Optional[str]:
        """Extract major version from version string."""
        match = re.match(r"(\d+)", version)
        if match:
            return match.group(1)
        return None

    def _find_version_data(
        self, api_ref: Dict[str, Any], framework: str, major_version: str, full_version: str
    ) -> Optional[Dict[str, Any]]:
        """Find version data, trying exact match first, then major version."""
        framework_data = api_ref.get(framework, {})

        # Try exact major version (e.g., "6")
        if major_version in framework_data:
            return framework_data[major_version]

        # Try with minor version for special cases (e.g., "2.5")
        minor_match = re.match(r"(\d+\.\d+)", full_version)
        if minor_match:
            version_key = minor_match.group(1)
            if version_key in framework_data:
                return framework_data[version_key]

        # Try version ranges (e.g., "2.0-2.4")
        for key, data in framework_data.items():
            if "-" in key:  # Range like "2.0-2.4"
                if self._version_in_range(full_version, key):
                    return data

        return None

    def _version_in_range(self, version: str, range_str: str) -> bool:
        """Check if version falls within a range like '2.0-2.4'."""
        try:
            start, end = range_str.split("-")
            version_parts = version.split(".")
            start_parts = start.split(".")
            end_parts = end.split(".")

            # Compare major.minor
            version_num = float(f"{version_parts[0]}.{version_parts[1]}")
            start_num = float(f"{start_parts[0]}.{start_parts[1] if len(start_parts) > 1 else 0}")
            end_num = float(f"{end_parts[0]}.{end_parts[1] if len(end_parts) > 1 else 0}")

            return start_num <= version_num <= end_num
        except (ValueError, IndexError):
            return False

    def _format_guidance(
        self, framework: str, full_version: str, version_data: Dict[str, Any]
    ) -> str:
        """Format version data into concise guidance string."""
        lines = []

        # Concise header
        lines.append(f"**{framework.upper()} {full_version} - VERSION-SPECIFIC API REQUIREMENTS:**")
        lines.append("")

        # Critical warnings first (most important)
        if "critical_warnings" in version_data:
            lines.append("**CRITICAL - YOU MUST FOLLOW THESE:**")
            for warning in version_data["critical_warnings"]:
                lines.append(f"- {warning}")
            lines.append("")

        # File upload API (for Struts) - imports and example
        if "file_upload" in version_data:
            fu = version_data["file_upload"]

            # Show required imports first
            if "imports" in fu:
                lines.append("**REQUIRED IMPORTS:**")
                for imp in fu["imports"]:
                    lines.append("```java")
                    lines.append(f"import {imp};")
                    lines.append("```")
                lines.append("")

            # Show the complete working example
            if "example" in fu:
                lines.append("**CORRECT FILE UPLOAD PATTERN:**")
                lines.append("```java")
                lines.append(fu["example"].strip())
                lines.append("```")
                lines.append("")

        # Parameters API (for Struts) - just the example
        if "parameters" in version_data and "example" in version_data["parameters"]:
            lines.append("**CORRECT PARAMETERS PATTERN:**")
            lines.append("```java")
            lines.append(version_data["parameters"]["example"].strip())
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

_api_loader = APIReferenceLoader()


def get_version_guidance(package_name: str, package_version: str) -> Optional[str]:
    """
    Get version-specific API guidance for a package (convenience function).

    Args:
        package_name: Package name (e.g., "org.apache.struts:struts2-core")
        package_version: Package version (e.g., "6.2.0")

    Returns:
        String with targeted API guidance, or None
    """
    return _api_loader.get_version_guidance(package_name, package_version)
