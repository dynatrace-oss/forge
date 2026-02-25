"""
Version Warning Enricher.

Adds version-specific warnings for breaking API changes (e.g., Struts 6.x, Spring 6.x).
Replaces hardcoded version warning logic.
"""

import logging
from typing import Any, Optional

import yaml

from services.prompts.enrichers.base_enricher import ContextEnricher
from utils.core.common import PROJECT_ROOT

logger = logging.getLogger(__name__)


class VersionWarningEnricher(ContextEnricher):
    """
    Enriches context with version-specific warnings for breaking changes.

    Uses version_warnings.yaml configuration to provide critical warnings
    for packages with breaking API changes (Struts 6.x, Spring 6.x, etc.).

    Adds to context:
        - version_warning: String with version-specific warnings
    """

    def __init__(self, config: dict[str, Any] = None):
        super().__init__(config)
        self.warnings_config: Optional[dict] = None
        self._load_warnings_config()

    def _load_warnings_config(self) -> None:
        """Load version warnings configuration from YAML."""
        config_path = PROJECT_ROOT / "src" / "config" / "version_warnings.yaml"

        if not config_path.exists():
            logger.warning(f"Version warnings config not found: {config_path}")
            self.warnings_config = self._get_fallback_config()
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.warnings_config = yaml.safe_load(f)
            logger.debug(f"Loaded version warnings config from {config_path}")

        except Exception as e:
            logger.error(f"Failed to load version warnings config: {e}")
            self.warnings_config = self._get_fallback_config()

    def _get_fallback_config(self) -> dict:
        """Fallback configuration if YAML file not available."""
        return {
            "packages": {
                "struts": {
                    "package_patterns": ["org.apache.struts", "struts2-core"],
                    "major_versions": {
                        "6": {
                            "severity": "CRITICAL",
                            "warning": "STRUTS 6.x DETECTED - CRITICAL API CHANGES:\n"
                                     "   - HttpParameters (immutable) NOT Map<String, Object>\n"
                                     "   - UploadedFile NOT File\n"
                                     "   - See version guidance for full API rules\n"
                                     "   - MANDATORY: Re-read version rules before code generation!"
                        }
                    }
                },
                "springframework": {
                    "package_patterns": ["org.springframework", "spring-core", "spring-web"],
                    "major_versions": {
                        "6": {
                            "severity": "CRITICAL",
                            "warning": "SPRING 6.x DETECTED - CRITICAL API CHANGES:\n"
                                     "   - jakarta.* imports NOT javax.*\n"
                                     "   - Requires Java 17+\n"
                                     "   - See version guidance for migration details"
                        }
                    }
                }
            }
        }

    def is_applicable(self, context: dict) -> bool:
        """Check if package name and version are present."""
        return "package_name" in context and "package_version" in context

    async def enrich(self, context: dict) -> dict:
        """
        Add version warnings to context.

        Args:
            context: Should contain package_name and package_version

        Returns:
            Context with version_warning added
        """
        package_name = context.get("package_name", "").lower()
        package_version = context.get("package_version", "")

        if not package_name or not package_version:
            context["version_warning"] = ""
            return context

        warning_text = self._get_version_warning(package_name, package_version)
        context["version_warning"] = warning_text

        if warning_text:
            logger.info(f"Added version warning for {package_name}:{package_version}")

        return context

    def _get_version_warning(self, package_name: str, package_version: str) -> str:
        """
        Get version-specific warning for package.

        Args:
            package_name: Package name (lowercase)
            package_version: Package version (e.g., "6.2.0")

        Returns:
            Warning text or empty string
        """
        if not self.warnings_config:
            return ""

        packages = self.warnings_config.get("packages", {})

        # Extract major version
        try:
            major_version = package_version.split('.')[0]
        except (IndexError, AttributeError):
            logger.debug(f"Could not extract major version from: {package_version}")
            return ""

        # Check each configured package
        for pkg_key, pkg_config in packages.items():
            package_patterns = pkg_config.get("package_patterns", [])

            # Check if package name matches any pattern
            if any(pattern in package_name for pattern in package_patterns):
                # Check if major version has warnings
                major_versions = pkg_config.get("major_versions", {})
                version_config = major_versions.get(major_version)

                if version_config:
                    severity = version_config.get("severity", "INFO")
                    warning = version_config.get("warning", "")
                    info = version_config.get("info", "")

                    if severity == "CRITICAL" and warning:
                        # Format critical warning prominently
                        formatted = f"\n\n{'='*60}\n"
                        formatted += f"TARGET VERSION: {package_version}\n"
                        formatted += f"{'='*60}\n\n"
                        formatted += warning
                        formatted += f"\n\nIMPORTANT: Use APIs appropriate for version {package_version}\n"
                        return formatted

                    elif info:
                        return f"\n{info}\n"

        return ""
