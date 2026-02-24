"""
Version Guidance Enricher.

Adds version-specific API guidance to context from YAML configuration files.
"""

import logging

from services.prompts.enrichers.base_enricher import ContextEnricher
from utils.core.llm_context_builder import LLMContextBuilder

logger = logging.getLogger(__name__)


class VersionGuidanceEnricher(ContextEnricher):
    """
    Enriches context with version-specific API guidance.

    Uses LLMContextBuilder.get_version_guidance() to load version-specific
    API requirements, migration notes, and code patterns for packages.

    Adds to context:
        - version_guidance: String with version-specific API guidance
    """

    def is_applicable(self, context: dict) -> bool:
        """Check if package name and version are present."""
        return "package_name" in context and "package_version" in context

    async def enrich(self, context: dict) -> dict:
        """
        Add version guidance to context.

        Args:
            context: Must contain package_name and package_version

        Returns:
            Context with version_guidance added
        """
        package_name = context.get("package_name", "")
        package_version = context.get("package_version", "")

        if not package_name or not package_version:
            logger.debug("Missing package_name or package_version, skipping version guidance")
            context["version_guidance"] = "No version-specific guidance available."
            return context

        try:
            # Use existing LLMContextBuilder method
            version_guidance = LLMContextBuilder.get_version_guidance(
                package_name=package_name,
                package_version=package_version
            )

            if version_guidance:
                context["version_guidance"] = version_guidance
                logger.debug(f"Added version guidance for {package_name}:{package_version}")
            else:
                context["version_guidance"] = f"No specific guidance available for {package_name} {package_version}."

        except Exception as e:
            logger.error(f"Failed to get version guidance: {e}")
            context["version_guidance"] = "Version guidance unavailable."

        return context
