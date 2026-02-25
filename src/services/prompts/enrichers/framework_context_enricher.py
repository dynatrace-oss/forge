"""
Framework Context Enricher.

Assembles framework detection context including framework type, rationale,
and recommended dependencies.
"""

import logging

from services.prompts.enrichers.base_enricher import ContextEnricher

logger = logging.getLogger(__name__)


class FrameworkContextEnricher(ContextEnricher):
    """
    Enriches context with framework detection information.

    Takes framework detection results and formats them into structured
    context for LLM prompts.

    Adds to context:
        - framework_context: Formatted framework detection context
    """

    def is_applicable(self, context: dict) -> bool:
        """Check if framework detection data is present."""
        return "framework_detection" in context or "framework_type" in context

    async def enrich(self, context: dict) -> dict:
        """
        Add formatted framework context.

        Args:
            context: Should contain framework_detection dict or framework_type

        Returns:
            Context with framework_context added
        """
        # Skip if already formatted
        if "framework_context" in context and context["framework_context"]:
            logger.debug("Framework context already present, skipping enrichment")
            return context

        # Get framework detection data
        framework_detection = context.get("framework_detection", {})
        framework_type = framework_detection.get("framework_type") or context.get("framework_type")

        if not framework_type:
            context["framework_context"] = ""
            return context

        # Skip standalone frameworks (no context needed)
        if framework_type == "standalone":
            context["framework_context"] = ""
            return context

        # Build framework context
        framework_context = self._build_framework_context(
            framework_type,
            framework_detection
        )

        context["framework_context"] = framework_context
        logger.debug(f"Added framework context for: {framework_type}")

        return context

    def _build_framework_context(
        self,
        framework_type: str,
        framework_detection: dict
    ) -> str:
        """
        Build framework context string.

        Args:
            framework_type: Detected framework type
            framework_detection: Framework detection results

        Returns:
            Formatted framework context string
        """
        context_parts = []

        # Framework type
        context_parts.append(f"Framework Type: {framework_type}")

        # Rationale
        rationale = framework_detection.get("rationale", "")
        if rationale:
            context_parts.append(f"Framework Rationale: {rationale}")

        # Required dependencies
        dependencies = framework_detection.get("required_dependencies", [])
        if dependencies:
            context_parts.append("Recommended Dependencies:")
            for dep in dependencies:
                group_id = dep.get("group_id", "")
                artifact_id = dep.get("artifact_id", "")
                version = dep.get("version", "")
                purpose = dep.get("purpose", "")

                dep_line = f"- {group_id}:{artifact_id}:{version}"
                if purpose:
                    dep_line += f" ({purpose})"

                context_parts.append(dep_line)

        return "\n".join(context_parts)
