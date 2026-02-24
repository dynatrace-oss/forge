import logging
from typing import Optional

from services.prompts.enrichers.base_enricher import ContextEnricher
from services.prompts.enrichers.cwe_description_enricher import CWEDescriptionEnricher
from services.prompts.enrichers.framework_context_enricher import FrameworkContextEnricher
from services.prompts.enrichers.github_context_enricher import GitHubContextEnricher
from services.prompts.enrichers.protocol_type_enricher import ProtocolTypeEnricher
from services.prompts.enrichers.version_guidance_enricher import VersionGuidanceEnricher
from services.prompts.enrichers.version_warning_enricher import VersionWarningEnricher

logger = logging.getLogger(__name__)


class EnricherRegistry:
    """
    Registry for managing context enrichers.

    Provides centralized access to all enrichers and coordinates
    their execution with proper ordering and error handling.
    """

    def __init__(self):
        """Initialize enricher registry with built-in enrichers."""
        self.enrichers: dict[str, ContextEnricher] = {}
        self._register_built_in_enrichers()

    def _register_built_in_enrichers(self) -> None:
        """Register all built-in enrichers."""
        self.register("version_guidance", VersionGuidanceEnricher())
        self.register("github_context", GitHubContextEnricher())
        self.register("protocol_type", ProtocolTypeEnricher())
        self.register("version_warning", VersionWarningEnricher())
        self.register("cwe_description", CWEDescriptionEnricher())
        self.register("framework_context", FrameworkContextEnricher())

        logger.debug(f"Registered {len(self.enrichers)} built-in enrichers")

    def register(self, name: str, enricher: ContextEnricher) -> None:
        """
        Register a new enricher.

        Args:
            name: Unique enricher name
            enricher: ContextEnricher instance
        """
        if name in self.enrichers:
            logger.warning(f"Enricher '{name}' already registered, overwriting")

        self.enrichers[name] = enricher
        logger.debug(f"Registered enricher: {name}")

    def unregister(self, name: str) -> bool:
        """
        Unregister an enricher.

        Args:
            name: Enricher name to remove

        Returns:
            True if removed, False if not found
        """
        if name in self.enrichers:
            del self.enrichers[name]
            logger.debug(f"Unregistered enricher: {name}")
            return True
        return False

    def get_enricher(self, name: str) -> Optional[ContextEnricher]:
        """
        Get an enricher by name.

        Args:
            name: Enricher name

        Returns:
            ContextEnricher instance or None if not found
        """
        return self.enrichers.get(name)

    async def enrich_context(
        self,
        context: dict,
        enrichers: list[str],
        fail_fast: bool = False
    ) -> dict:
        """
        Apply multiple enrichers to context.

        Args:
            context: Base context dictionary
            enrichers: List of enricher names to apply (in order)
            fail_fast: If True, stop on first enrichment error; if False, continue

        Returns:
            Enriched context dictionary

        Raises:
            ValueError: If fail_fast=True and an enricher fails
        """
        enriched = context.copy()

        for enricher_name in enrichers:
            enricher = self.enrichers.get(enricher_name)

            if not enricher:
                logger.warning(f"Enricher not found: {enricher_name}")
                continue

            try:
                enriched = await enricher.safe_enrich(enriched)
                logger.debug(f"Applied enricher: {enricher_name}")

            except Exception as e:
                error_msg = f"Enricher '{enricher_name}' failed: {e}"

                if fail_fast:
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                else:
                    logger.warning(error_msg)
                    # Continue with next enricher

        return enriched

    def list_enrichers(self) -> list[str]:
        """
        Get list of registered enricher names.

        Returns:
            Sorted list of enricher names
        """
        return sorted(self.enrichers.keys())

    def get_enricher_info(self, name: str) -> Optional[dict]:
        """
        Get information about an enricher.

        Args:
            name: Enricher name

        Returns:
            Dictionary with enricher info or None if not found
        """
        enricher = self.enrichers.get(name)
        if not enricher:
            return None

        return {
            "name": name,
            "class": enricher.__class__.__name__,
            "config": enricher.config
        }


# Global singleton instance
_enricher_registry_instance: Optional[EnricherRegistry] = None


def get_enricher_registry() -> EnricherRegistry:
    """Get singleton EnricherRegistry instance."""
    global _enricher_registry_instance
    if _enricher_registry_instance is None:
        _enricher_registry_instance = EnricherRegistry()
    return _enricher_registry_instance


# Export singleton instance for easy access
enricher_registry = get_enricher_registry()
