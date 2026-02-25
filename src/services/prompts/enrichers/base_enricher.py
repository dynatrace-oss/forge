import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class ContextEnricher(ABC):
    """
    Abstract base class for context enrichers.

    Context enrichers transform and augment context dictionaries
    before they are used to render prompt templates.

    Subclasses must implement the enrich() method.
    """

    def __init__(self, config: dict[str, Any] = None):
        """
        Initialize enricher with optional configuration.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    async def enrich(self, context: dict) -> dict:
        """
        Enrich context with additional data.

        Args:
            context: Input context dictionary

        Returns:
            Enriched context dictionary (should include original context)

        Raises:
            Exception: If enrichment fails (implementation-specific)
        """
        pass

    def is_applicable(self, context: dict) -> bool:
        """
        Check if this enricher is applicable to the given context.

        Args:
            context: Context dictionary

        Returns:
            True if enricher should run, False otherwise
        """
        # Default: always applicable
        return True

    async def safe_enrich(self, context: dict) -> dict:
        """
        Safely enrich context with error handling.

        Args:
            context: Input context dictionary

        Returns:
            Enriched context, or original context if enrichment fails
        """
        try:
            if not self.is_applicable(context):
                self.logger.debug(f"{self.__class__.__name__} not applicable, skipping")
                return context

            return await self.enrich(context)

        except Exception as e:
            self.logger.error(f"{self.__class__.__name__} enrichment failed: {e}")
            # Return original context on failure (graceful degradation)
            return context

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(config={self.config})"
