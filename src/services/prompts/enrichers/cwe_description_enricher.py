import logging
from typing import Any, Optional

import yaml

from services.prompts.enrichers.base_enricher import ContextEnricher
from utils.core.common import PROJECT_ROOT

logger = logging.getLogger(__name__)


class CWEDescriptionEnricher(ContextEnricher):
    """
    Enriches context with formatted CWE descriptions.

    Uses vulnerability_patterns.yaml to map CWE IDs to vulnerability types
    and formats them with human-readable descriptions.

    Adds to context:
        - cwe_descriptions: Formatted CWE descriptions string
    """

    def __init__(self, config: dict[str, Any] = None):
        super().__init__(config)
        self.cwe_map: Optional[dict] = None
        self._load_cwe_mappings()

    def _load_cwe_mappings(self) -> None:
        """Load CWE mappings from vulnerability_patterns.yaml."""
        config_path = PROJECT_ROOT / "src" / "config" / "vulnerability_patterns.yaml"

        if not config_path.exists():
            logger.warning(f"Vulnerability patterns config not found: {config_path}")
            self.cwe_map = {}
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                patterns = yaml.safe_load(f)
                self.cwe_map = patterns.get("cwe_mappings", {})
            logger.debug(f"Loaded {len(self.cwe_map)} CWE mappings")

        except Exception as e:
            logger.error(f"Failed to load CWE mappings: {e}")
            self.cwe_map = {}

    def is_applicable(self, context: dict) -> bool:
        """Check if cwe_ids is present."""
        cwe_ids = context.get("cwe_ids")
        if not cwe_ids:
            return False
        # Handle both list and string formats
        if isinstance(cwe_ids, str):
            return bool(cwe_ids.strip())
        return isinstance(cwe_ids, list) and len(cwe_ids) > 0

    async def enrich(self, context: dict) -> dict:
        """
        Add formatted CWE descriptions to context.

        Args:
            context: Should contain cwe_ids (list or string)

        Returns:
            Context with cwe_descriptions added
        """
        cwe_ids = context.get("cwe_ids", [])

        # Handle string format (comma-separated)
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe.strip() for cwe in cwe_ids.split(',') if cwe.strip()]

        if not cwe_ids:
            context["cwe_descriptions"] = "No CWE classifications available."
            return context

        descriptions = self._format_cwe_descriptions(cwe_ids)
        context["cwe_descriptions"] = descriptions

        logger.debug(f"Added descriptions for {len(cwe_ids)} CWE IDs")
        return context

    def _format_cwe_descriptions(self, cwe_ids: list) -> str:
        """
        Format CWE IDs with human-readable descriptions.

        Args:
            cwe_ids: List of CWE IDs (e.g., ["CWE-79", "CWE-502"])

        Returns:
            Formatted string with CWE descriptions
        """
        if not cwe_ids:
            return "No CWE classifications available."

        descriptions = []

        for cwe_id in cwe_ids:
            # Normalize CWE ID format
            cwe_id_normalized = cwe_id.upper().strip()
            if not cwe_id_normalized.startswith("CWE-"):
                cwe_id_normalized = f"CWE-{cwe_id_normalized}"

            # Look up vulnerability type
            vuln_type = self.cwe_map.get(cwe_id_normalized, "unknown")

            if vuln_type != "unknown":
                # Convert snake_case to Title Case
                readable_type = vuln_type.replace('_', ' ').title()
                descriptions.append(f"- {cwe_id_normalized}: {readable_type}")
            else:
                # Unknown CWE, just list the ID
                descriptions.append(f"- {cwe_id_normalized}: (classification not available)")

        if descriptions:
            return "\n".join(descriptions)
        else:
            return "No CWE classifications available."
