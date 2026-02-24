"""
Protocol Type Enricher.

Infers protocol type from CVE description and package name using configuration.
Replaces hardcoded protocol inference logic.
"""

import logging
from typing import Any, Optional

import yaml

from services.prompts.enrichers.base_enricher import ContextEnricher
from utils.core.common import PROJECT_ROOT

logger = logging.getLogger(__name__)


class ProtocolTypeEnricher(ContextEnricher):
    """
    Enriches context with inferred protocol type.

    Uses protocol_detection.yaml configuration to detect protocol types
    from CVE descriptions and package names, replacing hardcoded if/elif chains.

    Adds to context:
        - protocol_type: Detected protocol type string (e.g., "HTTP/2", "WebSocket")
    """

    def __init__(self, config: dict[str, Any] = None):
        super().__init__(config)
        self.protocol_config: Optional[dict] = None
        self._load_protocol_config()

    def _load_protocol_config(self) -> None:
        """Load protocol detection configuration from YAML."""
        config_path = PROJECT_ROOT / "src" / "config" / "protocol_detection.yaml"

        if not config_path.exists():
            logger.warning(f"Protocol detection config not found: {config_path}")
            self.protocol_config = self._get_fallback_config()
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.protocol_config = yaml.safe_load(f)
            logger.debug(f"Loaded protocol detection config from {config_path}")

        except Exception as e:
            logger.error(f"Failed to load protocol detection config: {e}")
            self.protocol_config = self._get_fallback_config()

    def _get_fallback_config(self) -> dict:
        """Fallback configuration if YAML file not available."""
        return {
            "protocol_patterns": {
                "http2": {
                    "keywords": ["http/2", "http2", "h2c"],
                    "package_keywords": ["http2"],
                    "display_name": "HTTP/2"
                },
                "websocket": {
                    "keywords": ["websocket", "ws://", "wss://"],
                    "package_keywords": ["websocket"],
                    "display_name": "WebSocket"
                },
                "grpc": {
                    "keywords": ["grpc", "protobuf"],
                    "package_keywords": ["grpc"],
                    "display_name": "gRPC"
                }
            },
            "package_protocol_mappings": {
                "netty": "Netty Protocol",
                "undertow": "Undertow Protocol",
                "jetty": "Jetty Protocol"
            },
            "fallback": {
                "display_name": "Protocol Server"
            }
        }

    def is_applicable(self, context: dict) -> bool:
        """Check if description or package name is present."""
        return "description" in context or "package_name" in context

    async def enrich(self, context: dict) -> dict:
        """
        Infer and add protocol type to context.

        Args:
            context: Should contain description and/or package_name

        Returns:
            Context with protocol_type added
        """
        # Skip if already present
        if "protocol_type" in context and context["protocol_type"]:
            logger.debug("Protocol type already present, skipping enrichment")
            return context

        description = context.get("description", "").lower()
        package_name = context.get("package_name", "").lower()

        protocol_type = self._detect_protocol(description, package_name)
        context["protocol_type"] = protocol_type

        logger.debug(f"Detected protocol type: {protocol_type}")
        return context

    def _detect_protocol(self, description: str, package_name: str) -> str:
        """
        Detect protocol type from description and package name.

        Args:
            description: CVE description (lowercase)
            package_name: Package name (lowercase)

        Returns:
            Protocol type display name
        """
        if not self.protocol_config:
            return "Protocol Server"

        # Check description keywords
        protocol_patterns = self.protocol_config.get("protocol_patterns", {})
        for proto_key, proto_config in protocol_patterns.items():
            keywords = proto_config.get("keywords", [])
            if any(keyword in description for keyword in keywords):
                return proto_config.get("display_name", proto_key.upper())

        # Check package name patterns
        for proto_key, proto_config in protocol_patterns.items():
            package_keywords = proto_config.get("package_keywords", [])
            if any(keyword in package_name for keyword in package_keywords):
                return proto_config.get("display_name", proto_key.upper())

        # Check package-specific mappings
        package_mappings = self.protocol_config.get("package_protocol_mappings", {})
        for pkg_pattern, proto_name in package_mappings.items():
            if pkg_pattern in package_name:
                return proto_name

        # Fallback
        fallback = self.protocol_config.get("fallback", {})
        return fallback.get("display_name", "Protocol Server")
