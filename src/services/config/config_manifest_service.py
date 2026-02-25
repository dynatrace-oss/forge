import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ConfigFileSpec:
    """Specification for a single config file."""
    template: str  # Path relative to templates/framework/configs/
    destination: str  # Destination in project structure
    render: bool  # Whether to use Jinja2 rendering
    variables: List[str]  # Variables required for rendering
    condition: Optional[Dict[str, Any]] = None  # Conditional inclusion


class ConfigManifestService:
    """Service for loading and managing framework config manifests."""

    def __init__(self, manifest_path: Optional[Path] = None):
        """Initialize with path to manifest YAML."""
        if manifest_path is None:
            manifest_path = Path(__file__).parent.parent.parent / "config" / "framework_config_manifests.yaml"

        self.manifest_path = manifest_path
        self.manifests: Dict[str, List[ConfigFileSpec]] = {}
        self._load_manifests()

    def _load_manifests(self):
        """Load config manifests from YAML file."""
        try:
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                logger.warning("Config manifest file is empty")
                return

            for framework, config in data.items():
                specs = []
                for file_config in config.get("config_files", []):
                    spec = ConfigFileSpec(
                        template=file_config["template"],
                        destination=file_config["destination"],
                        render=file_config.get("render", False),
                        variables=file_config.get("variables", []),
                        condition=file_config.get("condition")
                    )
                    specs.append(spec)

                self.manifests[framework.lower()] = specs

            logger.info(f"Loaded config manifests for {len(self.manifests)} frameworks")

        except FileNotFoundError:
            logger.error(f"Config manifest file not found: {self.manifest_path}")
            self.manifests = {}
        except Exception as e:
            logger.error(f"Failed to load config manifests: {e}")
            self.manifests = {}

    def get_config_specs(self, framework_type: str) -> List[ConfigFileSpec]:
        """Get config file specifications for a framework."""
        return self.manifests.get(framework_type.lower(), [])

    def filter_by_condition(
        self,
        specs: List[ConfigFileSpec],
        context: Dict[str, Any]
    ) -> List[ConfigFileSpec]:
        """
        Filter config specs by conditions.

        Args:
            specs: List of config file specifications
            context: Context values (e.g., protocol_type, config_values)

        Returns:
            Filtered list of specs that meet conditions
        """
        filtered = []

        for spec in specs:
            if spec.condition is None:
                # No condition, always include
                filtered.append(spec)
            else:
                # Check condition
                field = spec.condition.get("field")
                expected_values = spec.condition.get("values", [])

                actual_value = context.get(field)
                if actual_value in expected_values:
                    filtered.append(spec)
                    logger.debug(f"Including {spec.template} (condition met: {field}={actual_value})")
                else:
                    logger.debug(f"Excluding {spec.template} (condition not met: {field}={actual_value})")

        return filtered
