import logging

from utils.core.loader import ConfigLoader

logger = logging.getLogger(__name__)


class SecurityRecommender:
    """Centralized security recommendations generation service."""

    def __init__(self, config_loader: ConfigLoader | None = None):
        """Initialize the security recommender with configuration."""
        self.config_loader = config_loader or ConfigLoader()
        self._load_recommendations_config()

    def _load_recommendations_config(self):
        """Load security recommendations from configuration files."""
        try:
            # Load vulnerability analysis configuration
            self.analysis_config = self.config_loader.load_config_safe("vulnerability_analysis", default={})

            # Extract recommendation configurations
            self.security_recommendations = self.analysis_config.get("security_recommendations", {})
            self.package_recommendations = self.analysis_config.get("package_recommendations", {})
            self.cve_immediate_actions = self.analysis_config.get("cve_immediate_actions", {})
            self.severity_actions = self.analysis_config.get("severity_actions", {})
            self.cvss_actions = self.analysis_config.get("cvss_actions", {})
            self.enterprise_recommendations = self.analysis_config.get("enterprise_recommendations", [])

        except Exception as e:
            logger.warning(f"Failed to load security recommendations: {e}. Using minimal defaults.")
            self._initialize_minimal_defaults()

    def _initialize_minimal_defaults(self):
        """Initialize minimal default recommendations if configuration loading fails."""
        self.security_recommendations = {
            "not_triggered": {
                "generic": [
                    "Review the test payload configuration and ensure it matches the vulnerability pattern",
                    "Verify the application is running the vulnerable version specified in the blueprint",
                ]
            },
            "triggered": {
                "immediate_actions": [
                    "Update the affected package to the latest secure version immediately",
                    "Review all applications and services using this dependency",
                ]
            },
        }
        self.package_recommendations = {}
        self.cve_immediate_actions = {}
        self.severity_actions = {}
        self.cvss_actions = {}
        self.enterprise_recommendations = []

    def generate_security_recommendations(self, vulnerability_triggered: bool, blueprint_data: dict = None) -> str:
        """Generate security recommendations using blueprint metadata and dynamic templates."""
        if not vulnerability_triggered:
            return self._generate_not_triggered_recommendations(blueprint_data)

        return self._generate_triggered_recommendations(blueprint_data)

    def _generate_not_triggered_recommendations(self, blueprint_data: dict = None) -> str:
        """Generate recommendations when vulnerability was not triggered."""
        recommendations = ["### Vulnerability Not Triggered"]

        # Generic troubleshooting from configuration
        generic_recs = self.security_recommendations.get("not_triggered", {}).get("generic", [])
        recommendations.extend([f"- {rec}" for rec in generic_recs])

        # Add blueprint-specific recommendations
        if blueprint_data:
            specific_recs = self._get_blueprint_specific_recommendations(blueprint_data, triggered=False)
            recommendations.extend(specific_recs)

        return "\n".join(recommendations)

    def _generate_triggered_recommendations(self, blueprint_data: dict = None) -> str:
        """Generate recommendations when vulnerability was successfully triggered."""
        recommendations = []

        # Immediate actions from configuration
        recommendations.append("### Immediate Actions")
        immediate_actions = self.security_recommendations.get("triggered", {}).get("immediate_actions", [])
        recommendations.extend([f"- {action}" for action in immediate_actions])

        # Add blueprint-specific immediate actions
        if blueprint_data:
            blueprint_immediate = self._get_immediate_actions_for_blueprint(blueprint_data)
            recommendations.extend(blueprint_immediate)

        # Long-term mitigations from configuration
        recommendations.extend(["", "### Long-term Mitigations"])
        longterm_actions = self.security_recommendations.get("triggered", {}).get("long_term_mitigations", [])
        recommendations.extend([f"- {action}" for action in longterm_actions])

        # Add blueprint-specific long-term recommendations
        if blueprint_data:
            longterm_recs = self._get_longterm_recommendations_for_blueprint(blueprint_data)
            recommendations.extend(longterm_recs)

        return "\n".join(recommendations)

    def _get_blueprint_specific_recommendations(self, blueprint_data: dict, triggered: bool) -> list[str]:
        """Get recommendations specific to the blueprint vulnerability using configuration."""
        recommendations = []
        package_name = blueprint_data.get("package_name", "").lower()

        # Find matching package recommendations
        for package_pattern, package_recs in self.package_recommendations.items():
            if package_pattern in package_name:
                if triggered:
                    recs = package_recs.get("triggered", [])
                else:
                    recs = package_recs.get("not_triggered", [])

                recommendations.extend([f"- {rec}" for rec in recs])

                # Add general recommendations for this package
                general_recs = package_recs.get("general", [])
                recommendations.extend([f"- {rec}" for rec in general_recs])
                break

        return recommendations

    def _get_immediate_actions_for_blueprint(self, blueprint_data: dict) -> list[str]:
        """Get immediate actions based on blueprint data using configuration."""
        actions = []

        # CVE-specific actions
        cve_ids = blueprint_data.get("cve_ids", [])
        for cve_id in cve_ids:
            for cve_pattern, action in self.cve_immediate_actions.items():
                if cve_pattern in cve_id:
                    actions.append(f"- {action}")

        # Severity-based actions
        metadata = blueprint_data.get("metadata", {})
        severity = metadata.get("cve_metadata", {}).get("severity_level")
        if severity and severity in self.severity_actions:
            actions.append(f"- {self.severity_actions[severity]}")

        # CVSS-based actions
        cvss_score = metadata.get("cve_metadata", {}).get("cvss_score")
        if cvss_score:
            for threshold, action in self.cvss_actions.items():
                if cvss_score >= float(threshold):
                    actions.append(f"- {action}")
                    break  # Use the highest applicable threshold

        return actions

    def _get_longterm_recommendations_for_blueprint(self, blueprint_data: dict) -> list[str]:
        """Get long-term recommendations based on blueprint data using configuration."""
        recommendations = []
        package_name = blueprint_data.get("package_name", "").lower()

        # Find matching package long-term recommendations
        for package_pattern, package_recs in self.package_recommendations.items():
            if package_pattern in package_name:
                longterm_recs = package_recs.get("longterm", [])
                recommendations.extend([f"- {rec}" for rec in longterm_recs])
                break

        # Add general enterprise recommendations
        recommendations.extend([f"- {rec}" for rec in self.enterprise_recommendations])

        return recommendations

    def get_package_specific_analysis(self, package_name: str) -> str:
        """Get package-specific vulnerability analysis from configuration."""
        package_lower = package_name.lower()

        # Load package analysis from configuration
        package_analysis = self.analysis_config.get("package_analysis", {})

        for pattern, analysis in package_analysis.items():
            if pattern in package_lower:
                return analysis

        # Fallback analysis
        return f"This {package_name} component vulnerability may be exploitable through various attack vectors depending on application usage."

    def get_supported_packages(self) -> list[str]:
        """Get list of packages with specific recommendations."""
        return list(self.package_recommendations.keys())
