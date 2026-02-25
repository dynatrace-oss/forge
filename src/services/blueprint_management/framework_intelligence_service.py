import logging
import re
import yaml
from pathlib import Path
from enum import Enum

from models.framework_adaptation import FrameworkCapability, FrameworkSuitability
from shared.constants import PROJECT_ROOT
from shared.interfaces import LLMServiceInterface
from shared.types import FrameworkType

logger = logging.getLogger(__name__)


class VulnerabilityLevel(Enum):
    """Classification of vulnerability demonstrability levels."""
    APPLICATION_LEVEL = "application_level"
    PROTOCOL_LEVEL = "protocol_level"
    FRAMEWORK_INTERNAL = "framework_internal"


class FrameworkIntelligenceService:
    """
    This service detects frameworksß using multiple strategies:
    1. Dependency signature analysis
    2. Package namespace analysis  
    3. Vulnerability pattern analysis
    4. OSV database cross-referencing
    5. LLM-powered contextual analysis
    """

    def __init__(self, llm_service: LLMServiceInterface | None = None):
        """
        Initialize the Framework Intelligence Service.
        
        Args:
            llm_service: Optional LLM service for advanced analysis
        """
        self.llm_service = llm_service
        self._initialize_detection_rules()
        
        logger.info("Framework Intelligence Service initialized")

    def _initialize_detection_rules(self) -> None:
        """Initialize framework detection rules and patterns from configuration."""
        # Load detection patterns from configuration file
        self.dependency_signatures = self._load_detection_patterns()

        # Initialize namespace patterns
        self.namespace_patterns = self._load_namespace_patterns()

        # Initialize vulnerability-framework associations
        self.vulnerability_framework_associations = self._load_vulnerability_associations()

        # Load vulnerability classification rules
        self.classification_rules = self._load_classification_rules()

        # Load framework packages config (for application_library guard)
        self.framework_packages = self._load_framework_packages()
        
    def _load_detection_patterns(self) -> dict[FrameworkType, dict[str, any]]:
        """Load framework detection patterns from configuration file."""
        patterns = {}
        
        try:
            detection_file = Path(PROJECT_ROOT) / "src" / "templates" / "framework" / "detection_patterns.txt"
            
            if not detection_file.exists():
                logger.warning(f"Detection patterns file not found: {detection_file}")
                return self._get_fallback_patterns()
            
            current_framework = None
            framework_patterns = []
            
            with open(detection_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Check for framework section header
                    if line.startswith('[') and line.endswith(']'):
                        # Save previous framework if exists
                        if current_framework and framework_patterns:
                            patterns[current_framework] = self._build_framework_config(framework_patterns)
                        
                        # Start new framework
                        framework_name = line[1:-1]
                        current_framework = self._map_framework_name(framework_name)
                        framework_patterns = []
                    else:
                        # Add pattern to current framework
                        if current_framework:
                            framework_patterns.append(line)
                
                # Save last framework
                if current_framework and framework_patterns:
                    patterns[current_framework] = self._build_framework_config(framework_patterns)
            
            logger.info(f"Loaded detection patterns for {len(patterns)} frameworks")
            return patterns
            
        except Exception as e:
            logger.error(f"Error loading detection patterns: {e}")
            return self._get_fallback_patterns()
    
    def _map_framework_name(self, framework_name: str) -> FrameworkType | None:
        """Map configuration framework names to FrameworkType enum."""
        mapping = {
            "SPRING_BOOT": FrameworkType.SPRING_BOOT,
            "APACHE_STRUTS": FrameworkType.APACHE_STRUTS,
            "MICRONAUT": FrameworkType.MICRONAUT,
            "QUARKUS": FrameworkType.QUARKUS,
            "JENKINS_PLUGIN": getattr(FrameworkType, 'JENKINS_PLUGIN', None),
            "WEB_APPLICATION": getattr(FrameworkType, 'WEB_APPLICATION', None),
        }
        return mapping.get(framework_name)
    
    def _build_framework_config(self, patterns: list[str]) -> dict[str, any]:
        """Build framework configuration from pattern list."""
        # Split patterns into required and optional based on specificity
        required_patterns = []
        optional_patterns = []
        
        for pattern in patterns:
            # More specific patterns (with dots or dashes) are required
            if '.' in pattern or '-' in pattern or len(pattern) > 8:
                required_patterns.append(pattern.replace('.', r'\.'))
            else:
                optional_patterns.append(pattern)
        
        return {
            "required_patterns": required_patterns[:3],  # Limit to most important
            "optional_patterns": optional_patterns + required_patterns[3:],
            "confidence_weight": 0.9,
        }
    
    def _get_fallback_patterns(self) -> dict[FrameworkType, dict[str, any]]:
        """Fallback patterns in case configuration file cannot be loaded."""
        return {
            FrameworkType.SPRING_BOOT: {
                "required_patterns": [r"org\.springframework\.boot", r"spring-boot-starter"],
                "optional_patterns": [r"org\.springframework", r"spring-context"],
                "confidence_weight": 0.9,
            },
            FrameworkType.APACHE_STRUTS: {
                "required_patterns": [r"org\.apache\.struts", r"struts2-core"],
                "optional_patterns": [r"struts2-convention", r"xwork-core"],
                "confidence_weight": 0.95,
            },
        }

    async def analyze_framework_requirements(
        self, 
        vulnerability_data: dict[str, any], 
        package_info: dict[str, any]
    ) -> dict[FrameworkType, FrameworkCapability]:
        """
        Analyze framework requirements and capabilities for a given vulnerability.
        
        Args:
            vulnerability_data: Vulnerability information including CVE, description, etc.
            package_info: Package information including dependencies, namespace, etc.
            
        Returns:
            Dictionary mapping framework types to their capabilities for this vulnerability
        """
        try:
            framework_capabilities = {}
            
            # Analyze each supported framework
            for framework_type in FrameworkType:
                capability = await self._analyze_framework_capability(
                    framework_type, vulnerability_data, package_info
                )
                framework_capabilities[framework_type] = capability
            
            # Sort by suitability and confidence
            sorted_capabilities = dict(
                sorted(
                    framework_capabilities.items(),
                    key=lambda x: (x[1].suitability.value, x[1].confidence_weight),
                    reverse=True
                )
            )
            
            logger.info(f"Analyzed framework capabilities for {vulnerability_data.get('package_name', 'unknown')}")
            return sorted_capabilities
            
        except Exception as e:
            logger.error(f"Error analyzing framework requirements: {e}")
            return {}

    def _analyze_framework_capability(
        self,
        framework_type: FrameworkType,
        vulnerability_data: dict[str, any],
        package_info: dict[str, any]
    ) -> FrameworkCapability:
        """Analyze a specific framework's capability for the given vulnerability."""
        
        # Extract relevant information
        package_name = vulnerability_data.get("package_name", "")
        vulnerability_type = vulnerability_data.get("vulnerability_type", "")
        description = vulnerability_data.get("description", "")
        
        # Base capability assessment
        suitability = self._assess_framework_suitability(
            framework_type, vulnerability_type, package_name, description
        )
        
        complexity = self._assess_adaptation_complexity(
            framework_type, vulnerability_data, package_info
        )
        
        required_deps = self._get_required_dependencies(framework_type)
        config_requirements = self._get_configuration_requirements(framework_type)
        
        performance_impact = self._assess_performance_impact(framework_type)
        security_considerations = self._get_security_considerations(framework_type)
        
        return FrameworkCapability(
            framework_type=framework_type,
            vulnerability_type=vulnerability_type,
            suitability=suitability,
            adaptation_complexity=complexity,
            required_dependencies=required_deps,
            configuration_requirements=config_requirements,
            performance_impact=performance_impact,
            security_considerations=security_considerations,
            notes=f"Analysis for {package_name} with {framework_type.value}",
        )

    def _assess_framework_suitability(
        self,
        framework_type: FrameworkType,
        vulnerability_type: str,
        package_name: str,
        description: str
    ) -> FrameworkSuitability:
        """Assess how suitable a framework is for demonstrating a specific vulnerability."""
        
        suitability_score = 0.5  # Base score
        
        # Check vulnerability type associations
        vuln_type_lower = vulnerability_type.lower()
        for pattern, associated_frameworks in self.vulnerability_framework_associations.items():
            if pattern in vuln_type_lower and framework_type in associated_frameworks:
                suitability_score += 0.3
        
        # Check package name associations
        package_lower = package_name.lower()
        if framework_type.value.lower() in package_lower:
            suitability_score += 0.4
        
        # Check description for framework mentions
        description_lower = description.lower()
        if framework_type.value.lower().replace("_", "-") in description_lower:
            suitability_score += 0.2
        
        # Special case handling
        if framework_type == FrameworkType.WEB_APPLICATION:
            # Web applications are versatile and good for most vulnerabilities
            suitability_score = max(0.7, suitability_score)
        
        # Web frameworks for web vulnerabilities
        web_frameworks = [FrameworkType.SPRING_BOOT, FrameworkType.APACHE_STRUTS]
        if framework_type in web_frameworks and any(
            term in vuln_type_lower for term in ["web", "http", "xss", "csrf", "injection"]
        ):
            suitability_score += 0.3
        
        # Convert score to suitability enum
        if suitability_score >= 0.9:
            return FrameworkSuitability.EXCELLENT
        elif suitability_score >= 0.7:
            return FrameworkSuitability.GOOD
        elif suitability_score >= 0.5:
            return FrameworkSuitability.FAIR
        elif suitability_score >= 0.3:
            return FrameworkSuitability.POOR
        else:
            return FrameworkSuitability.INCOMPATIBLE

    def _assess_adaptation_complexity(
        self,
        framework_type: FrameworkType,
        vulnerability_data: dict[str, any],
        package_info: dict[str, any]
    ) -> str:
        """Assess the complexity of adapting to a framework."""
        
        complexity_score = 0.5  # Base complexity
        
        # Framework-specific complexity factors
        framework_complexity = {
            FrameworkType.WEB_APPLICATION: 0.2,
            FrameworkType.SPRING_BOOT: 0.3,
            FrameworkType.MICRONAUT: 0.4,
            FrameworkType.QUARKUS: 0.4,
            FrameworkType.APACHE_STRUTS: 0.6,
        }
        
        complexity_score += framework_complexity.get(framework_type, 0.5)
        
        # Vulnerability type complexity
        vulnerability_type = vulnerability_data.get("vulnerability_type", "").lower()
        if any(term in vulnerability_type for term in ["deserial", "rce", "injection"]):
            complexity_score += 0.2
        
        # Package dependency complexity
        existing_deps = package_info.get("dependencies", [])
        if len(existing_deps) > 5:
            complexity_score += 0.1
        
        # Convert to complexity level
        if complexity_score <= 0.3:
            return "simple"
        elif complexity_score <= 0.6:
            return "moderate"
        elif complexity_score <= 0.8:
            return "complex"
        else:
            return "advanced"

    def _get_required_dependencies(
        self,
        framework_type: FrameworkType,
    ) -> list[str]:
        """Get required dependencies for the framework."""
        
        base_dependencies = {
            FrameworkType.SPRING_BOOT: [
                "org.springframework.boot:spring-boot-starter",
                "org.springframework.boot:spring-boot-starter-web",
            ],
            FrameworkType.APACHE_STRUTS: [
                "org.apache.struts:struts2-core",
                "org.apache.struts:struts2-convention-plugin",
            ],
            FrameworkType.MICRONAUT: [
                "io.micronaut:micronaut-http",
                "io.micronaut:micronaut-http-server-netty",
            ],
            FrameworkType.QUARKUS: [
                "io.quarkus:quarkus-resteasy",
                "io.quarkus:quarkus-arc",
            ],
            FrameworkType.WEB_APPLICATION: [
                "org.springframework.boot:spring-boot-starter",
                "org.springframework.boot:spring-boot-starter-web",
            ],
        }
        
        return base_dependencies.get(framework_type, [])

    def _get_configuration_requirements(
        self,
        framework_type: FrameworkType,
    ) -> list[str]:
        """Get configuration requirements for the framework."""
        
        config_requirements = {
            FrameworkType.SPRING_BOOT: [
                "application.properties or application.yml",
                "Main class with @SpringBootApplication",
                "Controller classes with @RestController",
            ],
            FrameworkType.APACHE_STRUTS: [
                "struts.xml configuration",
                "web.xml deployment descriptor",
                "Action classes extending ActionSupport",
            ],
            FrameworkType.MICRONAUT: [
                "application.yml configuration",
                "Main class with @Application",
                "Controller classes with @Controller",
            ],
            FrameworkType.QUARKUS: [
                "application.properties",
                "JAX-RS resource classes with @Path",
                "CDI beans configuration",
            ],
            FrameworkType.WEB_APPLICATION: [
                "application.properties or application.yml",
                "Main class with @SpringBootApplication",
                "Controller classes with @RestController for HTTP endpoints",
            ],
        }
        
        return config_requirements.get(framework_type, [])

    def _assess_performance_impact(
        self,
        framework_type: FrameworkType,
    ) -> str:
        """Assess the performance impact of using this framework."""
        
        performance_characteristics = {
            FrameworkType.WEB_APPLICATION: "low",
            FrameworkType.QUARKUS: "low",
            FrameworkType.MICRONAUT: "low",
            FrameworkType.SPRING_BOOT: "medium",
            FrameworkType.APACHE_STRUTS: "medium",
        }
        
        return performance_characteristics.get(framework_type, "medium")

    def _get_security_considerations(
        self,
        framework_type: FrameworkType,
    ) -> list[str]:
        """Get security considerations for the framework."""
        
        security_considerations = {
            FrameworkType.SPRING_BOOT: [
                "Disable Spring Security for vulnerability demonstration",
                "Configure actuator endpoints appropriately",
                "Be aware of auto-configuration security defaults",
            ],
            FrameworkType.APACHE_STRUTS: [
                "Ensure vulnerable Struts version is used",
                "Configure interceptors to allow vulnerability exploitation",
                "Be aware of OGNL expression evaluation security",
            ],
            FrameworkType.MICRONAUT: [
                "Be aware of compile-time security configurations",
            ],
            FrameworkType.QUARKUS: [
                "Be aware of native compilation security implications",
            ],
            FrameworkType.WEB_APPLICATION: [
                "Configure HTTP endpoints for vulnerability demonstration",
                "Ensure web server runs on port 8080",
                "Disable security for vulnerability testing",
            ],
        }
        
        return security_considerations.get(framework_type, [])

    def detect_framework_from_dependencies(self, dependencies: list[str]) -> dict[str, float]:
        """
        Detect likely frameworks based on dependency signatures.
        
        Args:
            dependencies: list of dependency strings (group:artifact:version format)
            
        Returns:
            Dictionary mapping framework names to confidence scores
        """
        framework_scores = {}
        
        try:
            for framework_type, signature in self.dependency_signatures.items():
                score = 0.0
                
                # Check required patterns
                required_matches = 0
                for pattern in signature["required_patterns"]:
                    if any(re.search(pattern, dep, re.IGNORECASE) for dep in dependencies):
                        required_matches += 1
                
                if required_matches > 0:
                    score += (required_matches / len(signature["required_patterns"])) * 0.7
                    
                    # Check optional patterns for additional confidence
                    optional_matches = 0
                    for pattern in signature.get("optional_patterns", []):
                        if any(re.search(pattern, dep, re.IGNORECASE) for dep in dependencies):
                            optional_matches += 1
                    
                    if signature.get("optional_patterns"):
                        score += (optional_matches / len(signature["optional_patterns"])) * 0.3
                    
                    # Apply framework-specific confidence weight
                    score *= signature.get("confidence_weight", 1.0)
                
                framework_scores[framework_type.value] = min(1.0, score)
            
            logger.info(f"Framework detection from dependencies: {framework_scores}")
            return framework_scores
            
        except Exception as e:
            logger.error(f"Error detecting framework from dependencies: {e}")
            return {}

    def detect_framework_from_namespace(self, package_name: str) -> dict[str, float]:
        """
        Detect likely frameworks based on package namespace analysis.
        
        Args:
            package_name: Package name to analyze
            
        Returns:
            Dictionary mapping framework names to confidence scores
        """
        framework_scores = {}
        
        try:
            for framework_type, patterns in self.namespace_patterns.items():
                score = 0.0
                
                for pattern in patterns:
                    if re.search(pattern, package_name, re.IGNORECASE):
                        score = max(score, 0.8)  # High confidence for namespace match
                        break
                
                framework_scores[framework_type.value] = score
            
            logger.info(f"Framework detection from namespace: {framework_scores}")
            return framework_scores
            
        except Exception as e:
            logger.error(f"Error detecting framework from namespace: {e}")
            return {}

    async def get_framework_recommendations(
        self,
        vulnerability_data: dict[str, any],
        package_info: dict[str, any],
        constraints: dict[str, any] | None = None
    ) -> list[tuple[FrameworkType, float, str]]:
        """
        Get ranked framework recommendations for a vulnerability.
        
        Args:
            vulnerability_data: Vulnerability information
            package_info: Package information
            constraints: Optional constraints (performance, security, etc.)
            
        Returns:
            list of tuples (framework_type, confidence_score, rationale)
        """
        try:
            # Analyze framework capabilities
            capabilities = await self.analyze_framework_requirements(vulnerability_data, package_info)
            
            recommendations = []
            
            for framework_type, capability in capabilities.items():
                # Calculate overall score
                suitability_scores = {
                    FrameworkSuitability.EXCELLENT: 1.0,
                    FrameworkSuitability.GOOD: 0.8,
                    FrameworkSuitability.FAIR: 0.6,
                    FrameworkSuitability.POOR: 0.4,
                    FrameworkSuitability.INCOMPATIBLE: 0.1,
                }
                
                complexity_penalties = {
                    "simple": 0.0,
                    "moderate": 0.1,
                    "complex": 0.2,
                    "advanced": 0.3,
                }
                
                base_score = suitability_scores.get(capability.suitability, 0.5)
                complexity_penalty = complexity_penalties.get(capability.adaptation_complexity, 0.1)
                
                overall_score = max(0.0, base_score - complexity_penalty)
                
                # Apply constraints if provided
                if constraints:
                    if constraints.get("prefer_performance") and capability.performance_impact in ["low", "minimal"]:
                        overall_score += 0.1
                    if constraints.get("prefer_simplicity") and capability.adaptation_complexity == "simple":
                        overall_score += 0.1
                
                # Generate rationale
                rationale = f"Suitability: {capability.suitability.value}, Complexity: {capability.adaptation_complexity}"
                if capability.required_dependencies:
                    rationale += f", Dependencies: {len(capability.required_dependencies)}"
                
                recommendations.append((framework_type, overall_score, rationale))
            
            # Sort by score descending
            recommendations.sort(key=lambda x: x[1], reverse=True)
            
            logger.info(f"Generated {len(recommendations)} framework recommendations")
            return recommendations
            
        except Exception as e:
            logger.error(f"Error getting framework recommendations: {e}")
            return [(FrameworkType.SPRING_BOOT, 0.7, "Fallback Spring Boot web application for error recovery")]

    async def validate_framework_choice(
        self,
        framework_type: FrameworkType,
        vulnerability_data: dict[str, any],
        package_info: dict[str, any]
    ) -> dict[str, any]:
        """
        Validate a framework choice for a specific vulnerability.
        
        Args:
            framework_type: Chosen framework type
            vulnerability_data: Vulnerability information
            package_info: Package information
            
        Returns:
            Validation result with success status, warnings, and recommendations
        """
        try:
            validation_result = {
                "valid": True,
                "confidence": 0.5,
                "warnings": [],
                "recommendations": [],
                "compatibility_issues": [],
            }
            
            # Get capability analysis for the chosen framework
            capability = await self._analyze_framework_capability(
                framework_type, vulnerability_data, package_info
            )
            
            # Validate suitability
            if capability.suitability == FrameworkSuitability.INCOMPATIBLE:
                validation_result["valid"] = False
                validation_result["warnings"].append(
                    f"{framework_type.value} is incompatible with {vulnerability_data.get('vulnerability_type', 'this vulnerability')}"
                )
            elif capability.suitability == FrameworkSuitability.POOR:
                validation_result["warnings"].append(
                    f"{framework_type.value} is poorly suited for {vulnerability_data.get('vulnerability_type', 'this vulnerability')}"
                )
            
            # Validate complexity
            if capability.adaptation_complexity == "advanced":
                validation_result["warnings"].append(
                    f"High complexity adaptation required for {framework_type.value}"
                )
            
            # Check for specific compatibility issues
            package_name = vulnerability_data.get("package_name", "")
            if "spring" in package_name.lower() and framework_type == FrameworkType.APACHE_STRUTS:
                validation_result["compatibility_issues"].append(
                    "Spring-specific package may not integrate well with Struts framework"
                )
            
            # Set confidence based on suitability
            confidence_map = {
                FrameworkSuitability.EXCELLENT: 0.9,
                FrameworkSuitability.GOOD: 0.8,
                FrameworkSuitability.FAIR: 0.6,
                FrameworkSuitability.POOR: 0.4,
                FrameworkSuitability.INCOMPATIBLE: 0.1,
            }
            validation_result["confidence"] = confidence_map.get(capability.suitability, 0.5)
            
            # Add recommendations if needed
            if validation_result["confidence"] < 0.7:
                alternatives = await self.get_framework_recommendations(vulnerability_data, package_info)
                if alternatives and alternatives[0][1] > validation_result["confidence"]:
                    validation_result["recommendations"].append(
                        f"Consider {alternatives[0][0].value} instead (confidence: {alternatives[0][1]:.2f})"
                    )
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating framework choice: {e}")
            return {
                "valid": False,
                "confidence": 0.0,
                "warnings": [f"Validation error: {str(e)}"],
                "recommendations": [],
                "compatibility_issues": [],
            }

    def _load_namespace_patterns(self) -> dict[FrameworkType, list[str]]:
        """Load namespace patterns for framework detection."""
        return {
            FrameworkType.SPRING_BOOT: [r"org\.springframework", r"spring-boot"],
            FrameworkType.APACHE_STRUTS: [r"org\.apache\.struts", r"struts2"],
            FrameworkType.MICRONAUT: [r"io\.micronaut"],
            FrameworkType.QUARKUS: [r"io\.quarkus"],
        }

    def _load_vulnerability_associations(self) -> dict[str, list[FrameworkType]]:
        """Load vulnerability type to framework associations."""
        return {
            "deserialization": [FrameworkType.SPRING_BOOT, FrameworkType.APACHE_STRUTS],
            "rce": [FrameworkType.SPRING_BOOT, FrameworkType.APACHE_STRUTS],
            "file upload": [FrameworkType.APACHE_STRUTS, FrameworkType.SPRING_BOOT],
            "path traversal": [FrameworkType.SPRING_BOOT, FrameworkType.APACHE_STRUTS],
        }

    def _load_classification_rules(self) -> dict[str, any]:
        """Load vulnerability classification rules from configuration."""
        try:
            config_path = Path(PROJECT_ROOT) / "src" / "config" / "vulnerability_classification.yaml"

            if not config_path.exists():
                logger.warning(f"Classification config not found: {config_path}")
                return self._get_fallback_classification_rules()

            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            logger.info("Loaded vulnerability classification rules")
            return config

        except Exception as e:
            logger.error(f"Error loading classification rules: {e}")
            return self._get_fallback_classification_rules()

    def _load_framework_packages(self) -> dict[str, any]:
        """Load framework packages config for application_library guard."""
        try:
            config_path = Path(PROJECT_ROOT) / "src" / "config" / "framework_packages.yaml"
            if not config_path.exists():
                logger.warning(f"Framework packages config not found: {config_path}")
                return {}
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Error loading framework packages: {e}")
            return {}

    def _get_fallback_classification_rules(self) -> dict[str, any]:
        """Fallback classification rules if config file cannot be loaded."""
        return {
            "classification_rules": {
                "protocol_level_indicators": [
                    "remoting protocol", "HTTP/2", "WebSocket upgrade", "connection leak"
                ],
                "framework_internal_indicators": [
                    "interceptor", "filter chain", "parameter binding", "request processing"
                ],
                "application_level_indicators": [
                    "endpoint", "controller", "user input", "deserialization"
                ],
            },
            "protocol_requirements": {},
            "thresholds": {
                "protocol_level_min_matches": 1,
                "framework_internal_min_matches": 2,
                "default_classification": "application_level",
            }
        }

    def classify_vulnerability(
        self,
        cve_description: str,
        github_context: dict[str, any] | None = None,
        package_name: str | None = None
    ) -> tuple[VulnerabilityLevel, str | None, str | None, str | None]:
        """
        Classify vulnerability based on its mechanism and demonstrability.

        Args:
            cve_description: CVE description text
            github_context: Optional GitHub context with fix commits and issues
            package_name: Optional package name (group:artifact) to guard against
                          false positives — application libraries skip protocol detection

        Returns:
            tuple of (vulnerability_level, template_name, framework_config, protocol_type)
        """
        try:
            rules = self.classification_rules.get("classification_rules", {})
            protocol_reqs = self.classification_rules.get("protocol_requirements", {})
            thresholds = self.classification_rules.get("thresholds", {})

            # Combine description with GitHub context for better analysis
            full_text = cve_description.lower()
            if github_context:
                # github_context is a GitHubContextResult dataclass, not a dict
                issues = getattr(github_context, "github_issues", [])
                for issue in issues:
                    full_text += " " + issue.get("body", "").lower()

            # Guard: application libraries should never be classified as PROTOCOL_LEVEL.
            # e.g. jackson-databind mentions "serialization" but is not a Kafka library.
            is_application_library = False
            if package_name:
                app_lib_packages = self.framework_packages.get("application_library_packages", [])
                for lib_entry in app_lib_packages:
                    # lib_entry is "group:artifact" — match if package_name contains it
                    if package_name in lib_entry or lib_entry in package_name:
                        is_application_library = True
                        break

            if is_application_library:
                logger.info(
                    f"Package '{package_name}' is an application library — "
                    f"skipping protocol classification"
                )
            else:
                # Check protocol-level indicators
                protocol_indicators = rules.get("protocol_level_indicators", [])
                protocol_matches = sum(
                    1 for indicator in protocol_indicators
                    if indicator.lower() in full_text
                )

                # Check for specific protocol requirements
                detected_protocol = None
                detected_template = None
                detected_framework_config = None

                for protocol_name, protocol_info in protocol_reqs.items():
                    keywords = protocol_info.get("keywords", [])
                    for keyword in keywords:
                        if keyword.lower() in full_text:
                            detected_protocol = protocol_name
                            detected_template = protocol_info.get("template")
                            detected_framework_config = protocol_info.get("framework_config")
                            break
                    if detected_protocol:
                        break

                # If protocol detected, classify as PROTOCOL_LEVEL
                min_protocol_matches = thresholds.get("protocol_level_min_matches", 2)
                if protocol_matches >= min_protocol_matches or detected_protocol:
                    logger.info(
                        f"Classified as PROTOCOL_LEVEL: {protocol_matches} indicators, "
                        f"protocol={detected_protocol}"
                    )
                    return (
                        VulnerabilityLevel.PROTOCOL_LEVEL,
                        detected_template,
                        detected_framework_config,
                        detected_protocol
                    )

            # Check framework-internal indicators
            internal_indicators = rules.get("framework_internal_indicators", [])
            internal_matches = sum(
                1 for indicator in internal_indicators
                if indicator.lower() in full_text
            )

            min_internal_matches = thresholds.get("framework_internal_min_matches", 2)
            if internal_matches >= min_internal_matches:
                logger.info(
                    f"Classified as FRAMEWORK_INTERNAL: {internal_matches} indicators"
                )
                return (VulnerabilityLevel.FRAMEWORK_INTERNAL, None, None, None)

            # Default to APPLICATION_LEVEL
            logger.info("Classified as APPLICATION_LEVEL (default)")
            return (VulnerabilityLevel.APPLICATION_LEVEL, None, None, None)

        except Exception as e:
            logger.error(f"Error classifying vulnerability: {e}")
            return (VulnerabilityLevel.APPLICATION_LEVEL, None, None, None)