import logging
import time

import yaml

from models.framework_adaptation import (
    FRAMEWORK_CONFIGURATIONS,
    VULNERABILITY_FRAMEWORK_SUITABILITY,
    AdaptationContext,
    AdaptationResult,
    AdaptationStrategy,
    CodeAdaptation,
    FrameworkChoice,
)
from shared.constants import PROJECT_ROOT
from shared.interfaces import LLMServiceInterface
from shared.types import FrameworkType
from utils.error_handling.decorators import with_error_recovery, with_retry, with_timeout

logger = logging.getLogger(__name__)


class FrameworkAdaptationService:
    """
    Service for LLM-driven framework adaptation and selection.
    
    This service orchestrates the process of:
    1. Analyzing vulnerability requirements
    2. Selecting optimal framework via LLM
    3. Adapting code to the selected framework
    4. Validating adaptation results
    """

    def __init__(
        self,
        llm_service: LLMServiceInterface,
    ):
        """
        Initialize the Framework Adaptation Service.
        
        Args:
            llm_service: LLM service for intelligent adaptation
        """
        self.llm_service = llm_service
        self.config = self._load_framework_config()
        
        logger.info("Framework Adaptation Service initialized")
    
    def _load_framework_config(self) -> dict[str, any]:
        """Load framework adaptation configuration from YAML file."""
        try:
            config_path = PROJECT_ROOT / "src" / "config" / "framework_adaptation.yaml"
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info("Framework adaptation configuration loaded successfully")
            return config
        except Exception as e:
            logger.error(f"Failed to load framework adaptation config: {e}")
            logger.warning("Using minimal fallback configuration")
            return {
                "frameworks": {
                    "spring_boot": {
                        "vulnerability_suitability": {
                            "web_vulnerability": "excellent",
                            "deserialization": "excellent", 
                            "injection": "excellent",
                            "library_vulnerability": "good"
                        }
                    }
                }
            }


    @with_timeout(timeout_seconds=300)  # 5 minutes for framework adaptation
    @with_retry(max_attempts=2, delay=5)
    async def analyze_and_adapt(self, context: AdaptationContext) -> AdaptationResult:
        """
        Analyze vulnerability requirements and perform framework adaptation.
        
        This is the main entry point for framework adaptation. It:
        1. Analyzes the vulnerability and package requirements
        2. Selects the optimal framework using LLM intelligence
        3. Adapts the code to the selected framework
        4. Validates the adaptation results
        
        Args:
            context: Adaptation context with vulnerability and package information
            
        Returns:
            Complete adaptation result with framework choice and adapted code
        """
        start_time = time.time()
        result = AdaptationResult(context=context)
        
        logger.info(f"Starting framework adaptation for {context.package_name}")
        
        #Select optimal framework using LLM
        framework_choice = await self._select_optimal_framework(context)
        result.framework_choice = framework_choice
        
        #Adapt code to selected framework if needed
        if self._requires_code_adaptation(context, framework_choice):
            logger.info(f"Code adaptation required. Required changes: {framework_choice.required_changes}")
            code_adaptation = await self._adapt_code_to_framework(context, framework_choice)
            result.code_adaptation = code_adaptation

            if code_adaptation is None:
                logger.error("Code adaptation returned None - likely missing code snippets or no adaptable code found")
                result.add_error("Code adaptation failed - no code returned")
                return result

            if code_adaptation.validation_status == "failed":
                logger.error(f"Code adaptation validation failed: {code_adaptation.validation_errors}")
                result.add_error(f"Code adaptation validation failed: {code_adaptation.validation_errors}")
                return result

            logger.info(f"Code adaptation succeeded: {len(code_adaptation.changes_made)} changes made")
        else:
            logger.info("Code adaptation not required - skipping")
        
        #Generate framework-specific configuration
        deployment_config = self._generate_deployment_configuration(framework_choice)
        result.deployment_configuration = deployment_config
        
        #Validate the complete adaptation
        validation_results = self._validate_adaptation(result)
        result.validation_results = validation_results
        
        if validation_results.get("success", True):
            result.mark_success()
        else:
            result.add_error("Adaptation validation failed")
        
        # Record timing
        adaptation_time = time.time() - start_time
        result.adaptation_time_seconds = adaptation_time
        
        logger.info(f"Framework adaptation completed: {framework_choice.selected_framework.value} "
                   f"(success: {result.success}) in {adaptation_time:.2f}s")
        
        return result

    @with_timeout(timeout_seconds=120)
    @with_retry(max_attempts=2, delay=3)
    async def _select_optimal_framework(self, context: AdaptationContext) -> FrameworkChoice:
        """
        Select the optimal framework for the given vulnerability context.
        
        Args:
            context: Adaptation context
            
        Returns:
            Framework choice with rationale and confidence score
        """
        # Prepare context for LLM
        llm_context = {
                "package_name": context.package_name,
                "package_version": context.package_version,
                "cve_ids": context.cve_ids,
                "vulnerability_type": context.vulnerability_type,
                "vulnerability_description": context.vulnerability_description,
            }
            
        # Get LLM recommendation
        llm_response = await self.llm_service.select_optimal_framework(llm_context)
        
        # Parse LLM response into FrameworkChoice
        framework_choice = self._parse_framework_choice(llm_response, context)
        
        # Apply rules and validation
        framework_choice = self._validate_and_refine_choice(framework_choice, context)
        
        logger.info(f"Selected framework: {framework_choice.selected_framework.value} "
                    f"(confidence: {framework_choice.confidence_score})")
        
        return framework_choice

    def _parse_framework_choice(self, llm_response: dict[str, any], context: AdaptationContext) -> FrameworkChoice:
        """Parse LLM response into FrameworkChoice object."""
        try:
            selected_framework_str = llm_response.get("selected_framework", "SPRING_BOOT")
            selected_framework = self._map_framework_string(selected_framework_str)
            
            # Parse adaptation strategy
            strategy_str = llm_response.get("adaptation_strategy", "wrap_standalone")
            adaptation_strategy = AdaptationStrategy(strategy_str)
            
            return FrameworkChoice(
                selected_framework=selected_framework,
                confidence_score=float(llm_response.get("confidence_score", 0.5)),
                rationale=llm_response.get("rationale", "LLM-driven selection"),
                alternative_frameworks=[
                    FrameworkType(alt["framework"].lower()) 
                    for alt in llm_response.get("alternative_frameworks", [])
                    if self._is_valid_framework(alt.get("framework", ""))
                ],
                vulnerability_analysis=llm_response.get("vulnerability_analysis", {}),
                package_analysis=llm_response.get("package_analysis", {}),
                adaptation_strategy=adaptation_strategy,
                required_changes=llm_response.get("required_changes", []),
                llm_metadata=llm_response,
            )
            
        except (ValueError, KeyError) as e:
            logger.warning(f"Error parsing LLM framework choice: {e}")
            fallback_choice = self._fallback_framework_selection(context)
            if fallback_choice is None:
                logger.error("Configuration-driven framework fallback also failed")
                raise RuntimeError(f"Unable to parse or fallback framework selection for: {context.vulnerability_type}")
            return fallback_choice

    def _map_framework_string(self, framework_str: str) -> FrameworkType:
        """Map LLM framework string to FrameworkType enum with robust handling."""
        # Create mapping from various formats to enum values
        framework_mapping = {
            # Uppercase variants (from LLM responses)
            "SPRING_BOOT": FrameworkType.SPRING_BOOT,
            "APACHE_STRUTS": FrameworkType.APACHE_STRUTS,
            "MICRONAUT": FrameworkType.MICRONAUT,
            "QUARKUS": FrameworkType.QUARKUS,
            "WEB_APPLICATION": FrameworkType.WEB_APPLICATION,
            
            # Lowercase variants (for compatibility)
            "spring_boot": FrameworkType.SPRING_BOOT,
            "apache_struts": FrameworkType.APACHE_STRUTS,
            "micronaut": FrameworkType.MICRONAUT,
            "quarkus": FrameworkType.QUARKUS,
            "web_application": FrameworkType.WEB_APPLICATION,
            
            # Mixed case and alternative names
            "SpringBoot": FrameworkType.SPRING_BOOT,
            "Struts": FrameworkType.APACHE_STRUTS,
            "struts": FrameworkType.APACHE_STRUTS,
        }
        
        # Try direct mapping first
        if framework_str in framework_mapping:
            return framework_mapping[framework_str]
        
        # Try case-insensitive mapping
        framework_str_normalized = framework_str.upper()
        if framework_str_normalized in framework_mapping:
            return framework_mapping[framework_str_normalized]
            
        # Fallback to Spring Boot web application
        logger.warning(f"Unknown framework string '{framework_str}', defaulting to SPRING_BOOT")
        return FrameworkType.SPRING_BOOT

    def _is_valid_framework(self, framework_str: str) -> bool:
        """Check if framework string is valid."""
        try:
            FrameworkType(framework_str.lower())
            return True
        except ValueError:
            return False

    def _validate_and_refine_choice(self, choice: FrameworkChoice, context: AdaptationContext) -> FrameworkChoice:
        """Validate and refine the framework choice with business rules."""
        
        # Check framework preferences and exclusions
        if context.framework_preferences and choice.selected_framework not in context.framework_preferences:
            choice.rationale += " (Not in preferred frameworks)"
        
        if context.framework_exclusions and choice.selected_framework in context.framework_exclusions:
            # Find alternative framework
            for alt_framework in choice.alternative_frameworks:
                if alt_framework not in context.framework_exclusions:
                    choice.selected_framework = alt_framework
                    choice.rationale += f" (Original choice excluded, using {alt_framework.value})"
                    break
        
        # Apply vulnerability-framework suitability rules for validation
        vuln_type = self._categorize_vulnerability_type(context.vulnerability_type)
        if vuln_type in VULNERABILITY_FRAMEWORK_SUITABILITY:
            suitability_map = VULNERABILITY_FRAMEWORK_SUITABILITY[vuln_type]
            if choice.selected_framework in suitability_map:
                suitability = suitability_map[choice.selected_framework]
                choice.rationale += f" (Suitability: {suitability.value})"
        
        return choice

    def _categorize_vulnerability_type(self, vulnerability_type: str) -> str:
        """Categorize vulnerability type for suitability mapping."""
        vuln_type_lower = vulnerability_type.lower()
        
        if any(term in vuln_type_lower for term in ["deserial", "pickle", "marshal"]):
            return "deserialization"
        elif any(term in vuln_type_lower for term in ["web", "http", "xss", "csrf"]):
            return "web_vulnerability"
        elif any(term in vuln_type_lower for term in ["inject", "sql", "command", "ldap"]):
            return "injection"
        elif any(term in vuln_type_lower for term in ["library", "jar", "dependency"]):
            return "library_vulnerability"
        else:
            return "other"

    def _fallback_framework_selection(self, context: AdaptationContext) -> FrameworkChoice | None:
        """Configuration-driven fallback framework selection."""
        logger.warning("LLM framework selection failed, using configuration-driven fallback")
        
        vuln_type = self._categorize_vulnerability_type(context.vulnerability_type)
        
        # Load framework configurations and find best match for vulnerability type
        try:
            framework_configs = self.config.get("frameworks", {})
            best_framework = None
            best_score = 0
            
            # Score frameworks based on vulnerability suitability
            for framework_key, config in framework_configs.items():
                suitability = config.get("vulnerability_suitability", {})
                score_text = suitability.get(vuln_type, "poor")
                
                # Convert suitability text to numeric score
                score_map = {"excellent": 4, "good": 3, "fair": 2, "poor": 1}
                score = score_map.get(score_text, 1)
                
                if score > best_score:
                    best_score = score
                    best_framework = framework_key
            
            if not best_framework:
                logger.error(f"No suitable framework found for vulnerability type: {vuln_type}")
                return None
                
            # Map framework key to FrameworkType enum
            framework_mapping = {
                "spring_boot": FrameworkType.SPRING_BOOT,
                "apache_struts": FrameworkType.APACHE_STRUTS,
                "micronaut": FrameworkType.MICRONAUT,
                "quarkus": FrameworkType.QUARKUS,
                "standalone_jar": FrameworkType.STANDALONE_JAR
            }
            
            selected_framework = framework_mapping.get(best_framework, FrameworkType.SPRING_BOOT)
            
            return FrameworkChoice(
                selected_framework=selected_framework,
                confidence_score=0.7,  # Lower confidence for fallback
                rationale=f"Configuration-driven selection: {best_framework} has '{framework_configs[best_framework]['vulnerability_suitability'].get(vuln_type, 'unknown')}' suitability for {vuln_type}",
                adaptation_strategy=AdaptationStrategy.WRAP_STANDALONE,
            )
            
        except Exception as e:
            logger.error(f"Configuration-driven framework selection failed: {e}")
            logger.error("Falling back to error state - framework selection unavailable")
            return None

    def _requires_code_adaptation(self, context: AdaptationContext, choice: FrameworkChoice) -> bool:
        """Determine if code adaptation is required."""
        # All frameworks now require web application structure - adaptation always needed for HTTP endpoints
        # Check if specific adaptation requirements exist
        if not choice.required_changes:
            return False
        
        # If we're switching frameworks or have specific adaptation requirements
        return True

    @with_timeout(timeout_seconds=240)  # 4 minutes for code adaptation
    @with_error_recovery(context="adapt_code_to_framework")
    async def _adapt_code_to_framework(
        self, context: AdaptationContext, choice: FrameworkChoice
    ) -> CodeAdaptation | None:
        """
        Adapt code to the selected framework.
        
        Args:
            context: Adaptation context
            choice: Framework choice with adaptation requirements
            
        Returns:
            Code adaptation result or None if adaptation not needed
        """
        # Extract code from blueprint code snippets
        code_snippets = context.additional_context.get("code_snippets", {})

        logger.info(f"Code snippets available: {list(code_snippets.keys()) if code_snippets else 'None'}")

        if not code_snippets:
            logger.warning("No code snippets provided for adaptation - cannot adapt code")
            return None

        # Combine all code snippets for adaptation
        original_code = ""
        for filename, content in code_snippets.items():
            if filename.endswith(('.java', '.py', '.js', '.ts')):
                original_code += f"// File: {filename}\n{content}\n\n"
                logger.debug(f"Added code from {filename} ({len(content)} chars)")

        if not original_code.strip():
            logger.warning(f"No adaptable code content found in {len(code_snippets)} code snippets")
            return None
        
        # Extract GitHub context from additional_context
        github_context = context.additional_context.get("github_context", "")

        # Prepare adaptation request for LLM
        adaptation_request = {
            "source_framework": "WEB_APPLICATION",  # Starting from web application template
            "target_framework": choice.selected_framework.value.upper(),
            "package_name": context.package_name,
            "package_version": context.package_version,
            "vulnerability_type": context.vulnerability_type,
            "adaptation_strategy": choice.adaptation_strategy.value,
            "original_code": original_code,
            "github_context": github_context,
        }
        
        # Get LLM adaptation
        adaptation_response = await self.llm_service.adapt_code_to_framework(adaptation_request)
        
        # Extract validation errors with proper handling
        error_response = adaptation_response.get("error")
        if isinstance(error_response, list):
            validation_errors = error_response
        elif error_response:
            validation_errors = [error_response]
        else:
            validation_errors = []

        # Enhanced dependency extraction with fallback using safe extraction
        from utils.core.llm_response_parser import LLMResponseParser
        
        dependencies_added = adaptation_response.get("dependencies_added", [])
        if not dependencies_added:
            logger.info("DEPENDENCY FALLBACK: LLM response had empty dependencies_added, trying safe enhanced extraction")
            
            # Get the raw LLM response and try dependency-specific extraction
            llm_metadata = getattr(adaptation_response, '_raw_response', None)
            if isinstance(llm_metadata, str):
                dependencies_added = LLMResponseParser.safe_extract_dependencies(
                    llm_metadata, 
                    f"code_adaptation_{context.package_name}"
                )
                logger.info(f"DEPENDENCY FALLBACK: Extracted {len(dependencies_added)} dependencies via safe parser")
            else:
                logger.warning("DEPENDENCY FALLBACK: No raw response available for enhanced extraction")
        else:
            # Validate existing dependencies using safe methods
            validated_deps = LLMResponseParser._validate_dependencies(dependencies_added)
            if len(validated_deps) != len(dependencies_added):
                logger.warning(f"DEPENDENCY VALIDATION: {len(dependencies_added) - len(validated_deps)} invalid dependencies filtered out")
                dependencies_added = validated_deps
            
            logger.info(f"DEPENDENCY EXTRACTION: Found {len(dependencies_added)} valid dependencies in LLM response")
        
        # Create CodeAdaptation object
        code_adaptation = CodeAdaptation(
            original_code=original_code,
            adapted_code=adaptation_response.get("adapted_code", original_code),
            source_framework=FrameworkType.WEB_APPLICATION,
            target_framework=choice.selected_framework,
            adaptation_strategy=choice.adaptation_strategy,
            changes_made=adaptation_response.get("changes_made", []),
            dependencies_added=dependencies_added,
            configuration_files=adaptation_response.get("configuration_files", {}),
            endpoint_metadata=adaptation_response.get("endpoint_metadata", []),
            imports_modified=adaptation_response.get("imports_modified", False),
            package_structure_changed=adaptation_response.get("package_structure_changed", False),
            framework_specific_features=adaptation_response.get("framework_specific_features", []),
            adaptation_notes=adaptation_response.get("adaptation_notes", ""),
            validation_status="success" if adaptation_response.get("adaptation_success", True) else "failed",
            validation_errors=validation_errors,
        )
        
        logger.info(f"Code adaptation completed: {len(code_adaptation.changes_made)} changes made")

        # Add automatic dependency detection as fallback
        detected_dependencies = self._detect_missing_dependencies(code_adaptation.adapted_code, choice.selected_framework)
        
        # Merge LLM dependencies with detected dependencies
        original_count = len(code_adaptation.dependencies_added)
        code_adaptation.dependencies_added = self._merge_dependencies(
            code_adaptation.dependencies_added, 
            detected_dependencies
        )
        #added_count = len(code_adaptation.dependencies_added) - original_count
        
        logger.info("=" * 80)
        logger.info("DEPENDENCY DECISION AUDIT")
        logger.info("=" * 80)
        logger.info(f"Package: {context.package_name} v{context.package_version}")
        logger.info(f"Framework: {choice.selected_framework.value}")
        logger.info(f"LLM suggested {original_count} dependencies")
        logger.info(f"Auto-detected {len(detected_dependencies)} additional dependencies")
        logger.info(f"Total dependencies: {len(code_adaptation.dependencies_added)}")

        # Check for forbidden dependencies
        forbidden_patterns = ["commons-fileupload", "commons-io"]
        for i, dep in enumerate(code_adaptation.dependencies_added):
            group_id = dep.get('group_id', '')
            artifact_id = dep.get('artifact_id', '')
            version = dep.get('version', 'NOT PROVIDED')
            dep_key = f"{group_id}:{artifact_id}"

            # Flag forbidden dependencies
            is_forbidden = any(pattern in dep_key.lower() for pattern in forbidden_patterns)
            is_detected = i >= original_count
            flag = ""
            if is_forbidden:
                flag += " FORBIDDEN"
            if is_detected:
                flag += " AUTO-DETECTED"

            logger.info(f"  - {dep_key} (version: {version}){flag}")

            if is_forbidden:
                logger.warning(f"WARNING: {artifact_id} may be a transitive dependency")
                logger.warning("LLM added this despite 'NO EXTERNAL DEPS' constraint in prompt")
                logger.warning("Check if this causes version conflicts at runtime")

        if not code_adaptation.dependencies_added:
            logger.info("  (No dependencies added)")

        logger.info(f"Adaptation notes: {code_adaptation.adaptation_notes[:200] if code_adaptation.adaptation_notes else 'None'}")
        logger.info("=" * 80)

        return code_adaptation

    def _generate_deployment_configuration(self, choice: FrameworkChoice) -> dict[str, any]:
        """Generate framework-specific deployment configuration."""
        framework_config = FRAMEWORK_CONFIGURATIONS.get(choice.selected_framework, {})
        
        return {
            "framework_type": choice.selected_framework.value,
            "required_dependencies": framework_config.get("required_dependencies", []),
            "main_class_pattern": framework_config.get("main_class_pattern", "VulnerableDemo"),
            "default_port": framework_config.get("default_port", 8080),
            "configuration_files": framework_config.get("configuration_files", []),
            "framework_features": framework_config.get("framework_features", []),
            "package_structure": framework_config.get("package_structure", "src/main/java"),
        }

    def _validate_adaptation(self, result: AdaptationResult) -> dict[str, any]:
        """Validate the complete adaptation result."""
        validation_results = {
            "success": True,
            "checks": [],
            "warnings": [],
            "errors": [],
        }
        
        try:
            # Validate framework choice
            validation_results["checks"].append("Framework selection validated")
            
            # Validate code adaptation if present
            if result.code_adaptation:
                if not result.code_adaptation.adapted_code.strip():
                    validation_results["errors"].append("Adapted code is empty")
                    validation_results["success"] = False
                
                if result.code_adaptation.validation_status == "failed":
                    validation_results["errors"].append("Code adaptation validation failed")
                    validation_results["success"] = False
            
            # Validate deployment configuration
            if not result.deployment_configuration:
                validation_results["warnings"].append("No deployment configuration generated")
            
            validation_results["checks"].append("Framework selection validated")
            if result.code_adaptation:
                validation_results["checks"].append("Code adaptation validated")
            validation_results["checks"].append("Deployment configuration validated")
            
        except Exception as e:
            validation_results["errors"].append(f"Validation error: {str(e)}")
            validation_results["success"] = False
        
        return validation_results

    def _detect_missing_dependencies(self, adapted_code: str, framework: FrameworkType) -> list[dict]:
        """
        Automatically detect missing dependencies by analyzing code imports and patterns.
        
        This serves as a fallback when LLM doesn't properly extract dependencies.
        
        Args:
            adapted_code: The generated code to analyze
            framework: Target framework type
            
        Returns:
            List of dependency dictionaries with group_id and artifact_id
        """
        dependencies = []
        
        # Spring Security patterns
        security_patterns = [
            'import org.springframework.security',
            '@EnableWebSecurity',
            'SecurityFilterChain',
            'HttpSecurity',
            'WebSecurityConfigurerAdapter',
            'AuthenticationManager',
            'UserDetailsService'
        ]
        
        # Spring Boot Actuator patterns  
        actuator_patterns = [
            'import org.springframework.boot.actuator',
            '@Endpoint',
            'HealthIndicator',
            'InfoContributor'
        ]
        
        # WebSocket patterns
        websocket_patterns = [
            'import org.springframework.web.socket',
            'import javax.websocket',
            '@ServerEndpoint',
            'WebSocketHandler',
            'SimpMessageSendingOperations'
        ]
        
        # Jackson patterns (JSON processing)
        jackson_patterns = [
            'import com.fasterxml.jackson',
            'ObjectMapper',
            'JsonNode',
            '@JsonProperty'
        ]
        
        # File upload patterns (be careful - might be transitive)
        fileupload_patterns = [
            'import org.apache.commons.fileupload',
            'FileUpload',
            'DiskFileItemFactory',
            'ServletFileUpload'
        ]
        
        # Struts convention plugin patterns
        struts_convention_patterns = [
            '@Action',
            '@Result',
            '@Namespace',
            'import org.apache.struts2.convention'
        ]
        
        logger.info(f"DEPENDENCY DETECTION: Analyzing {len(adapted_code)} characters of code")
        
        # Check Spring Security
        if any(pattern in adapted_code for pattern in security_patterns):
            dependencies.append({
                'group_id': 'org.springframework.boot',
                'artifact_id': 'spring-boot-starter-security'
            })
            logger.info("DEPENDENCY DETECTION: Found Spring Security imports - adding spring-boot-starter-security")
        
        # Check Actuator
        if any(pattern in adapted_code for pattern in actuator_patterns):
            dependencies.append({
                'group_id': 'org.springframework.boot', 
                'artifact_id': 'spring-boot-starter-actuator'
            })
            logger.info("DEPENDENCY DETECTION: Found Actuator imports - adding spring-boot-starter-actuator")
        
        # Check WebSocket
        if any(pattern in adapted_code for pattern in websocket_patterns):
            dependencies.append({
                'group_id': 'org.springframework.boot',
                'artifact_id': 'spring-boot-starter-websocket'
            })
            logger.info("DEPENDENCY DETECTION: Found WebSocket imports - adding spring-boot-starter-websocket")
        
        # Check Jackson (but only if not using Spring Boot Web which includes it)
        if any(pattern in adapted_code for pattern in jackson_patterns):
            # Only add if we're not using spring-boot-starter-web (which includes Jackson)
            if framework != FrameworkType.SPRING_BOOT:
                dependencies.append({
                    'group_id': 'com.fasterxml.jackson.core',
                    'artifact_id': 'jackson-databind'
                })
                logger.info("DEPENDENCY DETECTION: Found Jackson imports (non-Spring Boot) - adding jackson-databind")
            else:
                logger.info("DEPENDENCY DETECTION: Found Jackson imports but Spring Boot includes this transitively")
        
        # Check Struts Convention Plugin (only for Struts 2.1+)
        if framework == FrameworkType.APACHE_STRUTS and any(pattern in adapted_code for pattern in struts_convention_patterns):
            dependencies.append({
                'group_id': 'org.apache.struts',
                'artifact_id': 'struts2-convention-plugin'  
            })
            logger.info("DEPENDENCY DETECTION: Found Struts @Action annotations - adding struts2-convention-plugin")
        
        # File upload: Only add if using non-framework file upload (risky)
        if any(pattern in adapted_code for pattern in fileupload_patterns):
            logger.warning("DEPENDENCY DETECTION: Found commons-fileupload imports - this might conflict with framework transitive deps")
            logger.warning("DEPENDENCY DETECTION: NOT auto-adding commons-fileupload to avoid version conflicts")
            # Intentionally NOT adding commons-fileupload as it's usually transitive
        
        logger.info(f"DEPENDENCY DETECTION: Auto-detected {len(dependencies)} dependencies")
        return dependencies

    def _merge_dependencies(self, llm_deps: list[dict], detected_deps: list[dict]) -> list[dict]:
        """
        Merge LLM-provided dependencies with auto-detected dependencies.
        
        Avoids duplicates by checking group_id:artifact_id combinations.
        
        Args:
            llm_deps: Dependencies provided by LLM
            detected_deps: Dependencies detected from code analysis
            
        Returns:
            Merged list without duplicates
        """
        merged = list(llm_deps)  # Start with LLM dependencies
        
        # Track existing dependencies to avoid duplicates
        existing = set()
        for dep in llm_deps:
            key = f"{dep.get('group_id', '')}:{dep.get('artifact_id', '')}"
            existing.add(key)
        
        # Add detected dependencies if not already present
        for dep in detected_deps:
            key = f"{dep.get('group_id', '')}:{dep.get('artifact_id', '')}"
            if key not in existing:
                merged.append(dep)
                existing.add(key)
                logger.info(f"DEPENDENCY MERGE: Added auto-detected dependency: {key}")
            else:
                logger.info(f"DEPENDENCY MERGE: Skipped duplicate dependency: {key}")
        
        return merged

