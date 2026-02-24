import json
import logging
import yaml
from pathlib import Path
from typing import Any, Dict, Optional

from models.validation_result import ValidationResult
from services.system.llm_service import LLMService
from shared.constants import PROJECT_ROOT
from utils.core.llm_response_parser import LLMResponseParser
from utils.core.prompt_manager import prompt_manager
from utils.error_handling.decorators import with_error_recovery, with_retry, with_timeout

logger = logging.getLogger(__name__)


class LLMValidationService:
    """
    Service for vulnerability validation using LLM analysis.
    Replaces hardcoded pattern matching with contextual understanding.
    """

    def __init__(self, llm_service: LLMService = None):
        """
        Initialize LLM validation service.

        Args:
            llm_service: LLM service instance
        """
        self.llm_service = llm_service or LLMService()

        # Load vulnerability validation contexts from configuration file
        self.vulnerability_contexts = self._load_validation_contexts()

    @with_error_recovery(context="load_validation_contexts", default_return={})
    def _load_validation_contexts(self) -> Dict[str, Any]:
        """
        Load vulnerability validation contexts from configuration file.

        Returns:
            Dictionary of vulnerability contexts for validation guidance
        """
        config_path = PROJECT_ROOT / "src" / "config" / "vulnerability_validation_contexts.yaml"

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                contexts = config.get("contexts", {})
                logger.info(f"Loaded {len(contexts)} vulnerability validation contexts from config")
                return contexts
        except Exception as e:
            logger.error(f"Failed to load vulnerability validation contexts from {config_path}: {e}")
            logger.warning("Using minimal fallback validation contexts")
            # Minimal fallback to prevent service failure
            return {
                "unknown": {
                    "description": "General vulnerability analysis when context loading failed",
                    "analysis_guidance": [
                        "Look for any evidence of unexpected application behavior",
                        "Check if the payload was processed by the application in any meaningful way",
                        "Distinguish between application-level rejections and environmental/OS-level blocks"
                    ],
                    "key_question": "Did the application's vulnerable code path execute, even if external factors prevented full exploitation?"
                }
            }

    @with_timeout(timeout_seconds=180)
    @with_retry(max_attempts=2, delay=5)
    async def validate_vulnerability_demonstration(
        self,
        vulnerability_type: str,
        cve_id: str,
        package_name: str,
        vulnerability_description: str,
        execution_results: Dict[str, Any],
        container_logs: str = ""
    ) -> ValidationResult:
        """
        Use LLM to determine if vulnerability was successfully demonstrated.

        Args:
            vulnerability_type: Type of vulnerability (e.g., "deserialization", "injection")
            cve_id: CVE identifier
            package_name: Target package name
            vulnerability_description: Description of the vulnerability
            execution_results: Dictionary containing execution results
            container_logs: Application container logs showing vulnerable application behavior

        Returns:
            ValidationResult with LLM analysis
        """
        try:
            logger.info(f"Starting LLM validation for {cve_id} ({vulnerability_type})")
            
            # Get vulnerability-specific context and key question
            context_info = self.vulnerability_contexts.get(vulnerability_type.lower(),
                                                          self.vulnerability_contexts.get("unknown", {}))
            vulnerability_context = self._get_vulnerability_context(vulnerability_type)
            key_question = context_info.get('key_question', 'Was the vulnerability mechanism triggered?')

            # Extract execution data
            http_response = execution_results.get('http_responses', [{}])[0] if execution_results.get('http_responses') else {}

            # Build prompt using PromptManager
            prompt = prompt_manager.format_prompt(
                "vulnerability_validation",
                vulnerability_type=vulnerability_type,
                cve_id=cve_id,
                package_name=package_name,
                vulnerability_description=vulnerability_description[:500] + "..." if len(vulnerability_description) > 500 else vulnerability_description,
                vulnerability_context=vulnerability_context,
                key_question=key_question,
                http_response=str(http_response.get('response_text', ''))[:1000],
                status_code=str(http_response.get('status_code', 'N/A')),
                response_body=str(http_response.get('response_text', ''))[:2000],
                stdout=execution_results.get('stdout', '')[:1000],
                stderr=execution_results.get('stderr', '')[:1000],
                exit_code=str(execution_results.get('exit_code', 'N/A')),
                container_logs=container_logs[:2000] if container_logs else "No container logs available"
            )
            
            # Call LLM
            llm_response = await self.llm_service.call_llm_async(prompt)
            
            # Parse LLM response
            validation_result = self._parse_llm_validation_response(llm_response, cve_id)
            
            logger.info(
                f"LLM Validation Result for {cve_id}: "
                f"Demonstrated={validation_result.vulnerability_demonstrated}, "
                f"Confidence={validation_result.confidence_score:.2f}"
            )
            
            return validation_result
            
        except Exception as e:
            logger.error(f"LLM validation failed for {cve_id}: {e}")
            # Return conservative result on error
            return ValidationResult(
                vulnerability_demonstrated=False,
                indicators_found=[f"LLM validation error: {str(e)}"],
                confidence_score=0.0,
                details=f"LLM validation service encountered an error: {str(e)}"
            )

    def _get_vulnerability_context(self, vulnerability_type: str) -> str:
        """
        Get context information for specific vulnerability type.
        Uses hardcoded contexts for well-known types, otherwise generates minimal context.
        """
        context_info = self.vulnerability_contexts.get(vulnerability_type.lower())

        if context_info:
            # Use pre-defined context for well-known vulnerability types
            context = f"{context_info['description']}\n\n"
            context += "Success Indicators:\n"
            # Only include first 3 guidance items to reduce tokens
            for guidance in context_info.get('analysis_guidance', [])[:3]:
                context += f"• {guidance}\n"
            return context

        # For unknown types, generate minimal generic context
        return f"Vulnerability Type: {vulnerability_type}\nLook for evidence that the vulnerable code path was executed."

    def _parse_llm_validation_response(self, llm_response: str, cve_id: str) -> ValidationResult:
        """Parse LLM response into ValidationResult with enhanced validation."""
        try:
            # Use enhanced parser with expected fields validation
            response_data = LLMResponseParser.parse_json_response(
                llm_response,
                expected_fields=["vulnerability_demonstrated", "confidence", "reasoning"],
                context=f"llm_validation_{cve_id}"
            )
            
            if response_data.get("parse_error"):
                logger.error(f"Failed to parse LLM validation response for {cve_id}: {response_data.get('error_message')}")
                return ValidationResult(
                    vulnerability_demonstrated=False,
                    confidence_score=0.0,
                    validation_details=f"Parse error: {response_data.get('error_message')}",
                    indicators_found=[]
                )
            
            # Validate required fields
            validated_data = self._validate_response_schema(response_data, cve_id)
            
            # Check if simulation was detected
            simulation_detected = validated_data.get('simulation_detected', False)
            simulation_indicators = validated_data.get('simulation_indicators', [])
            
            # If simulation detected, override the result
            if simulation_detected:
                logger.warning(f"Simulation detected for {cve_id}: {simulation_indicators}")
                details = validated_data.get('reasoning', '') + f"\nWARNING: Simulation patterns detected: {', '.join(simulation_indicators)}"
                return ValidationResult(
                    vulnerability_demonstrated=False,
                    indicators_found=simulation_indicators,
                    confidence_score=0.1,  # Very low confidence for simulations
                    details=details
                )
            
            # Build indicators list from multiple possible fields
            indicators = []
            indicators.extend(validated_data.get('evidence_found', []))
            indicators.extend(validated_data.get('indicators_detected', []))
            indicators.extend(validated_data.get('indicators_found', []))  # Alternative field name
            
            return ValidationResult(
                vulnerability_demonstrated=validated_data.get('vulnerability_demonstrated', False),
                indicators_found=indicators,
                confidence_score=float(validated_data.get('confidence_score', 0.0)),
                details=validated_data.get('reasoning', '')
            )
                
        except ValueError as e:
            logger.warning(f"Failed to parse LLM response as JSON for {cve_id}: {e}")
            return self._parse_text_response(llm_response, cve_id)
        except Exception as e:
            logger.error(f"Unexpected error parsing validation response for {cve_id}: {e}")
            # Return conservative result on unexpected error
            return ValidationResult(
                vulnerability_demonstrated=False,
                indicators_found=[f"Parsing error: {str(e)}"],
                confidence_score=0.0,
                details=f"Error parsing validation response: {str(e)}"
            )

    def _parse_text_response(self, response: str, cve_id: str) -> ValidationResult:
        """Fallback parser for non-JSON responses."""
        response_lower = response.lower()
        
        # Look for key phrases
        positive_indicators = [
            'vulnerability demonstrated', 'exploit successful', 'vulnerability confirmed',
            'exploitation successful', 'vulnerability triggered', 'attack successful'
        ]
        negative_indicators = [
            'vulnerability not demonstrated', 'exploit failed', 'no evidence',
            'exploitation failed', 'vulnerability not triggered', 'attack failed'
        ]
        
        # Calculate confidence based on indicators
        positive_count = sum(1 for indicator in positive_indicators if indicator in response_lower)
        negative_count = sum(1 for indicator in negative_indicators if indicator in response_lower)
        
        demonstrated = positive_count > negative_count
        confidence = min(0.8, (positive_count + negative_count) * 0.2) if demonstrated else 0.3
        
        return ValidationResult(
            vulnerability_demonstrated=demonstrated,
            indicators_found=[f"Text analysis: {positive_count} positive, {negative_count} negative indicators"],
            confidence_score=confidence,
            details=f"Parsed text response for {cve_id} (fallback analysis)"
        )

    def _validate_response_schema(self, response_data: dict, cve_id: str) -> dict:
        """
        Validate and standardize the response schema.
        
        Args:
            response_data: Raw response data from LLM
            cve_id: CVE identifier for logging
            
        Returns:
            Validated and standardized response data
        """
        validated = {}
        
        # Required boolean field: vulnerability_demonstrated
        vulnerability_demonstrated = response_data.get('vulnerability_demonstrated')
        if isinstance(vulnerability_demonstrated, bool):
            validated['vulnerability_demonstrated'] = vulnerability_demonstrated
        elif isinstance(vulnerability_demonstrated, str):
            validated['vulnerability_demonstrated'] = vulnerability_demonstrated.lower() in ['true', 'yes', '1']
        else:
            logger.warning(f"Invalid vulnerability_demonstrated field for {cve_id}: {vulnerability_demonstrated}")
            validated['vulnerability_demonstrated'] = False
        
        # Required float field: confidence_score
        confidence_score = response_data.get('confidence_score')
        if isinstance(confidence_score, (int, float)):
            validated['confidence_score'] = max(0.0, min(1.0, float(confidence_score)))
        elif isinstance(confidence_score, str):
            try:
                validated['confidence_score'] = max(0.0, min(1.0, float(confidence_score)))
            except ValueError:
                logger.warning(f"Invalid confidence_score for {cve_id}: {confidence_score}")
                validated['confidence_score'] = 0.0
        else:
            logger.warning(f"Missing confidence_score for {cve_id}")
            validated['confidence_score'] = 0.0
        
        # Optional string field: reasoning/details  
        reasoning = response_data.get('reasoning') or response_data.get('details') or ''
        validated['reasoning'] = str(reasoning) if reasoning else ''
        
        # Optional list fields: indicators/evidence
        for field_name in ['evidence_found', 'indicators_detected', 'indicators_found']:
            field_value = response_data.get(field_name)
            if isinstance(field_value, list):
                validated[field_name] = [str(item) for item in field_value if item]
            elif isinstance(field_value, str) and field_value:
                validated[field_name] = [field_value]
            else:
                validated[field_name] = []
        
        # Simulation detection fields
        simulation_detected = response_data.get('simulation_detected')
        if isinstance(simulation_detected, bool):
            validated['simulation_detected'] = simulation_detected
        elif isinstance(simulation_detected, str):
            validated['simulation_detected'] = simulation_detected.lower() in ['true', 'yes', '1']
        else:
            validated['simulation_detected'] = False
        
        simulation_indicators = response_data.get('simulation_indicators')
        if isinstance(simulation_indicators, list):
            validated['simulation_indicators'] = [str(item) for item in simulation_indicators if item]
        elif isinstance(simulation_indicators, str) and simulation_indicators:
            validated['simulation_indicators'] = [simulation_indicators]
        else:
            validated['simulation_indicators'] = []
        
        logger.debug(f"Schema validation for {cve_id}: {len(validated)} validated fields")
        return validated
