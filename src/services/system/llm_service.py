import ast
import asyncio
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path

import openai
import yaml
from llama_index.core.llms import LLM
from llama_index.llms.azure_openai import AzureOpenAI

from models.vulnerability import Vulnerability
from services.blueprint_management.framework_intelligence_service import (
    FrameworkIntelligenceService,
    VulnerabilityLevel,
)
from services.exploit_generation.github_context_service import GitHubContextService
from services.system.reliability_service import CircuitOpenError, reliability_manager
from shared.constants import (
    PACKAGE_AVAILABLE_LIBRARIES,
    PROJECT_ROOT,
)
from utils.analysis.endpoint_utils import extract_endpoint_metadata
from utils.api_references.api_reference_loader import get_version_guidance
from utils.core.common import format_similar_blueprints
from utils.core.llm_context_builder import LLMContextBuilder
from utils.core.llm_response_parser import LLMResponseParser
from utils.core.prompt_manager import prompt_manager
from utils.error_handling.llm_error_handler import llm_error_handler
from utils.testing.json_validator import JSONValidator

logger = logging.getLogger(__name__)


class LLMService:
    """
    Service for interacting with LLMs via Azure OpenAI and LlamaIndex.
    """

    def __init__(self, config_path: Path = None):
        """Initialize LLM service with just core functionality."""
        self.config = self._load_config(config_path)

        # Initialize circuit breaker
        self.circuit_breaker = reliability_manager.get_circuit_breaker("llm_service")

        # Initialize LLM service if config is available
        self.llm = self._initialize_llm()

        # Initialize JSON validator for response validation
        try:
            self.json_validator = JSONValidator()
            logger.info("JSON validator initialized for LLM response validation")
        except Exception as e:
            logger.warning(f"Failed to initialize JSON validator: {e}")
            self.json_validator = None

        # Initialize GitHub context service for vulnerability analysis
        try:
            self.github_context_service = GitHubContextService()
        except Exception as e:
            logger.warning(f"Failed to initialize GitHub context service: {e}")
            self.github_context_service = None

        # Initialize framework intelligence service for vulnerability classification
        try:
            self.framework_intelligence_service = FrameworkIntelligenceService(llm_service=self)
            logger.info("Framework intelligence service initialized for classification")
        except Exception as e:
            logger.warning(f"Failed to initialize framework intelligence service: {e}")
            self.framework_intelligence_service = None

        # The LLM service should not initialize itself
        self.llm_service = None

    def _load_config(self, config_path: str | Path | None = None) -> dict:
        """
        Load LLM configuration from environment variables.

        Note: config_path parameter kept for backward compatibility but is now unused.
        All configuration comes from os.environ (populated by .env or AWS Secrets Manager).

        Args:
            config_path: Deprecated, kept for backward compatibility

        Returns:
            Configuration dictionary
        """
        config = {
            # Provider settings
            "provider": "azure",
            "model": os.getenv("LLM_MODEL", "gpt-4"),
            "temperature": float(os.getenv("LLM_TEMPERATURE", "0.1")),
            "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "8000")),

            # Azure OpenAI credentials (from AWS Secrets Manager or .env)
            "api_key": os.getenv("AZURE_OPENAI_API_KEY", ""),
            "azure_endpoint": os.getenv("AZURE_OPENAI_ENDPOINT", ""),
            "azure_deployment": os.getenv("AZURE_OPENAI_DEPLOYMENT", ""),
            "api_version": os.getenv("AZURE_OPENAI_API_VERSION", "2023-05-15"),

            # Other settings
            "prompts_dir": "config/prompts",
        }

        # Validate required credentials
        if not config["api_key"]:
            raise ValueError("AZURE_OPENAI_API_KEY is required but not set")
        if not config["azure_endpoint"]:
            raise ValueError("AZURE_OPENAI_ENDPOINT is required but not set")
        if not config["azure_deployment"]:
            raise ValueError("AZURE_OPENAI_DEPLOYMENT is required but not set")

        return config

    def _initialize_llm(self) -> LLM:
        """
        Initialize the LLM based on configuration.

        Returns:
            Configured LLM instance
        """
        provider = self.config.get("provider", "azure").lower()

        if provider == "azure":
            # Get critical configuration
            azure_deployment = self.config.get("azure_deployment")
            api_key = self.config.get("api_key")
            azure_endpoint = self.config.get("azure_endpoint")
            api_version = str(self.config.get("api_version", "2023-05-15"))

            # Validate required configuration
            if not azure_deployment:
                raise ValueError("Missing azure_deployment. Set AZURE_OPENAI_DEPLOYMENT env var.")
            if not api_key:
                raise ValueError("Missing api_key. Set AZURE_OPENAI_API_KEY env var.")
            if not azure_endpoint:
                raise ValueError("Missing azure_endpoint. Set AZURE_OPENAI_ENDPOINT env var.")

            # Initialize the LLM
            return AzureOpenAI(
                model=self.config.get("model", "gpt-4"),
                deployment_name=azure_deployment,
                api_key=api_key,
                azure_endpoint=azure_endpoint,
                api_version=api_version,
                temperature=self.config.get("temperature", 0.1),
                max_tokens=self.config.get("max_tokens", 8000),
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

    def reload_prompt_templates(self) -> None:
        """Reload prompt templates from disk to pick up any changes."""
        logger.info("Reloading prompt templates from disk...")
        prompt_manager.reload_prompts()
        logger.info("Template reload complete via PromptManager")

    def get_prompt_template(self, template_name: str) -> str | None:
        """
        Get a prompt template by name.

        Args:
            template_name: Name of the template

        Returns:
            Template content or None if not found
        """
        template_obj = prompt_manager.get_prompt(template_name)
        return template_obj.template if template_obj else None

    def format_prompt(self, template_name: str, **kwargs) -> str:
        """Format prompt template with support for optional placeholders - delegates to PromptManager."""
        return prompt_manager.format_prompt(template_name, **kwargs)

    async def generate(self, prompt: str, retries: int = 2) -> str | None:
        """
        Generate text with enhanced reliability and circuit breaker protection.

        Args:
            prompt: Input prompt text
            retries: Number of retry attempts

        Returns:
            Generated text response

        Raises:
            RuntimeError: If generation fails after retries
            CircuitOpenError: If circuit breaker is open
        """

        async def _generate_with_retries():
            attempt = 0
            last_exception = None

            while attempt <= retries:
                try:
                    response = await self.llm.acomplete(prompt)
                    if not response or not response.text:
                        raise ValueError("Empty response from LLM")
                    return response.text

                except ValueError:
                    # Re-raise ValueError (empty response) without retry
                    raise

                except Exception as e:
                    attempt += 1
                    last_exception = e

                    # Log the error with proper status code and Azure message
                    llm_error_handler.log_error(e, context=f"attempt {attempt}/{retries + 1}")

                    # Check if we should retry
                    if llm_error_handler.is_retryable(e) and attempt <= retries:
                        wait_time = llm_error_handler.get_backoff_delay(attempt, e)
                        logger.info(f"Retrying in {wait_time:.1f}s (attempt {attempt}/{retries + 1})")
                        await asyncio.sleep(wait_time)
                    else:
                        # Non-retryable error or max retries reached
                        status_code = llm_error_handler.get_status_code(e)
                        error_msg = llm_error_handler.get_error_message(e)

                        if llm_error_handler.is_content_filter_error(e):
                            raise ValueError(f"Content policy violation: {error_msg}")
                        elif status_code in (401, 403):
                            raise ValueError(f"Azure OpenAI authentication error: {error_msg}")
                        elif status_code == 404:
                            raise ValueError(f"Azure OpenAI deployment not found: {error_msg}")
                        elif attempt > retries:
                            raise RuntimeError(
                                f"Failed after {retries + 1} attempts. "
                                f"Last error (status {status_code}): {error_msg}"
                            )
                        else:
                            raise

            # Should not reach here, but just in case
            if last_exception:
                raise last_exception

        try:
            # Use circuit breaker for LLM calls
            return await self.circuit_breaker.call(_generate_with_retries)

        except CircuitOpenError as e:
            logger.error(f"LLM service circuit breaker is open: {e}")

    async def generate_with_template(self, template_name: str, **kwargs) -> str | None:
        """
        Generate text using a prompt template.

        Args:
            template_name: Name of the template
            **kwargs: Variables to format the template with

        Returns:
            Generated text response
        """
        prompt = self.format_prompt(template_name, **kwargs)
        if not prompt:
            logger.error("Unable to generated text using prompt template")
        else:
            return await self.generate(prompt)

    async def generate_vulnerability_code(self, vulnerability_data: dict) -> dict[str, str]:
        """Generate vulnerable code using framework detection for enhanced context."""
        try:
            # First, detect the appropriate framework for this vulnerability
            framework_detection = await self.detect_framework_with_llm(vulnerability_data)

            # Extract framework context from detection results
            framework_context = ""
            if framework_detection.get("framework_type") != "standalone":
                rationale = framework_detection.get("rationale", "")
                deps = framework_detection.get("required_dependencies", [])

                framework_context = f"Framework Type: {framework_detection.get('framework_type', 'standalone')}\n"
                if rationale:
                    framework_context += f"Framework Rationale: {rationale}\n"
                if deps:
                    framework_context += "Recommended Dependencies:\n"
                    for dep in deps:
                        version = dep.get("version", "")
                        purpose = dep.get("purpose", "")
                        framework_context += (
                            f"- {dep.get('group_id', '')}:{dep.get('artifact_id', '')}:{version} ({purpose})\n"
                        )

                # Add version-specific guidance with prominent formatting
                package_version = vulnerability_data.get("package_version", "")
                package_name = vulnerability_data.get("package_name", "").lower()

                if package_version:
                    # Make version information visually prominent
                    framework_context += f"\n\n{'='*60}\n"
                    framework_context += f"TARGET VERSION: {package_version}\n"
                    framework_context += f"{'='*60}\n\n"

                    # Add framework-specific critical warnings
                    if "struts" in package_name:
                        major_version = package_version.split('.')[0] if package_version else "unknown"
                        if major_version == "6":
                            framework_context += (
                                "STRUTS 6.x DETECTED - CRITICAL API CHANGES:\n"
                                "   - HttpParameters (immutable) NOT Map<String, Object>\n"
                                "   - UploadedFile NOT File\n"
                                "   - See lines 39-101 in prompt for full Struts 6.x API rules\n"
                                "   - MANDATORY: Re-read version rules before code generation!\n\n"
                            )
                        elif major_version in ["2", "5"]:
                            framework_context += (
                                f"Struts {major_version}.x uses traditional APIs (Map, File)\n\n"
                            )

                    elif "springframework" in package_name or "spring-" in package_name:
                        major_version = package_version.split('.')[0] if package_version else "unknown"
                        if major_version == "6":
                            framework_context += (
                                "SPRING 6.x DETECTED - CRITICAL API CHANGES:\n"
                                "   - jakarta.* imports NOT javax.*\n"
                                "   - Requires Java 17+\n\n"
                            )

                    framework_context += f"IMPORTANT: Use APIs and patterns appropriate for version {package_version}\n"

            # Get targeted version-specific API guidance from reference system
            version_guidance = LLMContextBuilder.get_version_guidance(
                package_name=vulnerability_data.get("package_name", ""),
                package_version=vulnerability_data.get("package_version", "")
            )

            # Extract GitHub context for vulnerability analysis
            github_context = "No GitHub context available."
            if self.github_context_service:
                try:
                    # Create Vulnerability object from vulnerability_data dict
                    # GitHubContextService expects a Vulnerability object, not individual parameters
                    vuln_obj = Vulnerability(
                        cve_id=vulnerability_data.get("cve_id", ""),
                        package_name=vulnerability_data.get("package_name", ""),
                        package_version=vulnerability_data.get("package_version", ""),
                        summary=vulnerability_data.get("summary", ""),
                        description=vulnerability_data.get("description", ""),
                        published_date=datetime.now(),
                        references=vulnerability_data.get("references", [])
                    )
                    github_data = await self.github_context_service.extract_github_context_from_vulnerability(vuln_obj)
                    if github_data:
                        github_context = self._format_github_context(github_data)
                except Exception as e:
                    logger.warning(f"Failed to extract GitHub context: {e}")
                    github_context = "GitHub context extraction failed."

            # Classify vulnerability to determine template and approach
            classification_level = VulnerabilityLevel.APPLICATION_LEVEL  # Default
            selected_template = None
            framework_config = None

            if self.framework_intelligence_service:
                try:
                    # Use raw github_data for classification (not formatted string)
                    github_context_for_classification = None
                    if self.github_context_service:
                        try:
                            vuln_obj = Vulnerability(
                                cve_id=vulnerability_data.get("cve_id", ""),
                                package_name=vulnerability_data.get("package_name", ""),
                                package_version=vulnerability_data.get("package_version", ""),
                                summary=vulnerability_data.get("summary", ""),
                                description=vulnerability_data.get("description", ""),
                                published_date=datetime.now(),
                                references=vulnerability_data.get("references", [])
                            )
                            github_context_for_classification = await self.github_context_service.extract_github_context_from_vulnerability(vuln_obj)
                        except Exception as e:
                            logger.debug(f"Could not get GitHub context for classification: {e}")

                    classification_level, selected_template, framework_config, detected_protocol = \
                        self.framework_intelligence_service.classify_vulnerability(
                            vulnerability_data.get("description", ""),
                            github_context=github_context_for_classification
                        )
                    logger.info(f"Vulnerability classified as: {classification_level.value}")
                    if selected_template:
                        logger.info(f"Selected template: {selected_template}")
                    if framework_config:
                        logger.info(f"Framework config: {framework_config}")
                    if detected_protocol:
                        logger.info(f"Detected protocol: {detected_protocol}")
                except Exception as e:
                    logger.warning(f"Vulnerability classification failed, using default APPLICATION_LEVEL: {e}")
                    classification_level = VulnerabilityLevel.APPLICATION_LEVEL

            # Build enhanced context from vulnerability data and framework detection
            context_kwargs = {
                "cve_id": vulnerability_data.get("cve_id", ""),
                "package_name": vulnerability_data.get("package_name", ""),
                "package_version": vulnerability_data.get("package_version", ""),
                "description": vulnerability_data.get("description", ""),
                "summary": vulnerability_data.get("summary", ""),
                "references": LLMContextBuilder.format_references(vulnerability_data.get("references", [])),
                "dependencies_section": LLMContextBuilder.format_dependencies(vulnerability_data),
                "dependency_context": vulnerability_data.get("dependency_context", ""),
                "framework_context": framework_context,
                "version_guidance": version_guidance,  # NEW: Targeted version-specific guidance
                "similar_examples": vulnerability_data.get("similar_examples", ""),
                "available_libraries": LLMContextBuilder.generate_available_libraries(
                    vulnerability_data.get("package_name", ""), PACKAGE_AVAILABLE_LIBRARIES
                ),
                "github_context": github_context,
                "vulnerability_type": vulnerability_data.get("vulnerability_type", "unknown"),
                "cwe_ids": ", ".join(vulnerability_data.get("cwe_ids", [])) if vulnerability_data.get("cwe_ids") else "Not specified",
                "cwe_descriptions": self._format_cwe_descriptions(vulnerability_data.get("cwe_ids", [])),
            }

            # Reload templates to ensure latest changes are applied
            self.reload_prompt_templates()

            # Select template based on classification
            if classification_level == VulnerabilityLevel.PROTOCOL_LEVEL:
                template_name = "protocol_vulnerability_generation"
                # Add protocol type to context
                if selected_template:
                    # Extract protocol type from template name
                    # e.g., "remoting_protocol_server" -> "Remoting Protocol"
                    protocol_type = selected_template.replace("_server", "").replace("_", " ").title()
                    context_kwargs["protocol_type"] = protocol_type
                else:
                    # Try to infer protocol from CVE description
                    description_lower = vulnerability_data.get("description", "").lower()
                    if "http/2" in description_lower or "http2" in description_lower:
                        context_kwargs["protocol_type"] = "HTTP/2"
                    elif "websocket" in description_lower:
                        context_kwargs["protocol_type"] = "WebSocket"
                    elif "grpc" in description_lower:
                        context_kwargs["protocol_type"] = "gRPC"
                    elif "smtp" in description_lower or "mail" in description_lower:
                        context_kwargs["protocol_type"] = "SMTP/Mail"
                    elif "ldap" in description_lower:
                        context_kwargs["protocol_type"] = "LDAP"
                    elif "ftp" in description_lower:
                        context_kwargs["protocol_type"] = "FTP"
                    else:
                        # Generic fallback based on package name
                        package_name = vulnerability_data.get("package_name", "").lower()
                        if "netty" in package_name:
                            context_kwargs["protocol_type"] = "Netty Protocol"
                        elif "undertow" in package_name:
                            context_kwargs["protocol_type"] = "Undertow Protocol"
                        elif "jetty" in package_name:
                            context_kwargs["protocol_type"] = "Jetty Protocol"
                        else:
                            context_kwargs["protocol_type"] = "Protocol Server"
                logger.info(f"Using protocol-level template for {context_kwargs['protocol_type']}")
            elif classification_level == VulnerabilityLevel.FRAMEWORK_INTERNAL:
                template_name = "framework_internal_doc"
                logger.info("Using framework-internal documentation template")
            else:
                template_name = "vulnerability_generation"
                logger.info("Using standard application-level vulnerability template")

            # Format prompt using selected template
            prompt = self.format_prompt(template_name, **context_kwargs)

            # Log the prompt being sent
            logger.info(f"VULNERABILITY CODE GENERATION PROMPT LENGTH: {len(prompt)} characters")
            logger.info(f"VULNERABILITY CODE GENERATION PROMPT (first 500 chars): {prompt[:500]}")
            logger.info(f"VULNERABILITY CODE GENERATION PROMPT (last 500 chars): {prompt[-500:]}")

            # Generate with circuit breaker protection
            try:
                response = await self.generate(prompt)
            except CircuitOpenError:
                raise RuntimeError(
                    "LLM service is temporarily unavailable (circuit breaker open). "
                    "Please check your LLM configuration and try again later."
                )

            if not response or not response.strip():
                raise RuntimeError(
                    "LLM service returned empty response. Please check your prompt template and LLM configuration."
                )

            # Log the response received
            logger.info(f"VULNERABILITY CODE GENERATION RESPONSE LENGTH: {len(response)} characters")
            logger.info(f"VULNERABILITY CODE GENERATION RESPONSE (first 500 chars): {response[:500]}")
            logger.info(f"VULNERABILITY CODE GENERATION RESPONSE (last 500 chars): {response[-500:]}")

            # Parse response
            code_snippets = LLMResponseParser.parse_vulnerability_code(response)

            if not code_snippets:
                raise ValueError(
                    "Failed to parse valid code snippets from LLM response. "
                    "Please check the vulnerability_generation.txt template format."
                )

            # Extract endpoint metadata if provided by LLM
            endpoint_metadata = LLMResponseParser.parse_endpoint_metadata(response)
            if endpoint_metadata:
                logger.info(f"Extracted {len(endpoint_metadata)} endpoint(s) from LLM response")
                code_snippets["__endpoint_metadata__"] = endpoint_metadata
            else:
                logger.debug("No endpoint metadata found in LLM response")

            # Extract config values if provided by LLM (for protocol servers)
            config_values = LLMResponseParser.parse_config_values(response)
            if config_values:
                logger.info(f"Extracted {len(config_values)} config value(s) from LLM response")
                code_snippets["__config_values__"] = config_values
            else:
                logger.debug("No config values found in LLM response")

            # Add classification metadata for validation routing
            code_snippets["__classification__"] = {
                "level": classification_level.value,
                "template": selected_template,
                "framework_config": framework_config,
                "protocol_type": detected_protocol if classification_level == VulnerabilityLevel.PROTOCOL_LEVEL else None,
                "config_values": config_values if config_values else None
            }

            return code_snippets

        except Exception as e:
            logger.error(f"Error in vulnerability code generation: {e}")
            raise RuntimeError(f"Vulnerability code generation failed: {str(e)}")

    async def generate_exploitation_guidance(self, vulnerability_data: dict) -> str:
        """Generate exploitation guidance using template - safe implementation."""
        try:
            context_kwargs = {
                "cve_id": vulnerability_data.get("cve_id", ""),
                "package_name": vulnerability_data.get("package_name", ""),
                "package_version": vulnerability_data.get("package_version", ""),
                "summary": vulnerability_data.get("summary", ""),
                "description": vulnerability_data.get("description", ""),
                "vulnerability_type": vulnerability_data.get("vulnerability_type", ""),
                "attack_vector": vulnerability_data.get("attack_vector", ""),
                "impact": vulnerability_data.get("impact", ""),
                "framework_type": vulnerability_data.get("framework_type", ""),
                "container_name": vulnerability_data.get("container_name", ""),
                "access_url": vulnerability_data.get("access_url", ""),
                "exposed_ports": vulnerability_data.get("exposed_ports", ""),
                "code_snippets_summary": vulnerability_data.get("code_snippets_summary", ""),
            }

            prompt = self.format_prompt("exploitation_guidance", **context_kwargs)
            response = await self.generate(prompt)
            
            # Log LLM response details for debugging
            if response:
                logger.info(f"Exploitation guidance generated: {len(response)} characters")
            else:
                logger.warning("Exploitation guidance LLM returned empty response")
            
            return response or ""

        except Exception as e:
            logger.warning(f"Failed to generate exploitation guidance: {e}")
            return ""  # Return empty string instead of raising

    async def analyze_similar_blueprints(self, current_vulnerability: dict, similar_blueprints: list) -> str:
        """Analyze similar blueprints for guidance - safe implementation."""
        try:
            context_kwargs = {
                "cve_id": current_vulnerability.get("cve_id", ""),
                "package_name": current_vulnerability.get("package_name", ""),
                "summary": current_vulnerability.get("summary", ""),
                "description": current_vulnerability.get("description", ""),
                "similar_examples": format_similar_blueprints(similar_blueprints),
                "dependency_examples": LLMContextBuilder.format_dependency_examples(similar_blueprints),
            }

            prompt = self.format_prompt("similar_blueprints_analysis", **context_kwargs)
            response = await self.generate(prompt)
            return response or ""

        except Exception as e:
            logger.warning(f"Failed to analyze similar blueprints: {e}")
            return ""

    async def detect_framework_with_llm(self, vulnerability_data: dict) -> dict:
        """Use LLM for framework detection with enhanced JSON validation."""
        try:
            context_kwargs = {
                "cve_id": vulnerability_data.get("cve_id", ""),
                "package_name": vulnerability_data.get("package_name", ""),
                "package_version": vulnerability_data.get("package_version", ""),
                "summary": vulnerability_data.get("summary", ""),
                "description": vulnerability_data.get("description", ""),
                "references": LLMContextBuilder.format_references(vulnerability_data.get("references", [])),
                "dependency_context": vulnerability_data.get("dependency_context", ""),
                "similar_examples": vulnerability_data.get("similar_examples", ""),
            }

            prompt = self.format_prompt("framework_detection", **context_kwargs)
            response = await self.generate(prompt)

            # DEBUG: Log the raw LLM response for framework detection
            logger.info(f"FRAMEWORK DETECTION RAW RESPONSE LENGTH: {len(response) if response else 0}")
            logger.info(f"FRAMEWORK DETECTION RAW RESPONSE TYPE: {type(response)}")
            if response:
                logger.info(f"FRAMEWORK DETECTION RAW RESPONSE (first 500 chars): {response[:500]}")
                logger.info(f"FRAMEWORK DETECTION RAW RESPONSE (last 200 chars): {response[-200:]}")
            else:
                logger.warning("FRAMEWORK DETECTION RAW RESPONSE IS EMPTY OR NONE")

            # Use JSON validator for robust parsing and validation
            if self.json_validator:
                validation_result = self.json_validator.validate_response(response, "framework_detection")
                
                if validation_result.is_valid or validation_result.parsed_data:
                    if validation_result.repaired:
                        logger.info(f"Framework detection JSON repaired successfully after {validation_result.repair_attempts} attempts")
                    return validation_result.parsed_data
                else:
                    logger.warning(f"Framework detection validation failed: {'; '.join(validation_result.errors)}")
                    # Return fallback from schema
                    return validation_result.parsed_data or {"framework_type": "standalone", "rationale": "JSON validation failed"}
            else:
                result = LLMResponseParser.parse_json_response(
                    response, 
                    expected_fields=["framework_type"],
                    context="framework_detection"
                )
                if result.get("parse_error"):
                    logger.warning(f"Framework detection parsing failed: {result.get('error_message')}")
                    return {"framework_type": "standalone", "rationale": "JSON parsing failed"}
                return result

        except Exception as e:
            logger.warning(f"Failed to detect framework with LLM: {e}")
            return {"framework_type": "standalone", "rationale": f"LLM detection failed: {str(e)}"}

    async def select_optimal_framework(self, adaptation_context: dict) -> dict:
        """
        Use LLM to select the optimal framework for vulnerability demonstration.
        
        Args:
            adaptation_context: Context including package info, vulnerability data, requirements
            
        Returns:
            Dictionary containing framework selection decision
        """
        try:
            context_kwargs = {
                "package_name": adaptation_context.get("package_name", ""),
                "package_version": adaptation_context.get("package_version", ""),
                "cve_ids": ", ".join(adaptation_context.get("cve_ids", [])),
                "vulnerability_type": adaptation_context.get("vulnerability_type", ""),
                "vulnerability_description": adaptation_context.get("vulnerability_description", ""),
            }

            prompt = self.format_prompt("framework_selection", **context_kwargs)
            logger.info(f"LLM FRAMEWORK SELECTION: Sending prompt for {context_kwargs.get('package_name', 'unknown')}")
            response = await self.generate(prompt)
            
            # DEBUG: Enhanced logging for framework selection response
            logger.info(f"LLM RAW RESPONSE LENGTH: {len(response)} characters")
            logger.info(f"LLM RAW RESPONSE TYPE: {type(response)}")
            if response:
                logger.info(f"LLM FRAMEWORK SELECTION RAW RESPONSE (first 500 chars): {response[:500]}")
                logger.info(f"LLM FRAMEWORK SELECTION RAW RESPONSE (last 200 chars): {response[-200:]}")
            else:
                logger.warning("LLM FRAMEWORK SELECTION RAW RESPONSE IS EMPTY OR NONE")

            # Use JSON validator for robust parsing and validation
            if self.json_validator:
                validation_result = self.json_validator.validate_response(response, "framework_selection")
                
                if validation_result.is_valid or validation_result.parsed_data:
                    if validation_result.repaired:
                        logger.info(f"Framework selection JSON repaired after {validation_result.repair_attempts} attempts")
                    framework_choice = validation_result.parsed_data
                    logger.info(f"LLM JSON VALIDATION SUCCESS: {framework_choice.get('selected_framework', 'unknown')}")
                else:
                    logger.warning(f"Framework selection validation failed: {'; '.join(validation_result.errors)}")
                    # Use fallback data from schema
                    framework_choice = validation_result.parsed_data
            else:
                framework_choice = LLMResponseParser.parse_json_response(
                    response,
                    expected_fields=["selected_framework", "confidence_score"],
                    context="framework_selection"
                )
                if framework_choice.get("parse_error"):
                    logger.error(f"LLM JSON PARSING FAILED: {framework_choice.get('error_message')}")
                    logger.error(f"   Raw response that failed: {response[:200]}...")
                    raise ValueError(f"Failed to parse framework selection: {framework_choice.get('error_message')}")
                logger.info(f"LLM JSON PARSING SUCCESS: {framework_choice.get('selected_framework', 'unknown')}")
            
            logger.info(f"LLM selected framework: {framework_choice.get('selected_framework', 'unknown')} "
                       f"(confidence: {framework_choice.get('confidence_score', 0)})")
            
            return framework_choice

        except Exception as e:
            logger.error(f"Failed to select framework with LLM: {e}")
            # Return schema fallback if available
            if self.json_validator:
                schema = self.json_validator.get_schema("framework_selection")
                if schema and 'fallback' in schema:
                    fallback = schema['fallback'].copy()
                    fallback['error'] = str(e)
                    return fallback
            
            # Ultimate fallback
            return {
                "selected_framework": "SPRING_BOOT", 
                "confidence_score": 0.7,
                "reasoning": "LLM framework selection failed, using Spring Boot web application fallback",
                "error": str(e)
            }

    async def adapt_code_to_framework(self, adaptation_request: dict) -> dict:
        """
        Use LLM to adapt vulnerability code from one framework to another.

        Args:
            adaptation_request: Request containing source code, frameworks, and context

        Returns:
            Dictionary containing adapted code and metadata
        """
        try:
            # Extract framework requirements based on target framework
            target_framework = adaptation_request.get("target_framework", "")
            framework_requirements = LLMContextBuilder.get_framework_requirements(target_framework)

            # Get version-specific API guidance for the package
            package_name = adaptation_request.get("package_name", "")
            package_version = adaptation_request.get("package_version", "")
            version_guidance = LLMContextBuilder.get_version_guidance(package_name, package_version)

            context_kwargs = {
                "source_framework": adaptation_request.get("source_framework", ""),
                "target_framework": target_framework,
                "package_name": package_name,
                "package_version": package_version,
                "vulnerability_type": adaptation_request.get("vulnerability_type", ""),
                "adaptation_strategy": adaptation_request.get("adaptation_strategy", "wrap_standalone"),
                "original_code": adaptation_request.get("original_code", ""),
                "framework_requirements": framework_requirements,
                "github_context": adaptation_request.get("github_context", "No GitHub context available."),
                "version_guidance": version_guidance if version_guidance else "No version-specific guidance available.",
            }

            prompt = self.format_prompt("code_adaptation", **context_kwargs)
            response = await self.generate(prompt)

            # Log the raw response for debugging
            logger.info(f"LLM CODE ADAPTATION RAW RESPONSE LENGTH: {len(response)}")
            logger.info(f"LLM CODE ADAPTATION RAW RESPONSE (first 500 chars): {response[:500]}")
            logger.info(f"LLM CODE ADAPTATION RAW RESPONSE (last 200 chars): {response[-200:]}")

            # 1. Extract code blocks first (using existing extraction logic)
            code_blocks = {}

            # Look for file: markers in code blocks
            file_pattern = r'```file:(.*?)\n(.*?)```'
            matches = re.findall(file_pattern, response, re.DOTALL)

            for file_path, file_content in matches:
                file_path = file_path.strip()
                code_blocks[file_path] = file_content.strip()
                logger.info(f"Extracted adapted code file: {file_path} ({len(file_content)} chars)")

            if not code_blocks:
                raise ValueError("No code files found in adaptation response (expected ```file:path format)")

            # Extract JSON metadata separately
            adaptation_metadata = LLMResponseParser.parse_json_response(
                response,
                expected_fields=["dependencies_added", "changes_made"],
                context="code_adaptation"
            )
            
            if adaptation_metadata.get("parse_error"):
                if self.json_validator:
                    validation_result = self.json_validator.validate_response(response, "code_adaptation")
                    if validation_result.is_valid or validation_result.parsed_data:
                        adaptation_metadata = validation_result.parsed_data
                    else:
                        logger.warning("Could not parse JSON metadata from adaptation response, using defaults")
                        adaptation_metadata = {}
                else:
                    logger.warning(f"Could not parse JSON metadata: {adaptation_metadata.get('error_message')}")
                    adaptation_metadata = {}

            # Combine code blocks into adapted_code field
            adapted_code_parts = []
            for file_path, file_content in code_blocks.items():
                adapted_code_parts.append(f"```file:{file_path}\n{file_content}\n```")

            # Extract endpoint metadata if provided by LLM
            endpoint_metadata = LLMResponseParser.parse_endpoint_metadata(response)

            adaptation_result = {
                "adapted_code": "\n\n".join(adapted_code_parts),
                "changes_made": adaptation_metadata.get("changes_made", ["Adapted code to target framework"]),
                "dependencies_added": adaptation_metadata.get("dependencies_added", []),
                "adaptation_notes": adaptation_metadata.get("adaptation_notes", "Code adapted successfully"),
            }

            # Add endpoint_metadata if found
            if endpoint_metadata:
                logger.info(f"Extracted {len(endpoint_metadata)} endpoint(s) from adaptation response")
                adaptation_result["endpoint_metadata"] = endpoint_metadata
            else:
                logger.debug("No endpoint metadata found in adaptation response")

            logger.info(f"Successfully extracted {len(code_blocks)} code files and metadata")
            
            logger.info(f"Successfully adapted code from {adaptation_request.get('source_framework')} "
                       f"to {target_framework}")
            
            return adaptation_result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse code adaptation JSON response: {e}")
            return {
                "adapted_code": adaptation_request.get("original_code", ""),
                "changes_made": ["LLM adaptation failed - returning original code"],
                "error": str(e),
                "adaptation_success": False
            }
        except Exception as e:
            logger.error(f"Failed to adapt code with LLM: {e}")
            return {
                "adapted_code": adaptation_request.get("original_code", ""),
                "changes_made": ["LLM adaptation failed - returning original code"],
                "error": str(e),
                "adaptation_success": False
            }

    def _validate_example_influence(self, code_snippets: dict[str, str], similar_examples: str) -> None:
        """
        Validate that similar examples influenced the generated code.

        Args:
            code_snippets: Generated code snippets
            similar_examples: Similar examples that were provided
        """
        example_imports = set(re.findall(r"import\s+([^;]+);", similar_examples))
        # example_classes = set(re.findall(r'class\s+(\w+)', similar_examples))
        example_methods = set(re.findall(r"(\w+)\s*\([^)]*\)\s*\{", similar_examples))

        # Check if generated code shows similar patterns
        generated_text = " ".join(code_snippets.values())
        generated_imports = set(re.findall(r"import\s+([^;]+);", generated_text))
        generated_methods = set(re.findall(r"(\w+)\s*\([^)]*\)\s*\{", generated_text))

        # Calculate influence metrics
        import_overlap = len(example_imports & generated_imports)
        method_overlap = len(example_methods & generated_methods)

        influence_score = (import_overlap + method_overlap) / max(len(example_imports) + len(example_methods), 1)

        logger.info(f"Example influence analysis: {influence_score:.2f} similarity score")
        logger.debug(f"Import overlap: {import_overlap}/{len(example_imports)}")
        logger.debug(f"Method overlap: {method_overlap}/{len(example_methods)}")

        if influence_score < 0.1:
            logger.warning("Low similarity to examples - guidance may not be effective")

    async def generate_blueprint_metadata(self, vulnerability_data: dict) -> dict:
        """
        Generate metadata for a blueprint based on vulnerability data.

        Args:
            vulnerability_data: Vulnerability information

        Returns:
            Generated metadata
        """
        prompt = self.format_prompt(
            "blueprint_creation",
            cve_id=vulnerability_data.get("cve_id", ""),
            package_name=vulnerability_data.get("package_name", ""),
            package_version=vulnerability_data.get("package_version", ""),
            description=vulnerability_data.get("description", ""),
            summary=vulnerability_data.get("summary", ""),
            references=json.dumps(vulnerability_data.get("references", []), indent=2),
        )

        # Generate metadata
        response = await self.generate(prompt)

        # Use enhanced parser with fallback
        metadata = LLMResponseParser.parse_json_response(
            response,
            context="metadata_generation"
        )
        
        if metadata.get("parse_error"):
            # Fallback: extract key-value pairs using regex
            logger.warning(f"JSON parsing failed, using regex fallback: {metadata.get('error_message')}")
            metadata = {}
            pattern = r"([a-zA-Z_]+):\s*(\[[^\]]*\]|[^\n]+)"
            pairs = re.findall(pattern, response)  # type: ignore

            for key, value in pairs:
                key = key.strip()
                value = value.strip()

                # Try to parse lists
                if value.startswith("[") and value.endswith("]"):
                    try:
                        metadata[key] = json.loads(value)
                    except json.JSONDecodeError:
                        metadata[key] = value
                else:
                    metadata[key] = value

        return metadata

    async def generate_from_template(
        self, 
        template_name: str, 
        context: dict = None, 
        temperature: float = None, 
        max_tokens: int = None,
        retries: int = 2
    ) -> str:
        """
        Generate text using a specific template with custom parameters.
        
        Args:
            template_name: Name of the prompt template to use
            context: Context variables to substitute in the template
            temperature: Temperature override for generation
            max_tokens: Max tokens override for generation
            retries: Number of retry attempts
            
        Returns:
            Generated text response
            
        Raises:
            ValueError: If template not found or formatting fails
            RuntimeError: If generation fails after retries
        """
        if context is None:
            context = {}
            
        # Format the prompt using the template
        try:
            prompt = self.format_prompt(template_name, **context)
        except Exception as e:
            raise ValueError(f"Error formatting template '{template_name}': {str(e)}")
        
        # Store original config values
        original_temp = self.config.get("temperature")
        original_tokens = self.config.get("max_tokens")
        
        try:
            # Temporarily override config if specified
            if temperature is not None:
                self.config["temperature"] = temperature
                # Update LLM instance if needed
                if hasattr(self.llm, 'temperature'):
                    self.llm.temperature = temperature
                    
            if max_tokens is not None:
                self.config["max_tokens"] = max_tokens
                if hasattr(self.llm, 'max_tokens'):
                    self.llm.max_tokens = max_tokens
            
            # Generate response
            response = await self.generate(prompt, retries=retries)
            
            if not response:
                raise RuntimeError(f"Empty response from template '{template_name}'")
                
            return response
            
        finally:
            # Restore original config
            if original_temp is not None:
                self.config["temperature"] = original_temp
                if hasattr(self.llm, 'temperature'):
                    self.llm.temperature = original_temp
                    
            if original_tokens is not None:
                self.config["max_tokens"] = original_tokens
                if hasattr(self.llm, 'max_tokens'):
                    self.llm.max_tokens = original_tokens

    async def analyze_error_for_recovery(
        self, 
        error_context: dict, 
        additional_context: dict = None
    ) -> dict:
        """
        Analyze an error using LLM for recovery insights.
        
        Args:
            error_context: Dictionary containing error information
            additional_context: Additional context for analysis
            
        Returns:
            Dictionary containing analysis results
        """
        context = error_context.copy()
        if additional_context:
            context.update(additional_context)
            
        try:
            response = await self.generate_from_template(
                "error_analysis",
                context=context,
                temperature=0.3,
                max_tokens=2000
            )
            
            # Parse the structured response
            analysis = LLMResponseParser.parse_structured_response(response)
            return analysis
            
        except Exception as e:
            logger.error(f"Error during LLM error analysis: {e}")
            return {
                "error": str(e),
                "classification": "UNKNOWN",
                "recovery_feasible": False,
                "confidence": 0.0
            }

    async def generate_fix_actions(
        self, 
        error_analysis: dict, 
        error_context: dict,
        osv_data: dict = None
    ) -> dict:
        """
        Generate fix actions based on error analysis.
        
        Args:
            error_analysis: Results from error analysis
            error_context: Original error context
            osv_data: Optional OSV reference data
            
        Returns:
            Dictionary containing generated fix actions
        """
        context = {
            **error_analysis,
            **error_context,
            "osv_references": json.dumps(osv_data) if osv_data else "No OSV data available"
        }
        
        try:
            response = await self.generate_from_template(
                "fix_generation",
                context=context,
                temperature=0.3,
                max_tokens=2000
            )
            
            # Parse the fix actions
            fix_actions = LLMResponseParser.parse_fix_actions(response)
            return fix_actions
            
        except Exception as e:
            logger.error(f"Error during LLM fix generation: {e}")
            return {
                "error": str(e),
                "fix_actions": [],
                "success": False
            }

    async def generate_react_reasoning(
        self, 
        react_context: dict, 
        iteration: int = 0
    ) -> dict:
        """
        Generate reasoning for ReAct loop iteration.
        
        Args:
            react_context: Context for ReAct reasoning
            iteration: Current iteration number
            
        Returns:
            Dictionary containing reasoning results
        """
        context = react_context.copy()
        context["iteration"] = iteration
        
        try:
            # Create a simplified prompt for ReAct reasoning
            prompt = self._create_react_reasoning_prompt(context)
            
            response = await self.generate(
                prompt,
                retries=2
            )
            
            # Parse reasoning response
            reasoning = LLMResponseParser.parse_react_reasoning(response)
            return reasoning
            
        except Exception as e:
            logger.error(f"Error during ReAct reasoning generation: {e}")
            return {
                "error": str(e),
                "analysis": "Failed to generate reasoning",
                "planned_action": "retry",
                "confidence": 0.1
            }

    async def generate_react_observation(
        self, 
        observation_context: dict, 
        iteration: int = 0
    ) -> dict:
        """
        Generate observation analysis for ReAct loop.
        
        Args:
            observation_context: Context for observation analysis
            iteration: Current iteration number
            
        Returns:
            Dictionary containing observation results
        """
        context = observation_context.copy()
        context["iteration"] = iteration
        
        try:
            # Create a simplified prompt for ReAct observation
            prompt = self._create_react_observation_prompt(context)
            
            response = await self.generate(
                prompt,
                retries=2
            )
            
            # Parse observation response
            observation = LLMResponseParser.parse_react_observation(response)
            return observation
            
        except Exception as e:
            logger.error(f"Error during ReAct observation generation: {e}")
            return {
                "error": str(e),
                "analysis": "Failed to generate observation",
                "recovery_complete": False,
                "should_continue": False,
                "confidence": 0.1
            }

    def _create_react_reasoning_prompt(self, context: dict) -> str:
        """Create a prompt for ReAct reasoning."""
        error_info = context.get("error_context", {})
        iteration = context.get("iteration", 0)
        
        return f"""
        You are an expert error recovery agent. Analyze this error and plan the next recovery action.

        ITERATION: {iteration + 1}
        ERROR: {error_info.get('error_message', 'Unknown error')}
        CONTAINER: {error_info.get('container_name', 'Unknown')}
        OPERATION: {error_info.get('operation', 'Unknown')}

        PREVIOUS ATTEMPTS: {context.get('previous_attempts', 'None')}

        Provide your analysis in this format:
        ANALYSIS: [Brief analysis of the situation]
        PLANNED_ACTION: [Specific action to take next]
        CONFIDENCE: [0.0-1.0 confidence level]
        """

    def _create_react_observation_prompt(self, context: dict) -> str:
        """Create a prompt for ReAct observation."""
        return f"""
        Evaluate the results of the recent recovery action.

        ACTION TAKEN: {context.get('action_description', 'Unknown')}
        RESULTS: {context.get('results', 'No results')}

        Provide your evaluation:
        ANALYSIS: [Analysis of results]
        RECOVERY_COMPLETE: [YES/NO]
        SHOULD_CONTINUE: [YES/NO]
        CONFIDENCE: [0.0-1.0]
        """

    def _extract_python_code(self, raw_response: str) -> str | None:
        """
        Extract executable Python code from LLM response that may contain mixed content.
        
        Args:
            raw_response: Raw LLM response potentially containing code and explanations
            
        Returns:
            Clean Python code or None if extraction fails
        """
        if not raw_response:
            return None
        
        # Strategy 1: If response starts with shebang, assume it's already clean Python
        if raw_response.strip().startswith('#!/usr/bin/env python3'):
            if self._validate_python_syntax(raw_response):
                logger.info("Code extraction: Strategy 1 (shebang detection) successful")
                return raw_response
        
        # Strategy 2: Use code block extraction
        code_blocks = LLMResponseParser.extract_code_blocks(raw_response, languages=['python'])
        
        if code_blocks and 'python' in code_blocks:
            python_code = code_blocks['python']
            if self._validate_python_syntax(python_code):
                logger.info("Code extraction: Strategy 2 (extract_code_blocks) successful")
                return python_code
            else:
                logger.warning("Extracted Python code failed syntax validation")
        
        # Strategy 3: Look for script structure patterns
        # Find content between shebang and end of script
        shebang_pos = raw_response.find('#!/usr/bin/env python3')
        if shebang_pos >= 0:
            # Extract from shebang to end, looking for natural script boundaries
            script_content = raw_response[shebang_pos:]

            natural_endings = [
                '\n\n# ',  # Start of new section/explanation
                '\n\n## ',  # Markdown heading
                '\n\n### ',  # Markdown subheading
                '\n\n**',  # Bold text
                '\n\nThis script',  # Explanation text
                '\n\nUsage',  # Usage instructions
                '\n\nExplanation',  # Explanation section
            ]
            
            best_script = script_content
            for ending in natural_endings:
                end_pos = script_content.find(ending)
                if end_pos > 0:
                    candidate = script_content[:end_pos].strip()
                    if self._validate_python_syntax(candidate):
                        best_script = candidate
                        break
            
            if self._validate_python_syntax(best_script):
                logger.info("Code extraction: Strategy 3 (pattern boundaries) successful")
                return best_script
        
        # Strategy 4: As fallback, try the raw response in case prompt worked
        if self._validate_python_syntax(raw_response):
            logger.info("Code extraction: Strategy 4 (raw response) successful")
            return raw_response
        
        logger.warning("All code extraction strategies failed - could not extract valid Python code")
        return None
    
    def _validate_python_syntax(self, code: str) -> bool:
        """
        Validate that the given code has valid Python syntax.
        
        Args:
            code: Python code to validate
            
        Returns:
            True if syntax is valid, False otherwise
        """
        if not code or not code.strip():
            return False
        
        try:
            ast.parse(code)
            return True
        except SyntaxError as e:
            logger.debug(f"Python syntax validation failed: {e}")
            return False
        except Exception as e:
            logger.debug(f"Python syntax validation error: {e}")
            return False

    async def call_llm_async(self, prompt: str, retries: int = 2) -> str:
        """
        Alias for generate method to maintain compatibility with exploit services.

        Args:
            prompt: Input prompt text
            retries: Number of retry attempts

        Returns:
            Generated text response
        """
        result = await self.generate(prompt, retries)
        return result or ""

    async def generate_exploit_script(
        self,
        vulnerability_data: dict,
        poc_context: list = None,
        blueprint_code_snippets: dict = None,
        endpoint_compliance_override: str = ""
    ) -> str | None:
        """
        Generate Python exploit script with PoC integration or LLM fallback.

        Args:
            vulnerability_data: Vulnerability information
            poc_context: Optional PoC data for enhanced generation
            blueprint_code_snippets: Code snippets from blueprint for coordination
            endpoint_compliance_override: Optional override message for endpoint compliance

        Returns:
            Generated Python exploit script
        """
        try:
            # Extract GitHub context for exploit generation
            github_context = "No GitHub context available."
            if self.github_context_service:
                try:
                    # Create Vulnerability object from vulnerability_data dict
                    # GitHubContextService expects a Vulnerability object, not individual parameters
                    vuln_obj = Vulnerability(
                        cve_id=vulnerability_data.get("cve_id", ""),
                        package_name=vulnerability_data.get("package_name", ""),
                        package_version=vulnerability_data.get("package_version", ""),
                        summary=vulnerability_data.get("summary", ""),
                        description=vulnerability_data.get("description", ""),
                        published_date=datetime.now(),
                        references=vulnerability_data.get("references", [])
                    )
                    github_data = await self.github_context_service.extract_github_context_from_vulnerability(vuln_obj)
                    if github_data:
                        github_context = self._format_github_context(github_data)
                except Exception as e:
                    logger.warning(f"Failed to extract GitHub context for exploit generation: {e}")
                    github_context = "GitHub context extraction failed."

            # Build context for exploit generation
            template_vars = {
                "cve_id": vulnerability_data.get("cve_id", ""),
                "package_name": vulnerability_data.get("package_name", ""),
                "vulnerability_type": vulnerability_data.get("vulnerability_type", "unknown"),
                "description": vulnerability_data.get("description", ""),
                "severity": vulnerability_data.get("severity", ""),
                "poc_available": poc_context is not None,
                "poc_techniques": [],
                "poc_endpoints": [],
                "poc_payloads": [],
                "container_code_context": "",
                "application_endpoints": "",
                "vulnerable_patterns": "",
                "references_context": LLMContextBuilder.format_references(vulnerability_data.get("references", [])),
                "github_context": github_context,
                "endpoint_compliance_override": endpoint_compliance_override,
            }

            # Add PoC context if available
            if poc_context:
                for poc in poc_context:
                    template_vars["poc_techniques"].extend(poc.get("attack_vectors", []))
                    template_vars["poc_endpoints"].extend(poc.get("target_endpoints", []))
                    template_vars["poc_payloads"].extend(poc.get("payload_patterns", []))

            # Add blueprint code context and extract endpoints
            if blueprint_code_snippets:
                logger.info(f"Providing {len(blueprint_code_snippets)} blueprint code files to LLM")
                # Format the blueprint code for the template
                code_context = []
                for filename, code_content in blueprint_code_snippets.items():
                    if code_content and isinstance(code_content, str):
                        code_context.append(f"=== {filename} ===\n{code_content}")

                template_vars["container_code_context"] = "\n\n".join(code_context)

                # Extract endpoints from blueprint code
                try:
                    endpoint_metadata = extract_endpoint_metadata(blueprint_code_snippets)
                    if endpoint_metadata:
                        # Format endpoints for LLM with all necessary details
                        endpoint_lines = []
                        for ep in endpoint_metadata:
                            endpoint_lines.append(f"Path: {ep['path']}")
                            endpoint_lines.append(f"Method: {ep.get('method', 'POST')}")
                            if ep.get('consumes'):
                                endpoint_lines.append(f"Content-Type: {ep['consumes']}")
                            if ep.get('parameter_types'):
                                params = ", ".join([f"{p['name']} ({p['type']})" for p in ep['parameter_types']])
                                endpoint_lines.append(f"Parameters: {params}")
                            endpoint_lines.append("")  # Blank line between endpoints

                        template_vars["application_endpoints"] = "\n".join(endpoint_lines)
                        logger.info(f"Extracted {len(endpoint_metadata)} endpoints from blueprint code")
                    else:
                        template_vars["application_endpoints"] = "No endpoints extracted from blueprint code"
                        logger.warning("No endpoints found in blueprint code")
                except Exception as e:
                    logger.error(f"Failed to extract endpoints from blueprint: {e}")
                    template_vars["application_endpoints"] = "Endpoint extraction failed - see APPLICATION CONTEXT above"

                template_vars["vulnerable_patterns"] = "See the vulnerable method implementations in APPLICATION CONTEXT above"

                logger.info("Blueprint code context and endpoints provided to LLM")
            else:
                logger.warning("No blueprint_code_snippets provided")
                template_vars["container_code_context"] = "No application code context available"
                template_vars["application_endpoints"] = "No endpoint information available"
                template_vars["vulnerable_patterns"] = "No vulnerable patterns available"

            # Use exploit generation template
            raw_script = await self.generate_with_template("llm_poc_generation", **template_vars)

            if not raw_script:
                logger.error(f"Failed to generate exploit script for {vulnerability_data.get('cve_id', 'Unknown CVE')}")
                logger.error("All exploit generation methods failed - no fallback script available")
                return None

            # Extract and validate Python code from LLM response
            logger.info(f"Extracting Python code from LLM response (length: {len(raw_script)} chars)")
            script = self._extract_python_code(raw_script)
            if not script:
                logger.error(f"Failed to extract valid Python code from LLM response for {vulnerability_data.get('cve_id', 'Unknown CVE')}")
                return None
            else:
                logger.info(f"Successfully extracted Python code (length: {len(script)} chars)")
                logger.debug(f"Extracted script preview: {script[:200]}...")

            return script

        except Exception as e:
            logger.error(f"Failed to generate exploit script: {e}")
            logger.error(f"CVE: {vulnerability_data.get('cve_id', 'Unknown')}, Package: {vulnerability_data.get('package_name', 'Unknown')}")
            return None

    async def generate_vulnerability_payloads(
        self, 
        vulnerability_type: str, 
        framework_context: str,
        poc_techniques: list = None
    ) -> list:
        """
        Generate dynamic payloads based on vulnerability and PoC analysis.
        
        Args:
            vulnerability_type: Type of vulnerability
            framework_context: Framework/technology context
            poc_techniques: Optional PoC techniques for guidance
            
        Returns:
            List of generated payload dictionaries
        """
        try:
            template_vars = {
                "vulnerability_type": vulnerability_type,
                "framework_context": framework_context,
                "poc_techniques": poc_techniques or [],
                "payload_count": 5
            }
            
            payload_response = await self.generate_with_template("payload_generation", **template_vars)
            
            if payload_response:
                # Try to parse structured response
                payloads = self._parse_payload_response(payload_response)
                if payloads:
                    return payloads
            
        except Exception as e:
            logger.error(f"Failed to generate payloads: {e}")

    def _format_cwe_descriptions(self, cwe_ids: list) -> str:
        """
        Format CWE IDs with descriptions from vulnerability_patterns.yaml config.

        Args:
            cwe_ids: List of CWE IDs (e.g., ["CWE-404", "CWE-770"])

        Returns:
            Formatted string with CWE meanings for LLM context
        """
        if not cwe_ids:
            return "No CWE classifications provided. Use the vulnerability description to determine the attack mechanism."

        # Load CWE mappings from config file
        config_path = PROJECT_ROOT / "src" / "config" / "vulnerability_patterns.yaml"
        try:
            with open(config_path, 'r') as f:
                patterns = yaml.safe_load(f)
                cwe_map = patterns.get("cwe_mappings", {})
        except Exception as e:
            logger.warning(f"Could not load CWE mappings from config: {e}")
            return "CWE configuration unavailable - rely on vulnerability description."

        # Format CWE descriptions
        descriptions = []
        for cwe_id in cwe_ids:
            vuln_type = cwe_map.get(cwe_id, "unknown")
            if vuln_type != "unknown":
                # Make human-readable by replacing underscores and title-casing
                readable_type = vuln_type.replace('_', ' ').title()
                descriptions.append(f"- {cwe_id}: {readable_type}")
            else:
                descriptions.append(f"- {cwe_id}: See vulnerability description for details")

        if not descriptions:
            return "Unknown CWE classifications - use vulnerability description."

        return "\n".join(descriptions)

    def _format_github_context(self, github_data) -> str:
        """
        Format GitHub context data for LLM consumption.

        Args:
            github_data: GitHubContextResult dataclass or dict

        Returns:
            Formatted string with GitHub context sections
        """
        if not github_data:
            return "No GitHub context available."

        # Check if github_data is a GitHubContextResult dataclass
        # If so, use its built-in helper methods for consistent formatting
        if hasattr(github_data, 'get_issue_context'):
            sections = []

            # Use existing helper methods from GitHubContextResult dataclass
            issue_context = github_data.get_issue_context()
            if issue_context:
                sections.append(issue_context)

            fix_analysis = github_data.get_fix_analysis()
            if fix_analysis:
                sections.append(fix_analysis)

            advisory_context = github_data.get_advisory_context()
            if advisory_context:
                sections.append(advisory_context)

            poc_refs = github_data.get_poc_references()
            if poc_refs:
                sections.append(poc_refs)

            return "\n\n".join(sections) if sections else "No GitHub context available."

        # Fallback: Handle dict format for backward compatibility
        # (should rarely be used now that we have GitHubContextResult)
        formatted_sections = []

        # Format issues
        issues = github_data.get("issues", [])
        if issues:
            formatted_sections.append("### GitHub Issues")
            for issue in issues:
                title = issue.get("title", "No title")
                url = issue.get("url", "")
                body = issue.get("body", "")
                formatted_sections.append(f"\n**Issue**: {title}")
                formatted_sections.append(f"**URL**: {url}")
                if body:
                    body_preview = body[:500] + "..." if len(body) > 500 else body
                    formatted_sections.append(f"**Description**: {body_preview}")

        # Format fix commits
        fix_commits = github_data.get("fix_commits", [])
        if fix_commits:
            formatted_sections.append("\n### Fix Commits")
            for commit in fix_commits:
                url = commit.get("url", "")
                message = commit.get("message", "No message")
                diff = commit.get("diff", "")
                formatted_sections.append(f"\n**Commit**: {message}")
                formatted_sections.append(f"**URL**: {url}")
                if diff:
                    diff_preview = diff[:1000] + "..." if len(diff) > 1000 else diff
                    formatted_sections.append(f"**Diff**:\n```\n{diff_preview}\n```")

        if not formatted_sections:
            return "No GitHub context available."

        return "\n".join(formatted_sections)

    def _parse_payload_response(self, response: str) -> list:
        """Parse payload generation response."""
        payloads = []
        
        try:
            # Try to extract JSON payload list
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                payload_list = json.loads(json_match.group())
                for payload in payload_list:
                    if isinstance(payload, dict):
                        payloads.append(payload)
                    else:
                        payloads.append({"value": str(payload), "type": "string"})
                return payloads
        except json.JSONDecodeError:
            pass
        
        # Fallback: extract payload-like strings
        payload_patterns = [
            r'"([^"]*payload[^"]*)"',
            r"'([^']*payload[^']*)'",
            r'"([^"]*exploit[^"]*)"',
            r"'([^']*exploit[^']*)'",
        ]
        
        for pattern in payload_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                payloads.append({"value": match, "type": "string"})
        
        return payloads[:10]  # Limit to 10 payloads
