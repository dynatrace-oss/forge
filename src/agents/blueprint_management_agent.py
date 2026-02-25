import asyncio
import logging
import re
from datetime import datetime

from models.blueprint import Blueprint
from models.error_handling import (
    ErrorCategory,
    ErrorSeverity,
    LLMError,
    TemplateError,
    VulnerabilityError,
)
from models.framework_adaptation import AdaptationContext
from services.blueprint_management.blueprint_repository_service import BlueprintRepositoryService
from services.blueprint_management.framework_adaptation_service import FrameworkAdaptationService
from services.blueprint_management.framework_intelligence_service import FrameworkIntelligenceService
from shared.interfaces import LLMServiceInterface, TemplateManagerInterface
from utils.core.common import get_class_name_for_package
from utils.core.loader import load_supported_packages
from utils.core.prompt_manager import prompt_manager
from utils.support.blueprint_diff import compare_code_snippets, summarize_blueprint_changes
from utils.support.osv_client import extract_vulnerability_metadata

logger = logging.getLogger(__name__)


class BlueprintManagementAgent:
    """
    Agent responsible for creating and managing vulnerability blueprints.
    Makes high-level decisions about blueprint structure and content.

    DYNAMIC PROMPT TEMPLATE SYSTEM INTEGRATION:

    This agent uses both simple and advanced prompt templates via PromptManager:

    1. SIMPLE TEMPLATES - String replacement only:
       - package_description (if available)
       - package_tags (if available)
       - container_generation (used in deployment)

    2. ADVANCED TEMPLATES - Jinja2 + automatic enrichers:
       Note: Blueprint generation is currently handled by LLMService.generate_vulnerability_code()
       which uses advanced templates internally. The agent doesn't call format_prompt() directly
       for vulnerability code generation, but the templates used are:

       - vulnerability_generation (APPLICATION_LEVEL)
         * Extends: base_vulnerability_code_generation
         * Auto-enrichers: version_checker, github_context_enricher, cwe_classifier
         * Auto-populated context: version_warnings, github_analysis, cwe_details

       - protocol_vulnerability_generation (PROTOCOL_SERVER)
         * Extends: base_vulnerability_code_generation
         * Auto-enrichers: version_checker, github_context_enricher, protocol_detector
         * Auto-populated context: protocol_type, server_config, version_warnings

       - framework_internal_doc (FRAMEWORK_INTERNAL)
         * Extends: base_vulnerability_code_generation
         * Auto-enrichers: version_checker, github_context_enricher
         * Auto-populated context: framework_limitations, internal_components

    USAGE PATTERN:

    When LLMService is called for code generation, it internally:
    1. Calls PromptManager.format_prompt(template_name, **context)
    2. PromptManager auto-detects if template is advanced
    3. If advanced, routes to PromptTemplateService
    4. PromptTemplateService invokes enrichers → enrichers populate context
    5. Jinja2 renders template with enriched context
    6. Returns final prompt to LLMService

    The agent doesn't need to manage enrichers - it just provides base vulnerability_data.
    """

    def __init__(
        self,
        blueprint_service: BlueprintRepositoryService = None,
        llm_service: LLMServiceInterface = None,
        template_manager: TemplateManagerInterface = None,
        framework_adaptation_service: FrameworkAdaptationService = None,
        framework_intelligence_service: FrameworkIntelligenceService = None,
        enable_framework_adaptation: bool = True,
    ):
        """Initialize with dependency injection."""
        self.blueprint_service = blueprint_service or BlueprintRepositoryService()
        self.llm_service = llm_service
        self.template_manager = template_manager
        self.enable_framework_adaptation = enable_framework_adaptation

        if not self.llm_service:
            raise ValueError("LLM service is required")
        if not self.template_manager:
            raise ValueError("Template manager is required")
        
        # Initialize framework adaptation services
        if self.enable_framework_adaptation:
            self.framework_adaptation_service = framework_adaptation_service or FrameworkAdaptationService(
                llm_service=self.llm_service
            )
            self.framework_intelligence_service = framework_intelligence_service or FrameworkIntelligenceService(
                llm_service=self.llm_service
            )
        else:
            self.framework_adaptation_service = None
            self.framework_intelligence_service = None

    def _apply_updates_to_blueprint(self, blueprint: Blueprint, updates: dict[str, any]) -> None:
        """
        Apply updates to a blueprint using its built-in update mechanism.

        Args:
            blueprint: The blueprint to update
            updates: dictionary of updates to apply
        """
        direct_update_fields = [
            "name",
            "description",
            "package_name",
            "package_version",
            "cve_ids",
            "tags",
            "code_snippets",
            "author",
            "version",
        ]
        direct_updates = {}
        for field in direct_update_fields:
            if field in updates:
                direct_updates[field] = updates[field]

        if direct_updates:
            blueprint.update(**direct_updates)

        if "metadata" in updates:
            blueprint.metadata.update(updates["metadata"])
            blueprint.updated_at = datetime.now()

    async def create_blueprint(
        self, vulnerability_data: dict[str, any], additional_dependencies: list[dict[str, str]] | None = None
    ) -> Blueprint:
        """
        Create a new blueprint from vulnerability data with dependency support.

        Args:
            vulnerability_data: dictionary with vulnerability information
            additional_dependencies: list of additional Maven dependencies
                Format: [{"group_id": "...", "artifact_id": "...", "version": "..."}]

        Returns:
            Created Blueprint object

        Raises:
            LLMError: When LLM generation fails
            TemplateError: When template processing fails
            VulnerabilityError: When blueprint creation or storage fails
        """
        try:
            logger.info(
                f"Creating blueprint for {vulnerability_data.get('package_name', 'Unknown')} \
                    with {len(additional_dependencies or [])} additional dependencies"
            )

            enhanced_vulnerability_data = vulnerability_data.copy()
            if additional_dependencies:
                enhanced_vulnerability_data["additional_dependencies"] = additional_dependencies
                dep_context = self._format_dependencies_for_llm(additional_dependencies)
                enhanced_vulnerability_data["dependency_context"] = dep_context

            try:
                blueprint_metadata = await self.llm_service.generate_blueprint_metadata(enhanced_vulnerability_data)
            except Exception as e:
                logger.error(f"Error generating blueprint metadata: {e}")
                raise LLMError(
                    message=f"Failed to generate blueprint metadata: {str(e)}",
                    cause=e,
                    remedy="Check LLM service configuration and connectivity.",
                )

            try:
                code_snippets = await self.llm_service.generate_vulnerability_code(enhanced_vulnerability_data)
            except Exception as e:
                logger.error(f"Error generating code snippets: {e}")
                raise LLMError(
                    message=f"Failed to generate code snippets: {str(e)}",
                    cause=e,
                    remedy="Check LLM service configuration and prompt templates.",
                )

            cve_id = vulnerability_data.get("cve_id", "Unknown-CVE")
            package_name = vulnerability_data.get("package_name", "Unknown-Package")
            package_version = vulnerability_data.get("package_version", "Unknown-Version")

            # Framework adaptation integration
            framework_adaptation_metadata = {}
            adapted_code_snippets = None

            # Check if this is a protocol-level vulnerability (should skip framework adaptation)
            classification_data = code_snippets.get("__classification__", {})
            vuln_level = classification_data.get("level", "").lower()
            is_protocol_level = vuln_level == "protocol_level"

            if is_protocol_level:
                logger.info(f"Skipping framework adaptation for PROTOCOL_LEVEL vulnerability: {package_name}")
                framework_adaptation_metadata = {
                    "framework_adaptation_enabled": False,
                    "skip_reason": "protocol_level_vulnerability",
                    "message": "Protocol-level vulnerabilities use protocol-specific templates without framework adaptation"
                }
            elif self.enable_framework_adaptation and self.framework_adaptation_service:
                try:
                    framework_adaptation_metadata, adapted_code_snippets = await self._perform_framework_adaptation(
                        enhanced_vulnerability_data, code_snippets
                    )
                    logger.info(f"Framework adaptation completed for {package_name}")

                    # If adaptation was successful and returned adapted code, use it instead of original
                    if adapted_code_snippets:
                        logger.info(f"Replacing {len(code_snippets)} original files with {len(adapted_code_snippets)} adapted files")
                        # Preserve special metadata keys from original code_snippets
                        classification_metadata = code_snippets.get("__classification__")
                        code_snippets = adapted_code_snippets
                        # Restore classification metadata if it existed
                        if classification_metadata:
                            code_snippets["__classification__"] = classification_metadata
                            logger.info(f"Preserved classification metadata: {classification_metadata.get('level')} (protocol: {classification_metadata.get('protocol_type')})")
                except Exception as e:
                    logger.warning(f"Framework adaptation failed for {package_name}: {e}")
                    # Don't fail blueprint creation if framework adaptation fails
                    framework_adaptation_metadata = {"framework_adaptation_error": str(e)}

            tags = self._generate_tags(vulnerability_data, additional_dependencies)

            dependency_metadata = {}
            if additional_dependencies:
                dependency_metadata["additional_dependencies"] = additional_dependencies
                dependency_metadata["dependency_count"] = len(additional_dependencies)

            osv_data = vulnerability_data.get("osv_data", {})
            cve_metadata = extract_vulnerability_metadata(osv_data) if osv_data else {}

            # Extract endpoint_metadata from code_snippets if present
            endpoint_metadata = code_snippets.pop("__endpoint_metadata__", None)
            if endpoint_metadata:
                logger.info(f"Extracted {len(endpoint_metadata)} endpoint(s) for blueprint")
            else:
                logger.debug("No endpoint metadata found in code snippets")

            # Extract classification metadata from code_snippets if present
            classification_metadata = code_snippets.pop("__classification__", {})
            if classification_metadata:
                logger.info(f"Classification: {classification_metadata.get('level')} "
                           f"(template: {classification_metadata.get('template')})")
            else:
                logger.debug("No classification metadata found in code snippets")

            # Merge framework adaptation metadata into blueprint metadata
            blueprint_metadata_complete = {
                "osv_data": vulnerability_data.get("osv_data", {}),
                "enhanced_metadata": blueprint_metadata,
                "vulnerability_details": vulnerability_data,
                "dependency_info": dependency_metadata,
                "cve_metadata": cve_metadata,
                "framework_adaptation": framework_adaptation_metadata,
                "classification": classification_metadata,
            }

            blueprint = Blueprint(
                blueprint_id="",  # Will be set by the repository service
                name=blueprint_metadata.get("name", f"Vulnerability in {package_name}"),
                description=blueprint_metadata.get(
                    "description",
                    vulnerability_data.get("description", "No description available"),
                ),
                package_name=package_name,
                package_version=package_version,
                cve_ids=[cve_id] if cve_id else [],
                metadata=blueprint_metadata_complete,
                tags=tags,
                author="cve-emulator-agent",
                version=1,
                created_at=datetime.now(),
                code_snippets=code_snippets,
                endpoint_metadata=endpoint_metadata,
                cvss_score=cve_metadata.get("cvss_score"),
                severity_level=cve_metadata.get("severity_level"),
                attack_vector=cve_metadata.get("attack_vector"),
                attack_complexity=cve_metadata.get("attack_complexity"),
            )

            result = await self.blueprint_service.store_blueprint(blueprint)

            if result.get("success"):
                logger.info(
                    f"Created blueprint {result.get('blueprint_id')} for {package_name}\
                        with {len(additional_dependencies or [])} additional dependencies"
                )
                blueprint.blueprint_id = result.get("blueprint_id", "")
                return blueprint
            else:
                logger.error(f"Error storing blueprint: {result.get('error')}")
                raise VulnerabilityError(
                    message=f"Failed to store blueprint: {result.get('error')}",
                    category=ErrorCategory.VALIDATION,
                    severity=ErrorSeverity.ERROR,
                    details={
                        "blueprint_name": blueprint.name,
                        "package_name": blueprint.package_name,
                    },
                )

        except Exception as e:
            if isinstance(e, (LLMError, TemplateError, VulnerabilityError)):
                raise

            logger.error(f"Error creating blueprint: {e}")
            raise VulnerabilityError(
                message=f"Blueprint creation failed: {str(e)}",
                category=ErrorCategory.CODE_GENERATION,
                severity=ErrorSeverity.ERROR,
                cause=e,
                details={"package_name": vulnerability_data.get("package_name", "Unknown")},
            )

    async def create_blueprint_with_guidance(
        self, vulnerability_data: dict[str, any], additional_dependencies: list[dict[str, str]] | None = None
    ) -> Blueprint:
        """Blueprint creation with optional LLM analysis of similar blueprints."""
        try:
            similar_blueprints = await self.find_similar_blueprints(vulnerability_data)

            if similar_blueprints:
                logger.info(f"Found {len(similar_blueprints)} similar blueprints to guide generation")

                llm_analysis = await self._analyze_similar_blueprints_safe(vulnerability_data, similar_blueprints)

                # Create enhanced context (existing logic + optional LLM analysis)
                enhanced_data = vulnerability_data.copy()
                enhanced_data["additional_dependencies"] = additional_dependencies or []

                if llm_analysis:
                    enhanced_data["similarity_analysis"] = llm_analysis
                    logger.info("Blueprint creation with LLM similarity analysis")

                examples = self._format_similar_examples(similar_blueprints)
                enhanced_data["similar_examples"] = examples

                combined_dependencies = self._combine_dependencies(additional_dependencies, similar_blueprints)

                return await self.create_blueprint(enhanced_data, combined_dependencies)
            else:
                return await self.create_blueprint(vulnerability_data, additional_dependencies)

        except Exception as e:
            logger.error(f"Error creating blueprint with guidance: {e}")
            return await self.create_blueprint(vulnerability_data, additional_dependencies)

    async def _analyze_similar_blueprints_safe(self, vulnerability_data: dict, similar_blueprints: list) -> str:
        """Safely analyze similar blueprints with LLM without breaking existing flow."""
        try:
            if not self.llm_service or not self.llm_service.get_prompt_template("similar_blueprints_analysis"):
                logger.debug("Similar blueprints analysis prompt not available")
                return ""
            try:
                analysis = await asyncio.wait_for(
                    self.llm_service.analyze_similar_blueprints(vulnerability_data, similar_blueprints),
                    timeout=45.0,
                )
                return analysis or ""
            except asyncio.TimeoutError:
                logger.warning("Similar blueprints analysis timed out")
                return ""

        except Exception as e:
            logger.debug(f"Error in safe similar blueprints analysis: {e}")
            return ""

    def _combine_dependencies(self, additional_dependencies: list, similar_blueprints: list) -> list:
        """Combine provided dependencies with examples from similar blueprints."""
        combined_dependencies = list(additional_dependencies or [])

        for blueprint in similar_blueprints:
            if "dependency_info" in blueprint.metadata:
                dep_info = blueprint.metadata["dependency_info"]
                if "additional_dependencies" in dep_info:
                    for dep_example in dep_info["additional_dependencies"]:
                        is_duplicate = any(
                            dep["group_id"] == dep_example["group_id"]
                            and dep["artifact_id"] == dep_example["artifact_id"]
                            for dep in combined_dependencies
                        )
                        if not is_duplicate:
                            combined_dependencies.append(dep_example)

        return combined_dependencies

    def _format_dependencies_for_llm(self, dependencies: list[dict[str, str]]) -> str:
        """
        Format dependencies for LLM consumption in prompts using template-based descriptions.

        PROMPT TEMPLATE USAGE:
        - May call prompt_manager.format_prompt("package_description", package_key=...) if template exists
        - This is a SIMPLE template (v1.0.0) - just string replacement, no enrichers
        - Falls back to LLM-based description generation if no template available

        Args:
            dependencies: List of dependency dictionaries with group_id, artifact_id, version

        Returns:
            Formatted dependency string for LLM prompt inclusion
        """
        if not dependencies:
            return ""

        formatted = "Additional Dependencies:\n"
        for dep in dependencies:
            artifact_id = dep.get("artifact_id", "")
            group_id = dep.get("group_id", "")
            version = dep.get("version", "")

            formatted += f"- {group_id}:{artifact_id}:{version}\n"

            # Get description from template system or supported packages
            description = self._get_dependency_description(group_id, artifact_id)
            if description:
                formatted += f"  ({description})\n"

        return formatted

    def _get_dependency_description(self, group_id: str, artifact_id: str) -> str:
        """Get dependency description using available template system and supported packages."""
        # Check if we have template information for this dependency
        package_key = f"{group_id}:{artifact_id}"

        # Load supported packages configuration for description mapping
        try:
            supported_packages = load_supported_packages()

            # If package is in supported list, we can derive its description
            if package_key in supported_packages:
                return self._derive_description_from_package_info(group_id, artifact_id)
        except Exception:
            pass

        # Fallback to pattern-based description
        return self._get_pattern_based_description(group_id)

    def _derive_description_from_package_info(self, group_id: str, artifact_id: str) -> str:
        """Derive description from package information using LLM-driven approach."""
        # Use template manager if available to get more detailed info
        if hasattr(self, "template_manager") and self.template_manager:
            try:
                # Check if we have import templates for this package
                package_key = f"{group_id}:{artifact_id}"
                template_info = self._get_template_info_for_package(package_key)
                if template_info:
                    return template_info
            except Exception:
                pass

        # Use LLM to generate description with external prompt template
        try:
            package_key = f"{group_id}:{artifact_id}"
            prompt = prompt_manager.format_prompt("package_description", package_key=package_key)

            response = self.llm_service.generate_text(prompt, max_tokens=100)
            if response and response.strip():
                return response.strip()
        except Exception as e:
            logger.debug(f"LLM description generation failed for {group_id}:{artifact_id}: {e}")

        # Simple fallback based on package structure
        return f"{artifact_id} - Java library from {group_id}"

    def _get_template_info_for_package(self, package_key: str) -> str:
        """Get template information for a specific package from template system."""
        try:
            # Try to get information from the template manager directly
            if hasattr(self.template_manager, 'get_package_info'):
                return self.template_manager.get_package_info(package_key)
            
            # Check if there are any import templates for this package
            if hasattr(self.template_manager, 'has_template_for_package'):
                if self.template_manager.has_template_for_package(package_key):
                    return f"Template available for {package_key}"
                    
        except Exception:
            pass

        return ""

    def _format_similar_examples(self, similar_blueprints: list[Blueprint]) -> str:
        """Format similar blueprint examples for LLM context."""
        if not similar_blueprints:
            return "No similar examples available"

        examples_text = "Similar Blueprint Examples:\n\n"

        for i, blueprint in enumerate(similar_blueprints[:3], 1):
            examples_text += f"Example {i}:\n"
            examples_text += f"- Package: {blueprint.package_name}\n"
            examples_text += f"- CVE: {', '.join(blueprint.cve_ids)}\n"
            examples_text += f"- Description: {blueprint.description[:200]}...\n"

            if blueprint.code_snippets:
                first_snippet_name = list(blueprint.code_snippets.keys())[0]
                first_snippet = blueprint.code_snippets[first_snippet_name]
                examples_text += f"- Code Preview ({first_snippet_name}):\n"
                examples_text += f"  {first_snippet[:300]}...\n"

            examples_text += "\n"

        return examples_text.strip()

    def _generate_tags(
        self, vulnerability_data: dict[str, any], additional_dependencies: list[dict[str, str]] | None = None
    ) -> list[str]:
        """Generate tags for a blueprint using dynamic template-based approach."""
        tags = []

        # Extract package-based tags
        package_name = vulnerability_data.get("package_name", "")
        if package_name:
            package_tags = self._extract_package_tags(package_name)
            tags.extend(package_tags)

        # Extract dependency-based tags dynamically
        if additional_dependencies:
            dependency_tags = self._extract_dependency_tags(additional_dependencies)
            tags.extend(dependency_tags)

        # Extract vulnerability metadata tags
        vuln_tags = self._extract_vulnerability_tags(vulnerability_data)
        tags.extend(vuln_tags)

        # Extract CVE-based tags
        cve_tags = self._extract_cve_tags(vulnerability_data.get("cve_id", ""))
        tags.extend(cve_tags)

        return list(set(tags))

    def _extract_package_tags(self, package_name: str) -> list[str]:
        """Extract tags from package name using LLM-driven approach."""
        tags = []

        if ":" in package_name:
            _, artifact_id = package_name.split(":", 1)
            tags.append(artifact_id)

            # Use LLM to generate contextual tags with external prompt template
            try:
                prompt = prompt_manager.format_prompt("package_tags", package_name=package_name)

                response = self.llm_service.generate_text(prompt, max_tokens=50)
                if response and response.strip():
                    llm_tags = [tag.strip() for tag in response.strip().split(',') if tag.strip()]
                    tags.extend(llm_tags[:5])  # Limit to 5 LLM-generated tags
            except Exception as e:
                logger.debug(f"LLM tag generation failed for {package_name}: {e}")

        else:
            # Handle non-Maven format packages
            parts = package_name.split(".")
            if parts:
                tags.append(parts[-1])

        return tags

    def _extract_dependency_tags(self, dependencies: list[dict[str, str]]) -> list[str]:
        """Extract tags from additional dependencies using template system."""
        tags = []

        for dep in dependencies:
            group_id = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")

            # Get package-specific tags
            package_name = f"{group_id}:{artifact_id}"
            dep_tags = self._extract_package_tags(package_name)
            tags.extend(dep_tags)

            # Functional tags are now handled by the LLM-driven _extract_package_tags method

        return tags

    def _extract_vulnerability_tags(self, vulnerability_data: dict[str, any]) -> list[str]:
        """Extract tags from vulnerability metadata."""
        tags = []

        # Vulnerability type
        vuln_type = vulnerability_data.get("vulnerability_type", "")
        if vuln_type:
            tags.append(vuln_type.lower())

            # Add category tags based on vulnerability type
            if "deserialization" in vuln_type.lower():
                tags.append("deserialization")
            elif "injection" in vuln_type.lower():
                tags.append("injection")
            elif "overflow" in vuln_type.lower():
                tags.append("overflow")

        # Severity level
        severity = vulnerability_data.get("severity", "")
        if severity:
            tags.append(severity.lower())

        # Attack vector if available
        attack_vector = vulnerability_data.get("attack_vector", "")
        if attack_vector:
            tags.append(f"attack-{attack_vector.lower()}")

        return tags

    def _extract_cve_tags(self, cve_id: str) -> list[str]:
        """Extract tags from CVE ID."""
        tags = []

        if cve_id and "CVE-" in cve_id:
            try:
                year_match = re.search(r"CVE-(\d{4})-", cve_id)
                if year_match:
                    year = year_match.group(1)
                    tags.append(f"cve-{year}")

                    # Add decade tag for broader categorization
                    decade = (int(year) // 10) * 10
                    tags.append(f"cve-{decade}s")

            except Exception as e:
                logger.error(f"Unable to extract CVE year from {cve_id}: {e}")

        return tags

    async def update_blueprint(self, blueprint_id: str, updates: dict[str, any]) -> dict[str, any]:
        """
        Update an existing blueprint with new information.

        Args:
            blueprint_id: ID of the blueprint to update
            updates: dictionary of fields to update

        Returns:
            dictionary with update result
        """
        try:
            blueprint = await self.blueprint_service.get_blueprint(blueprint_id)
            if not blueprint:
                return {
                    "success": False,
                    "error": f"Blueprint {blueprint_id} not found",
                }

            original_blueprint_dict = blueprint.to_dict()

            self._apply_updates_to_blueprint(blueprint, updates)

            result = await self.blueprint_service.store_blueprint(blueprint)

            if result.get("success"):
                updated_blueprint_dict = blueprint.to_dict()
                changes = summarize_blueprint_changes(original_blueprint_dict, updated_blueprint_dict)

                return {
                    "success": True,
                    "blueprint_id": blueprint_id,
                    "changes": changes,
                    "message": f"Blueprint {blueprint_id} updated successfully",
                }
            else:
                return {
                    "success": False,
                    "error": result.get("error", "Unknown error updating blueprint"),
                }

        except Exception as e:
            logger.error(f"Error updating blueprint {blueprint_id}: {e}")
            return {"success": False, "error": str(e)}

    async def find_similar_blueprints(self, vulnerability_data: dict[str, any], limit: int = 3) -> list[Blueprint]:
        """
        Find blueprints similar to the given vulnerability data with enhanced matching.

        Args:
            vulnerability_data: Vulnerability information
            limit: Maximum number of similar blueprints to return

        Returns:
            List of similar blueprints ranked by relevance
        """
        try:
            blueprint_scores = []
            all_blueprints = self.blueprint_service.list_blueprints()

            for bp_meta in all_blueprints:
                try:
                    blueprint = await self.blueprint_service.get_blueprint(bp_meta["id"])
                    if not blueprint:
                        continue

                    score = self._calculate_similarity_score(blueprint, vulnerability_data)
                    if score > 0:
                        blueprint_scores.append((blueprint, score))

                except Exception as e:
                    logger.warning(f"Error loading blueprint {bp_meta['id']}: {e}")

            blueprint_scores.sort(key=lambda x: x[1], reverse=True)
            similar_blueprints = [bp for bp, score in blueprint_scores[:limit]]

            logger.info(
                f"Found {len(similar_blueprints)} similar blueprints with scores: {[score for _, score in blueprint_scores[:limit]]}"
            )
            return similar_blueprints

        except Exception as e:
            logger.error(f"Error finding similar blueprints: {e}")
            return []

    def _calculate_similarity_score(self, blueprint: Blueprint, vulnerability_data: dict[str, any]) -> float:
        """Calculate similarity score between a blueprint and vulnerability data"""
        score = 0.0

        target_package = vulnerability_data.get("package_name", "")
        if target_package and target_package in blueprint.package_name:
            score += 0.4  # Exact package match
        elif target_package and any(part in blueprint.package_name for part in target_package.split(":")):
            score += 0.2  # Partial package match

        target_cve = vulnerability_data.get("cve_id", "")
        if target_cve and blueprint.cve_ids:
            target_year = self._extract_cve_year(target_cve)
            blueprint_years = [self._extract_cve_year(cve) for cve in blueprint.cve_ids]
            if target_year and target_year in blueprint_years:
                score += 0.2

        target_vuln_type = vulnerability_data.get("vulnerability_type", "").lower()
        blueprint_vuln_type = blueprint.metadata.get("enhanced_metadata", {}).get("vulnerability_type", "").lower()
        if target_vuln_type and blueprint_vuln_type and target_vuln_type in blueprint_vuln_type:
            score += 0.2

        target_tags = set(self._generate_tags(vulnerability_data))
        blueprint_tags = set(blueprint.tags)
        tag_overlap = len(target_tags & blueprint_tags) / max(len(target_tags | blueprint_tags), 1)
        score += tag_overlap * 0.1

        # Code quality bonus (blueprints with more code snippets are better examples)
        if blueprint.code_snippets:
            code_quality = min(len(blueprint.code_snippets) / 3.0, 0.1)
            score += code_quality

        return min(score, 1.0)

    def _extract_cve_year(self, cve_id: str) -> str:
        """Extract year from CVE ID."""
        match = re.search(r"CVE-(\d{4})-", cve_id)
        return match.group(1) if match else ""

    async def _load_blueprints(self, blueprint_metadata_list: list[dict[str, any]]) -> list[Blueprint]:
        """Load full blueprints from metadata list."""
        blueprints = []

        for metadata in blueprint_metadata_list:
            blueprint_id = metadata.get("id")
            if blueprint_id:
                blueprint = await self.blueprint_service.get_blueprint(blueprint_id)
                if blueprint:
                    blueprints.append(blueprint)

        return blueprints

    def extract_template_from_blueprint(self, blueprint: Blueprint) -> dict[str, any]:
        """
        Extract a reusable template from a successful blueprint.

        Args:
            blueprint: Blueprint to extract template from

        Returns:
            Template data dictionary
        """
        template_data = {
            "name": f"extracted_{blueprint.blueprint_id[:8]}",
            "template_type": self._detect_template_type(blueprint),
            "metadata": {
                "vulnerability_type": blueprint.metadata.get("enhanced_metadata", {}).get(
                    "vulnerability_type", "unknown"
                ),
                "severity": blueprint.metadata.get("enhanced_metadata", {}).get("severity", "UNKNOWN"),
                "description": blueprint.description,
            },
            "sections": {},
        }

        for name, code in blueprint.code_snippets.items():
            if name.endswith(".java"):
                imports = "\n".join(re.findall(r"import\s+[^;]+;", code))
                if imports:
                    template_data["sections"]["imports"] = imports

                # Potential imporvements possible
                main_method = re.search(
                    r"(public\s+static\s+void\s+main\s*\([^)]*\)\s*\{[^\}]*\})",
                    code,
                    re.DOTALL,
                )
                if main_method:
                    template_data["sections"]["demo_code"] = main_method.group(1)
                break

        for name, code in blueprint.code_snippets.items():
            if not name.endswith(".java") and not name.endswith(".xml"):
                template_data.setdefault("sections", {}).setdefault("resources", {})[name] = {
                    "content": code,
                    "description": f"Resource file from blueprint {blueprint.blueprint_id}",
                }

        return template_data

    async def regenerate_code(self, blueprint_id: str) -> dict[str, any]:
        """
        Regenerate code snippets for a blueprint.

        Args:
            blueprint_id: ID of the blueprint

        Returns:
            dictionary with regeneration result
        """
        try:
            blueprint = await self.blueprint_service.get_blueprint(blueprint_id)
            if not blueprint:
                return {
                    "success": False,
                    "error": f"Blueprint {blueprint_id} not found",
                }
            original_code_snippets = blueprint.code_snippets.copy()

            vulnerability_data = {
                "cve_id": blueprint.cve_ids[0] if blueprint.cve_ids else "Unknown-CVE",
                "package_name": blueprint.package_name,
                "package_version": blueprint.package_version,
                "description": blueprint.description,
                "summary": blueprint.metadata.get("enhanced_metadata", {}).get("summary", blueprint.description),
                "references": blueprint.metadata.get("osv_data", {}).get("references", []),
            }

            try:
                new_code_snippets = await self.llm_service.generate_vulnerability_code(vulnerability_data)
            except Exception as e:
                logger.error(f"Error generating code snippets: {e}")
                return {
                    "success": False,
                    "error": f"Failed to generate code snippets: {str(e)}",
                }

            self._apply_updates_to_blueprint(blueprint, {"code_snippets": new_code_snippets})

            result = await self.blueprint_service.store_blueprint(blueprint)

            if result.get("success"):
                code_diff = compare_code_snippets(original_code_snippets, new_code_snippets)

                return {
                    "success": True,
                    "blueprint_id": blueprint_id,
                    "name": blueprint.name,
                    "code_snippets": list(new_code_snippets.keys()),
                    "diff": code_diff,
                    "message": f"Code snippets regenerated for blueprint {blueprint_id}",
                }
            else:
                return {
                    "success": False,
                    "error": result.get("error", "Unknown error updating blueprint"),
                }

        except Exception as e:
            logger.error(f"Error regenerating code for blueprint {blueprint_id}: {e}")
            return {"success": False, "error": str(e)}

    async def create_blueprint_from_template(
        self, template_name: str, cve_id: str, package_name: str, package_version: str
    ) -> dict[str, any]:
        """
        Create a blueprint from a predefined template.

        Args:
            template_name: Name of the template to use
            cve_id: CVE ID
            package_name: Package name
            package_version: Package version

        Returns:
            dictionary with creation result
        """
        try:
            template = self.template_manager.get_template_by_name(template_name)

            blueprint = Blueprint(
                blueprint_id="",  # Will be set by the repository service
                name=f"{template.vulnerability_type.capitalize()} vulnerability in {package_name}",
                description=template.description,
                package_name=package_name,
                package_version=package_version,
                cve_ids=[cve_id] if cve_id else [],
                metadata={
                    "template_source": template_name,
                    "enhanced_metadata": {
                        "vulnerability_type": template.vulnerability_type,
                        "vulnerability_category": template.vulnerability_category.value,
                        "severity": template.severity,
                    },
                },
                tags=[
                    template.vulnerability_category.value,
                    template.vulnerability_type,
                ],
                author="cve-emulator-agent",
                version=1,
                created_at=datetime.now(),
                code_snippets={},
            )

            code_snippets = {}

            main_class_name = get_class_name_for_package(package_name)
            imports = template.get_imports()
            demo_code = template.get_demo_code()

            code_snippets[f"{main_class_name}.java"] = f"""
                                                            {imports}

                                                            /**
                                                            * Vulnerability demonstration for {cve_id} in {package_name}
                                                            * Type: {template.vulnerability_type}
                                                            * Severity: {template.severity}
                                                            */
                                                            public class {main_class_name} {{
                                                                public static void main(String[] args) {{
                                                                    System.out.println("Vulnerability demonstration for {cve_id}");
                                                                    System.out.println("Package: {package_name} {package_version}");

                                                                    try {{
                                                                        // Demonstrate the vulnerability
                                                                        demoVulnerability();
                                                                    }} catch (Exception e) {{
                                                                        System.err.println("Error: " + e.getMessage());
                                                                        e.printStackTrace();
                                                                    }}
                                                                }}

                                                                private static void demoVulnerability() {{
                                                            {demo_code}
                                                                }}
                                                            }}
                                                        """

            resources = template.get_resources()
            for name, resource in resources.items():
                code_snippets[name] = resource["content"]

            blueprint.code_snippets = code_snippets

            result = await self.blueprint_service.store_blueprint(blueprint)

            if result.get("success"):
                return {
                    "success": True,
                    "blueprint_id": result.get("blueprint_id"),
                    "name": blueprint.name,
                    "code_snippets": list(code_snippets.keys()),
                    "message": f"Blueprint created from template {template_name}",
                }
            else:
                return {
                    "success": False,
                    "error": result.get("error", "Unknown error creating blueprint"),
                }

        except Exception as e:
            logger.error(f"Error creating blueprint from template {template_name}: {e}")
            return {"success": False, "error": str(e)}

    async def _perform_framework_adaptation(
        self,
        vulnerability_data: dict[str, any],
        code_snippets: dict[str, str]
    ) -> tuple[dict[str, any], dict[str, str] | None]:
        """
        Perform framework adaptation for the vulnerability using the Framework Adaptation Service.

        Args:
            vulnerability_data: Enhanced vulnerability data with context
            code_snippets: Generated code snippets to potentially adapt

        Returns:
            Tuple of (framework_metadata, adapted_code_snippets)
            - framework_metadata: Dictionary containing framework adaptation metadata
            - adapted_code_snippets: Dictionary of adapted code files (or None if no adaptation)
        """
        try:
            # Create adaptation context from vulnerability data
            adaptation_context = AdaptationContext(
                package_name=vulnerability_data.get("package_name", ""),
                package_version=vulnerability_data.get("package_version", "1.0.0"),
                vulnerability_type=vulnerability_data.get("vulnerability_type", "unknown"),
                vulnerability_description=vulnerability_data.get("description", ""),
                cve_ids=[vulnerability_data.get("cve_id")] if vulnerability_data.get("cve_id") else [],
                osv_metadata=vulnerability_data.get("osv_data", {}),
                existing_dependencies=vulnerability_data.get("additional_dependencies", []),
                additional_context={
                    "code_snippets": code_snippets,
                    "blueprint_context": "blueprint_creation",
                    "original_vulnerability_data": vulnerability_data
                }
            )
            
            # Perform framework adaptation analysis
            logger.info(f"Starting framework adaptation for {adaptation_context.package_name}")
            adaptation_result = await self.framework_adaptation_service.analyze_and_adapt(adaptation_context)
            
            # Extract metadata for blueprint
            framework_metadata = {
                "framework_adaptation_enabled": True,
                "adaptation_timestamp": adaptation_result.timestamp.isoformat(),
                "adaptation_success": adaptation_result.success,
                "adaptation_time_seconds": adaptation_result.adaptation_time_seconds,
            }

            # Extract adapted code snippets
            adapted_code_snippets = None

            if adaptation_result.success:
                # Include successful adaptation details
                if adaptation_result.framework_choice:
                    framework_metadata.update({
                        "selected_framework": adaptation_result.framework_choice.selected_framework.value,
                        "framework_confidence": adaptation_result.framework_choice.confidence_score,
                        "framework_rationale": adaptation_result.framework_choice.rationale,
                        "adaptation_strategy": adaptation_result.framework_choice.adaptation_strategy.value,
                        "estimated_complexity": adaptation_result.framework_choice.estimated_complexity.value,
                        "required_changes": adaptation_result.framework_choice.required_changes,
                    })

                if adaptation_result.code_adaptation:
                    framework_metadata.update({
                        "code_adapted": True,
                        "source_framework": adaptation_result.code_adaptation.source_framework.value,
                        "target_framework": adaptation_result.code_adaptation.target_framework.value,
                        "changes_made": adaptation_result.code_adaptation.changes_made,
                        "dependencies_added": adaptation_result.code_adaptation.dependencies_added,
                        "framework_features": adaptation_result.code_adaptation.framework_specific_features,
                    })

                    # Parse adapted code into file snippets
                    if adaptation_result.code_adaptation.adapted_code:
                        try:
                            from utils.core.common import extract_files_from_llm_response
                            adapted_code_snippets = extract_files_from_llm_response(adaptation_result.code_adaptation.adapted_code)

                            # VALIDATION SAFETY NET: Remove LLM-generated config files that should come from templates
                            config_file_patterns = ['.xml', '.properties', '.yml', '.yaml', '.conf']
                            original_count = len(adapted_code_snippets)
                            config_files_removed = []

                            for file_path in (adapted_code_snippets.keys()):
                                if any(file_path.endswith(pattern) for pattern in config_file_patterns):
                                    config_files_removed.append(file_path)
                                    del adapted_code_snippets[file_path]

                            if config_files_removed:
                                logger.info(f"VALIDATION SAFETY NET: LLM generated {len(config_files_removed)} config files (removing them - templates will inject these):")
                                for cf in config_files_removed:
                                    logger.info(f"Removed: {cf}")

                            logger.info(f"Parsed adapted code into {len(adapted_code_snippets)} files (Java/source only, {original_count - len(adapted_code_snippets)} config files filtered)")
                            logger.info(f"Final file count: {len(adapted_code_snippets)} Java files")

                            # Preserve endpoint_metadata from framework adaptation if present
                            if adaptation_result.code_adaptation.endpoint_metadata:
                                logger.info(f"Preserving {len(adaptation_result.code_adaptation.endpoint_metadata)} endpoint(s) from framework adaptation")
                                adapted_code_snippets["__endpoint_metadata__"] = adaptation_result.code_adaptation.endpoint_metadata

                        except Exception as e:
                            logger.warning(f"Failed to parse adapted code: {e}")
                            adapted_code_snippets = None

                # Include template customizations
                if adaptation_result.template_customizations:
                    framework_metadata["template_customizations"] = list(adaptation_result.template_customizations.keys())

                # Include deployment configuration
                if adaptation_result.deployment_configuration:
                    framework_metadata["deployment_config"] = adaptation_result.deployment_configuration

                # Include performance metrics
                if adaptation_result.performance_metrics:
                    framework_metadata["performance_metrics"] = adaptation_result.performance_metrics

                logger.info(f"Framework adaptation successful for {adaptation_context.package_name}: "
                           f"{adaptation_result.framework_choice.selected_framework.value if adaptation_result.framework_choice else 'unknown'}")
            else:
                # Include failure details
                framework_metadata.update({
                    "adaptation_errors": adaptation_result.error_details,
                    "adaptation_warnings": adaptation_result.warnings,
                })
                logger.warning(f"Framework adaptation failed for {adaptation_context.package_name}: "
                             f"{'; '.join(adaptation_result.error_details)}")

            # Include LLM usage statistics
            if adaptation_result.llm_usage_stats:
                framework_metadata["llm_usage"] = adaptation_result.llm_usage_stats

            return framework_metadata, adapted_code_snippets
            
        except Exception as e:
            logger.error(f"Framework adaptation error: {e}")
            return {
                "framework_adaptation_enabled": True,
                "adaptation_success": False,
                "adaptation_error": str(e),
                "adaptation_timestamp": datetime.now().isoformat(),
            }, None

    def _detect_template_type(self, blueprint: Blueprint) -> str:
        """Detect the appropriate template type based on blueprint content using framework intelligence."""
        try:
            # Use framework intelligence service for detection
            enhanced_metadata = blueprint.metadata.get("enhanced_metadata", {})
            package_name = enhanced_metadata.get("package_name", "")
            
            # Extract package name for framework detection
            
            # Use framework intelligence service for detection
            if hasattr(self, 'framework_intelligence_service') and self.framework_intelligence_service:
                # This would be async, but for template type detection we need sync
                # Use simple pattern matching based on package name
                package_lower = package_name.lower()
                
                # Check against loaded detection patterns
                for framework_type, config in self.framework_intelligence_service.dependency_signatures.items():
                    required_patterns = config.get("required_patterns", [])
                    optional_patterns = config.get("optional_patterns", [])
                    
                    # Check if package matches any patterns
                    all_patterns = required_patterns + optional_patterns
                    for pattern in all_patterns:
                        # Simple string matching (not regex for simplicity in sync context)
                        pattern_simple = pattern.replace(r'\.', '.').replace(r'\\', '')
                        if pattern_simple.lower() in package_lower:
                            return self._framework_type_to_template_type(framework_type)
            
            # Fallback to basic detection
            return self._basic_template_detection(package_name, enhanced_metadata)
            
        except Exception as e:
            logger.warning(f"Template type detection failed: {e}")
            return "java"  # Safe default
    
    def _framework_type_to_template_type(self, framework_type) -> str:
        """Map framework type to template type string."""
        from shared.types import FrameworkType
        
        mapping = {
            FrameworkType.SPRING_BOOT: "java",
            FrameworkType.APACHE_STRUTS: "java", 
            FrameworkType.MICRONAUT: "java",
            FrameworkType.QUARKUS: "java",
        }
        return mapping.get(framework_type, "java")
    
    def _basic_template_detection(self, package_name: str, metadata: dict) -> str:
        """Basic template detection fallback."""
        package_lower = package_name.lower()
        
        # Simple language detection
        if any(indicator in package_lower for indicator in ["spring", "java", "apache", "maven"]):
            return "java"
        elif any(indicator in package_lower for indicator in ["python", "django", "flask"]):
            return "python"
        elif any(indicator in package_lower for indicator in ["javascript", "node", "npm"]):
            return "javascript"
        elif any(indicator in package_lower for indicator in ["php", "laravel", "wordpress"]):
            return "php"
        
        # Check vulnerability type
        vuln_type = metadata.get("vulnerability_type", "").lower()
        if "sql injection" in vuln_type or "xss" in vuln_type:
            return "web"
        elif "rce" in vuln_type or "remote code execution" in vuln_type:
            return "generic"
            
        return "java"  # Default
