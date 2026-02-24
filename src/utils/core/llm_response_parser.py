import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class LLMResponseParser:
    """
    Centralized parser for all LLM response formats.

    This class consolidates 10+ different parsing methods that were previously
    scattered across llm_service.py and vulnerability_detector.py.

    All methods are static for easy importing without instantiation.
    """

    @staticmethod
    def extract_json(response: str) -> dict:
        """
        Extract JSON from LLM response with flexible parsing.

        Tries multiple strategies:
        1. Direct JSON parsing
        2. Markdown code blocks (```json ... ```)
        3. Generic code blocks (``` ... ```)
        4. Pattern matching for specific fields
        5. Last resort: field-by-field extraction

        Args:
            response: Raw LLM response that may contain JSON

        Returns:
            Parsed JSON dictionary

        Raises:
            json.JSONDecodeError: If no valid JSON can be extracted
        """
        logger.debug(f"JSON EXTRACTION: Attempting to parse response of length {len(response)}")

        # First try to parse the entire response as JSON
        try:
            result = json.loads(response.strip(), strict=False)
            logger.debug("JSON EXTRACTION: Direct parsing successful")
            return result
        except json.JSONDecodeError as e:
            logger.debug(f"JSON EXTRACTION: Direct parsing failed: {e}")

        # Look for JSON within markdown code blocks and other patterns
        json_patterns = [
            (r"```json\s*\n(.*?)\n```", "json code block"),
            (r"```\s*\n(.*?)\n```", "generic code block"),
            # Framework selection patterns
            (r'\{[^{}]*"selected_framework"[^{}]*\}', "simple framework JSON"),
            (r'\{.*?"selected_framework".*?\}', "extended framework JSON"),
            # Dependency patterns
            (r'\{[^{}]*"dependencies_added"[^{}]*\}', "simple dependencies JSON"),
            (r'\{.*?"dependencies_added".*?\}', "extended dependencies JSON"),
            # Validation patterns
            (r'\{[^{}]*"vulnerability_demonstrated"[^{}]*\}', "simple validation JSON"),
            (r'\{.*?"vulnerability_demonstrated".*?\}', "extended validation JSON"),
            (r'\{[^{}]*"simulation_detected"[^{}]*\}', "simple simulation JSON"),
            (r'\{.*?"simulation_detected".*?\}', "extended simulation JSON"),
            # Generic patterns
            (r"\{[^{}]*\}", "simple brace pattern"),
            (r"\{.*\}", "any brace content"),
        ]

        for pattern, description in json_patterns:
            logger.debug(f"JSON EXTRACTION: Trying pattern: {description}")
            matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)

            for i, match in enumerate(matches):
                try:
                    result = json.loads(match.strip())
                    logger.info(f"JSON EXTRACTION SUCCESS: Found valid JSON using {description} (match {i+1})")
                    return result
                except json.JSONDecodeError as e:
                    logger.debug(f"Match {i+1} failed: {e}")
                    continue

        # Last resort: try to find individual JSON fields and construct object
        logger.warning("JSON EXTRACTION: Attempting field-by-field extraction as last resort")
        try:
            framework_match = re.search(r'"selected_framework"\s*:\s*"([^"]+)"', response, re.IGNORECASE)
            confidence_match = re.search(r'"confidence_score"\s*:\s*([\d.]+)', response, re.IGNORECASE)
            rationale_match = re.search(r'"rationale"\s*:\s*"([^"]+)"', response, re.IGNORECASE)

            if framework_match:
                result = {
                    "selected_framework": framework_match.group(1),
                    "confidence_score": float(confidence_match.group(1)) if confidence_match else 0.5,
                    "rationale": rationale_match.group(1) if rationale_match else "Extracted from partial response",
                }
                logger.warning(f"JSON EXTRACTION: Reconstructed from fields: {result}")
                return result
        except Exception as e:
            logger.error(f"JSON EXTRACTION: Field extraction failed: {e}")

        # If no JSON found, raise the original error
        logger.error("JSON EXTRACTION FAILED: No valid JSON found in response")
        logger.error(f"Response preview: {response[:200]}...")
        raise json.JSONDecodeError("No valid JSON found in response", response, 0)

    @staticmethod
    def parse_vulnerability_code(response: str) -> dict[str, str]:
        """
        Parse code snippets from vulnerability generation LLM response.

        Extracts code blocks with various formats:
        - ```file:path/to/file.java ... ```
        - ```java ... ```
        - ```xml ... ```
        - Generic ``` ... ``` blocks

        Args:
            response: Raw LLM response containing code blocks

        Returns:
            Dictionary mapping filename to code content
        """
        logger.info("=" * 60)
        logger.info("LLM RESPONSE PARSING - DEBUG SESSION")
        logger.info("=" * 60)

        # Log response characteristics
        logger.info(f"Response length: {len(response)} characters")
        logger.info(f"Response line count: {len(response.splitlines())}")

        # Search for code block indicators
        code_block_indicators = [
            "```",
            "file:",
            "```java",
            "```xml",
            "```yaml",
            "```properties",
            "class ",
            "import ",
            "public static void main",
        ]

        logger.info("Code block indicators found:")
        for indicator in code_block_indicators:
            count = response.count(indicator)
            if count > 0:
                logger.info(f"  '{indicator}': {count} occurrences")

        # Try different parsing patterns and log results
        code_snippets = {}

        # Pattern 1: file: markers
        logger.info("\nTrying Pattern 1: file: markers")
        file_pattern = r"```file:([^\n]+)\n(.*?)```"
        file_matches = re.findall(file_pattern, response, re.DOTALL)
        logger.info(f"Pattern 1 matches: {len(file_matches)}")

        for i, (filepath, code) in enumerate(file_matches):
            logger.info(f"  Match {i + 1}: '{filepath.strip()}' ({len(code)} chars)")
            clean_path = filepath.strip()
            clean_code = code.strip()
            if clean_code:
                code_snippets[clean_path] = clean_code

        # Pattern 2: language-specific blocks
        logger.info("\nTrying Pattern 2: language-specific blocks")
        lang_patterns = [
            (r"```java\n(.*?)```", "java"),
            (r"```xml\n(.*?)```", "xml"),
            (r"```yaml\n(.*?)```", "yaml"),
            (r"```properties\n(.*?)```", "properties"),
        ]

        for pattern, lang in lang_patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            logger.info(f"  {lang} blocks found: {len(matches)}")

            for i, code in enumerate(matches):
                if code.strip():
                    filename = f"code_{lang}_{i + 1}.{lang}"
                    code_snippets[filename] = code.strip()
                    logger.info(f"    Added: {filename} ({len(code)} chars)")

        # Pattern 3: Generic code blocks
        logger.info("\nTrying Pattern 3: generic code blocks")
        generic_pattern = r"```\n(.*?)```"
        generic_matches = re.findall(generic_pattern, response, re.DOTALL)
        logger.info(f"Generic code blocks found: {len(generic_matches)}")

        for i, code in enumerate(generic_matches):
            if code.strip() and len(code.strip()) > 20:  # Only meaningful code blocks
                # Try to detect content type
                if "class " in code and "public static void main" in code:
                    filename = f"JavaClass_{i + 1}.java"
                elif "<project" in code or "<dependencies" in code:
                    filename = f"pom_{i + 1}.xml"
                elif code.strip().startswith("!!"):
                    filename = f"payload_{i + 1}.yaml"
                else:
                    filename = f"code_block_{i + 1}.txt"

                code_snippets[filename] = code.strip()
                logger.info(f"    Added: {filename} ({len(code)} chars)")

        # Log final results
        logger.info(f"Total files extracted: {len(code_snippets)}")

        for filename, content in code_snippets.items():
            logger.info(f"  {filename}: {len(content)} characters")
            # Log first 100 chars of each file
            preview = content[:100].replace("\n", "\\n")
            logger.info(f"    Preview: {preview}...")

        # If no structured code found, log this clearly
        if not code_snippets:
            logger.warning("NO STRUCTURED CODE FOUND - storing raw response")
            logger.info("This might indicate:")
            logger.info("1. LLM didn't use expected code block format")
            logger.info("2. Response is primarily text/explanation")
            logger.info("3. Code blocks are malformed or incomplete")
            logger.info("4. Different parsing patterns needed")

            # Store raw response for manual inspection
            code_snippets["implementation_guidance"] = response

        return code_snippets

    @staticmethod
    def parse_structured_response(response: str) -> dict:
        """
        Parse a structured LLM response with key-value pairs.

        Expected format:
            **ERROR_CLASSIFICATION**: value
            **SEVERITY**: value
            **ROOT_CAUSE**: value
            etc.

        Args:
            response: Raw LLM response with structured fields

        Returns:
            Dictionary of parsed fields (keys lowercased)
        """
        parsed = {}

        # Common patterns for structured responses
        patterns = {
            "ERROR_CLASSIFICATION": r"\*\*ERROR_CLASSIFICATION\*\*:\s*(.+)",
            "SEVERITY": r"\*\*SEVERITY\*\*:\s*(.+)",
            "ROOT_CAUSE": r"\*\*ROOT_CAUSE\*\*:\s*(.+)",
            "CONFIDENCE": r"\*\*CONFIDENCE\*\*:\s*([\d.]+)",
            "RECOVERY_FEASIBLE": r"\*\*RECOVERY_FEASIBLE\*\*:\s*(YES|NO)",
            "RECOVERY_STRATEGY": r"\*\*RECOVERY_STRATEGY\*\*:\s*(.+)",
            "PATTERN_MATCH": r"\*\*PATTERN_MATCH\*\*:\s*(YES|NO)",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key == "CONFIDENCE":
                    try:
                        parsed[key.lower()] = float(value)
                    except ValueError:
                        parsed[key.lower()] = 0.5
                elif key in ["RECOVERY_FEASIBLE", "PATTERN_MATCH"]:
                    parsed[key.lower()] = value.upper() == "YES"
                else:
                    parsed[key.lower()] = value

        return parsed

    @staticmethod
    def extract_dependencies(response: str) -> list[dict]:
        """
        Extract and validate dependency lists from LLM response.
        
        This provides a more robust extraction specifically for dependencies_added fields
        which are critical for proper build functionality.
        
        Args:
            response: Raw LLM response containing dependency information
            
        Returns:
            List of dependency dictionaries with group_id and artifact_id
        """
        logger.debug("DEPENDENCY EXTRACTION: Starting dependency-specific extraction")
        
        try:
            # First try standard JSON extraction
            data = LLMResponseParser.extract_json(response)
            if "dependencies_added" in data:
                deps = data["dependencies_added"]
                if isinstance(deps, list):
                    validated_deps = LLMResponseParser._validate_dependencies(deps)
                    logger.info(f"DEPENDENCY EXTRACTION: Found {len(validated_deps)} valid dependencies via JSON")
                    return validated_deps
        except json.JSONDecodeError:
            logger.debug("DEPENDENCY EXTRACTION: JSON extraction failed, trying pattern matching")
        
        # Fallback: Look for dependency patterns in text
        dependency_patterns = [
            # Look for dependencies_added arrays
            r'"dependencies_added"\s*:\s*\[(.*?)\]',
            # Look for individual dependency objects
            r'\{\s*"group_id"\s*:\s*"([^"]+)"\s*,\s*"artifact_id"\s*:\s*"([^"]+)"[^}]*\}',
        ]
        
        dependencies = []
        
        for pattern in dependency_patterns:
            matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
            logger.debug(f"DEPENDENCY EXTRACTION: Pattern found {len(matches)} matches")
            
            for match in matches:
                if isinstance(match, tuple) and len(match) == 2:
                    # Individual dependency match
                    group_id, artifact_id = match
                    dep = {
                        "group_id": group_id.strip(),
                        "artifact_id": artifact_id.strip()
                    }
                    if LLMResponseParser._is_valid_dependency(dep):
                        dependencies.append(dep)
                        logger.debug(f"DEPENDENCY EXTRACTION: Added {group_id}:{artifact_id}")
                elif isinstance(match, str):
                    # Array content match - parse individual items
                    try:
                        # Try to parse as JSON array content
                        array_content = f"[{match}]"
                        deps_list = json.loads(array_content)
                        for dep in deps_list:
                            if LLMResponseParser._is_valid_dependency(dep):
                                dependencies.append(dep)
                                logger.debug(f"DEPENDENCY EXTRACTION: Added from array {dep.get('group_id', '')}:{dep.get('artifact_id', '')}")
                    except json.JSONDecodeError:
                        logger.debug("DEPENDENCY EXTRACTION: Failed to parse array content as JSON")
        
        logger.info(f"DEPENDENCY EXTRACTION: Final count: {len(dependencies)} dependencies")
        return dependencies

    @staticmethod
    def _validate_dependencies(deps_list: list) -> list[dict]:
        """
        Validate and clean a list of dependencies.
        
        Args:
            deps_list: Raw list of dependency objects
            
        Returns:
            Validated list of dependency dictionaries
        """
        validated = []
        
        for i, dep in enumerate(deps_list):
            if not isinstance(dep, dict):
                logger.warning(f"DEPENDENCY VALIDATION: Item {i} is not a dictionary: {type(dep)}")
                continue
                
            if LLMResponseParser._is_valid_dependency(dep):
                # Clean the dependency
                clean_dep = {
                    "group_id": dep.get("group_id", "").strip(),
                    "artifact_id": dep.get("artifact_id", "").strip()
                }
                validated.append(clean_dep)
                logger.debug(f"DEPENDENCY VALIDATION: Validated {clean_dep['group_id']}:{clean_dep['artifact_id']}")
            else:
                logger.warning(f"DEPENDENCY VALIDATION: Invalid dependency at index {i}: {dep}")
        
        return validated

    @staticmethod  
    def _is_valid_dependency(dep: dict) -> bool:
        """
        Check if a dependency object is valid.
        
        Args:
            dep: Dependency dictionary to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(dep, dict):
            return False
            
        group_id = dep.get("group_id", "").strip()
        artifact_id = dep.get("artifact_id", "").strip()
        
        # Both group_id and artifact_id must be present and non-empty
        if not group_id or not artifact_id:
            return False
            
        # Basic format validation (no spaces, reasonable length)
        if " " in group_id or " " in artifact_id:
            return False
            
        if len(group_id) > 100 or len(artifact_id) > 100:
            return False
            
        return True

    @staticmethod
    def safe_extract_json(response: str, context: str = "unknown") -> dict:
        """
        Safely extract JSON with standardized error handling.
        
        Args:
            response: Raw LLM response
            context: Context for logging (e.g., "framework_selection", "dependency_extraction")
            
        Returns:
            Extracted JSON dict or empty dict on failure
        """
        try:
            return LLMResponseParser.extract_json(response)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON extraction failed for {context}: {e}")
            logger.debug(f"Failed response preview: {response[:200]}...")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error during JSON extraction for {context}: {e}")
            return {}

    @staticmethod
    def safe_extract_dependencies(response: str, context: str = "unknown") -> list[dict]:
        """
        Safely extract dependencies with standardized error handling.
        
        Args:
            response: Raw LLM response
            context: Context for logging
            
        Returns:
            List of dependency dicts or empty list on failure
        """
        try:
            return LLMResponseParser.extract_dependencies(response)
        except Exception as e:
            logger.warning(f"Dependency extraction failed for {context}: {e}")
            return []

    @staticmethod
    def extract_with_fallback(response: str, extractors: list[tuple], context: str = "unknown") -> dict:
        """
        Try multiple extractors in sequence until one succeeds.
        
        Args:
            response: Raw LLM response
            extractors: List of (extractor_function, description) tuples
            context: Context for logging
            
        Returns:
            Extracted data or empty dict if all fail
        """
        for extractor_func, description in extractors:
            try:
                result = extractor_func(response)
                if result:  # Non-empty result
                    logger.debug(f"Extraction succeeded for {context} using {description}")
                    return result
            except Exception as e:
                logger.debug(f"Extractor {description} failed for {context}: {e}")
                continue
        
        logger.warning(f"All extractors failed for {context}")
        return {}

    @staticmethod
    def parse_fix_actions(response: str) -> dict:
        """
        Parse fix actions from LLM response.

        Expected format:
            **FIX_ACTIONS**: <count>
            **ACTION_1**: ...
            **ACTION_2**: ...
            **VALIDATION_COMMANDS**: ...
            **ESTIMATED_SUCCESS_RATE**: <float>

        Args:
            response: Raw LLM response with fix actions

        Returns:
            Dictionary with fix_actions list, validation_commands, and success info
        """
        result = {
            "fix_actions": [],
            "success": True,
            "validation_commands": [],
            "estimated_success_rate": 0.5,
        }

        try:
            # Extract number of actions
            action_count_match = re.search(r"\*\*FIX_ACTIONS\*\*:\s*(\d+)", response)
            if action_count_match:
                action_count = int(action_count_match.group(1))

                # Extract each action
                for i in range(1, action_count + 1):
                    action_pattern = rf"\*\*ACTION_{i}\*\*:(.*?)(?=\*\*ACTION_{i+1}\*\*|\*\*VALIDATION_COMMANDS\*\*|$)"
                    action_match = re.search(action_pattern, response, re.DOTALL)

                    if action_match:
                        action_text = action_match.group(1)
                        action = LLMResponseParser.parse_single_action(action_text, i)
                        if action:
                            result["fix_actions"].append(action)

            # Extract validation commands
            validation_match = re.search(r"\*\*VALIDATION_COMMANDS\*\*:\s*(.*)(?=\*\*|$)", response, re.DOTALL)
            if validation_match:
                result["validation_commands"] = [
                    cmd.strip() for cmd in validation_match.group(1).split("\n") if cmd.strip()
                ]

            # Extract success rate
            success_rate_match = re.search(r"\*\*ESTIMATED_SUCCESS_RATE\*\*:\s*([\d.]+)", response)
            if success_rate_match:
                result["estimated_success_rate"] = float(success_rate_match.group(1))

        except Exception as e:
            logger.error(f"Error parsing fix actions: {e}")
            result["success"] = False
            result["error"] = str(e)

        return result

    @staticmethod
    def parse_single_action(action_text: str, action_num: int) -> dict:
        """
        Parse a single fix action from text.

        Expected format:
            - **TYPE**: <action_type>
            - **DESCRIPTION**: <description>
            - **TARGET_FILE**: <file_path>
            - **PRIORITY**: <1-10>
            - **CONFIDENCE**: <0.0-1.0>
            - **CHANGES**: OLD: <old> NEW: <new>

        Args:
            action_text: Text containing single action details
            action_num: Action number for ID generation

        Returns:
            Dictionary with action details
        """
        action = {
            "action_id": f"llm_action_{action_num}",
            "type": "CODE_MODIFICATION",
            "description": "",
            "target_file": None,
            "priority": 5,
            "confidence": 0.5,
            "changes": {},
        }

        try:
            # Extract action fields
            type_match = re.search(r"- \*\*TYPE\*\*:\s*(.+)", action_text, re.IGNORECASE)
            if type_match:
                action["type"] = type_match.group(1).strip()

            desc_match = re.search(r"- \*\*DESCRIPTION\*\*:\s*(.+)", action_text, re.IGNORECASE)
            if desc_match:
                action["description"] = desc_match.group(1).strip()

            file_match = re.search(r"- \*\*TARGET_FILE\*\*:\s*(.+)", action_text, re.IGNORECASE)
            if file_match:
                target = file_match.group(1).strip()
                action["target_file"] = target if target != "null" else None

            priority_match = re.search(r"- \*\*PRIORITY\*\*:\s*(\d+)", action_text, re.IGNORECASE)
            if priority_match:
                action["priority"] = int(priority_match.group(1))

            conf_match = re.search(r"- \*\*CONFIDENCE\*\*:\s*([\d.]+)", action_text, re.IGNORECASE)
            if conf_match:
                action["confidence"] = float(conf_match.group(1))

            # Extract changes (simplified)
            changes_match = re.search(r"- \*\*CHANGES\*\*:\s*(.+)", action_text, re.IGNORECASE | re.DOTALL)
            if changes_match:
                changes_text = changes_match.group(1)
                if "OLD:" in changes_text and "NEW:" in changes_text:
                    old_match = re.search(r"OLD:\s*(.+)(?=NEW:|$)", changes_text, re.DOTALL)
                    new_match = re.search(r"NEW:\s*(.+)", changes_text, re.DOTALL)

                    if old_match and new_match:
                        old_content = old_match.group(1).strip()
                        new_content = new_match.group(1).strip()
                        action["changes"][old_content] = new_content

        except Exception as e:
            logger.error(f"Error parsing action {action_num}: {e}")

        return action

    @staticmethod
    def parse_react_reasoning(response: str) -> dict:
        """
        Parse ReAct reasoning phase response.

        Expected format:
            ANALYSIS: <analysis_text>
            PLANNED_ACTION: <action_description>
            CONFIDENCE: <0.0-1.0>

        Args:
            response: Raw LLM response from reasoning phase

        Returns:
            Dictionary with analysis, planned_action, and confidence
        """
        result = {"analysis": "", "planned_action": "", "confidence": 0.5}

        patterns = {
            "analysis": r"ANALYSIS:\s*(.+?)(?=PLANNED_ACTION:|$)",
            "planned_action": r"PLANNED_ACTION:\s*(.+?)(?=CONFIDENCE:|$)",
            "confidence": r"CONFIDENCE:\s*([\d.]+)",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key == "confidence":
                    try:
                        result[key] = float(value)
                    except ValueError:
                        result[key] = 0.5
                else:
                    result[key] = value

        return result

    @staticmethod
    def parse_react_observation(response: str) -> dict:
        """
        Parse ReAct observation phase response.

        Expected format:
            ANALYSIS: <analysis_text>
            RECOVERY_COMPLETE: YES/NO
            SHOULD_CONTINUE: YES/NO
            CONFIDENCE: <0.0-1.0>

        Args:
            response: Raw LLM response from observation phase

        Returns:
            Dictionary with analysis, recovery_complete, should_continue, confidence
        """
        result = {"analysis": "", "recovery_complete": False, "should_continue": True, "confidence": 0.5}

        patterns = {
            "analysis": r"ANALYSIS:\s*(.+?)(?=RECOVERY_COMPLETE:|$)",
            "recovery_complete": r"RECOVERY_COMPLETE:\s*(YES|NO)",
            "should_continue": r"SHOULD_CONTINUE:\s*(YES|NO)",
            "confidence": r"CONFIDENCE:\s*([\d.]+)",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key == "confidence":
                    try:
                        result[key] = float(value)
                    except ValueError:
                        result[key] = 0.5
                elif key in ["recovery_complete", "should_continue"]:
                    result[key] = value.upper() == "YES"
                else:
                    result[key] = value

        return result

    @staticmethod
    def parse_template_customization(response: str) -> dict:
        """
        Parse JSON response from template customization LLM.

        Expected JSON structure:
        {
            "customized_template": "...",
            "configuration_files": {...},
            "framework_files": {...},
            "changes_made": [...],
            "dependencies_added": [...],
            "dependencies_removed": [...],
            "build_optimizations": [...],
            "vulnerability_specific_notes": [...]
        }

        Args:
            response: Raw LLM response containing JSON

        Returns:
            Dictionary with parsed template customization data
        """
        try:
            # Extract JSON from response (LLM might include markdown formatting)
            json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON without markdown
                json_str = response.strip()

            parsed = json.loads(json_str)

            return {
                "customized_template": parsed.get("customized_template", ""),
                "configuration_files": parsed.get("configuration_files", {}),
                "framework_files": parsed.get("framework_files", {}),
                "customization_notes": f"Changes: {', '.join(parsed.get('changes_made', []))}",
                "customization_success": True,
                "dependencies_added": parsed.get("dependencies_added", []),
                "dependencies_removed": parsed.get("dependencies_removed", []),
                "build_optimizations": parsed.get("build_optimizations", []),
                "vulnerability_specific_notes": parsed.get("vulnerability_specific_notes", []),
                "success": True,
            }

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse template customization JSON: {e}")
            return {"success": False, "error": f"JSON parse error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error processing template customization response: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def parse_classification(response: str) -> dict[str, Any] | None:
        """
        Parse LLM classification response.

        Expected JSON structure:
        {
            "vulnerability_type": "...",
            "exploitation_indicators": [...],
            "security_impact": "...",
            "monitoring_keywords": [...]
        }

        Args:
            response: Raw LLM response containing classification JSON

        Returns:
            Parsed classification dictionary or None if parsing fails
        """
        try:
            # Try to find JSON in response
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                result = json.loads(json_str)

                # Validate required fields
                if "vulnerability_type" in result:
                    logger.debug(f"Parsed classification result: {result}")
                    return result
                else:
                    logger.warning(f"Classification response missing vulnerability_type: {response}")
            else:
                logger.warning(f"No valid JSON found in classification response: {response}")

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse classification JSON: {e}, Response: {response}")
        except Exception as e:
            logger.error(f"Error parsing classification response: {e}")

        return None

    @staticmethod
    def parse_endpoint_metadata(response: str) -> list[dict[str, Any]]:
        """
        Extract endpoint metadata from LLM response.

        Looks for JSON block with "endpoints" array containing endpoint information
        (path, method, consumes) that LLM provides alongside generated code.

        Expected format:
        ```json
        {
          "endpoints": [
            {"path": "/vuln/vulnerable.action", "method": "POST", "consumes": "multipart/form-data"}
          ]
        }
        ```

        Args:
            response: Raw LLM response that may contain endpoint metadata

        Returns:
            List of endpoint dictionaries (empty list if not found)
        """
        logger.debug("ENDPOINT METADATA EXTRACTION: Starting extraction")

        try:
            # Try to find JSON block with endpoints
            json_patterns = [
                # Pattern 1: Markdown json code block
                (r"```json\s*\n(.*?)\n```", "json code block"),
                # Pattern 2: Generic code block
                (r"```\s*\n(.*?)\n```", "generic code block"),
                # Pattern 3: Direct JSON with endpoints field
                (r'\{[^{}]*"endpoints"[^{}]*\}', "simple endpoints JSON"),
                (r'\{.*?"endpoints".*?\}', "extended endpoints JSON"),
            ]

            for pattern, description in json_patterns:
                logger.debug(f"ENDPOINT METADATA: Trying pattern: {description}")
                matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)

                for i, match in enumerate(matches):
                    try:
                        data = json.loads(match.strip())

                        # Check if it has endpoints field
                        if isinstance(data, dict) and "endpoints" in data:
                            endpoints = data["endpoints"]

                            if isinstance(endpoints, list):
                                logger.info(
                                    f"ENDPOINT METADATA SUCCESS: Found {len(endpoints)} endpoints using {description}"
                                )

                                # Validate endpoint structure
                                valid_endpoints = []
                                for endpoint in endpoints:
                                    if isinstance(endpoint, dict) and "path" in endpoint:
                                        valid_endpoints.append(endpoint)
                                    else:
                                        logger.warning(f"Invalid endpoint structure: {endpoint}")

                                if valid_endpoints:
                                    logger.debug(f"Validated endpoints: {valid_endpoints}")
                                    return valid_endpoints

                    except json.JSONDecodeError:
                        logger.debug(f"Match {i+1} is not valid JSON")
                        continue
                    except Exception as e:
                        logger.debug(f"Error processing match {i+1}: {e}")
                        continue

            # If no endpoint metadata found, return empty list
            logger.debug("ENDPOINT METADATA: No endpoint metadata found in response")
            return []

        except Exception as e:
            logger.error(f"ENDPOINT METADATA EXTRACTION ERROR: {e}")
            return []

    @staticmethod
    def parse_config_values(response: str) -> dict[str, Any]:
        """
        Extract config values from LLM response for protocol servers.

        Looks for JSON block with "config_values" field containing application.yml variables
        that LLM provides alongside generated code.

        Expected format:
        ```json
        {
          "config_values": {
            "server_port": 8080,
            "max_connections": "unlimited",
            "auto_close_connections": false,
            "cve_id": "CVE-2024-XXXXX",
            "vulnerability_config_explanation": "..."
          }
        }
        ```

        Args:
            response: Raw LLM response that may contain config values

        Returns:
            Dictionary of config values (empty dict if not found)
        """
        logger.debug("CONFIG VALUES EXTRACTION: Starting extraction")

        try:
            # Try to find JSON block with config_values
            json_patterns = [
                # Pattern 1: Markdown json code block
                (r"```json\s*\n(.*?)\n```", "json code block"),
                # Pattern 2: Generic code block
                (r"```\s*\n(.*?)\n```", "generic code block"),
                # Pattern 3: Direct JSON with config_values field
                (r'\{[^{}]*"config_values"[^{}]*\}', "simple config JSON"),
                (r'\{.*?"config_values".*?\}', "extended config JSON"),
            ]

            for pattern, description in json_patterns:
                logger.debug(f"CONFIG VALUES: Trying pattern: {description}")
                matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)

                for i, match in enumerate(matches):
                    try:
                        data = json.loads(match.strip())

                        # Check if it has config_values field
                        if isinstance(data, dict) and "config_values" in data:
                            config_values = data["config_values"]

                            if isinstance(config_values, dict):
                                logger.info(
                                    f"CONFIG VALUES SUCCESS: Found {len(config_values)} values using {description}"
                                )
                                logger.debug(f"Config values: {config_values}")
                                return config_values

                    except json.JSONDecodeError:
                        logger.debug(f"Match {i+1} is not valid JSON")
                        continue
                    except Exception as e:
                        logger.debug(f"Error processing match {i+1}: {e}")
                        continue

            # If no config values found, return empty dict
            logger.debug("CONFIG VALUES: No config values found in response")
            return {}

        except Exception as e:
            logger.error(f"CONFIG VALUES EXTRACTION ERROR: {e}")
            return {}
    
    @staticmethod
    def parse_json_response(response: str, expected_fields: list[str] = None, context: str = "unknown") -> dict:
        """
        Unified JSON parsing with validation and fallback strategies.
        Consolidates 6+ duplicate JSON extraction patterns.
        
        Args:
            response: Raw LLM response
            expected_fields: Optional list of required fields to validate
            context: Context for logging
            
        Returns:
            Parsed JSON dict or empty dict with error info
        """
        logger.debug(f"UNIFIED JSON PARSE ({context}): Starting with {len(response)} char response")
        
        try:
            # Try standard extraction
            result = LLMResponseParser.extract_json(response)
            
            # Validate expected fields if provided
            if expected_fields:
                missing = [f for f in expected_fields if f not in result]
                if missing:
                    logger.warning(f"UNIFIED JSON PARSE ({context}): Missing fields: {missing}")
                    # Try to add defaults or extract missing fields
                    for field in missing:
                        result[field] = LLMResponseParser._extract_field_fallback(response, field)
            
            logger.info(f"UNIFIED JSON PARSE ({context}): Success - {len(result)} fields")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"UNIFIED JSON PARSE ({context}): Failed - {e}")
            # Return structured error response
            return {
                "parse_error": True,
                "error_message": str(e),
                "context": context,
                "raw_response_preview": response[:200]
            }
    
    @staticmethod
    def extract_code_blocks(response: str, languages: list[str] = None) -> dict[str, str]:
        """
        Extract code blocks from LLM response supporting multiple languages.
        Consolidates duplicate code extraction logic.
        
        Args:
            response: Raw LLM response
            languages: Optional list of languages to filter (e.g., ['java', 'python', 'xml'])
            
        Returns:
            Dictionary mapping identifier to code content
        """
        code_blocks = {}
        
        # If specific languages requested, filter to those
        if languages:
            patterns = [(rf"```{lang}\n(.*?)```", lang) for lang in languages]
        else:
            # Extract all language-tagged blocks
            patterns = [
                (r"```(\w+)\n(.*?)```", "tagged"),  # Captures language tag and code
                (r"```file:([^\n]+)\n(.*?)```", "file"),  # File-tagged blocks
            ]
        
        for pattern, pattern_type in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            
            for match in matches:
                if pattern_type == "tagged":
                    lang, code = match
                    identifier = f"{lang}_{len([k for k in code_blocks if k.startswith(lang)])}"
                    code_blocks[identifier] = code.strip()
                elif pattern_type == "file":
                    filepath, code = match
                    code_blocks[filepath.strip()] = code.strip()
                else:
                    # Single language match
                    code_blocks[f"{pattern_type}_{len(code_blocks)}"] = match.strip()
        
        logger.info(f"CODE BLOCK EXTRACTION: Found {len(code_blocks)} blocks")
        return code_blocks
    
    @staticmethod
    def parse_with_fallback(
        response: str,
        primary_parser: callable,
        fallback_parsers: list[callable],
        context: str = "unknown"
    ) -> Any:
        """
        Cascading parser with multiple fallback strategies.
        Implements consistent error recovery pattern.
        
        Args:
            response: Raw LLM response
            primary_parser: Primary parsing function to try first
            fallback_parsers: List of fallback parser functions
            context: Context for logging
            
        Returns:
            Parsed result from first successful parser
        """
        # Try primary parser
        try:
            result = primary_parser(response)
            if result:
                logger.debug(f"CASCADING PARSE ({context}): Primary parser succeeded")
                return result
        except Exception as e:
            logger.debug(f"CASCADING PARSE ({context}): Primary failed - {e}")
        
        # Try fallback parsers in order
        for i, fallback in enumerate(fallback_parsers):
            try:
                result = fallback(response)
                if result:
                    logger.info(f"CASCADING PARSE ({context}): Fallback {i+1} succeeded")
                    return result
            except Exception as e:
                logger.debug(f"CASCADING PARSE ({context}): Fallback {i+1} failed - {e}")
                continue
        
        logger.error(f"CASCADING PARSE ({context}): All parsers failed")
        return None
    
    @staticmethod
    def _extract_field_fallback(response: str, field_name: str) -> Any:
        """
        Extract a specific field from response when JSON parsing fails.
        
        Args:
            response: Raw response
            field_name: Field to extract
            
        Returns:
            Extracted value or None
        """
        # Try common field patterns
        patterns = [
            rf'"{field_name}"\s*:\s*"([^"]+)"',  # String value
            rf'"{field_name}"\s*:\s*([0-9.]+)',   # Numeric value
            rf'"{field_name}"\s*:\s*(true|false)',  # Boolean value
            rf'\*\*{field_name.upper()}\*\*:\s*(.+)',  # Markdown bold format
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                # Try to convert to appropriate type
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
        
        return None
