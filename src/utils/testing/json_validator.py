
import json
import logging
import re
import time
from dataclasses import dataclass

import yaml
from jsonschema import Draft7Validator, ValidationError

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of JSON validation operation."""
    is_valid: bool
    parsed_data: dict[str, any] | None
    errors: list[str]
    repaired: bool
    repair_attempts: int
    validation_time_ms: float

class JSONValidator:
    """JSON schema validator with repair capabilities for LLM responses."""
    
    def __init__(self, config_path: str | None = None):
        """Initialize the JSON validator with schema configuration."""
        if config_path is None:
            config_path = PROJECT_ROOT / "src" / "config" / "llm_schemas.yaml"
        
        self.config_path = config_path
        self.schemas = {}
        self.validation_cache = {}
        self.config = {}
        
        self._load_schemas()
        
    def _load_schemas(self) -> None:
        """Load JSON schemas from configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            self.config = config
            
            # Extract schemas (exclude metadata sections)
            metadata_sections = {'validation', 'json_repair', 'performance'}
            for key, value in config.items():
                if key not in metadata_sections and isinstance(value, dict):
                    if 'type' in value:  # This is a schema
                        self.schemas[key] = value
                        logger.debug(f"Loaded schema: {key}")
            
            logger.info(f"Loaded {len(self.schemas)} JSON schemas for validation")
            
        except Exception as e:
            logger.warning(f"Failed to load JSON schemas: {e}")
            self.schemas = {}
            self.config = self._get_default_config()
    
    def _get_default_config(self) -> dict[str, any]:
        """Get default configuration when config file fails to load."""
        return {
            'validation': {
                'max_response_size': 50000,
                'validation_timeout': 5,
                'log_validation_failures': True,
                'attempt_json_repair': True,
                'fallback_behavior': 'use_fallback_values'
            },
            'json_repair': {
                'patterns': [],
                'max_repair_attempts': 3
            },
            'performance': {
                'enable_validation_cache': True,
                'cache_ttl': 3600,
                'max_cache_size': 1000
            }
        }
    
    def validate_response(self, response: str, schema_name: str) -> ValidationResult:
        """
        Validate and parse an LLM response against a schema.
        
        Args:
            response: Raw response string from LLM
            schema_name: Name of the schema to validate against
            
        Returns:
            ValidationResult with validation status and parsed data
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = f"{schema_name}:{hash(response)}"
        if self._should_use_cache() and cache_key in self.validation_cache:
            cached_result = self.validation_cache[cache_key]
            cached_result.validation_time_ms = (time.time() - start_time) * 1000
            return cached_result
        
        # Get schema
        schema = self.schemas.get(schema_name)
        if not schema:
            logger.warning(f"Schema '{schema_name}' not found")
            return ValidationResult(
                is_valid=False,
                parsed_data=None,
                errors=[f"Schema '{schema_name}' not found"],
                repaired=False,
                repair_attempts=0,
                validation_time_ms=(time.time() - start_time) * 1000
            )
        
        # Check response size
        max_size = self.config.get('validation', {}).get('max_response_size', 50000)
        if len(response) > max_size:
            logger.warning(f"Response too large for validation: {len(response)} > {max_size}")
            return self._create_fallback_result(schema_name, schema, start_time, 
                                               errors=[f"Response too large: {len(response)} characters"])
        
        # Try to parse and validate
        result = self._validate_with_repair(response, schema_name, schema, start_time)
        
        # Cache result if enabled
        if self._should_use_cache():
            self._cache_result(cache_key, result)
        
        return result
    
    def _validate_with_repair(self, response: str, schema_name: str, schema: dict[str, any], start_time: float) -> ValidationResult:
        """Validate with repair attempts if needed."""
        errors = []
        repair_attempts = 0
        repaired = False
        
        # Check for empty or whitespace-only response
        if not response or not response.strip():
            logger.warning(f"Empty response received for schema '{schema_name}'")
            return self._create_fallback_result(schema_name, schema, start_time, 
                                               ["Empty or whitespace-only response"])
        
        # First attempt: try to parse as-is
        try:
            parsed_data = json.loads(response)
            self._validate_against_schema(parsed_data, schema)
            
            return ValidationResult(
                is_valid=True,
                parsed_data=parsed_data,
                errors=[],
                repaired=False,
                repair_attempts=0,
                validation_time_ms=(time.time() - start_time) * 1000
            )
            
        except json.JSONDecodeError as e:
            errors.append(f"JSON parsing failed: {str(e)}")
            
        except ValidationError as e:
            errors.append(f"Schema validation failed: {str(e)}")
            # If JSON parsed but schema validation failed, try to use partial data
            try:
                parsed_data = json.loads(response)
                if self._should_use_partial_data():
                    return self._create_partial_result(parsed_data, schema_name, schema, start_time, errors)
            except (ValueError):
                pass
        
        # Attempt repair if enabled
        if self._should_attempt_repair():
            repair_result = self._attempt_repair(response, schema_name, schema, start_time)
            if repair_result.is_valid:
                return repair_result
            errors.extend(repair_result.errors)
            repair_attempts = repair_result.repair_attempts
            repaired = repair_result.repaired
        
        # All attempts failed, return fallback
        return self._create_fallback_result(schema_name, schema, start_time, errors, repair_attempts, repaired)
    
    def _attempt_repair(self, response: str, schema_name: str, schema: dict[str, any], start_time: float) -> ValidationResult:
        """Attempt to repair JSON and validate."""
        repair_patterns = self.config.get('json_repair', {}).get('patterns', [])
        max_attempts = self.config.get('json_repair', {}).get('max_repair_attempts', 3)
        
        current_response = response.strip()
        errors = []
        
        # Check if response contains any JSON-like structure
        if '{' not in current_response and '[' not in current_response:
            errors.append(f"No JSON structure found in response: {current_response[:100]}...")
            return ValidationResult(
                is_valid=False,
                parsed_data=schema.get('fallback', {}),
                errors=errors,
                repaired=False,
                repair_attempts=0,
                validation_time_ms=(time.time() - start_time) * 1000
            )
        
        for attempt in range(max_attempts):
            try:
                # Apply repair patterns
                for pattern_config in repair_patterns:
                    pattern = pattern_config.get('pattern', '')
                    replacement = pattern_config.get('replacement', '')
                    if pattern:
                        current_response = re.sub(pattern, replacement, current_response)
                
                # Try to parse repaired JSON
                parsed_data = json.loads(current_response)
                
                # Validate against schema
                self._validate_against_schema(parsed_data, schema)
                
                logger.info(f"JSON repair successful for schema '{schema_name}' after {attempt + 1} attempts")
                return ValidationResult(
                    is_valid=True,
                    parsed_data=parsed_data,
                    errors=[],
                    repaired=True,
                    repair_attempts=attempt + 1,
                    validation_time_ms=(time.time() - start_time) * 1000
                )
                
            except json.JSONDecodeError as e:
                errors.append(f"Repair attempt {attempt + 1} JSON parsing failed: {str(e)}")
                # Try more aggressive repairs
                current_response = self._aggressive_json_repair(current_response)
                # Also try extracting just the JSON part if there's extra text
                current_response = self._extract_json_content(current_response)
                
            except ValidationError as e:
                errors.append(f"Repair attempt {attempt + 1} schema validation failed: {str(e)}")
                break  # Schema validation failed, no point in more repairs
        
        return ValidationResult(
            is_valid=False,
            parsed_data=None,
            errors=errors,
            repaired=False,
            repair_attempts=max_attempts,
            validation_time_ms=(time.time() - start_time) * 1000
        )
    
    def _aggressive_json_repair(self, response: str) -> str:
        """Apply aggressive JSON repair techniques."""
        # Remove non-JSON content before and after
        response = response.strip()
        
        # Find JSON boundaries
        start_idx = response.find('{')
        end_idx = response.rfind('}')
        
        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
            response = response[start_idx:end_idx + 1]
        
        # Fix common issues
        repairs = [
            # Remove markdown code blocks and LLM preambles first
            (r'```json\s*', ''),
            (r'```\s*$', ''),
            (r'^[^{]*?(?={)', ''),  # Remove text before first {
            (r'}\s*[^}]*$', '}'),  # Remove text after last }
            
            # Remove trailing commas
            (r',(\s*[}\]])', r'\1'),
            # Fix unescaped quotes in values
            (r':\s*([^",{\[\]]+)"([^",{\[\]]+)"', r': "\1\2"'),
            # Add missing quotes around keys
            (r'(\w+)(\s*:)', r'"\1"\2'),
            # Fix boolean values
            (r'\bTrue\b', 'true'),
            (r'\bFalse\b', 'false'),
            (r'\bNone\b', 'null'),
            
            # Fix missing commas between key-value pairs
            (r'"\s*\n\s*"', '",\n"'),
            (r'}\s*\n\s*"', '},\n"'),
            (r']\s*\n\s*"', '],\n"'),
            
            # Fix missing quotes around string values
            (r':\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*([,}])', r': "\1"\2'),
            
            # Fix malformed arrays
            (r'\[\s*,', '['),
            (r',\s*\]', ']'),
            
            # Fix multiple commas
            (r',,+', ','),
            
            # Remove comments
            (r'//.*?\n', '\n'),
            (r'/\*.*?\*/', ''),
            
            # Fix newlines in strings (replace with spaces)
            (r'"([^"]*?)\n([^"]*?)"', r'"\1 \2"'),
            
            # Fix missing quotes on object values that look like strings
            (r':\s*([A-Za-z][A-Za-z0-9_\s]*)\s*([,}])', r': "\1"\2'),
        ]
        
        for pattern, replacement in repairs:
            response = re.sub(pattern, replacement, response)
        
        return response
    
    def _extract_json_content(self, response: str) -> str:
        """Extract JSON content from response with LLM text."""
        # Try to find JSON objects/arrays in the response
        import re
        
        # Pattern to match JSON objects or arrays
        json_patterns = [
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',  # Simple nested objects
            r'\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]',  # Simple nested arrays
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            if matches:
                # Return the largest match (likely the main JSON)
                return max(matches, key=len)
        
        # If no patterns match, try to find boundaries more aggressively
        lines = response.split('\n')
        json_lines = []
        in_json = False
        brace_count = 0
        
        for line in lines:
            stripped = line.strip()
            if not in_json and (stripped.startswith('{') or stripped.startswith('[')):
                in_json = True
                json_lines.append(line)
                brace_count += stripped.count('{') + stripped.count('[')
                brace_count -= stripped.count('}') + stripped.count(']')
            elif in_json:
                json_lines.append(line)
                brace_count += stripped.count('{') + stripped.count('[')
                brace_count -= stripped.count('}') + stripped.count(']')
                if brace_count <= 0:
                    break
        
        if json_lines:
            return '\n'.join(json_lines)
        
        return response
    
    def _validate_against_schema(self, data: dict[str, any], schema: dict[str, any]) -> None:
        """Validate data against JSON schema."""
        # Create validator
        validator = Draft7Validator(schema)
        
        # Validate
        errors = list(validator.iter_errors(data))
        if errors:
            error_messages = [f"{error.json_path}: {error.message}" for error in errors]
            raise ValidationError(f"Schema validation failed: {'; '.join(error_messages)}")
    
    def _create_fallback_result(self, schema_name: str, schema: dict[str, any], start_time: float, 
                               errors: list[str], repair_attempts: int = 0, repaired: bool = False) -> ValidationResult:
        """Create a fallback result using schema's fallback values."""
        fallback_data = schema.get('fallback', {})
        
        if self.config.get('validation', {}).get('log_validation_failures', True):
            logger.debug(f"JSON validation failed for schema '{schema_name}': {'; '.join(errors)}")
        
        return ValidationResult(
            is_valid=False,
            parsed_data=fallback_data if fallback_data else None,
            errors=errors,
            repaired=repaired,
            repair_attempts=repair_attempts,
            validation_time_ms=(time.time() - start_time) * 1000
        )
    
    def _create_partial_result(self, data: dict[str, any], schema_name: str, schema: dict[str, any], 
                              start_time: float, errors: list[str]) -> ValidationResult:
        """Create a partial result using available valid data."""
        # Extract valid fields based on schema
        valid_data = {}
        schema_properties = schema.get('properties', {})
        
        for key, value in data.items():
            if key in schema_properties:
                valid_data[key] = value
        
        # Add fallback values for missing required fields
        required_fields = schema.get('required', [])
        fallback_data = schema.get('fallback', {})
        
        for field in required_fields:
            if field not in valid_data and field in fallback_data:
                valid_data[field] = fallback_data[field]
        
        logger.info(f"Using partial data for schema '{schema_name}': {len(valid_data)} valid fields")
        
        return ValidationResult(
            is_valid=False,  # Mark as invalid since it didn't fully validate
            parsed_data=valid_data,
            errors=errors,
            repaired=False,
            repair_attempts=0,
            validation_time_ms=(time.time() - start_time) * 1000
        )
    
    def _should_use_cache(self) -> bool:
        """Check if caching should be used."""
        return self.config.get('performance', {}).get('enable_validation_cache', True)
    
    def _should_attempt_repair(self) -> bool:
        """Check if JSON repair should be attempted."""
        return self.config.get('validation', {}).get('attempt_json_repair', True)
    
    def _should_use_partial_data(self) -> bool:
        """Check if partial data should be used."""
        fallback_behavior = self.config.get('validation', {}).get('fallback_behavior', 'use_fallback_values')
        return fallback_behavior == 'use_partial'
    
    def _cache_result(self, cache_key: str, result: ValidationResult) -> None:
        """Cache validation result."""
        max_cache_size = self.config.get('performance', {}).get('max_cache_size', 1000)
        
        # Simple cache size management
        if len(self.validation_cache) >= max_cache_size:
            # Remove oldest entries (simple FIFO)
            keys_to_remove = list(self.validation_cache.keys())[:max_cache_size // 4]
            for key in keys_to_remove:
                del self.validation_cache[key]
        
        self.validation_cache[cache_key] = result
    
    def get_schema_names(self) -> list[str]:
        """Get list of available schema names."""
        return list(self.schemas.keys())
    
    def get_schema(self, schema_name: str) -> dict[str, any] | None:
        """Get a specific schema by name."""
        return self.schemas.get(schema_name)
    
    def clear_cache(self) -> None:
        """Clear the validation cache."""
        self.validation_cache.clear()
        logger.info("Validation cache cleared")

# Convenience function for easy usage
def validate_llm_response(response: str, schema_name: str, config_path: str | None = None) -> ValidationResult:
    """
    Convenience function to validate LLM responses.
    
    Args:
        response: Raw LLM response string
        schema_name: Name of the schema to validate against
        config_path: Optional path to schema config file
        
    Returns:
        ValidationResult with validation status and parsed data
    """
    validator = JSONValidator(config_path)
    return validator.validate_response(response, schema_name)