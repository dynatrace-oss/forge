import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EndpointContext:
    """Structured information about a controller endpoint."""

    endpoint_path: str
    http_method: str
    method_name: str
    method_signature: str
    parameter_types: List[str]
    accepts_content_types: List[str]
    key_operations: List[str]
    full_method_body: str
    file_name: str


def extract_endpoint_context(code_snippets: Dict[str, str]) -> List[EndpointContext]:
    """
    Extract structured endpoint information from Java controller code.

    Args:
        code_snippets: Dictionary mapping filenames to Java source code

    Returns:
        List of EndpointContext objects with detailed endpoint information
    """
    endpoints = []

    for filename, code in code_snippets.items():
        if not code or not isinstance(code, str):
            continue

        # Focus on controller files
        if "Controller.java" in filename or "@RestController" in code or "@Controller" in code:
            logger.debug(f"Analyzing controller file: {filename}")
            endpoints.extend(_extract_endpoints_from_controller(filename, code))

    logger.info(f"Extracted {len(endpoints)} endpoint contexts from {len(code_snippets)} code snippets")
    return endpoints


def _extract_endpoints_from_controller(filename: str, code: str) -> List[EndpointContext]:
    """Extract all endpoint contexts from a single controller file."""
    endpoints = []
    lines = code.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i]

        # Look for HTTP mapping annotations
        if any(annotation in line for annotation in ['@PostMapping', '@GetMapping', '@PutMapping', '@DeleteMapping', '@RequestMapping']):
            endpoint = _parse_endpoint_at_line(lines, i, filename)
            if endpoint:
                endpoints.append(endpoint)
                logger.debug(f"Found endpoint: {endpoint.http_method} {endpoint.endpoint_path}")

        i += 1

    return endpoints


def _parse_endpoint_at_line(lines: List[str], start_idx: int, filename: str) -> Optional[EndpointContext]:
    """Parse endpoint starting at the given line index."""
    try:
        # Extract HTTP method and path from annotation
        annotation_line = lines[start_idx]
        http_method, endpoint_path = _parse_mapping_annotation(annotation_line)

        if not http_method:
            return None

        # Find the method signature (should be next non-empty, non-comment line)
        method_line_idx = start_idx + 1
        while method_line_idx < len(lines):
            line = lines[method_line_idx].strip()
            if line and not line.startswith('//') and not line.startswith('/*') and not line.startswith('*'):
                break
            method_line_idx += 1

        if method_line_idx >= len(lines):
            return None

        # Extract method signature
        method_signature = _extract_method_signature(lines, method_line_idx)
        
        # Validate this is actually a method signature, not a class declaration
        if not _is_method_signature(method_signature):
            return None
            
        method_name = _extract_method_name(method_signature)
        parameter_types = _extract_parameter_types(method_signature)

        # Infer accepted Content-Types from parameter types
        accepts_content_types = _infer_content_types(parameter_types)

        # Extract method body and key operations
        method_body, key_operations = _extract_method_body_and_operations(lines, method_line_idx)

        return EndpointContext(
            endpoint_path=endpoint_path,
            http_method=http_method,
            method_name=method_name,
            method_signature=method_signature,
            parameter_types=parameter_types,
            accepts_content_types=accepts_content_types,
            key_operations=key_operations,
            full_method_body=method_body,
            file_name=filename
        )

    except Exception as e:
        logger.warning(f"Failed to parse endpoint at line {start_idx}: {e}")
        return None


def _parse_mapping_annotation(annotation_line: str) -> tuple[str, str]:
    """Extract HTTP method and path from mapping annotation."""
    # Match patterns like @PostMapping("/api/vulnerable") or @RequestMapping(value = "/path", method = RequestMethod.POST)

    if '@PostMapping' in annotation_line:
        http_method = 'POST'
    elif '@GetMapping' in annotation_line:
        http_method = 'GET'
    elif '@PutMapping' in annotation_line:
        http_method = 'PUT'
    elif '@DeleteMapping' in annotation_line:
        http_method = 'DELETE'
    elif '@RequestMapping' in annotation_line:
        # Try to determine method from annotation
        if 'POST' in annotation_line.upper():
            http_method = 'POST'
        elif 'GET' in annotation_line.upper():
            http_method = 'GET'
        else:
            http_method = 'REQUEST'
    else:
        return None, None

    # Extract path from annotation
    path_match = re.search(r'["\']([^"\']+)["\']', annotation_line)
    if path_match:
        endpoint_path = path_match.group(1)
    else:
        endpoint_path = "/unknown"

    return http_method, endpoint_path


def _extract_method_signature(lines: List[str], start_idx: int) -> str:
    """Extract complete method signature, handling multi-line signatures."""
    signature_parts = []
    idx = start_idx
    paren_count = 0

    while idx < len(lines):
        line = lines[idx].strip()
        signature_parts.append(line)

        # Count parentheses to find signature end
        paren_count += line.count('(') - line.count(')')

        # Check if we've found the opening brace or reached the end of signature
        if '{' in line or (paren_count == 0 and '(' in ''.join(signature_parts)):
            break

        idx += 1
        if idx - start_idx > 10:  # Safety limit for multi-line signatures
            break

    # Remove opening brace if present
    signature = ' '.join(signature_parts)
    if '{' in signature:
        signature = signature[:signature.index('{')].strip()

    return signature


def _is_method_signature(signature: str) -> bool:
    """Check if the signature is a method (not a class declaration or other construct)."""
    signature = signature.strip()
    
    # Skip class declarations
    if 'class ' in signature and '{' in signature:
        return False
        
    # Skip interface declarations
    if 'interface ' in signature:
        return False
        
    # Must have parentheses to be a method
    if '(' not in signature or ')' not in signature:
        return False
        
    # Should have a method name pattern before parentheses
    method_pattern = r'\s+(\w+)\s*\('
    if not re.search(method_pattern, signature):
        return False
        
    return True


def _extract_method_name(signature: str) -> str:
    """Extract method name from signature."""
    # Pattern: public String methodName(params)
    match = re.search(r'\s+(\w+)\s*\(', signature)
    if match:
        return match.group(1)
    return "unknown"


def _extract_parameter_types(signature: str) -> List[str]:
    """Extract parameter type annotations and types from method signature."""
    parameter_types = []

    # Find the method name first to identify where parameters start
    method_name_match = re.search(r'\s+(\w+)\s*\(', signature)
    if not method_name_match:
        return parameter_types
    
    # Find the opening parenthesis after the method name
    method_name_end = method_name_match.end() - 1  # Position of opening parenthesis
    
    # Find the matching closing parenthesis
    paren_depth = 0
    start_pos = method_name_end
    end_pos = -1
    
    for i in range(start_pos, len(signature)):
        if signature[i] == '(':
            paren_depth += 1
        elif signature[i] == ')':
            paren_depth -= 1
            if paren_depth == 0:
                end_pos = i
                break
    
    if end_pos == -1:
        return parameter_types
    
    # Extract parameters between the method parentheses
    params_str = signature[start_pos + 1:end_pos].strip()
    if not params_str:
        return parameter_types

    # Split by comma, but be careful of generics and annotation parentheses
    params = _smart_split_parameters(params_str)

    for param in params:
        param = param.strip()
        if not param:
            continue

        # Extract full parameter definition (annotations + type)
        # Examples: "@RequestBody String payload", "MultipartFile file", "@RequestParam(required=false) String filename"
        parameter_types.append(param)

    return parameter_types


def _smart_split_parameters(params_str: str) -> List[str]:
    """Split parameters by comma, respecting generic brackets and annotation parentheses."""
    params = []
    current_param = []
    depth = 0  # Track nesting depth of <> and ()

    for char in params_str:
        if char in '<(':
            depth += 1
            current_param.append(char)
        elif char in '>)':
            depth -= 1
            current_param.append(char)
        elif char == ',' and depth == 0:
            params.append(''.join(current_param).strip())
            current_param = []
        else:
            current_param.append(char)

    if current_param:
        params.append(''.join(current_param).strip())

    return params


def _infer_content_types(parameter_types: List[str]) -> List[str]:
    """Infer accepted Content-Types from parameter annotations."""
    content_types = []

    for param in parameter_types:
        param_lower = param.lower()

        if '@requestbody' in param_lower:
            if 'string' in param_lower:
                # @RequestBody String accepts various content types
                content_types.append('application/json')
                content_types.append('application/xml')
                content_types.append('text/plain')
            else:
                # @RequestBody Object expects JSON
                content_types.append('application/json')

        elif 'multipartfile' in param_lower:
            # MultipartFile requires multipart
            content_types.append('multipart/form-data')
            
        elif '@requestparam' in param_lower:
            # @RequestParam uses form data (either URL-encoded or multipart)
            if 'multipartfile' in param_lower:
                content_types.append('multipart/form-data')
            else:
                # Regular @RequestParam uses form data
                content_types.append('application/x-www-form-urlencoded')

        elif 'httpservletrequest' in param_lower:
            # Raw request - accepts various types
            content_types.append('application/json')
            content_types.append('application/octet-stream')
            content_types.append('text/plain')

    # Default if nothing specific found
    if not content_types:
        content_types.append('application/json')

    # Remove duplicates while preserving order
    seen = set()
    unique_types = []
    for ct in content_types:
        if ct not in seen:
            seen.add(ct)
            unique_types.append(ct)

    return unique_types


def _extract_method_body_and_operations(lines: List[str], method_start_idx: int) -> tuple[str, List[str]]:
    """Extract method body and identify key vulnerable operations."""
    # Find opening brace
    idx = method_start_idx
    while idx < len(lines) and '{' not in lines[idx]:
        idx += 1

    if idx >= len(lines):
        return "", []

    # Extract method body until closing brace
    brace_count = 0
    body_lines = []
    started = False

    while idx < len(lines):
        line = lines[idx]

        if '{' in line:
            brace_count += line.count('{')
            started = True

        if started:
            body_lines.append(line)

        if '}' in line:
            brace_count -= line.count('}')
            if brace_count == 0:
                break

        idx += 1
        if len(body_lines) > 100:  # Safety limit
            break

    full_body = '\n'.join(body_lines)

    # Extract key operations (lines with important keywords)
    key_operations = _identify_key_operations(body_lines)

    return full_body, key_operations


def _identify_key_operations(body_lines: List[str]) -> List[str]:
    """Identify key lines showing potentially interesting operations."""
    key_ops = []

    # More generic patterns rather than specific keywords
    patterns = [
        # Method calls that commonly appear in vulnerable code
        r'\w+\.\w+\(',  # Object method calls
        r'new \w+\(',   # Object instantiation
        r'\.read\(',    # Read operations
        r'\.write\(',   # Write operations  
        r'\.parse\(',   # Parse operations
        r'\.serialize\(',  # Serialization
        r'\.deserialize\(',  # Deserialization
        r'throw new',   # Exception throwing
        r'catch \(',    # Exception catching
        r'try \{',      # Try blocks
    ]
    
    for line in body_lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
            continue

        # Check if line matches any patterns or contains interesting operations
        is_interesting = False
        
        # Pattern-based detection
        for pattern in patterns:
            if re.search(pattern, line):
                is_interesting = True
                break
        
        # Also include lines with specific method calls, assignments, or return statements
        if not is_interesting:
            interesting_indicators = [
                '=', 'return', 'if (', 'while (', 'for (', 
                'String', 'Object', 'Exception', 'Error'
            ]
            if any(indicator in line for indicator in interesting_indicators):
                is_interesting = True

        if is_interesting and len(key_ops) < 10:  # Limit to 10 key operations
            key_ops.append(line_stripped)

    return key_ops


def format_endpoint_contexts_for_llm(endpoints: List[EndpointContext]) -> Dict[str, str]:
    """
    Format extracted endpoint contexts into strings suitable for LLM prompt.

    Returns:
        Dictionary with 'application_endpoints', 'container_code_context', and 'vulnerable_patterns'
    """
    if not endpoints:
        return {
            "application_endpoints": "No endpoints found",
            "container_code_context": "No code context available",
            "vulnerable_patterns": "No vulnerable patterns identified"
        }

    # Format endpoints section
    endpoint_descriptions = []
    for ep in endpoints:
        desc = f"""
{ep.http_method} {ep.endpoint_path}
  Method: {ep.method_signature}
  Accepts: {', '.join(ep.accepts_content_types)}
  Parameter Types: {'; '.join(ep.parameter_types) if ep.parameter_types else 'None'}
"""
        endpoint_descriptions.append(desc.strip())

    # Format code context section
    code_contexts = []
    for ep in endpoints:
        if ep.key_operations:
            context = f"""
File: {ep.file_name}
Endpoint: {ep.http_method} {ep.endpoint_path}
Method: {ep.method_name}
Key Operations:
{chr(10).join('  - ' + op for op in ep.key_operations)}
"""
            code_contexts.append(context.strip())

    # Format vulnerable patterns section
    all_key_ops = []
    for ep in endpoints:
        all_key_ops.extend(ep.key_operations)

    return {
        "application_endpoints": '\n\n'.join(endpoint_descriptions),
        "container_code_context": '\n\n'.join(code_contexts) if code_contexts else "See endpoint descriptions above",
        "vulnerable_patterns": '\n'.join(all_key_ops) if all_key_ops else "See key operations in endpoint descriptions"
    }
