import logging
import re

logger = logging.getLogger(__name__)


def detect_framework(code_snippets: dict[str, str]) -> str:
    """
    Detect web framework from code patterns and annotations.

    Args:
        code_snippets: Dictionary of filename -> code content

    Returns:
        Framework name: "struts2", "spring", "jaxrs", "servlet", or "unknown"
    """
    all_code = " ".join(code_snippets.values())

    # Order matters - check most specific first
    if "@Action" in all_code or "ActionSupport" in all_code:
        return "struts2"
    elif "@PostMapping" in all_code or "@RestController" in all_code or "@RequestMapping" in all_code:
        return "spring"
    elif "@Path" in all_code and ("@POST" in all_code or "@GET" in all_code):
        return "jaxrs"
    elif "@WebServlet" in all_code:
        return "servlet"

    return "unknown"


def _infer_content_type_from_action_class(action_class: str, code_snippets: dict[str, str]) -> str:
    """
    Infer Content-Type by checking if Action class has File upload properties.

    Args:
        action_class: Fully qualified class name (e.g., "com.vuln.VulnerableAction")
        code_snippets: Dictionary of filename -> code content

    Returns:
        "multipart/form-data" if File properties found, else "application/x-www-form-urlencoded"
    """
    # Extract simple class name from fully qualified name
    simple_class_name = action_class.split('.')[-1]

    # Find the Action class file by class name
    action_class_content = None
    for filename, content in code_snippets.items():
        if not isinstance(content, str):
            continue
        # Look for class definition: "public class VulnerableAction"
        if f"class {simple_class_name}" in content:
            action_class_content = content
            logger.debug(f"Found Action class {simple_class_name} in {filename}")
            break

    if not action_class_content:
        logger.warning(f"Could not find Action class {simple_class_name} in code snippets")
        return "application/x-www-form-urlencoded"

    # Look for setter methods with File type: setUpload(File f), setFile(File f), etc.
    # Pattern: public void set*(File ...) or set*(File[] ...)
    setter_pattern = r'public\s+void\s+set\w+\s*\(\s*(File(?:\[\])?)\s+\w+\s*\)'
    file_setters = re.findall(setter_pattern, action_class_content)

    if file_setters:
        logger.info(f"Detected File upload in {simple_class_name} (found {len(file_setters)} File setters) → multipart/form-data")
        return "multipart/form-data"
    else:
        logger.debug(f"No File properties in {simple_class_name} → application/x-www-form-urlencoded")
        return "application/x-www-form-urlencoded"


def extract_struts_xml_actions(code_snippets: dict[str, str]) -> list[dict[str, any]]:
    """
    Extract action mappings from struts.xml configuration file.

    Struts 2.0.x - 2.1.x primarily use XML configuration instead of annotations.
    Parse <action name="..." class="..." method="..."> elements.

    Args:
        code_snippets: Dictionary of filename -> content (should include struts.xml)

    Returns:
        list of endpoint metadata dictionaries
    """
    endpoints = []

    # Find struts.xml in code snippets
    struts_xml_content = None
    struts_xml_filename = None
    for filename, content in code_snippets.items():
        if "struts.xml" in filename.lower() and isinstance(content, str):
            struts_xml_content = content
            struts_xml_filename = filename
            logger.debug(f"Found struts.xml at: {filename}")
            break

    if not struts_xml_content:
        logger.warning(f"No struts.xml found in code snippets. Available files: {list(code_snippets.keys())}")
        return endpoints

    logger.debug(f"Parsing struts.xml content (length: {len(struts_xml_content)} chars)")

    # Extract namespace from <package namespace="..."> attribute (NOT the name attribute)
    # In Struts 2.x, 'name' is a package identifier; 'namespace' determines the URL prefix
    # If no namespace attribute exists, Struts defaults to root namespace ""
    namespace_match = re.search(r'<package\s+[^>]*namespace="([^"]*)"', struts_xml_content)
    namespace = namespace_match.group(1).rstrip("/") if namespace_match else ""

    # Parse <action ...> tags with flexible attribute order
    # Method attribute is optional, defaults to "execute"
    # The regex now handles any attribute order: name/class/method can appear in any sequence
    action_tag_pattern = r'<action\s+([^>]+)>'

    for action_match in re.finditer(action_tag_pattern, struts_xml_content):
        attributes_str = action_match.group(1)

        # Extract individual attributes with separate regexes
        name_match = re.search(r'name\s*=\s*"([^"]+)"', attributes_str)
        class_match = re.search(r'class\s*=\s*"([^"]+)"', attributes_str)
        method_match = re.search(r'method\s*=\s*"([^"]+)"', attributes_str)

        # Skip if missing required attributes
        if not name_match or not class_match:
            logger.debug(f"Skipping invalid action tag (missing name or class): {attributes_str[:100]}")
            continue

        action_name = name_match.group(1)  # e.g., "vulnerable"
        action_class = class_match.group(1)  # e.g., "com.vuln.VulnerableAction"
        method_name = method_match.group(1) if method_match else "execute"  # default

        # Struts 2.x action URLs: /{namespace}/{actionName}.action
        # Example: /vulnerable.action or /vuln/vulnerable.action
        path = f"{namespace}/{action_name}.action" if namespace else f"/{action_name}.action"
        path = path.replace("//", "/")  # Clean up double slashes

        # Infer Content-Type by checking if Action class has File upload properties
        content_type = _infer_content_type_from_action_class(action_class, code_snippets)

        endpoints.append({
            "path": path,
            "method": "POST",  # Struts actions default to POST
            "consumes": content_type,
            "produces": None,
            "parameter_types": [],  # Would need to parse Action class for properties
            "handler_class": action_class,
            "handler_method": method_name,
            "framework": "struts2",
            "config_type": "xml"
        })

        logger.debug(f"Extracted Struts XML action: {path} -> {action_class}.{method_name}()")

    if endpoints:
        logger.info(f"Successfully extracted {len(endpoints)} actions from {struts_xml_filename}")
    else:
        logger.warning(f"No actions extracted from {struts_xml_filename}. Check XML structure.")
        logger.debug(f"struts.xml preview: {struts_xml_content[:500]}...")

    return endpoints


def extract_struts2_endpoints(code_snippets: dict[str, str]) -> list[dict[str, any]]:
    """
    Extract Struts2 endpoints from both @Action annotations AND struts.xml config.

    Struts 2.0.x - 2.1.x: Primarily XML configuration
    Struts 2.1.x+: Convention plugin with @Action annotations

    Priority order:
    1. struts.xml config (most reliable, has namespace)
    2. @Action annotations with smart inference
    3. Package name → namespace inference if no config

    Args:
        code_snippets: Dictionary of filename -> Struts2 Action code/config

    Returns:
        list of endpoint metadata dictionaries
    """
    # Priority 1: Try XML config first (most reliable)
    xml_endpoints = extract_struts_xml_actions(code_snippets)
    if xml_endpoints:
        logger.debug(f"Using {len(xml_endpoints)} endpoints from struts.xml (priority 1)")
        return xml_endpoints

    # Priority 2: Extract from @Action annotations with smart namespace inference
    endpoints = []
    inferred_namespace = None

    for filename, content in code_snippets.items():
        if not isinstance(content, str):
            continue

        # Extract package name to infer namespace (package com.vuln → namespace /vuln)
        if inferred_namespace is None:
            package_match = re.search(r'package\s+([\w.]+)\s*;', content)
            if package_match:
                package_name = package_match.group(1)
                # Take last part of package as namespace (com.vuln.actions → actions, com.vuln → vuln)
                namespace_part = package_name.split('.')[-1]
                inferred_namespace = f"/{namespace_part}"
                logger.debug(f"Inferred Struts namespace '{inferred_namespace}' from package '{package_name}'")

        # Extract @Namespace at class level (overrides inferred)
        namespace_match = re.search(r'@Namespace\s*\(\s*["\']([^"\']+)["\']\s*\)', content)
        base_path = namespace_match.group(1) if namespace_match else (inferred_namespace or "/")

        # Find @Action annotations
        action_pattern = r'@Action\s*\(\s*value\s*=\s*["\']([^"\']+)["\']'
        for action_match in re.finditer(action_pattern, content):
            action_name = action_match.group(1)

            # Construct Struts 2.x action URL: /{namespace}/{actionName}.action
            # Clean up path and add .action extension
            full_path = f"{base_path}/{action_name}".replace("//", "/")
            if not full_path.endswith('.action'):
                full_path += '.action'

            # Extract JavaBean properties from setter methods
            properties = []
            setter_pattern = r'public\s+void\s+set(\w+)\s*\(\s*(\w+(?:\[\])?)?\s+\w+\s*\)'
            for setter in re.finditer(setter_pattern, content):
                prop_name_pascal = setter.group(1)  # e.g., "FileName"
                prop_type = setter.group(2) if setter.group(2) else "String"
                # Convert to camelCase (FileName -> fileName)
                prop_name = prop_name_pascal[0].lower() + prop_name_pascal[1:]

                properties.append({
                    "annotation": "property",
                    "type": prop_type,
                    "name": prop_name
                })

            # Infer Content-Type from property types
            has_file = any(p["type"] in ["File", "File[]"] for p in properties)
            consumes = None
            if has_file:
                consumes = "multipart/form-data"
            elif properties:
                consumes = "application/x-www-form-urlencoded"

            endpoints.append({
                "path": full_path,
                "method": "POST",  # Struts actions typically use POST
                "consumes": consumes,
                "produces": None,
                "parameter_types": properties,
                "method_name": action_name,
                "source_file": filename,
                "framework": "struts2",
                "config_type": "annotation"
            })

            logger.debug(f"Extracted Struts annotation endpoint: {full_path} (namespace: {base_path})")

    if endpoints:
        logger.debug(f"Using {len(endpoints)} annotation-based endpoints with smart namespace inference (priority 2)")

    return endpoints


def extract_spring_endpoints(code_snippets: dict[str, str]) -> list[dict[str, any]]:
    """
    Extract Spring Boot/MVC endpoints from @RequestMapping annotations.

    This is the existing Spring extraction logic refactored into a function.

    Args:
        code_snippets: Dictionary of filename -> Spring controller code

    Returns:
        list of endpoint metadata dictionaries
    """
    endpoints = []

    for filename, content in code_snippets.items():
        if not isinstance(content, str):
            continue

        # Find all endpoint methods with their full signatures
        # Pattern captures: (annotation) (method_name) (parameters)
        method_pattern = r'(@(?:Post|Get|Put|Delete|Request)Mapping[^)]+\))\s*\n\s*public\s+\w+\s+(\w+)\(([^)]*)\)'

        for match in re.finditer(method_pattern, content, re.MULTILINE):
            annotation = match.group(1)
            method_name = match.group(2)
            parameters = match.group(3)

            # Extract path from annotation
            path_match = re.search(r'(?:value\s*=\s*)?["\']([^"\']+)["\']', annotation)
            path = path_match.group(1) if path_match else "/"

            # Extract HTTP method from annotation type
            if "@PostMapping" in annotation:
                http_method = "POST"
            elif "@GetMapping" in annotation:
                http_method = "GET"
            elif "@PutMapping" in annotation:
                http_method = "PUT"
            elif "@DeleteMapping" in annotation:
                http_method = "DELETE"
            else:
                http_method = "REQUEST"

            # Extract consumes attribute (required Content-Type)
            consumes_match = re.search(r'consumes\s*=\s*["\']([^"\']+)["\']', annotation)
            consumes = consumes_match.group(1) if consumes_match else None

            # Extract produces attribute (response Content-Type)
            produces_match = re.search(r'produces\s*=\s*["\']([^"\']+)["\']', annotation)
            produces = produces_match.group(1) if produces_match else None

            # Parse parameter types and annotations
            param_types = []
            if parameters.strip():
                # Extract @RequestBody, @RequestParam, etc. with their types
                # Pattern: @Annotation(optional_params) Type variableName
                param_pattern = r'(?:@(\w+)(?:\([^)]*\))?\s+)?(\S+)\s+(\w+)'
                for param_match in re.finditer(param_pattern, parameters):
                    param_annotation = param_match.group(1)
                    param_type = param_match.group(2)
                    param_name = param_match.group(3)

                    # Skip common Java keywords that aren't parameters
                    if param_type in ['final', 'static', 'public', 'private', 'protected']:
                        continue

                    param_types.append({
                        "annotation": param_annotation,
                        "type": param_type,
                        "name": param_name
                    })

            endpoints.append({
                "path": path,
                "method": http_method,
                "consumes": consumes,
                "produces": produces,
                "parameter_types": param_types,
                "method_name": method_name,
                "source_file": filename,
                "framework": "spring"
            })

    return endpoints


def extract_endpoint_metadata(blueprint_code_snippets: dict[str, str]) -> list[dict[str, any]]:
    """
    Framework-agnostic endpoint metadata extraction.

    Detects the web framework used in the blueprint and calls the appropriate
    extractor function. Supports Spring Boot, Struts2, JAX-RS, and servlets.

    This provides structured information for constructing accurate HTTP requests.

    Args:
        blueprint_code_snippets: Dictionary of filename -> Java code content

    Returns:
        list of endpoint metadata dictionaries containing:
        - path: endpoint URL path
        - method: HTTP method (GET, POST, etc.)
        - consumes: Content-Type from consumes attribute
        - produces: Content-Type from produces attribute
        - parameter_types: list of dicts with annotation, type, and name
        - method_name: Java method name
        - source_file: Source filename
        - framework: Detected framework name
    """
    # Detect framework from code patterns
    framework = detect_framework(blueprint_code_snippets)
    logger.info(f"Detected framework: {framework}")

    # Call appropriate extractor based on framework
    if framework == "struts2":
        endpoints = extract_struts2_endpoints(blueprint_code_snippets)
    elif framework == "spring":
        endpoints = extract_spring_endpoints(blueprint_code_snippets)
    elif framework == "jaxrs":
        # Future: JAX-RS (@Path, @POST, @GET) support
        logger.warning("JAX-RS framework detected but extractor not yet implemented")
        endpoints = []
    elif framework == "servlet":
        # Future: @WebServlet support
        logger.warning("Servlet framework detected but extractor not yet implemented")
        endpoints = []
    else:
        logger.warning(f"Unknown or unsupported framework: {framework}")
        endpoints = []

    # Log results
    if endpoints:
        logger.info(f"Extracted {len(endpoints)} endpoint metadata entries from {framework} blueprint")
    else:
        logger.warning(f"No endpoints extracted from {framework} blueprint")

    return endpoints


def extract_endpoints_from_blueprint(blueprint_code_snippets: dict[str, str]) -> list[str]:
    """
    Extract target endpoints from blueprint code snippets.

    Args:
        blueprint_code_snippets: Dictionary of filename -> Java code content

    Returns:
        list of endpoint paths (e.g., ["/api/vulnerable", "/api/parse"])
    """
    endpoints = []

    # Patterns to match Spring Boot method-level endpoint annotations
    # Enhanced to handle both simple and complex annotation formats:
    # - Simple: @PostMapping("/path")
    # - Complex: @PostMapping(value = "/path", consumes = "...")
    endpoint_patterns = [
        r'@PostMapping\((?:value\s*=\s*)?["\']([^"\']+)["\']',  # @PostMapping("/path") or @PostMapping(value = "/path", ...)
        r'@GetMapping\((?:value\s*=\s*)?["\']([^"\']+)["\']',   # @GetMapping("/path") or @GetMapping(value = "/path", ...)
        r'@PutMapping\((?:value\s*=\s*)?["\']([^"\']+)["\']',   # @PutMapping support
        r'@DeleteMapping\((?:value\s*=\s*)?["\']([^"\']+)["\']', # @DeleteMapping support
        r'@RequestMapping\([^)]*value\s*=\s*["\']([^"\']+)["\']',  # @RequestMapping(value="/api/test", ...)
    ]

    # Base path patterns for controller-level mappings
    base_path_patterns = [
        r'@RequestMapping\(["\']([^"\']+)["\']\)\s*\n\s*public\s+class',  # Controller base path
    ]

    controller_base_path = ""

    # Search through all code snippets
    for _, content in blueprint_code_snippets.values():
        if not isinstance(content, str):
            continue

        # First, extract controller base path
        for pattern in base_path_patterns:
            matches = re.findall(pattern, content, re.MULTILINE)
            if matches:
                controller_base_path = matches[0].rstrip('/')
                break

        # Then extract individual endpoint mappings
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                # Combine base path with endpoint path
                full_endpoint = (controller_base_path + match).replace('//', '/')
                endpoints.append(full_endpoint)

    # Log extraction results for debugging
    unique_endpoints = list(set(endpoints))
    logger.info(f"Extracted {len(unique_endpoints)} endpoints from blueprint: {unique_endpoints}")
    if len(unique_endpoints) == 0:
        logger.warning("No endpoints extracted from blueprint - LLM may not know target URL")
        logger.debug(f"Blueprint files analyzed: {list(blueprint_code_snippets.keys())}")

    return unique_endpoints
