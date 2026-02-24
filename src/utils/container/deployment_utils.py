import logging
import os
import re

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


def extract_vulnerability_code(llm_response: str) -> str:
    """
    Extract vulnerability code from LLM response.

    Args:
        llm_response: LLM response to extract vulnerability code from

    Returns:
        Vulnerability code
    """
    # First, look for any code blocks
    code_blocks = re.findall(r"```(?:java)?\s*([\s\S]*?)```", llm_response)

    # For each code block, extract the vulnerability demonstration code
    for block in code_blocks:
        # Look for a complete Java class with main method
        if "class" in block and "public static void main" in block:
            # Extract a demonstrateVulnerability or similar method
            method_match = re.search(
                r"(?:private|public|protected)?\s+static\s+void\s+(?:demonstrateVulnerability|exploit|runVulnerability|showVulnerability)\s*\([^)]*\)\s*\{([\s\S]*?)\}",
                block,
            )
            if method_match:
                return method_match.group(1).strip()

            # Extract code from main method if no specific vulnerability method
            main_match = re.search(r"public\s+static\s+void\s+main\s*\([^)]*\)\s*\{([\s\S]*?)\}", block)
            if main_match:
                main_code = main_match.group(1).strip()
                # Skip boilerplate code like print statements at the beginning
                clean_code = re.sub(
                    r"^\s*System\.out\.println\([^)]*\);\s*",
                    "",
                    main_code,
                    flags=re.MULTILINE,
                )
                return clean_code

    # If no code blocks with methods found, look for snippets with Yaml usage
    yaml_pattern = re.search(
        r'(?:String\s+\w+\s*=\s*"[^"]*!!)[^;]*(.*?)(?:Object\s+\w+\s*=\s*yaml\.load\([^)]*\))',
        llm_response,
        re.DOTALL,
    )
    if yaml_pattern:
        return yaml_pattern.group(0)

    # Try extracting any code block that mentions Yaml and load
    yaml_code = re.findall(r"((?:Yaml\s+\w+|new\s+Yaml).*?(?:load|dump).*;)", llm_response, re.DOTALL)
    if yaml_code:
        return "\n".join(yaml_code)

    # If nothing found, return empty string
    return ""

def normalize_file_paths(files: dict[str, str]) -> dict[str, str]:
    """
    Normalize file paths to ensure proper Maven structure and fix naming issues.
    Now creates proper package directory structure (e.g., src/main/java/com/vuln/).

    Args:
        files: Dictionary of file paths to content

    Returns:
        Dictionary with normalized file paths
    """
    normalized_files = {}

    for file_path, content in files.items():
        if file_path.endswith(".java"):
            # Improved regex to match class declarations more accurately
            class_match = re.search(r"^\s*(?:public\s+)?(?:final\s+|abstract\s+)?class\s+(\w+)", content, re.MULTILINE)
            if class_match:
                class_name = class_match.group(1)

                # Avoid using reserved keywords or invalid class names
                if class_name.lower() in {"package", "public", "class"}:
                    logger.warning(f"Ignored invalid class name '{class_name}' in {file_path}")
                    continue

                logger.info(f"Class name extracted from file: {class_name}")

                # Extract package declaration to create proper directory structure
                package_match = re.search(r"^\s*package\s+([a-zA-Z_][\w.]*)\s*;", content, re.MULTILINE)
                if package_match:
                    package_name = package_match.group(1).strip()
                    # Convert package name to directory path (e.g., com.vuln -> com/vuln)
                    package_path = package_name.replace(".", "/")
                    package_dir = f"src/main/java/{package_path}"
                else:
                    # No package declaration - use default structure (will be added later)
                    package_dir = "src/main/java/com/vuln"

                # Fix problematic file names or incorrect paths
                if (
                    file_path.endswith("package.java")
                    or "code_java_" in file_path
                    or "code_block_" in file_path
                    or file_path.endswith("/public.java")
                    or class_name not in file_path
                ):
                    normalized_path = f"{package_dir}/{class_name}.java"
                    logger.info(f"Normalized LLM-generated file: {file_path} -> {normalized_path}")
                else:
                    # Ensure proper Java file path structure
                    if not file_path.startswith("src/main/java/"):
                        normalized_path = f"{package_dir}/{class_name}.java"
                        logger.info(f"Fixed path structure: {file_path} -> {normalized_path}")
                    else:
                        normalized_path = file_path

                # Store the normalized file
                normalized_files[normalized_path] = content
            else:
                # These might be valid Java files that need to be included
                logger.warning(f"No class declaration found in Java file {file_path}, attempting to include anyway")

                # If it's a code snippet file, try to include it with a generic name
                if "code_java_" in file_path or "code_block_" in file_path:
                    # Extract number from filename like code_java_1.java
                    num_match = re.search(r'code_java_(\d+)', file_path)
                    if num_match:
                        num = num_match.group(1)
                        normalized_path = f"src/main/java/com/vuln/GeneratedClass{num}.java"
                        logger.warning(f"Including file without class declaration: {file_path} -> {normalized_path}")
                        normalized_files[normalized_path] = content
                    else:
                        logger.warning(f"Skipping malformed code snippet: {file_path}")
                else:
                    logger.warning(f"Skipping Java file without class declaration: {file_path}")

        elif file_path.endswith(".jsp"):
            # JSP files MUST go to webapp root for servlet containers (WAR projects)
            if file_path.startswith("src/main/webapp/"):
                # Already correct from LLM framework adaptation
                normalized_path = file_path
                logger.debug(f"Preserving LLM-generated JSP path: {file_path}")
            else:
                filename = file_path.split("/")[-1]
                normalized_path = f"src/main/webapp/{filename}"
                logger.info(f"Normalized JSP file: {file_path} -> {normalized_path}")

            normalized_files[normalized_path] = content

        elif file_path.endswith((".yaml", ".yml", ".properties", ".xml", ".json")):
            # CRITICAL: Preserve LLM-generated paths for webapp structure
            # WAR projects (Struts) need src/main/webapp/WEB-INF/web.xml
            # JAR projects (Spring Boot) need src/main/resources/
            if file_path.startswith(("src/main/webapp/", "src/main/resources/", "src/main/java/")):
                # Path already correct from LLM framework adaptation - preserve it
                normalized_path = file_path
                logger.debug(f"Preserving LLM-generated path: {file_path}")
            else:
                # Path needs normalization - determine correct location
                filename = file_path.split("/")[-1]

                # web.xml MUST go to webapp/WEB-INF for WAR projects
                if filename == "web.xml":
                    normalized_path = "src/main/webapp/WEB-INF/web.xml"
                    logger.info(f"Normalized web.xml to WAR location: {file_path} -> {normalized_path}")
                # struts.xml goes to classpath (resources) per Struts convention
                elif filename == "struts.xml":
                    normalized_path = "src/main/resources/struts.xml"
                    logger.info(f"Normalized struts.xml to resources: {file_path} -> {normalized_path}")
                else:
                    # Other config files go to resources
                    normalized_path = f"src/main/resources/{filename}"
                    logger.info(f"Normalized resource file: {file_path} -> {normalized_path}")

            normalized_files[normalized_path] = content

        else:
            # Keep other files as-is
            normalized_path = file_path
            normalized_files[normalized_path] = content

    return normalized_files


def ensure_consistent_package_declarations(files: dict[str, str]) -> dict[str, str]:
    """
    Ensure all Java files have consistent package declarations.

    This fixes the common issue where LLM-generated files have inconsistent
    or missing package declarations, which causes Maven compilation failures.

    Args:
        files: Dictionary of file paths to content

    Returns:
        Fixed files with consistent package declarations
    """
    fixed_files = {}
    java_files = {path: content for path, content in files.items() if path.endswith(".java")}

    if not java_files:
        return files

    # Find the package declaration from existing files (prefer one that already has it)
    target_package = "demo"  # Default package

    for content in java_files.values():
        package_match = re.search(r"^\s*package\s+([a-zA-Z_][\w.]*)\s*;", content, re.MULTILINE)
        if package_match:
            target_package = package_match.group(1).strip()
            break

    logger.info(f"Ensuring all Java files use package: {target_package}")

    for file_path, content in files.items():
        if not file_path.endswith(".java"):
            fixed_files[file_path] = content
            continue

        # Check if package declaration exists
        package_match = re.search(r"^\s*package\s+([a-zA-Z_][\w.]*)\s*;", content, re.MULTILINE)

        if package_match:
            # Package exists, ensure it matches target package
            existing_package = package_match.group(1).strip()
            if existing_package != target_package:
                logger.info(f"Updating package declaration in {file_path}: {existing_package} -> {target_package}")
                content = re.sub(
                    r"^\s*package\s+[a-zA-Z_][\w.]*\s*;", f"package {target_package};", content, flags=re.MULTILINE
                )
        else:
            # No package declaration, add it
            logger.info(f"Adding package declaration to {file_path}: {target_package}")
            # Add package declaration at the beginning, after any comments

            # Find the first import or class declaration
            import_match = re.search(r"^\s*import\s+", content, re.MULTILINE)
            class_match = re.search(r"^\s*(?:public\s+)?class\s+", content, re.MULTILINE)

            insert_pos = 0
            if import_match:
                insert_pos = import_match.start()
            elif class_match:
                insert_pos = class_match.start()

            # Insert package declaration
            content = content[:insert_pos] + f"package {target_package};\n\n" + content[insert_pos:]

        fixed_files[file_path] = content

    return fixed_files


def fix_resource_access_patterns(files: dict[str, str]) -> dict[str, str]:
    """
    Fix only problematic resource access patterns in Java code for containerized environments.

    This function handles:
    - Only hardcoded "src/main/resources/" paths that won't work in containers
    - Leaves working variable-based code alone

    Args:
        files: Dictionary of file paths to content

    Returns:
        Fixed files with proper resource access patterns
    """
    fixed_files = {}

    FILE_INPUT_MAPPINGS = {
        "FileInputStream": "InputStream",
        "FileReader": "InputStreamReader",
        "BufferedReader": "BufferedReader",
    }

    for file_path, content in files.items():
        if not file_path.endswith(".java"):
            fixed_files[file_path] = content
            continue

        logger.info(f"Comprehensively fixing resource access patterns in {file_path}")

        # Extract class name once for the entire file
        class_match = re.search(r"class\s+(\w+)", content)
        class_name = class_match.group(1) if class_match else "VulnerabilityDemo"

        modified = False

        for file_input_type, stream_type in FILE_INPUT_MAPPINGS.items():
            direct_pattern = rf'({file_input_type})\s+(\w+)\s*=\s*new\s+{file_input_type}\s*\(\s*["\']src/main/resources/([^"\']+)["\']\s*\)'

            def replace_direct(match, stream_type=stream_type, class_name=class_name):
                _, var_name, resource_name = match.groups()
                return f'{stream_type} {var_name} = {class_name}.class.getResourceAsStream("/{resource_name}") /* Fixed: Use classpath resource */'

            if re.search(direct_pattern, content):
                logger.info(f"Found direct {file_input_type} pattern in {file_path}")
                content = re.sub(direct_pattern, replace_direct, content)
                modified = True

            try_pattern = rf'try\s*\(\s*{file_input_type}\s+(\w+)\s*=\s*new\s+{file_input_type}\s*\(\s*["\']src/main/resources/([^"\']+)["\']\s*\)\s*\)'

            def replace_try(match, stream_type=stream_type, class_name=class_name):
                var_name, resource_name = match.groups()
                return f'try ({stream_type} {var_name} = {class_name}.class.getResourceAsStream("/{resource_name}") /* Fixed: Use classpath resource */)'

            if re.search(try_pattern, content):
                logger.info(f"Found try-with-resources {file_input_type} pattern in {file_path}")
                content = re.sub(try_pattern, replace_try, content)
                modified = True

        if modified:
            required_imports = set()

            # Check which stream types are now being used
            for stream_type in FILE_INPUT_MAPPINGS.values():
                if (
                    stream_type in content and stream_type != "BufferedReader"
                ):  # BufferedReader might be there originally
                    if stream_type == "InputStream":
                        required_imports.add("java.io.InputStream")
                    elif stream_type == "InputStreamReader":
                        required_imports.add("java.io.InputStreamReader")

            # Add missing imports
            for import_stmt in required_imports:
                if f"import {import_stmt};" not in content:
                    logger.info(f"Adding missing import: {import_stmt}")
                    # Find import section and add
                    import_section = re.search(r"((?:import\s+[^;]+;\s*)+)", content)
                    if import_section:
                        imports = import_section.group(1)
                        new_imports = imports + f"import {import_stmt};\n"
                        content = content.replace(imports, new_imports)
                    else:
                        # Add after package declaration
                        package_match = re.search(r"package\s+[^;]+;\s*", content)
                        if package_match:
                            package_end = package_match.end()
                            content = content[:package_end] + f"\nimport {import_stmt};\n" + content[package_end:]
                        else:
                            content = f"import {import_stmt};\n" + content

        fixed_files[file_path] = content

    return fixed_files


def ensure_required_imports(files: dict[str, str]) -> dict[str, str]:
    """
    Comprehensively analyze Java code and ensure all required imports are present.

    This function scans for:
    - Class usage patterns (new ClassName, ClassName.method, etc.)
    - Method return types and parameters
    - Exception types in catch blocks
    - Static imports

    Args:
        files: Dictionary of file paths to content

    Returns:
        Fixed files with all required imports
    """
    # Comprehensive mapping of classes to their full import paths
    IMPORT_MAP = {
        # Java standard library - I/O
        "File": "java.io.File",
        "InputStream": "java.io.InputStream",
        "OutputStream": "java.io.OutputStream",
        "FileInputStream": "java.io.FileInputStream",
        "FileOutputStream": "java.io.FileOutputStream",
        "BufferedReader": "java.io.BufferedReader",
        "BufferedWriter": "java.io.BufferedWriter",
        "FileReader": "java.io.FileReader",
        "FileWriter": "java.io.FileWriter",
        "StringReader": "java.io.StringReader",
        "StringWriter": "java.io.StringWriter",
        "PrintWriter": "java.io.PrintWriter",
        "ByteArrayInputStream": "java.io.ByteArrayInputStream",
        "ByteArrayOutputStream": "java.io.ByteArrayOutputStream",
        "ObjectInputStream": "java.io.ObjectInputStream",
        "ObjectOutputStream": "java.io.ObjectOutputStream",
        "Serializable": "java.io.Serializable",
        "IOException": "java.io.IOException",
        # Java standard library - Collections
        "List": "java.util.List",
        "ArrayList": "java.util.ArrayList",
        "LinkedList": "java.util.LinkedList",
        "Map": "java.util.Map",
        "HashMap": "java.util.HashMap",
        "TreeMap": "java.util.TreeMap",
        "Set": "java.util.Set",
        "HashSet": "java.util.HashSet",
        "TreeSet": "java.util.TreeSet",
        "Collection": "java.util.Collection",
        "Collections": "java.util.Collections",
        "Arrays": "java.util.Arrays",
        "Scanner": "java.util.Scanner",
        "Properties": "java.util.Properties",
        "Base64": "java.util.Base64",
        # Java standard library - Other common classes
        "String": None,  # Primitive, no import needed
        "StringBuilder": None,  # java.lang, no import needed
        "StringBuffer": None,  # java.lang, no import needed
        "Exception": None,  # java.lang, no import needed
        "RuntimeException": None,  # java.lang, no import needed
        "System": None,  # java.lang, no import needed
        # SnakeYAML library
        "Yaml": "org.yaml.snakeyaml.Yaml",
        "Constructor": "org.yaml.snakeyaml.constructor.Constructor",
        "SafeConstructor": "org.yaml.snakeyaml.constructor.SafeConstructor",
        # EHCache library
        "Cache": "net.sf.ehcache.Cache",
        "CacheManager": "net.sf.ehcache.CacheManager",
        "Element": "net.sf.ehcache.Element",
        # Jackson library
        "ObjectMapper": "com.fasterxml.jackson.databind.ObjectMapper",
        "JsonNode": "com.fasterxml.jackson.databind.JsonNode",
    }

    fixed_files = {}

    for file_path, content in files.items():
        if not file_path.endswith(".java"):
            fixed_files[file_path] = content
            continue

        logger.info(f"Ensuring required imports for {file_path}")

        # Find all existing imports
        existing_imports = set()
        existing_import_lines = []
        import_pattern = r"import\s+([^;]+);"
        for match in re.finditer(import_pattern, content):
            import_stmt = match.group(1).strip()
            existing_imports.add(import_stmt)
            existing_import_lines.append(match.group(0))
            # Also track simple class names
            class_name = import_stmt.split(".")[-1]
            existing_imports.add(class_name)

        # Find all class references in the code
        needed_imports = set()

        # Pattern 1: new ClassName() or ClassName.staticMethod()
        class_usage_patterns = [
            r"\bnew\s+([A-Z][a-zA-Z0-9_]*)\s*\(",  # new ClassName()
            r"\b([A-Z][a-zA-Z0-9_]*)\s*\.\s*[a-zA-Z]",  # ClassName.method
            r"\b([A-Z][a-zA-Z0-9_]*)\s+\w+\s*[=;]",  # ClassName variable
            r"catch\s*\(\s*([A-Z][a-zA-Z0-9_]*)",  # catch (ExceptionType
            r"throws\s+([A-Z][a-zA-Z0-9_]*)",  # throws ExceptionType
            r"implements\s+([A-Z][a-zA-Z0-9_]*)",  # implements InterfaceType
            r"extends\s+([A-Z][a-zA-Z0-9_]*)",  # extends ClassType
        ]

        for pattern in class_usage_patterns:
            for match in re.finditer(pattern, content):
                class_name = match.group(1)
                if class_name in IMPORT_MAP and class_name not in existing_imports:
                    import_path = IMPORT_MAP[class_name]
                    if import_path and import_path not in existing_imports:
                        needed_imports.add(import_path)
                        logger.debug(f"Found usage of {class_name}, adding import {import_path}")

        # Add missing imports
        if needed_imports:
            logger.info(f"Adding {len(needed_imports)} missing imports to {file_path}")

            # Find where to insert imports
            package_match = re.search(r"package\s+[^;]+;\s*", content)
            if package_match:
                insert_pos = package_match.end()
            else:
                # Insert at the beginning if no package
                insert_pos = 0

            # Create import statements
            import_statements = []
            for import_path in sorted(needed_imports):
                import_statements.append(f"import {import_path};")

            # Insert imports
            new_imports = "\n".join(import_statements) + "\n"
            if insert_pos == 0:
                content = new_imports + content
            else:
                content = content[:insert_pos] + "\n" + new_imports + content[insert_pos:]

        fixed_files[file_path] = content

    return fixed_files


def validate_and_fix_java_imports(files: dict[str, str]) -> dict[str, str]:
    """
    Validation and fixing of Java imports with type casting fixes.

    Args:
        files: Dictionary of file paths to content

    Returns:
        Fixed files with proper imports and type corrections
    """
    # Import fixes including EHCache-specific classes
    # TODO: Replace with a non-static approach
    import_fixes = {
        "File": "java.io.File",
        "IOException": "java.io.IOException",
        "FileReader": "java.io.FileReader",
        "BufferedReader": "java.io.BufferedReader",
        "FileInputStream": "java.io.FileInputStream",
        "ObjectInputStream": "java.io.ObjectInputStream",
        "ObjectOutputStream": "java.io.ObjectOutputStream",
        "ByteArrayInputStream": "java.io.ByteArrayInputStream",
        "ByteArrayOutputStream": "java.io.ByteArrayOutputStream",
        "Serializable": "java.io.Serializable",
        "ArrayList": "java.util.ArrayList",
        "List": "java.util.List",
        "Map": "java.util.Map",
        "HashMap": "java.util.HashMap",
        "Scanner": "java.util.Scanner",
        "Properties": "java.util.Properties",
        "Base64": "java.util.Base64",
        # EHCache specific
        "Element": "net.sf.ehcache.Element",
        "Cache": "net.sf.ehcache.Cache",
        "CacheManager": "net.sf.ehcache.CacheManager",
    }

    fixed_files = {}

    for file_path, content in files.items():
        if not file_path.endswith(".java"):
            fixed_files[file_path] = content
            continue

        # Fix type casting issues FIRST
        content = fix_java_type_casting(content)

        # Find existing imports
        existing_imports = set()
        import_pattern = r"import\s+([^;]+);"
        for match in re.finditer(import_pattern, content):
            import_stmt = match.group(1).strip()
            existing_imports.add(import_stmt)
            class_name = import_stmt.split(".")[-1]
            existing_imports.add(class_name)

        # Find classes used that might need imports
        missing_imports = []

        for class_name, import_path in import_fixes.items():
            # Check if class is used but not imported
            class_pattern = rf"\b{re.escape(class_name)}\b"
            if (
                re.search(class_pattern, content)
                and class_name not in existing_imports
                and import_path not in existing_imports
            ):
                missing_imports.append(import_path)

        # Add missing imports
        if missing_imports:
            logger.info(f"Adding missing imports to {file_path}: {missing_imports}")
            content = insert_imports(content, missing_imports)

        fixed_files[file_path] = content

    return fixed_files


def fix_java_type_casting(content: str) -> str:
    """
    Fix common Java type casting issues that cause compilation errors.

    Args:
        content: Java code content

    Returns:
        Fixed Java code
    """
    # Cast cache.get() results to Element first
    content = re.sub(
        r"(\w+)\s*=\s*cache\.get\(([^)]+)\)\.getObjectValue\(\);",
        r"\1 = (Serializable) cache.get(\2).getObjectValue();",
        content,
    )

    # Handle Element retrieval separately
    content = re.sub(r"Element\s+(\w+)\s*=\s*cache\.get\(([^)]+)\);", r"Element \1 = cache.get(\2);", content)

    # Cast getObjectValue() results
    content = re.sub(
        r"Serializable\s+(\w+)\s*=\s*(\w+)\.getObjectValue\(\);",
        r"Serializable \1 = (Serializable) \2.getObjectValue();",
        content,
    )

    # Ensure new Element() calls have proper Serializable casting
    content = re.sub(
        r"new\s+Element\(([^,]+),\s*([^)]+)\)",
        lambda m: f"new Element({m.group(1)}, (Serializable) {m.group(2)})"
        if "Serializable" not in m.group(2) and not m.group(2).strip().startswith("new")
        else m.group(0),
        content,
    )

    # Handle direct cache.get() assignments
    content = re.sub(
        r"(\w+)\s*=\s*cache\.get\(([^)]+)\);",
        lambda m: f"Element {m.group(1)} = cache.get({m.group(2)});"
        if "Element" not in content[: m.start()]
        else m.group(0),
        content,
    )

    return content


def insert_imports(content: str, imports_to_add: list[str]) -> str:
    """
    Insert imports at the correct location in Java file.

    Args:
        content: Java file content
        imports_to_add: List of import statements to add

    Returns:
        Content with imports added
    """
    lines = content.split("\n")
    insert_index = 0

    # Find insertion point (after package, before class)
    for i, line in enumerate(lines):
        if line.strip().startswith("package "):
            insert_index = i + 1
        elif line.strip().startswith("import "):
            insert_index = i + 1
        elif line.strip().startswith("public class ") or line.strip().startswith("class "):
            break

    # Insert missing imports
    for import_stmt in sorted(imports_to_add):
        lines.insert(insert_index, f"import {import_stmt};")
        insert_index += 1

    # Add blank line after imports if needed
    if insert_index < len(lines) and lines[insert_index].strip():
        lines.insert(insert_index, "")

    return "\n".join(lines)


def get_main_class_name(files: dict[str, str]) -> str:
    """
    Extract the fully qualified main class name from the generated Java files.

    This function now properly handles package declarations to return the
    correct fully qualified class name (e.g., "com.example.VulnerabilityDemo")
    instead of just the simple class name ("VulnerabilityDemo").

    Args:
        files: dictionary of file paths and content

    Returns:
        Fully qualified main class name if package found, otherwise simple class name
    """
    def extract_fully_qualified_name(file_path: str, content: str) -> str:
        """Extract fully qualified class name from Java file content."""
        # Extract class name from file path
        class_name = os.path.basename(file_path).replace(".java", "")

        try:
            # Look for package declaration at the beginning of the file
            # Match: "package com.example.demo;" or "package demo;"
            package_match = re.search(r"^\s*package\s+([a-zA-Z_][\w.]*)\s*;", content, re.MULTILINE)
            if package_match:
                package_name = package_match.group(1).strip()
                fully_qualified_name = f"{package_name}.{class_name}"
                logger.info(f"Found packaged main class: {fully_qualified_name} in {file_path}")
                return fully_qualified_name
            else:
                # No package declaration found - return simple class name for backward compatibility
                logger.info(f"Found main class: {class_name} in {file_path} (no package declaration)")
                return class_name
        except Exception as e:
            # Fallback to simple class name if regex parsing fails
            logger.warning(f"Error parsing package from {file_path}: {e}. Using simple class name: {class_name}")
            return class_name

    # First pass: Look for files with main methods
    for file_path, content in files.items():
        if file_path.endswith(".java"):
            # Verify by checking for main method
            if "public static void main" in content:
                return extract_fully_qualified_name(file_path, content)

    # Second pass: If no main method found, still try to get a class name
    # This is normal for WAR-packaged applications (Struts, servlets, etc.)
    for file_path, content in files.items():
        if file_path.endswith(".java"):
            class_name = extract_fully_qualified_name(file_path, content)

            # Check if this is a WAR-based application (no main method needed)
            is_war_app = any([
                "ActionSupport" in content,  # Struts
                "@WebServlet" in content,     # Servlet
                "HttpServlet" in content,     # Servlet
                "web.xml" in files,           # WAR config
                "WEB-INF" in str(files.keys())  # WAR structure
            ])

            if is_war_app:
                logger.debug(f"WAR application detected - main method not required for {class_name}")
            else:
                logger.warning(f"Using class {class_name} without main method verification")
            return class_name

    # Fallback: Return empty string if no Java files found
    return ""


def validate_java_syntax_enhanced(filename: str, content: str) -> bool:
    """
    Java syntax validation with compilation error checks.

    Args:
        filename: Name of the Java file
        content: Java code content

    Returns:
        True if basic syntax is valid
    """
    try:
        # Check for basic class declaration (only actual class declarations, not in comments)
        class_match = re.search(r"^\s*(?:public\s+)?class\s+(\w+)", content, re.MULTILINE)
        if not class_match:
            logger.warning(f"No class declaration found in {filename}")
            return False

        class_name = class_match.group(1)

        # Check that filename matches class name
        expected_filename = f"{class_name}.java"
        if not filename.endswith(expected_filename):
            logger.error(f"CRITICAL: Filename {filename} doesn't match class name {class_name}")
            return False

        # Check for balanced braces
        open_braces = content.count("{")
        close_braces = content.count("}")
        if open_braces != close_braces:
            logger.warning(f"Unbalanced braces in {filename}: {open_braces} open, {close_braces} close")
            return False

        # Uncasted Object to Serializable assignments
        if re.search(r"Serializable\s+\w+\s*=\s*cache\.get\([^)]+\)\s*;", content):
            if "(Serializable)" not in content:
                logger.error(f"Missing Serializable cast in {filename}")
                return False

        # Check for proper package structure if package declaration exists
        package_match = re.search(r"package\s+([^;]+);", content)
        if package_match:
            package_name = package_match.group(1)
            # Validate package name format
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", package_name):
                logger.warning(f"Invalid package name format in {filename}: {package_name}")
                return False

        return True

    except Exception as e:
        logger.error(f"Error validating Java syntax for {filename}: {e}")
        return False