import asyncio
import logging
import os
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.resolve()


def get_class_name_for_package(package_name: str, suffix: str = "VulnerabilityDemo") -> str:
    """
    Generate a class name for a package.

    Args:
        package_name: Package name to generate class name for
        suffix: Suffix to append to the class name (default: "VulnerabilityDemo")

    Returns:
        A valid Java class name
    """
    # Extract the last part of the package name and capitalize it
    package_parts = package_name.split(":")
    last_part = package_parts[-1] if len(package_parts) > 0 else package_name

    # Clean up the name
    cleaned_name = re.sub(r"[^a-zA-Z0-9]", "", last_part.title())

    # Ensure it starts with a letter and is a valid Java class name
    if not cleaned_name or not cleaned_name[0].isalpha():
        cleaned_name = "Vulnerability" + cleaned_name

    return f"{cleaned_name}{suffix}"


def ensure_dir_exists(directory: Path) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        directory: Path to the directory

    Returns:
        The directory path
    """
    os.makedirs(directory, exist_ok=True)
    return directory


def parse_key_value_args(args_str: str) -> dict[str, str]:
    """
    Parse key=value arguments from a string.

    Args:
        args_str: String containing key=value pairs

    Returns:
        dictionary of key-value pairs
    """
    result = {}
    if not args_str:
        return result

    tokens = args_str.split()
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value

    return result


def truncate_string(s: str, max_length: int = 100, add_ellipsis: bool = True) -> str:
    """
    Truncate a string to a maximum length.

    Args:
        s: String to truncate
        max_length: Maximum length of the string
        add_ellipsis: Whether to add "..." to the end of truncated strings

    Returns:
        Truncated string
    """
    if not s or len(s) <= max_length:
        return s

    if add_ellipsis:
        return s[: max_length - 3] + "..."
    else:
        return s[:max_length]


def format_iso_datetime(dt_str: str) -> str:
    """
    Format an ISO datetime string in a human-readable format.

    Args:
        dt_str: ISO datetime string

    Returns:
        Formatted datetime string
    """
    try:
        dt = datetime.fromisoformat(dt_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return dt_str


def extract_imports_from_java_code(code: str) -> str:
    """
    Extract import statements from Java code.

    Args:
        code: Java code

    Returns:
        Import statements as a string
    """
    imports = []
    for line in code.splitlines():
        line = line.strip()
        if line.startswith("import ") and line.endswith(";"):
            imports.append(line)

    return "\n".join(imports)


def extract_package_parts(package_name: str) -> tuple[str, str]:
    """
    Extract group ID and artifact ID from a Maven package name.

    Args:
        package_name: Maven package name (group:artifact)

    Returns:
        tuple of (group_id, artifact_id)
    """
    if ":" in package_name:
        parts = package_name.split(":")
        return parts[0], parts[1]
    else:
        # For non-Maven packages, use the package name as both group and artifact
        return package_name, package_name.split(".")[-1] if "." in package_name else package_name


def standardize_package_name(package_name: str) -> str:
    """
    Standardize a package name for consistent storage and retrieval.

    Args:
        package_name: Package name

    Returns:
        Standardized package name
    """
    # Remove whitespace
    name = package_name.strip()

    # If it's a Maven coordinate but missing version, add a wildcard version
    if ":" in name and name.count(":") == 1:
        name = f"{name}:*"

    return name


def parse_maven_dependency(dep_str: str) -> dict[str, str]:
    """
    Parse a Maven dependency string in the format 'groupId:artifactId:version'.

    Args:
        dep_str: Maven dependency string

    Returns:
        dictionary with keys 'group_id', 'artifact_id', and 'version'
    """
    parts = dep_str.split(":")
    if len(parts) >= 3:
        return {"group_id": parts[0], "artifact_id": parts[1], "version": parts[2]}
    else:
        logger.warning(f"Invalid Maven dependency format: {dep_str}")
        return {
            "group_id": parts[0] if len(parts) > 0 else "unknown",
            "artifact_id": parts[1] if len(parts) > 1 else "unknown",
            "version": "*",
        }


def validate_container_name(container_name: str) -> str:
    """
    Validate and normalize a container name.

    Args:
        container_name: Container name to validate

    Returns:
        Normalized container name

    Raises:
        ValueError: If the container name is invalid
    """
    # Remove any non-alphanumeric characters except hyphen and underscore
    cleaned_name = re.sub(r"[^a-zA-Z0-9_\-]", "", container_name)

    # Ensure name starts with a letter
    if not cleaned_name or not cleaned_name[0].isalpha():
        cleaned_name = "container-" + cleaned_name

    if len(cleaned_name) < 3:
        raise ValueError("Container name must be at least 3 characters long")

    return cleaned_name.lower()


def parse_port_mapping(port_mapping: str) -> tuple[int, int]:
    """
    Parse and validate port mapping string.

    Args:
        port_mapping: Port mapping in format "host_port:container_port"

    Returns:
        Tuple of (host_port, container_port)

    Raises:
        ValueError: If port mapping is invalid
    """
    try:
        if ":" not in port_mapping:
            raise ValueError("Port mapping must be in format 'host:container'")

        host_str, container_str = port_mapping.split(":", 1)

        host_port = int(host_str.strip())
        container_port = int(container_str.strip())

        # Validate port ranges
        if not (1 <= host_port <= 65535):
            raise ValueError(f"Host port {host_port} must be between 1 and 65535")

        if not (1 <= container_port <= 65535):
            raise ValueError(f"Container port {container_port} must be between 1 and 65535")

        # Avoid privileged ports for host
        if host_port < 1024:
            logger.warning(f"Using privileged host port {host_port}, may require elevated permissions")

        return host_port, container_port

    except ValueError as e:
        if "invalid literal for int()" in str(e):
            raise ValueError(f"Port mapping '{port_mapping}' contains non-numeric ports")
        raise
    except Exception as e:
        raise ValueError(f"Invalid port mapping format '{port_mapping}': {e}")


def extract_files_from_llm_response(response: str) -> dict[str, str]:
    """
    Extract files from an LLM response based on file: markers.

    Supports two formats:
    1. Preferred: ```file:path/to/file.java
    2. Alternative: // File: path/to/file.java (for backwards compatibility)

    Args:
        response: LLM response text

    Returns:
        dictionary mapping file paths to content
    """
    files = {}

    # Normalize line endings for consistent processing
    response = response.replace("\r\n", "\n")

    # Pattern 1: Standard format - ```file:path/to/file.java or file:path/to/file.java
    # Matches: file:src/main/java/com/vuln/VulnApplication.java
    pattern1 = r"(?:```)?file:([\w/.-]+\.\w+)"

    # Pattern 2: Alternative format with comment slashes - // File: path/to/file.java
    # Matches: // File: src/main/java/com/vuln/VulnApplication.java
    pattern2 = r"//\s*File:\s*([\w/.-]+\.\w+)"

    # Combine both patterns with OR operator
    combined_pattern = f"(?:{pattern1})|(?:{pattern2})"

    # Find all starting positions of file markers (both formats)
    file_positions = []
    for m in re.finditer(combined_pattern, response):
        # Group 1 is from pattern1 (file:), Group 2 is from pattern2 (// File:)
        filename = m.group(1) if m.group(1) else m.group(2)
        file_positions.append((m.start(), filename))

    # Process each file by determining its content boundary
    for i, (pos, filename) in enumerate(file_positions):
        # Find the start of the content (after the newline following the marker)
        content_start = response.find("\n", pos) + 1

        # Determine the end boundary (next file marker or end of string)
        if i < len(file_positions) - 1:
            content_end = file_positions[i + 1][0]
        else:
            content_end = len(response)

        # Extract the content
        if content_start < content_end:
            content = response[content_start:content_end].strip()

            # Clean up the content (remove code block markers if present)
            content = re.sub(r"^```\w*\n", "", content)
            content = re.sub(r"\n```$", "", content)

            # Add to files dictionary
            files[filename] = content

    logger.info(f"Extracted {len(files)} files from LLM response")
    return files


def generate_safe_id() -> str:
    """
    Generate a safe, unique identifier.

    Returns:
        A safe, unique identifier
    """
    return str(uuid.uuid4())[:8]


def format_command_output(output: str, max_lines: int = 20) -> str:
    """
    Format command output for display.

    Args:
        output: Command output
        max_lines: Maximum number of lines to show

    Returns:
        Formatted output
    """
    if not output:
        return "No output"

    lines = output.splitlines()

    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n[...{len(lines) - max_lines} more lines...]"
    else:
        return output


def format_error_message(message: str, cause: Exception | None = None) -> str:
    """
    Format an error message with cause information.

    Args:
        message: Error message
        cause: Optional cause exception

    Returns:
        Formatted error message
    """
    if cause:
        return f"{message}: {str(cause)}"
    else:
        return message


def format_similar_blueprints(similar_blueprints: list) -> str:
    """Format similar blueprints for prompt context."""
    if not similar_blueprints:
        return "No similar blueprints found"

    formatted = "Similar blueprints found:\n"
    for i, blueprint in enumerate(similar_blueprints[:3]):  # Limit to 3 examples
        formatted += f"\nExample {i + 1}:\n"
        formatted += f"- Name: {blueprint.name}\n"
        formatted += f"- Package: {blueprint.package_name}\n"
        formatted += f"- CVEs: {', '.join(blueprint.cve_ids)}\n"
        formatted += f"- Tags: {', '.join(blueprint.tags)}\n"

        # Add code snippet summary
        if blueprint.code_snippets:
            formatted += f"- Code files: {', '.join(blueprint.code_snippets.keys())}\n"

    return formatted


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to a human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Human-readable duration string
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        minutes = seconds // 60
        seconds = seconds % 60
        return f"{minutes:.0f}m {seconds:.0f}s"


async def cleanup_containers(running_containers: list = None):
    """
    Clean up running containers on exit.

    Args:
        running_containers: List of container info dicts to clean up
    """
    if running_containers is None:
        # Instead of importing, require explicit parameter passing
        logger.warning("No running containers list provided for cleanup")
        return

    if not running_containers:
        return

    print(f"\n\nCleaning up {len(running_containers)} running containers...")

    cleanup_tasks = []
    for container in running_containers:
        try:
            container_id = container["id"]
            print(f"Stopping {container['name']}...")

            # Create cleanup task
            process = await asyncio.create_subprocess_exec(
                "podman", "stop", container_id, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            cleanup_tasks.append(process.communicate())
        except Exception as e:
            logger.error(f"Error preparing to stop container {container.get('name', 'unknown')}: {e}")

    # Wait for all containers to stop
    if cleanup_tasks:
        results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error stopping container: {result}")

    running_containers.clear()
    print("Container cleanup completed.")


def cleanup_build_resources(resources: list[str]) -> None:
    """
    Cleanup temporary build resources.

    Args:
        resources: List of file/directory paths to cleanup
    """
    cleanup_errors = []

    for resource in resources:
        try:
            if os.path.exists(resource):
                if os.path.isfile(resource):
                    os.remove(resource)
                    logger.debug(f"Cleaned up file: {resource}")
                elif os.path.isdir(resource):
                    shutil.rmtree(resource)
                    logger.debug(f"Cleaned up directory: {resource}")
        except PermissionError as e:
            cleanup_errors.append(f"Permission denied cleaning {resource}: {e}")
        except OSError as e:
            cleanup_errors.append(f"OS error cleaning {resource}: {e}")
        except Exception as e:
            cleanup_errors.append(f"Unexpected error cleaning {resource}: {e}")

    if cleanup_errors:
        logger.warning(f"Resource cleanup issues: {'; '.join(cleanup_errors)}")
