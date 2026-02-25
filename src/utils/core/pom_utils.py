import logging
import re

logger = logging.getLogger(__name__)


def remove_duplicate_dependencies(pom_content: str) -> str:
    """
    Remove duplicate dependencies from a POM XML string.

    Args:
        pom_content: POM XML content

    Returns:
        POM XML with duplicates removed
    """
    # This pattern matches entire dependency blocks
    dep_pattern = re.compile(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>.*?</dependency>",
        re.DOTALL,
    )

    # Find all matches
    all_deps = list(dep_pattern.finditer(pom_content))
    if len(all_deps) <= 1:
        # No duplicates possible with 0 or 1 dependency
        return pom_content

    # Track unique dependencies by group:artifact ID
    unique_deps = {}
    duplicate_indices = []

    for i, match in enumerate(all_deps):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        key = f"{group_id}:{artifact_id}"

        if key in unique_deps:
            # This is a duplicate
            duplicate_indices.append(i)
        else:
            unique_deps[key] = i

    # If no duplicates found, return original content
    if not duplicate_indices:
        return pom_content

    # Process duplicates (remove from the end to preserve positions)
    duplicate_indices.sort(reverse=True)
    content_lines = pom_content.split("\n")

    for idx in duplicate_indices:
        match = all_deps[idx]

        # Find line numbers for the start and end of this dependency
        start_line = pom_content.count("\n", 0, match.start())
        end_line = pom_content.count("\n", 0, match.end())

        # Remove those lines
        if start_line <= end_line:
            # Remove lines from end to start to preserve positions
            del content_lines[start_line : end_line + 1]

    # Join lines back together
    result = "\n".join(content_lines)

    logger.info(f"Removed {len(duplicate_indices)} duplicate dependencies from POM")
    return result


def fix_repositories_tag(pom_content: str) -> str:
    """
    Fix repository tags to ensure proper XML structure.

    Args:
        pom_content: POM XML content

    Returns:
        Fixed POM XML content
    """
    # Check for double-wrapped repositories (nested tags)
    if re.search(r"<repositories>\s*<repositories>", pom_content):
        logger.info("Fixing nested <repositories> tags")
        # First, replace the opening nested tag
        fixed_content = re.sub(r"<repositories>\s*<repositories>", "<repositories>", pom_content)
        # Then replace the closing nested tag
        fixed_content = re.sub(r"</repositories>\s*</repositories>", "</repositories>", fixed_content)
        return fixed_content

    # Check for other repository tag issues
    if "<repository>" in pom_content:
        # Check if we have any repository tags that are NOT inside a repositories tag
        if not re.search(r"<repositories>.*<repository>", pom_content, re.DOTALL):
            logger.info("Fixing repository tags - adding missing <repositories> wrapper")

            # Find the position where repositories should be
            # Use a greedy match to capture all content between these markers
            repos_section = re.search(r"<!-- Repositories -->(.*)<dependencies>", pom_content, re.DOTALL)
            if repos_section:
                # Replace with properly wrapped repositories
                section_text = repos_section.group(1)
                # Make sure we keep the dependencies tag intact
                new_section = f"<!-- Repositories -->\n    <repositories>\n{section_text}    </repositories>\n\n    <dependencies>"
                fixed_content = pom_content.replace(repos_section.group(0), new_section)
                return fixed_content

    # If there are no repository tags at all, just return the original content
    return pom_content


def ensure_valid_pom_xml(pom_content: str) -> str:
    """
    Ensure the POM XML is valid by fixing common issues.

    Args:
        pom_content: POM XML content

    Returns:
        Valid POM XML content
    """
    # Step 1: Remove duplicate dependencies
    pom_content = remove_duplicate_dependencies(pom_content)

    # Step 2: Fix repository tags
    pom_content = fix_repositories_tag(pom_content)

    # Fix any missing tags for vital sections
    if "<dependencies>" not in pom_content:
        logger.warning("Missing <dependencies> section in POM")
        # Add dependencies section before build if needed
        if "<build>" in pom_content:
            pom_content = pom_content.replace("<build>", "<dependencies>\n    </dependencies>\n\n    <build>", 1)

    # Fix any XML formatting issues
    pom_content = pom_content.replace("  <", "    <")  # Ensure consistent indentation

    # Make sure repository tags have proper naming elements
    pom_content = pom_content.replace("<n>", "<name>")
    pom_content = pom_content.replace("</n>", "</name>")

    logger.info("POM XML validation complete")
    return pom_content
