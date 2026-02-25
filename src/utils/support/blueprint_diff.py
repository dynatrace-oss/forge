import difflib


def generate_diff(old_content: str, new_content: str, context_lines: int = 3) -> str:
    """
    Generate a unified diff between two strings.

    Args:
        old_content: Original content
        new_content: Modified content
        context_lines: Number of context lines to include

    Returns:
        Unified diff as a string
    """
    old_lines = old_content.splitlines(True)
    new_lines = new_content.splitlines(True)

    diff = difflib.unified_diff(old_lines, new_lines, fromfile="original", tofile="modified", n=context_lines)

    return "".join(diff)


def compare_code_snippets(old_snippets: dict[str, str], new_snippets: dict[str, str]) -> dict:
    """
    Compare two sets of code snippets and generate diffs.

    Args:
        old_snippets: Original code snippets
        new_snippets: Modified code snippets

    Returns:
        dictionary with comparison results
    """
    all_keys = set(old_snippets.keys()) | set(new_snippets.keys())
    result = {"added": [], "removed": [], "modified": [], "unchanged": [], "diffs": {}}

    for key in all_keys:
        if key not in old_snippets:
            # Added snippet
            result["added"].append(key)
        elif key not in new_snippets:
            # Removed snippet
            result["removed"].append(key)
        elif old_snippets[key] == new_snippets[key]:
            # Unchanged snippet
            result["unchanged"].append(key)
        else:
            # Modified snippet
            result["modified"].append(key)
            result["diffs"][key] = generate_diff(old_snippets[key], new_snippets[key])

    return result


def summarize_blueprint_changes(old_blueprint: dict, new_blueprint: dict) -> dict:
    """
    Generate a summary of changes between two blueprint versions.

    Args:
        old_blueprint: Original blueprint dictionary
        new_blueprint: Modified blueprint dictionary

    Returns:
        dictionary with change summary
    """
    changes = {
        "metadata_changes": {},
        "code_changes": None,
        "summary": {
            "metadata_fields_changed": 0,
            "code_snippets_added": 0,
            "code_snippets_removed": 0,
            "code_snippets_modified": 0,
        },
    }

    # Compare metadata fields
    metadata_fields = [
        "name",
        "description",
        "package_name",
        "package_version",
        "cve_ids",
        "author",
        "tags",
        "version",
    ]

    for field in metadata_fields:
        old_value = old_blueprint.get(field)
        new_value = new_blueprint.get(field)

        if old_value != new_value:
            changes["metadata_changes"][field] = {"old": old_value, "new": new_value}
            changes["summary"]["metadata_fields_changed"] += 1

    # Compare code snippets
    old_snippets = old_blueprint.get("code_snippets", {})
    new_snippets = new_blueprint.get("code_snippets", {})

    code_changes = compare_code_snippets(old_snippets, new_snippets)
    changes["code_changes"] = code_changes

    # Update summary counts
    changes["summary"]["code_snippets_added"] = len(code_changes["added"])
    changes["summary"]["code_snippets_removed"] = len(code_changes["removed"])
    changes["summary"]["code_snippets_modified"] = len(code_changes["modified"])

    return changes


def format_diff_for_display(diff_result: dict) -> str:
    """
    Format diff result for display.

    Args:
        diff_result: Result from compare_code_snippets or summarize_blueprint_changes

    Returns:
        Formatted string for display
    """
    output = []

    # Add metadata changes if present
    if "metadata_changes" in diff_result:
        output.append("=== Metadata Changes ===")

        if diff_result["metadata_changes"]:
            for field, changes in diff_result["metadata_changes"].items():
                output.append(f"\n{field}:")
                output.append(f"  - Old: {changes['old']}")
                output.append(f"  - New: {changes['new']}")
        else:
            output.append("No metadata changes")

    # Add code changes
    code_changes = diff_result.get("code_changes", diff_result)

    output.append("\n=== Code Changes ===")

    if code_changes["added"]:
        output.append("\nAdded snippets:")
        for snippet in code_changes["added"]:
            output.append(f"  - {snippet}")

    if code_changes["removed"]:
        output.append("\nRemoved snippets:")
        for snippet in code_changes["removed"]:
            output.append(f"  - {snippet}")

    if code_changes["modified"]:
        output.append("\nModified snippets:")
        for snippet in code_changes["modified"]:
            output.append(f"\n  {snippet}:")
            diff = code_changes["diffs"].get(snippet, "")
            output.append(f"\n{diff}")

    # Add summary
    if "summary" in diff_result:
        output.append("\n=== Summary ===")
        summary = diff_result["summary"]
        output.append(f"Metadata fields changed: {summary['metadata_fields_changed']}")
        output.append(f"Code snippets added: {summary['code_snippets_added']}")
        output.append(f"Code snippets removed: {summary['code_snippets_removed']}")
        output.append(f"Code snippets modified: {summary['code_snippets_modified']}")

    return "\n".join(output)
