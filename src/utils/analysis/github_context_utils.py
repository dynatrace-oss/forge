from models.poc_data import GitHubContextResult


def format_comprehensive_github_context(github_result: GitHubContextResult) -> str:
    """
    Format comprehensive GitHub context for LLM prompts.
    
    Prioritize high-value information:
    - Full issue descriptions (up to 3000 chars)
    - Maintainer comments from issues
    - Focused code diffs (when commits are small/targeted)
    - Smart filtering to avoid noise from large commits

    Args:
        github_result: GitHubContextResult with extracted GitHub metadata

    Returns:
        Formatted string ready for LLM prompt inclusion
    """
    if not isinstance(github_result, GitHubContextResult):
        return ""

    context_parts = ["GITHUB REFERENCE CONTEXT (Vulnerability Analysis):"]
    context_parts.append("")
    context_parts.append("⚠️⚠️⚠️ CRITICAL: READ THIS SECTION CAREFULLY ⚠️⚠️⚠️")
    context_parts.append("This context contains ACTUAL vulnerability details from GitHub:")
    context_parts.append("- Full issue descriptions explaining the vulnerability mechanism")
    context_parts.append("- Maintainer comments with additional insights")
    context_parts.append("- Code diffs showing exact changes (when commits are focused)")
    context_parts.append("")

    # Section 1: GitHub Issues (HIGHEST PRIORITY - Best Explanations)
    issue_context = github_result.get_issue_context()
    if issue_context:
        context_parts.append(issue_context)
        context_parts.append("")

    # Section 2: Fix Commits with Diffs (When Available)
    fix_analysis = github_result.get_fix_analysis()
    if fix_analysis:
        context_parts.append(fix_analysis)
        context_parts.append("")

    # Section 3: Security Advisories
    advisory_context = github_result.get_advisory_context()
    if advisory_context:
        context_parts.append(advisory_context)
        context_parts.append("")

    # Section 4: PoC References (URLs only - lowest priority)
    poc_refs = github_result.get_poc_references()
    if poc_refs:
        context_parts.append(poc_refs)
        context_parts.append("")

    # Add comprehensive usage guidance
    context_parts.append("=" * 80)
    context_parts.append("HOW TO USE THIS CONTEXT:")
    context_parts.append("1. START WITH ISSUES: Read full descriptions and discussions")
    context_parts.append("2. USE CODE DIFFS: When available, see exact changes made in fix")
    context_parts.append("3. REVERSE ENGINEER: Understand pre-fix code from diffs")
    context_parts.append("4. SYNTHESIZE: Combine issues + diffs for complete understanding")
    context_parts.append("5. MATCH PRECISELY: Generate code matching the exact mechanism")
    context_parts.append("=" * 80)

    return "\n".join(context_parts)


def get_github_context_summary(github_result: GitHubContextResult) -> dict:
    """
    Get summary statistics of extracted GitHub context.
    Useful for logging and debugging.

    Returns:
        Dictionary with counts and flags
    """
    if not isinstance(github_result, GitHubContextResult):
        return {}

    commits_with_diffs = sum(
        1 for commit in github_result.fix_commits
        if commit.get('has_focused_diff', False)
    )

    return {
        "total_issues": len(github_result.github_issues),
        "total_fix_commits": len(github_result.fix_commits),
        "commits_with_focused_diffs": commits_with_diffs,
        "total_advisories": len(github_result.security_advisories),
        "total_poc_references": len(github_result.poc_reference_urls),
        "has_issue_descriptions": any(
            issue.get('description') for issue in github_result.github_issues
        ),
        "has_issue_comments": any(
            issue.get('comments') for issue in github_result.github_issues
        ),
    }
