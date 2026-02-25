from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GitHubContextResult:
    """
    Represents GitHub metadata context extracted from vulnerability references.
    This class focuses on metadata only (no PoC code) to provide context for
    LLM-driven exploit generation.
    """

    vulnerability_id: str
    total_references: int
    processed_references: int

    # GitHub metadata (no PoC code)
    github_issues: list[dict[str, str]] = field(default_factory=list)
    fix_commits: list[dict[str, str]] = field(default_factory=list)
    security_advisories: list[dict[str, str]] = field(default_factory=list)
    poc_reference_urls: list[str] = field(default_factory=list)  # URLs only, no code

    # Error tracking
    failed_urls: list[str] = field(default_factory=list)
    extraction_errors: list[str] = field(default_factory=list)

    # Metadata
    extraction_duration: float = 0.0
    extraction_timestamp: datetime = field(default_factory=datetime.now)

    def get_fix_analysis(self) -> str:
        """
        Format fix commits for LLM with code diffs when available.
        Prioritizes focused, relevant diffs - not all commits have diffs.
        """
        if not self.fix_commits:
            return ""

        analysis_parts = ["=== FIX COMMITS (What Was Changed to Prevent Vulnerability) ==="]

        for i, fix_commit in enumerate(self.fix_commits, 1):
            commit_msg = fix_commit.get("commit_message", "No message")
            url = fix_commit.get("url", "")
            files_changed = fix_commit.get("files_changed", "unknown")
            diff_summary = fix_commit.get("diff_summary", "")
            has_focused_diff = fix_commit.get("has_focused_diff", False)

            analysis_parts.append(f"\n{i}. Fix Commit: {commit_msg}")
            analysis_parts.append(f"   URL: {url}")
            analysis_parts.append(f"   Files Changed: {files_changed}")

            # Include diff if available and focused
            if diff_summary and has_focused_diff:
                analysis_parts.append("\n CODE CHANGES (Exact modifications made):")
                analysis_parts.append(f"   {'-' * 70}")
                analysis_parts.append(f"{diff_summary}")
                analysis_parts.append(f"   {'-' * 70}")
                analysis_parts.append("")
                analysis_parts.append("   ANALYSIS GUIDANCE:")
                analysis_parts.append("   - Look at the '+' lines (what was ADDED)")
                analysis_parts.append("   - Look at the '-' lines (what was REMOVED)")
                analysis_parts.append("   - The vulnerable code is the BEFORE state (removed lines)")
                analysis_parts.append("   - The fix is the AFTER state (added lines)")
            elif diff_summary:
                analysis_parts.append("\nNote: Partial diff available (commit too broad for full extraction)")
            else:
                analysis_parts.append(f"\nNote: Diff not extracted (commit involves {files_changed} files)")
                analysis_parts.append("Refer to GitHub Issues for vulnerability mechanism details")

            analysis_parts.append("")
            analysis_parts.append("   REVERSE ENGINEERING TASK:")
            analysis_parts.append("   - Understand what code existed BEFORE this commit")
            analysis_parts.append("   - Identify the specific weakness this fix addresses")
            analysis_parts.append("   - Create application code that exercises that vulnerable pattern")

        return "\n".join(analysis_parts)

    def get_issue_context(self) -> str:
        """
        Format GitHub issues with FULL descriptions and comments.
        Issues are PRIMARY source for understanding vulnerability mechanism.
        """
        if not self.github_issues:
            return ""

        context_parts = ["=== GITHUB ISSUES (Vulnerability Mechanism & Discussions) ==="]
        context_parts.append("")
        context_parts.append("Issues provide the BEST explanation of how the vulnerability works!")

        for i, issue in enumerate(self.github_issues, 1):
            issue_type = issue.get("type", "unknown")
            title = issue.get("title", "No title")
            url = issue.get("url", "")

            if issue_type == "github_issue":
                description = issue.get("description", "No description")
                comments = issue.get("comments", [])
                labels = issue.get("labels", [])

                context_parts.append(f"\n{'=' * 70}")
                context_parts.append(f"Issue #{i}: {title}")
                context_parts.append(f"URL: {url}")
                if labels:
                    context_parts.append(f"Labels: {', '.join(labels)}")
                context_parts.append(f"{'-' * 70}")
                context_parts.append("DESCRIPTION:")
                context_parts.append(description)

                # Include maintainer comments - often contain key insights
                if comments:
                    context_parts.append(f"\n{'-' * 70}")
                    context_parts.append("KEY DISCUSSION POINTS:")
                    for j, comment in enumerate(comments[:3], 1):  # Top 3 comments
                        context_parts.append(f"\n  Comment {j}:")
                        context_parts.append(f"  {comment}")

                context_parts.append(f"{'=' * 70}")

            elif issue_type == "github_pull_request":
                description = issue.get("description", "No description")
                merged = issue.get("merged", False)

                context_parts.append(f"\n{'=' * 70}")
                context_parts.append(f"Pull Request #{i}: {title}")
                context_parts.append(f"URL: {url}")
                context_parts.append(f"Status: {'Merged' if merged else 'Not merged'}")
                context_parts.append(f"{'-' * 70}")
                context_parts.append("DESCRIPTION:")
                context_parts.append(description)
                context_parts.append(f"{'=' * 70}")

            else:
                # Repository or other reference
                context_parts.append(f"\n{i}. {title}")
                context_parts.append(f"   URL: {url}")

        return "\n".join(context_parts)

    def get_advisory_context(self) -> str:
        """
        Format security advisories for LLM.

        Returns:
            Formatted string with advisory information
        """
        if not self.security_advisories:
            return ""

        context_parts = ["=== SECURITY ADVISORIES ==="]

        for i, advisory in enumerate(self.security_advisories, 1):
            title = advisory.get("title", "No title")
            url = advisory.get("url", "")

            context_parts.append(f"\n{i}. Advisory: {title}")
            context_parts.append(f"   URL: {url}")

        return "\n".join(context_parts)

    def get_poc_references(self) -> str:
        """
        Format PoC reference URLs for LLM with usage guidance.

        Returns:
            Formatted string with PoC reference URLs
        """
        if not self.poc_reference_urls:
            return ""

        context_parts = ["=== POC REFERENCES (External Exploit Resources) ==="]
        context_parts.append("WARNING: These are reference URLs only. DO NOT blindly copy PoC patterns.")
        context_parts.append("✓ Use these to validate your understanding from fix commits")
        context_parts.append("✓ If PoC contradicts fix commit analysis, TRUST THE FIX COMMIT")

        for i, url in enumerate(self.poc_reference_urls, 1):
            context_parts.append(f"\n{i}. PoC Reference: {url}")

        return "\n".join(context_parts)

    def to_dict(self) -> dict[str, any]:
        """
        Convert GitHub context result to dictionary representation.

        Returns:
            dictionary representation of the result
        """
        return {
            "vulnerability_id": self.vulnerability_id,
            "total_references": self.total_references,
            "processed_references": self.processed_references,
            "github_issues": self.github_issues,
            "fix_commits": self.fix_commits,
            "security_advisories": self.security_advisories,
            "poc_reference_urls": self.poc_reference_urls,
            "failed_urls": self.failed_urls,
            "extraction_errors": self.extraction_errors,
            "extraction_duration": self.extraction_duration,
            "extraction_timestamp": self.extraction_timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, any]) -> "GitHubContextResult":
        """
        Create a GitHubContextResult instance from a dictionary.

        Args:
            data: dictionary representation of GitHub context result

        Returns:
            GitHubContextResult instance
        """
        if isinstance(data.get("extraction_timestamp"), str):
            data["extraction_timestamp"] = datetime.fromisoformat(data["extraction_timestamp"])

        # Ensure all list fields exist (backwards compatibility)
        for field_name in ["github_issues", "fix_commits", "security_advisories",
                          "poc_reference_urls", "failed_urls", "extraction_errors"]:
            if field_name not in data:
                data[field_name] = []

        return cls(**data)