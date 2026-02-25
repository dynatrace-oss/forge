"""
GitHub Context Enricher.

Formats GitHub advisory, commit, and issue data for LLM prompts.
"""

import logging

from services.prompts.enrichers.base_enricher import ContextEnricher

logger = logging.getLogger(__name__)


class GitHubContextEnricher(ContextEnricher):
    """
    Enriches context with formatted GitHub advisory/reference data.

    Takes raw GitHub data and formats it into structured context
    suitable for LLM prompts.

    Adds to context:
        - github_context: Formatted GitHub context string
    """

    def is_applicable(self, context: dict) -> bool:
        """Check if GitHub data is present."""
        return "github_data" in context or "github_context_raw" in context

    async def enrich(self, context: dict) -> dict:
        """
        Add formatted GitHub context.

        Args:
            context: Should contain github_data or github_context_raw

        Returns:
            Context with github_context added
        """
        # Check if already formatted
        if "github_context" in context and context["github_context"]:
            logger.debug("GitHub context already present, skipping enrichment")
            return context

        # Get raw GitHub data
        github_data = context.get("github_data") or context.get("github_context_raw")

        if not github_data:
            context["github_context"] = "No GitHub context available."
            return context

        try:
            formatted = self._format_github_data(github_data)
            context["github_context"] = formatted
            logger.debug("Added formatted GitHub context")

        except Exception as e:
            logger.error(f"Failed to format GitHub context: {e}")
            context["github_context"] = "GitHub context formatting failed."

        return context

    def _format_github_data(self, github_data: dict) -> str:
        """
        Format GitHub data into structured string.

        Args:
            github_data: Dictionary containing GitHub advisory/reference data

        Returns:
            Formatted GitHub context string
        """
        if not github_data:
            return "No GitHub context available."

        formatted = "GitHub Context:\n"

        # Add description
        if "description" in github_data and github_data["description"]:
            formatted += f"Description: {github_data['description']}\n"

        # Add severity
        if "severity" in github_data and github_data["severity"]:
            formatted += f"Severity: {github_data['severity']}\n"

        # Add CWE IDs
        if "cwe_ids" in github_data and github_data["cwe_ids"]:
            cwe_list = github_data["cwe_ids"]
            if isinstance(cwe_list, list):
                formatted += f"CWE IDs: {', '.join(cwe_list)}\n"
            else:
                formatted += f"CWE IDs: {cwe_list}\n"

        # Add affected versions
        if "affected_versions" in github_data and github_data["affected_versions"]:
            formatted += f"Affected Versions: {github_data['affected_versions']}\n"

        # Add references
        if "references" in github_data:
            refs = github_data["references"]
            if refs:
                formatted += "References:\n"
                if isinstance(refs, list):
                    for ref in refs[:5]:  # Limit to 5
                        formatted += f"- {ref}\n"
                else:
                    formatted += f"- {refs}\n"

        # Add fix commits if available
        if "fix_commits" in github_data:
            commits = github_data["fix_commits"]
            if commits:
                formatted += "Fix Commits:\n"
                if isinstance(commits, list):
                    for commit in commits[:3]:  # Limit to 3
                        formatted += f"- {commit}\n"
                else:
                    formatted += f"- {commits}\n"

        # Add advisory URL if available
        if "advisory_url" in github_data and github_data["advisory_url"]:
            formatted += f"Advisory URL: {github_data['advisory_url']}\n"

        return formatted.strip()
