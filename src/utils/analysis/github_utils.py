import logging
import re

import yaml

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


class GitHubClassifier:
    """
    Config-driven classifier for GitHub commits and references.
    Distinguishes fix commits from exploit demonstrations using patterns from config.
    """

    _instance = None
    _config = None

    def __new__(cls):
        """Singleton pattern to avoid reloading config."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Load classification config on first initialization."""
        if self._config is None:
            self._load_config()

    def _load_config(self):
        """Load GitHub classification configuration from YAML."""
        config_path = PROJECT_ROOT / "src" / "config" / "github_classification.yaml"
        try:
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f)
            logger.info(f"Loaded GitHub classification config from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load GitHub classification config: {e}")
            # Fallback to minimal default config
            self._config = {
                "commit_classification": {
                    "fix_indicators": {
                        "commit_message_keywords": ["fix", "patch", "security"],
                        "commit_message_patterns": ["cve-"],
                        "code_change_patterns": []
                    },
                    "exploit_indicators": {
                        "commit_message_keywords": ["exploit", "poc"]
                    },
                    "confidence_thresholds": {
                        "fix_commit_min_keyword_matches": 1,
                        "fix_commit_min_code_pattern_matches": 2,
                        "exploit_commit_min_keyword_matches": 1
                    }
                }
            }

    def classify_commit_type(
        self,
        commit_message: str = "",
        code_content: str = "",
        metadata: dict[str, str] | None  = None
    ) -> str:
        """
        Classify a GitHub commit as fix, exploit, or reference.

        Args:
            commit_message: The commit message text
            code_content: The commit code changes (optional)
            metadata: Optional metadata with commit information

        Returns:
            "fix_commit", "exploit_poc", or "reference"
        """
        # Extract commit message from metadata if not provided
        if not commit_message and metadata:
            commit_message = metadata.get("commit_message", "")

        commit_msg_lower = commit_message.lower()

        # Get configuration
        config = self._config["commit_classification"]
        fix_indicators = config["fix_indicators"]
        exploit_indicators = config["exploit_indicators"]
        thresholds = config["confidence_thresholds"]

        # Check for fix indicators in commit message
        fix_keyword_matches = 0
        for keyword in fix_indicators["commit_message_keywords"]:
            if keyword in commit_msg_lower:
                fix_keyword_matches += 1
                logger.debug(f"Fix keyword matched: {keyword}")

        # Check for fix patterns in commit message
        for pattern in fix_indicators["commit_message_patterns"]:
            if re.search(pattern, commit_msg_lower):
                fix_keyword_matches += 1
                logger.debug(f"Fix pattern matched: {pattern}")

        # If commit message has enough fix indicators, classify as fix
        if fix_keyword_matches >= thresholds["fix_commit_min_keyword_matches"]:
            logger.debug(f"Classified as FIX COMMIT based on {fix_keyword_matches} keyword matches")
            return "fix_commit"

        # Check code content for fix patterns
        if code_content:
            fix_code_pattern_matches = 0
            for pattern in fix_indicators["code_change_patterns"]:
                try:
                    if re.search(pattern, code_content, re.MULTILINE):
                        fix_code_pattern_matches += 1
                        logger.debug(f"Fix code pattern matched: {pattern}")
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")

            # If code has enough fix patterns, classify as fix
            if fix_code_pattern_matches >= thresholds["fix_commit_min_code_pattern_matches"]:
                logger.debug(f"Classified as FIX COMMIT based on {fix_code_pattern_matches} code pattern matches")
                return "fix_commit"

        # Check for exploit indicators
        exploit_keyword_matches = 0
        for keyword in exploit_indicators["commit_message_keywords"]:
            if keyword in commit_msg_lower:
                exploit_keyword_matches += 1
                logger.debug(f"Exploit keyword matched: {keyword}")

        # If commit has exploit indicators, classify as exploit
        if exploit_keyword_matches >= thresholds["exploit_commit_min_keyword_matches"]:
            logger.debug(f"Classified as EXPLOIT POC based on {exploit_keyword_matches} keyword matches")
            return "exploit_poc"

        # Default: classify as general reference
        logger.debug("Classified as REFERENCE (no clear fix or exploit markers)")
        return "reference"

    def get_reference_priority(self, url: str) -> int:
        """
        Get priority score for a GitHub reference URL.
        Lower scores = higher priority.

        Args:
            url: GitHub reference URL

        Returns:
            Priority score (1-7, lower is higher priority)
        """
        url_lower = url.lower()
        priorities = self._config.get("reference_filtering", {}).get("url_priorities", {})

        # Check each priority type
        for priority_type, priority_config in priorities.items():
            # Handle both single pattern and list of patterns
            patterns = priority_config.get("patterns", [priority_config.get("pattern")])
            patterns = [p for p in patterns if p]  # Filter out None values

            for pattern in patterns:
                if pattern in url_lower:
                    return priority_config.get("priority", 8)

        # Default priority for unknown URLs
        return 8

    def filter_github_references(self, references: list[str]) -> list[str]:
        """
        Filter and prioritize GitHub references.

        Args:
            references: list of all reference URLs

        Returns:
            Filtered and sorted list of GitHub references
        """
        github_refs = []

        # GitHub patterns
        github_patterns = [
            r'github\.com.*exploit',
            r'github\.com.*poc',
            r'exploit-db\.com',
            r'packetstormsecurity\.com',
            r'github\.com/[^/]+/[^/]+/issues/\d+',
            r'github\.com/[^/]+/[^/]+/commit/[a-f0-9]+',
            r'github\.com/[^/]+/[^/]+/pull/\d+',
            r'github\.com/[^/]+/[^/]+/security/',
            r'github\.com/[^/]+/[^/]+/?$',
        ]

        for url in references:
            for pattern in github_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    github_refs.append(url)
                    break

        # Sort by priority
        sorted_refs = sorted(github_refs, key=self.get_reference_priority)

        logger.info(f"Filtered {len(sorted_refs)} GitHub references from {len(references)} total references")
        return sorted_refs

    def get_rate_limit_delay(self) -> float:
        """Get rate limit delay from config."""
        return self._config.get("rate_limiting", {}).get("delay_between_requests_seconds", 2.0)

    def get_max_references(self) -> int:
        """Get max references to process from config."""
        return self._config.get("rate_limiting", {}).get("max_references_per_vulnerability", 10)

    def get_request_timeout(self) -> int:
        """Get request timeout from config."""
        return self._config.get("rate_limiting", {}).get("request_timeout_seconds", 30)

    def get_cache_retention_days(self) -> int:
        """Get cache retention days from config."""
        return self._config.get("caching", {}).get("retention_days", 7)


_classifier = None


def get_github_classifier() -> GitHubClassifier:
    """
    Get or create the singleton GitHub classifier instance.

    Returns:
        GitHubClassifier instance
    """
    global _classifier
    if _classifier is None:
        _classifier = GitHubClassifier()
    return _classifier


# Convenience functions for common operations
def classify_commit_type(
    commit_message: str = "",
    code_content: str = "",
    metadata: dict[str, str] | None = None
) -> str:
    """
    Classify a GitHub commit type.

    Args:
        commit_message: The commit message text
        code_content: The commit code changes (optional)
        metadata: Optional metadata with commit information

    Returns:
        "fix_commit", "exploit_poc", or "reference"
    """
    classifier = get_github_classifier()
    return classifier.classify_commit_type(commit_message, code_content, metadata)


def filter_github_references(references: list) -> list[str]:
    """
    Filter and prioritize GitHub references.

    Args:
        references: list of reference URLs (can be strings or dicts with 'url' field from OSV)

    Returns:
        Filtered and sorted list of GitHub reference URLs
    """
    # Handle both string references and dict references (OSV format: {type: ..., url: ...})
    ref_strings = []
    for ref in references:
        if isinstance(ref, str):
            ref_strings.append(ref)
        elif isinstance(ref, dict):
            url = ref.get('url', '')
            if url:
                ref_strings.append(url)

    classifier = get_github_classifier()
    return classifier.filter_github_references(ref_strings)


def get_rate_limit_settings() -> dict[str, float]:
    """
    Get rate limiting settings.

    Returns:
        dictionary with delay, max_references, and timeout
    """
    classifier = get_github_classifier()
    return {
        "delay": classifier.get_rate_limit_delay(),
        "max_references": classifier.get_max_references(),
        "timeout": classifier.get_request_timeout()
    }
