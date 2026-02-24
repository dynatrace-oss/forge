import json
import logging
import xml.etree.ElementTree as ET
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

from shared.constants import PROJECT_ROOT

logger = logging.getLogger(__name__)


@dataclass
class VersionInfo:
    """Information about a resolved version."""
    version: str
    resolved_via: str  # "exact", "match_major", "latest", "fallback"
    source: str  # "maven_central", "cache", "fallback_registry"


class MavenVersionResolver:
    """
    Resolves Maven dependency versions using Maven Central API.

    Features:
    - Queries Maven Central search API
    - Smart version selection (exact, match_major, latest)
    - Fallback to known-good versions for common frameworks
    """
    FALLBACK_VERSIONS = {
        "org.apache.struts:struts2-core": "2.5.31",
        "org.apache.struts:struts2-convention-plugin": "2.5.31",
        "org.apache.struts:struts2-config-browser-plugin": "2.5.31",
        "org.springframework.boot:spring-boot-starter": "2.7.18",
        "org.springframework.boot:spring-boot-starter-web": "2.7.18",
        "org.springframework.boot:spring-boot-starter-actuator": "2.7.18",
        "org.springframework.security:spring-security-core": "5.7.11",
        "org.springframework.security:spring-security-web": "5.7.11",
        "io.micronaut:micronaut-http-server": "3.8.0",
        "io.micronaut:micronaut-http-client": "3.8.0",
        "io.quarkus:quarkus-core": "2.16.0",
        "io.quarkus:quarkus-resteasy": "2.16.0",
    }

    def __init__(self, cache_dir: Path = None, cache_ttl_hours: int = 24):
        """
        Initialize Maven Version Resolver.

        Args:
            cache_dir: Directory for caching version data (default: data/maven_cache)
            cache_ttl_hours: Cache TTL in hours (default: 24)
        """
        self.cache_dir = cache_dir or (PROJECT_ROOT / "data" / "maven_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

        logger.info(f"Maven Version Resolver initialized (cache: {self.cache_dir}, TTL: {cache_ttl_hours}h)")

    def resolve_version(
        self,
        group_id: str,
        artifact_id: str,
        target_version: Optional[str] = None,
        strategy: str = "match_major"
    ) -> VersionInfo:
        """
        Resolve Maven artifact version using smart selection strategy.

        Args:
            group_id: Maven group ID (e.g., "org.apache.struts")
            artifact_id: Maven artifact ID (e.g., "struts2-convention-plugin")
            target_version: Target version to match against (e.g., "2.0.11")
            strategy: Selection strategy ("exact", "match_major", "latest", "fallback")

        Returns:
            VersionInfo with resolved version and metadata

        Raises:
            ValueError: If no suitable version found and no fallback available
        """
        dep_key = f"{group_id}:{artifact_id}"
        logger.info(f"Resolving version for {dep_key} (target: {target_version}, strategy: {strategy})")

        try:
            cached_versions = self._get_from_cache(group_id, artifact_id)

            if cached_versions:
                logger.debug(f"Using {len(cached_versions)} cached versions for {dep_key}")
                versions = cached_versions
                source = "cache"
            else:
                logger.debug(f"Querying Maven Central for {dep_key}")
                versions = self._query_maven_central(group_id, artifact_id)

                if versions:
                    # Cache the results
                    self._save_to_cache(group_id, artifact_id, versions)
                    source = "maven_central"
                    logger.info(f"Found {len(versions)} versions in Maven Central for {dep_key}")
                else:
                    logger.warning(f"No versions found in Maven Central for {dep_key}")
                    source = "fallback_registry"

            if versions:
                selected_version, resolved_via = self._select_version(versions, target_version, strategy)

                if selected_version:
                    logger.info(f"Resolved {dep_key} → {selected_version} (via: {resolved_via}, source: {source})")
                    return VersionInfo(version=selected_version, resolved_via=resolved_via, source=source)

            # Fallback to known-good version
            logger.warning(f"Version selection failed for {dep_key}, trying fallback")
            fallback_version = self._get_fallback_version(group_id, artifact_id)

            if fallback_version:
                logger.info(f"Using fallback version for {dep_key} → {fallback_version}")
                return VersionInfo(version=fallback_version, resolved_via="fallback", source="fallback_registry")

            raise ValueError(f"No suitable version found for {dep_key}")

        except Exception as e:
            logger.error(f"Error resolving version for {dep_key}: {e}")

            # Try fallback as last resort
            fallback_version = self._get_fallback_version(group_id, artifact_id)
            if fallback_version:
                logger.warning(f"Using fallback version for {dep_key} after error: {fallback_version}")
                return VersionInfo(version=fallback_version, resolved_via="fallback", source="fallback_registry")

            raise

    def version_exists(self, group_id: str, artifact_id: str, version: str) -> bool:
        """
        Check if a specific version exists in Maven Central.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID
            version: Version to check

        Returns:
            True if version exists, False otherwise
        """
        try:
            versions = self._get_from_cache(group_id, artifact_id)

            if not versions:
                versions = self._query_maven_central(group_id, artifact_id)

                if versions:
                    self._save_to_cache(group_id, artifact_id, versions)

            exists = version in versions if versions else False
            logger.debug(f"Version check: {group_id}:{artifact_id}:{version} → {'EXISTS' if exists else 'NOT FOUND'}")
            return exists

        except Exception as e:
            logger.error(f"Error checking version existence: {e}")
            return False

    def _query_maven_central(self, group_id: str, artifact_id: str) -> List[str]:
        """
        Query Maven Central for available versions using maven-metadata.xml.

        This uses the more reliable maven-metadata.xml approach which lists all
        versions without pagination issues.

        Args:
            group_id: Maven group ID (e.g., "org.apache.struts")
            artifact_id: Maven artifact ID (e.g., "struts2-convention-plugin")

        Returns:
            List of available versions (sorted newest to oldest)
        """
        try:
            # Convert group_id dots to slashes for URL path
            group_path = group_id.replace('.', '/')

            # Build maven-metadata.xml URL
            url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/maven-metadata.xml"

            logger.debug(f"Querying Maven Central metadata: {url}")

            with urllib.request.urlopen(url, timeout=15) as response:
                xml_content = response.read().decode('utf-8')

            # Parse XML to extract versions
            root = ET.fromstring(xml_content)

            # Find all <version> tags under <versioning><versions>
            versions = []
            versioning = root.find('versioning')

            if versioning is not None:
                versions_element = versioning.find('versions')

                if versions_element is not None:
                    for version_elem in versions_element.findall('version'):
                        version = version_elem.text
                        if version:
                            versions.append(version.strip())

            # Sort versions (newest first)
            versions = self._sort_versions(versions)

            logger.debug(f"Found {len(versions)} versions for {group_id}:{artifact_id}")
            return versions

        except urllib.error.URLError as e:
            logger.error(f"Network error querying Maven Central metadata: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error querying Maven Central metadata: {e}")
            return []

    def _select_version(
        self,
        versions: List[str],
        target: Optional[str],
        strategy: str
    ) -> Tuple[Optional[str], str]:
        """
        Select best version from available versions based on strategy.

        Args:
            versions: List of available versions
            target: Target version to match against
            strategy: Selection strategy

        Returns:
            Tuple of (selected_version, strategy_used)
        """
        if not versions:
            return None, "none"

        # Strategy: exact match
        if strategy == "exact" and target and target in versions:
            logger.info(f"Selected: {target} (exact match)")
            logger.info("─" * 80)
            return target, "exact"

        # Strategy: match major.minor version
        if strategy == "match_major" and target:
            try:
                major, minor, _ = self._parse_version(target)

                # Find all versions matching major.minor
                matching = [v for v in versions if self._matches_major_minor(v, major, minor)]

                if matching:
                    # Return latest patch version in this major.minor
                    latest = matching[0]  # Already sorted newest first
                    logger.info(f"Selected: {latest} (match_major: {major}.{minor}.x)")
                    logger.info("─" * 80)
                    return latest, "match_major"
                else:
                    logger.info(f"No versions found matching {major}.{minor}.x, falling back to latest")
            except Exception as e:
                logger.debug(f"Error parsing target version {target}: {e}")

        # Strategy: latest version
        if strategy in ("latest", "match_major"):  # Fallback from match_major
            if versions:
                logger.info(f"Selected: {versions[0]} (latest available)")
                logger.info("WARNING: Using 'latest' strategy - may not match target framework version")
                logger.info("─" * 80)
                return versions[0], "latest"  # Already sorted newest first

        logger.warning("No version selected")
        logger.info("─" * 80)
        return None, "none"

    def _parse_version(self, version: str) -> Tuple[int, int, int]:
        """
        Parse version string into major, minor, patch components.

        Args:
            version: Version string (e.g., "2.0.11", "6.4.0")

        Returns:
            Tuple of (major, minor, patch) as integers
        """
        parts = version.split('.')

        # Handle versions like "2.0.11.1" or "1.5.22.RELEASE"
        major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0

        return major, minor, patch

    def _matches_major_minor(self, version: str, target_major: int, target_minor: int) -> bool:
        """
        Check if version matches target major.minor.

        Args:
            version: Version to check
            target_major: Target major version
            target_minor: Target minor version

        Returns:
            True if version matches major.minor
        """
        try:
            major, minor, _ = self._parse_version(version)
            return major == target_major and minor == target_minor
        except Exception:
            return False

    def _is_prerelease(self, version: str) -> bool:
        """
        Check if version is a pre-release (BETA, ALPHA, RC, M, SNAPSHOT).

        Pre-release versions should be avoided in production testing
        as they may be unstable or have compatibility issues.

        Args:
            version: Version string

        Returns:
            True if pre-release, False if stable
        """
        prerelease_markers = [
            'BETA', 'beta', 'Beta',
            'ALPHA', 'alpha', 'Alpha',
            'RC', 'rc',
            'M',  # Milestone (e.g., 2.5.0.M1)
            'SNAPSHOT', 'snapshot'
        ]

        version_upper = version.upper()
        return any(marker.upper() in version_upper for marker in prerelease_markers)

    def _sort_versions(self, versions: List[str]) -> List[str]:
        """
        Sort versions from newest to oldest.
        Pre-release versions are sorted but given lower priority than stable releases.

        Args:
            versions: List of version strings

        Returns:
            Sorted list (newest first, stable releases before pre-release)
        """
        def version_key(v: str) -> Tuple:
            try:
                # Parse version numbers
                major, minor, patch = self._parse_version(v)
                # Stable releases get priority (1) over pre-release (0)
                is_stable = 0 if self._is_prerelease(v) else 1
                return (is_stable, major, minor, patch)
            except Exception:
                # Unparseable versions go last
                return (0, 0, 0, 0)

        return sorted(versions, key=version_key, reverse=True)

    def _get_fallback_version(self, group_id: str, artifact_id: str) -> Optional[str]:
        """
        Get fallback version for common framework dependencies.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID

        Returns:
            Fallback version or None
        """
        dep_key = f"{group_id}:{artifact_id}"
        return self.FALLBACK_VERSIONS.get(dep_key)

    def _get_cache_path(self, group_id: str, artifact_id: str) -> Path:
        """Get cache file path for a dependency."""
        cache_key = f"{group_id}_{artifact_id}".replace(".", "_").replace(":", "_")
        return self.cache_dir / f"{cache_key}.json"

    def _get_from_cache(self, group_id: str, artifact_id: str) -> Optional[List[str]]:
        """
        Get cached versions if available and not expired.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID

        Returns:
            List of versions or None if cache miss/expired
        """
        cache_path = self._get_cache_path(group_id, artifact_id)

        if not cache_path.exists():
            return None

        try:
            # Check cache age
            cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)

            if cache_age > self.cache_ttl:
                logger.debug(f"Cache expired for {group_id}:{artifact_id} (age: {cache_age})")
                return None

            # Read cache
            with open(cache_path, 'r') as f:
                data = json.load(f)

            versions = data.get('versions', [])
            logger.debug(f"Cache hit for {group_id}:{artifact_id} ({len(versions)} versions)")
            return versions

        except Exception as e:
            logger.debug(f"Error reading cache for {group_id}:{artifact_id}: {e}")
            return None

    def _save_to_cache(self, group_id: str, artifact_id: str, versions: List[str]) -> None:
        """
        Save versions to cache.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID
            versions: List of versions to cache
        """
        cache_path = self._get_cache_path(group_id, artifact_id)

        try:
            data = {
                'group_id': group_id,
                'artifact_id': artifact_id,
                'versions': versions,
                'cached_at': datetime.now().isoformat(),
            }

            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Cached {len(versions)} versions for {group_id}:{artifact_id}")

        except Exception as e:
            logger.warning(f"Error saving cache for {group_id}:{artifact_id}: {e}")

