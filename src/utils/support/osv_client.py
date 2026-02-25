import asyncio
import logging
import os
import re
from datetime import datetime

import aiohttp

from utils.core.loader import load_supported_packages

logger = logging.getLogger(__name__)


class OSVClient:
    """
    Client for interacting with the OSV (Open Source Vulnerabilities) database API.
    """

    OSV_URL = "https://api.osv.dev/v1"

    # Load configuration from file
    _config = load_supported_packages()
    SUPPORTED_PACKAGES = _config.get("supported_packages", {})
    TRANSITIVE_VULNERABLE_PACKAGES = set(_config.get("transitive_vulnerable_packages", []))
    PACKAGE_FALLBACKS = _config.get("package_fallbacks", {})
    CROSS_ECOSYSTEM_MAPPINGS = _config.get("cross_ecosystem_mappings", {})

    def __init__(self, base_url: str | None = None, timeout: int = 30):
        """
        Initialize the OSV client.

        Args:
            base_url:  custom base URL for the OSV API
            timeout: Request timeout in seconds
        """
        self.base_url = base_url or os.environ.get("OSV_API_URL", self.OSV_URL)
        self.timeout = timeout

    async def query_vulnerabilities(
        self, package_name: str, ecosystem: str | None = None, cve_id: str | None = None
    ) -> list[dict]:
        """
        Query vulnerabilities for a specific package.

        Args:
            package_name: Name of the package
            ecosystem: ecosystem (e.g., "PyPI", "Maven")
            cve_id: Optional specific CVE ID to search for

        Returns:
            list of vulnerability data dictionaries
        """
        # If a specific CVE ID is provided, fetch it directly
        if cve_id:
            vuln = await self.get_vulnerability_by_id(cve_id)
            if vuln:
                # Verify the vulnerability affects the requested package
                if await self._vulnerability_affects_package(vuln, package_name, ecosystem):
                    return [vuln]
                else:
                    logger.warning(f"CVE {cve_id} does not affect package {package_name}")
                    return []
            else:
                logger.warning(f"CVE {cve_id} not found in OSV database")
                return []

        # Otherwise, query for all vulnerabilities for the package
        query = {"package": {"name": package_name}}

        if ecosystem:
            query["package"]["ecosystem"] = ecosystem

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.base_url}/query",
                    json=query,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"OSV API error: {response.status} - {error_text}")
                        return []

                    data = await response.json()
                    return data.get("vulns", [])
            except aiohttp.ClientError as e:
                logger.error(f"OSV API request failed: {str(e)}")
                return []
            except asyncio.TimeoutError:
                logger.error(f"OSV API request timed out after {self.timeout}s")
                return []

    async def get_vulnerability(self, vuln_id: str) -> dict | None:
        """
        Get detailed information about a specific vulnerability by ID.
        Alias for get_vulnerability_by_id for compatibility.

        Args:
            vuln_id: Vulnerability ID (e.g., CVE-2021-44228)

        Returns:
            Vulnerability data dictionary or None if not found
        """
        return await self.get_vulnerability_by_id(vuln_id)

    async def get_vulnerability_by_id(self, vuln_id: str) -> dict | None:
        """
        Get detailed information about a specific vulnerability by ID.

        Args:
            vuln_id: Vulnerability ID (e.g., CVE-2021-44228)

        Returns:
            Vulnerability data dictionary or None if not found
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.base_url}/vulns/{vuln_id}",
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.debug(f"OSV API error for {vuln_id}: {response.status} - {error_text}")
                        return None

                    return await response.json()
            except aiohttp.ClientError as e:
                logger.debug(f"OSV API request failed for {vuln_id}: {str(e)}")
                return None
            except asyncio.TimeoutError:
                logger.debug(f"OSV API request timed out for {vuln_id} after {self.timeout}s")
                return None

    async def get_ecosystem_vulnerabilities(
        self, package_names: list[str], ecosystem: str, limit: int = 3
    ) -> dict[str, list[dict]]:
        """
        Get vulnerabilities for multiple packages within the same ecosystem.

        Args:
            package_names: list of package names to query
            ecosystem: Ecosystem identifier (e.g., "Maven" for Java packages)
            limit: Maximum number of vulnerabilities to return per package

        Returns:
            dictionary mapping package names to lists of vulnerability data
        """
        results = {}

        # Process each package in parallel for efficiency
        tasks = []
        for package_name in package_names:
            if package_name in self.TRANSITIVE_VULNERABLE_PACKAGES:
                task = self._query_package_vulnerabilities_with_fallback(package_name, ecosystem, limit)
            else:
                task = self._query_package_vulnerabilities(package_name, ecosystem, limit)
            tasks.append(task)

        # Wait for all requests to complete
        package_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for i, package_name in enumerate(package_names):
            result = package_results[i]
            if isinstance(result, Exception):
                logger.error(f"Error fetching vulnerabilities for {package_name}: {result}")
                results[package_name] = []
            else:
                results[package_name] = result

        return results

    async def get_vulnerability_by_cve_for_package(
        self, cve_id: str, package_name: str, ecosystem: str | None = None
    ) -> dict | None:
        """
        Get vulnerability information for a specific CVE ID and verify it affects the given package.

        Args:
            cve_id: CVE ID to fetch (e.g., "CVE-2021-44228")
            package_name: Package name to verify the CVE affects
            ecosystem: Optional ecosystem for the package

        Returns:
            Vulnerability data if found and affects the package, None otherwise
        """
        vuln = await self.get_vulnerability_by_id(cve_id)

        if not vuln:
            logger.warning(f"CVE {cve_id} not found in OSV database")
            return None

        # Check if the vulnerability affects the requested package
        if await self._vulnerability_affects_package(vuln, package_name, ecosystem):
            return vuln
        else:
            # Try to adapt the vulnerability for transitive dependencies
            if package_name in self.TRANSITIVE_VULNERABLE_PACKAGES:
                logger.info(f"Checking if {cve_id} affects {package_name} through transitive dependencies")

                # Check if this CVE is in our known list for this package
                if package_name in self.LATEST_KNOWN_CVES:
                    if cve_id in self.LATEST_KNOWN_CVES[package_name]:
                        return self._adapt_vulnerability_for_package(vuln, package_name)

                # Check if the vulnerability mentions the package
                if self._vulnerability_mentions_package(vuln, package_name):
                    return self._adapt_vulnerability_for_package(vuln, package_name)

            logger.warning(f"CVE {cve_id} does not affect package {package_name}")
            return None

    async def _vulnerability_affects_package(
        self, vuln: dict, package_name: str, ecosystem: str | None = None
    ) -> bool:
        """
        Check if a vulnerability affects the given package.

        Args:
            vuln: Vulnerability data
            package_name: Package name to check
            ecosystem: Optional ecosystem to verify

        Returns:
            True if the vulnerability affects the package, False otherwise
        """
        logger.debug(f"The vuln is: {vuln}")
        if "affected" not in vuln or not vuln["affected"]:
            return False

        # Extract artifact ID for Maven packages
        artifact_id = package_name.split(":")[-1] if ":" in package_name else package_name

        for affected in vuln["affected"]:
            pkg = affected.get("package", {})
            affected_name = pkg.get("name", "")

            # Check exact match
            if affected_name == package_name:
                if ecosystem and pkg.get("ecosystem") != ecosystem:
                    continue
                return True

            # This handles cases where OSV has "snakeyaml" but we're looking for "org.yaml:snakeyaml"
            if ":" in package_name and affected_name == artifact_id:
                # Additional check: ensure it's a Maven-related ecosystem or no ecosystem specified
                affected_ecosystem = pkg.get("ecosystem", "")
                if not affected_ecosystem or "Maven" in affected_ecosystem or "Debian" in affected_ecosystem:
                    return True

            # Check cross-ecosystem mappings
            if affected_name in self.CROSS_ECOSYSTEM_MAPPINGS:
                mapped_packages = self.CROSS_ECOSYSTEM_MAPPINGS[affected_name]
                if package_name in mapped_packages:
                    logger.info(f"Found cross-ecosystem mapping: {affected_name} -> {package_name}")
                    return True

        # If no direct match found, check aliases (especially GHSA entries) for cross-ecosystem mapping
        aliases = vuln.get("aliases", [])
        for alias in aliases:
            # Check GHSA aliases specifically as they often have better ecosystem coverage
            if alias.startswith("GHSA-"):
                logger.debug(f"Checking alias {alias} for package {package_name}")
                try:
                    # Fetch the alias vulnerability data
                    alias_vuln = await self.get_vulnerability_by_id(alias)
                    if alias_vuln and alias_vuln.get("affected"):
                        # Recursively check if the alias affects the package
                        if self._check_affected_packages_direct(
                            alias_vuln.get("affected", []), package_name, ecosystem
                        ):
                            logger.info(f"Package {package_name} found in alias {alias} of {vuln.get('id', 'unknown')}")
                            # Replace the vulnerability data with the alias data for better version extraction
                            vuln.update(alias_vuln)
                            return True
                except Exception as e:
                    logger.debug(f"Error checking alias {alias}: {e}")
                    continue

        return False

    def _check_affected_packages_direct(
        self, affected_packages: list, package_name: str, ecosystem: str | None = None
    ) -> bool:
        """
        Helper method to check if a package is directly affected by checking the affected packages list.
        This avoids infinite recursion when checking aliases.

        Args:
            affected_packages: List of affected package dictionaries
            package_name: Package name to check
            ecosystem: Optional ecosystem to verify

        Returns:
            True if the package is found in the affected list, False otherwise
        """
        artifact_id = package_name.split(":")[-1] if ":" in package_name else package_name

        for affected in affected_packages:
            pkg = affected.get("package", {})
            affected_name = pkg.get("name", "")

            # Check exact match
            if affected_name == package_name:
                if ecosystem and pkg.get("ecosystem") != ecosystem:
                    continue
                return True

            # Check artifact ID match with ecosystem compatibility
            if ":" in package_name and affected_name == artifact_id:
                affected_ecosystem = pkg.get("ecosystem", "")
                if not affected_ecosystem or "Maven" in affected_ecosystem or "Debian" in affected_ecosystem:
                    return True

        return False

    async def _query_package_vulnerabilities(self, package_name: str, ecosystem: str, limit: int) -> list[dict]:
        """
        Query vulnerabilities for a single package with proper error handling.

        Args:
            package_name: Package name to query
            ecosystem: Ecosystem identifier
            limit: Maximum number of vulnerabilities to return

        Returns:
            list of vulnerability data dictionaries
        """
        try:
            query = {"package": {"name": package_name, "ecosystem": ecosystem}}

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/query",
                    json=query,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    if response.status != 200:
                        logger.debug(f"OSV API error for {package_name}: {response.status}")
                        return []

                    data = await response.json()
                    vulns = data.get("vulns", [])

                    # Sort vulnerabilities by published date (newest first)
                    sorted_vulns = sorted(
                        vulns,
                        key=lambda v: v.get("published", "2000-01-01").replace("Z", "+00:00"),
                        reverse=True,
                    )

                    return sorted_vulns[:limit]
        except Exception as e:
            logger.debug(f"Error querying vulnerabilities for {package_name}: {str(e)}")
            return []

    async def _query_package_vulnerabilities_with_fallback(
        self, package_name: str, ecosystem: str, limit: int
    ) -> list[dict]:
        """
        Query vulnerabilities for a single package with fallback strategies.
        Only used for packages known to have transitive dependency issues.

        Args:
            package_name: Package name to query
            ecosystem: Ecosystem identifier
            limit: Maximum number of vulnerabilities to return

        Returns:
            list of vulnerability data dictionaries
        """
        logger.info(f"Querying vulnerabilities for {package_name} (supports transitive dependency fallback)")

        # Try direct query first
        vulns = await self._query_package_vulnerabilities(package_name, ecosystem, limit)

        if vulns:
            logger.info(f"Found {len(vulns)} vulnerabilities via direct query for {package_name}")
            return vulns

        # Only use fallback strategies for packages known to have transitive issues
        logger.info(
            f"No direct vulnerabilities found for {package_name}, trying transitive dependency fallback strategies..."
        )

        # Try fallback package queries for known problematic packages
        if package_name in self.PACKAGE_FALLBACKS:
            logger.info(f"Attempting transitive dependency queries for {package_name}")
            for fallback_query in self.PACKAGE_FALLBACKS[package_name]:
                try:
                    fallback_package_name = fallback_query["package"]["name"]
                    logger.debug(f"Querying transitive dependency: {fallback_package_name}")

                    fallback_vulns = await self._query_package_vulnerabilities(
                        fallback_package_name,
                        fallback_query["package"]["ecosystem"],
                        limit,
                    )

                    if fallback_vulns:
                        logger.info(
                            f"Found {len(fallback_vulns)} vulnerabilities via transitive dependency {fallback_package_name}"
                        )
                        # Filter to only include vulnerabilities that mention the original package
                        relevant_vulns = []
                        for vuln in fallback_vulns:
                            if self._vulnerability_mentions_package(vuln, package_name):
                                relevant_vulns.append(vuln)

                        if relevant_vulns:
                            logger.info(
                                f"Filtered to {len(relevant_vulns)} relevant transitive vulnerabilities for {package_name}"
                            )
                            return relevant_vulns[:limit]

                except Exception as e:
                    logger.debug(f"Transitive dependency query failed for {fallback_query}: {e}")

        # Query latest known CVEs directly
        if package_name in self.LATEST_KNOWN_CVES:
            logger.info(f"Attempting known CVE lookup for {package_name}")
            cve_vulns = []

            for cve_id in self.LATEST_KNOWN_CVES[package_name][:limit]:
                try:
                    logger.debug(f"Looking up known CVE: {cve_id}")
                    vuln = await self.get_vulnerability_by_id(cve_id)
                    if vuln:
                        # Modify the vulnerability to indicate it affects our package
                        vuln = self._adapt_vulnerability_for_package(vuln, package_name)
                        cve_vulns.append(vuln)
                        logger.debug(f"Successfully retrieved known CVE {cve_id} for {package_name}")
                    else:
                        logger.debug(f"Known CVE {cve_id} not found in OSV database")
                except Exception as e:
                    logger.debug(f"Failed to fetch known CVE {cve_id}: {e}")

            if cve_vulns:
                logger.info(f"Found {len(cve_vulns)} vulnerabilities via known CVE lookup for {package_name}")
                return cve_vulns

        logger.warning(f"No vulnerabilities found for {package_name} after trying all transitive dependency strategies")
        return []

    def _vulnerability_mentions_package(self, vuln: dict, package_name: str) -> bool:
        """Check if a vulnerability mentions the given package name."""
        package_simple = package_name.split(":")[-1] if ":" in package_name else package_name

        summary = vuln.get("summary", "").lower()
        details = vuln.get("details", "").lower()

        return (
            package_simple.lower() in summary
            or package_simple.lower() in details
            or package_name.lower() in summary
            or package_name.lower() in details
        )

    def _adapt_vulnerability_for_package(self, vuln: dict, package_name: str) -> dict:
        """Adapt a vulnerability record to indicate it affects the given package."""
        # Clone the vulnerability
        adapted_vuln = vuln.copy()

        # Add affected package information if not present
        if "affected" not in adapted_vuln:
            adapted_vuln["affected"] = []

        # Check if package is already in affected list
        package_already_listed = False
        for affected in adapted_vuln["affected"]:
            pkg = affected.get("package", {})
            if pkg.get("name") == package_name:
                package_already_listed = True
                break

        # Add package to affected list if not already there
        if not package_already_listed:
            adapted_vuln["affected"].append(
                {
                    "package": {"name": package_name, "ecosystem": "Maven"},
                    "versions": ["*"],  # Indicates all versions potentially affected
                }
            )

        # Update summary to mention this is a transitive vulnerability
        original_summary = adapted_vuln.get("summary", "")
        if package_name.split(":")[-1] not in original_summary.lower():
            adapted_vuln["summary"] = f"{original_summary} (affects {package_name} via transitive dependency)"

        return adapted_vuln


async def get_vulnerabilities_for_selected_packages(
    selected_packages: list[str], vuln_limit: int = 3, min_year: int = 2018, cve_ids: dict[str, str] | None = None
) -> dict[str, list[dict]]:
    """
    Get vulnerabilities for the selected packages with year filtering.

    Args:
        selected_packages: list of selected package names
        vuln_limit: Maximum number of vulnerabilities to return per package
        min_year: Minimum year for vulnerabilities
        cve_ids: Optional dictionary mapping package names to specific CVE IDs

    Returns:
        dictionary mapping package names to lists of vulnerability data
    """
    client = OSVClient()
    logger.debug(f"Selected pacakge is: {selected_packages}")
    logger.debug(f"CVE IDS: {cve_ids}")
    # Validate selected packages are supported
    validated_packages = []
    for package in selected_packages:
        if package in client.SUPPORTED_PACKAGES:
            validated_packages.append(package)
        else:
            logger.warning(f"Unsupported package: {package}")

    if not validated_packages:
        logger.error("No supported packages selected")
        return {}

    # If specific CVE IDs are provided, fetch them
    if cve_ids:
        all_results = {}
        for package in validated_packages:
            if package in cve_ids:
                # Fetch specific CVE for this package
                ecosystem = client.SUPPORTED_PACKAGES[package]
                vuln = await client.get_vulnerability_by_cve_for_package(cve_ids[package], package, ecosystem)
                if vuln:
                    all_results[package] = [vuln]
                else:
                    all_results[package] = []
            else:
                # No specific CVE requested, use normal query
                ecosystem = client.SUPPORTED_PACKAGES[package]
                vulns = await client.query_vulnerabilities(package, ecosystem)
                all_results[package] = vulns[:vuln_limit] if vulns else []

        return all_results

    # Otherwise, proceed with normal vulnerability queries
    # Group packages by ecosystem for efficient querying
    ecosystem_packages: dict[str, list[str]] = {}
    for package in validated_packages:
        ecosystem = client.SUPPORTED_PACKAGES[package]
        if ecosystem not in ecosystem_packages:
            ecosystem_packages[ecosystem] = []
        ecosystem_packages[ecosystem].append(package)

    # Query vulnerabilities by ecosystem
    all_results: dict[str, list[dict]] = {}
    for ecosystem, packages in ecosystem_packages.items():
        ecosystem_results = await client.get_ecosystem_vulnerabilities(packages, ecosystem, vuln_limit)
        all_results.update(ecosystem_results)

    # Filter by year
    for package, vulns in all_results.items():
        if vulns:
            filtered_vulns = []
            for vuln in vulns:
                published_date = vuln.get("published", "")
                if published_date:
                    try:
                        pub_date = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
                        if pub_date.year >= min_year:
                            filtered_vulns.append(vuln)
                    except (ValueError, TypeError):
                        # If date parsing fails, include the vulnerability
                        filtered_vulns.append(vuln)
                else:
                    # No date info, include it
                    filtered_vulns.append(vuln)

            if filtered_vulns:
                logger.info(
                    f"Filtered {len(vulns)} vulnerabilities to {len(filtered_vulns)} for {package} (>= {min_year})"
                )
                all_results[package] = filtered_vulns
            else:
                logger.warning(
                    f"No vulnerabilities found for {package} after year filtering (>= {min_year}). "
                    f"Using {len(vulns)} older vulnerabilities."
                )
                all_results[package] = vulns
        else:
            all_results[package] = []

    return all_results


def format_vulnerability_summary(vulnerability: dict) -> str:
    """
    Format a vulnerability into a human-readable summary.

    Args:
        vulnerability: Vulnerability data from OSV

    Returns:
        Formatted summary string
    """
    vuln_id = vulnerability.get("id", "Unknown ID")
    aliases = vulnerability.get("aliases", [])
    cve_id = next((alias for alias in aliases if alias.startswith("CVE-")), "No CVE ID")

    summary = vulnerability.get("summary", "No summary available")

    published = vulnerability.get("published", "")
    if published:
        try:
            pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            published = pub_date.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            published = "Unknown date"

    affected_packages = []
    if "affected" in vulnerability and vulnerability["affected"]:
        for affected in vulnerability["affected"]:
            pkg = affected.get("package", {})
            name = pkg.get("name", "Unknown package")
            ecosystem = pkg.get("ecosystem", "Unknown ecosystem")

            # Get version info
            versions = affected.get("versions", [])
            version_info = f"{len(versions)} versions" if versions else "version info not available"

            affected_packages.append(f"{name} ({ecosystem}): {version_info}")

    return (
        f"{cve_id} ({vuln_id}) - {published}\n"
        f"Summary: {summary}\n"
        f"Affected: {', '.join(affected_packages) if affected_packages else 'No package information'}"
    )


def extract_cvss_score(vulnerability: dict) -> float | None:
    """
    Extract CVSS score from vulnerability data.

    Args:
        vulnerability: Vulnerability data from OSV

    Returns:
        CVSS score as float, or None if not available
    """
    # Check for CVSS v3 score first (preferred)
    severity = vulnerability.get("severity", [])

    for sev in severity:
        if sev.get("type") == "CVSS_V3":
            score = sev.get("score")
            if score:
                try:
                    return float(score)
                except (ValueError, TypeError):
                    continue

    # Check for CVSS v2 score as fallback
    for sev in severity:
        if sev.get("type") == "CVSS_V2":
            score = sev.get("score")
            if score:
                try:
                    return float(score)
                except (ValueError, TypeError):
                    continue

    # Try to extract from database_specific field
    db_specific = vulnerability.get("database_specific", {})
    cvss_score = db_specific.get("cvss_score") or db_specific.get("cvss")
    if cvss_score:
        try:
            return float(cvss_score)
        except (ValueError, TypeError):
            pass

    return None


def extract_severity_level(vulnerability: dict) -> str | None:
    """
    Extract severity level from vulnerability data.

    Args:
        vulnerability: Vulnerability data from OSV

    Returns:
        Severity level string (LOW, MEDIUM, HIGH, CRITICAL) or None
    """
    # First try to get from CVSS score
    cvss_score = extract_cvss_score(vulnerability)
    if cvss_score is not None:
        if cvss_score <= 3.9:
            return "LOW"
        elif cvss_score <= 6.9:
            return "MEDIUM"
        elif cvss_score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"

    # Try to extract from severity field
    severity = vulnerability.get("severity", [])
    for sev in severity:
        severity_level = sev.get("severity") or sev.get("level")
        if severity_level:
            # Normalize common severity strings
            severity_upper = severity_level.upper()
            if severity_upper in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                return severity_upper
            elif severity_upper in ["MODERATE"]:
                return "MEDIUM"
            elif severity_upper in ["IMPORTANT"]:
                return "HIGH"

    # Try database_specific field
    db_specific = vulnerability.get("database_specific", {})
    severity_level = db_specific.get("severity") or db_specific.get("severity_level")
    if severity_level:
        severity_upper = str(severity_level).upper()
        if severity_upper in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            return severity_upper

    return None


def extract_attack_vector(vulnerability: dict) -> str | None:
    """
    Extract attack vector from vulnerability data.

    Args:
        vulnerability: Vulnerability data from OSV

    Returns:
        Attack vector string (NETWORK, ADJACENT, LOCAL, PHYSICAL) or None
    """
    # Try to extract from CVSS vector string
    severity = vulnerability.get("severity", [])

    for sev in severity:
        if sev.get("type") in ["CVSS_V3", "CVSS_V2"]:
            vector = sev.get("vector") or sev.get("cvss_vector")
            if vector:
                # Parse CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                if "AV:N" in vector:
                    return "NETWORK"
                elif "AV:A" in vector:
                    return "ADJACENT"
                elif "AV:L" in vector:
                    return "LOCAL"
                elif "AV:P" in vector:
                    return "PHYSICAL"

    # Try database_specific field
    db_specific = vulnerability.get("database_specific", {})
    attack_vector = db_specific.get("attack_vector")
    if attack_vector:
        attack_vector_upper = str(attack_vector).upper()
        if attack_vector_upper in ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]:
            return attack_vector_upper

    return None


def extract_attack_complexity(vulnerability: dict) -> str | None:
    """
    Extract attack complexity from vulnerability data.

    Args:
        vulnerability: Vulnerability data from OSV

    Returns:
        Attack complexity string (LOW, HIGH) or None
    """
    # Try to extract from CVSS vector string
    severity = vulnerability.get("severity", [])

    for sev in severity:
        if sev.get("type") in ["CVSS_V3", "CVSS_V2"]:
            vector = sev.get("vector") or sev.get("cvss_vector")
            if vector:
                # Parse CVSS vector string
                if "AC:L" in vector:
                    return "LOW"
                elif "AC:H" in vector:
                    return "HIGH"

    # Try database_specific field
    db_specific = vulnerability.get("database_specific", {})
    attack_complexity = db_specific.get("attack_complexity")
    if attack_complexity:
        attack_complexity_upper = str(attack_complexity).upper()
        if attack_complexity_upper in ["LOW", "HIGH"]:
            return attack_complexity_upper

    return None


def extract_vulnerability_metadata(vulnerability: dict) -> dict:
    """
    Extract all available metadata from vulnerability data.

    Args:
        vulnerability: Vulnerability data from OSV

    Returns:
        Dictionary with extracted metadata
    """
    return {
        "cvss_score": extract_cvss_score(vulnerability),
        "severity_level": extract_severity_level(vulnerability),
        "attack_vector": extract_attack_vector(vulnerability),
        "attack_complexity": extract_attack_complexity(vulnerability),
    }


def extract_vulnerable_version(vuln_data: dict, package_name: str) -> str:
    """
    Extract a vulnerable version from OSV data intelligently with Maven Central validation.

    Args:
        vuln_data: OSV vulnerability data
        package_name: Package name (format: "groupId:artifactId" or just "artifactId")

    Returns:
        Appropriate vulnerable version string that exists in Maven Central

    Raises:
        ValueError: If no valid Maven version found in OSV data or Maven Central
    """
    try:
        # Import Maven version resolver for validation
        from services.dependency.maven_version_resolver import MavenVersionResolver
        maven_resolver = MavenVersionResolver()

        # Parse package name to get group_id and artifact_id
        if ":" in package_name:
            group_id, artifact_id = package_name.split(":", 1)
        else:
            # If no group_id provided, we'll try to extract from OSV data
            group_id = None
            artifact_id = package_name

        logger.info(f"Extracting vulnerable version for {package_name} with Maven Central validation")

        # Strategy 1: Use actual vulnerable versions from OSV data (HIGHEST PRIORITY)
        affected_packages = vuln_data.get("affected", [])
        for affected in affected_packages:
            # Check if this affected package matches our target package
            pkg = affected.get("package", {})
            affected_name = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", "")

            # Match package name (exact or artifact ID match for Maven)
            package_matches = affected_name == package_name or (
                ":" in package_name and affected_name == package_name.split(":")[-1]
            )

            if not package_matches:
                continue

            # Check ecosystem compatibility (Maven/Java)
            ecosystem_compatible = (
                not ecosystem
                or "maven" in ecosystem.lower()
                or "java" in ecosystem.lower()
                or "debian" in ecosystem.lower()
            )

            if not ecosystem_compatible:
                continue

            # PRIORITY 1: Use actual versions array if available + Maven validation
            versions = affected.get("versions", [])
            if versions and isinstance(versions, list) and len(versions) > 0:
                # Try to get group_id from OSV data if not provided
                if not group_id:
                    # Try to extract from purl (Package URL) if available
                    purl = pkg.get("purl", "")
                    if purl and "pkg:maven/" in purl:
                        # Format: pkg:maven/groupId/artifactId@version
                        parts = purl.replace("pkg:maven/", "").split("/")
                        if len(parts) >= 2:
                            group_id = parts[0]
                            artifact_id = parts[1].split("@")[0]
                            logger.debug(f"Extracted Maven coordinates from purl: {group_id}:{artifact_id}")

                # Select the best-looking version from the list
                selected_version = _select_best_version_from_list(versions)
                if selected_version:
                    logger.info(f"OSV suggested version {selected_version} for {package_name}")

                    # Validate version exists in Maven Central
                    if group_id:
                        if maven_resolver.version_exists(group_id, artifact_id, selected_version):
                            logger.info(f"Validated {group_id}:{artifact_id}:{selected_version} exists in Maven Central")
                            return selected_version
                        else:
                            logger.warning(f"Version {selected_version} from OSV does NOT exist in Maven Central for {group_id}:{artifact_id}")
                            logger.info("Attempting fallback version resolution strategies...")

                            # Fallback: Try to find a valid version using MavenVersionResolver
                            try:
                                version_info = maven_resolver.resolve_version(
                                    group_id,
                                    artifact_id,
                                    target_version=selected_version,
                                    strategy="match_major"
                                )
                                logger.info(f"Fallback resolution found valid version: {version_info.version} (via: {version_info.resolved_via})")
                                return version_info.version
                            except Exception as e:
                                logger.warning(f"Fallback resolution failed: {e}")
                                # Continue to other strategies
                    else:
                        logger.warning(f"Cannot validate version {selected_version} - group_id not available")
                        # Return OSV version without validation if we can't determine group_id
                        return selected_version

            # PRIORITY 2: Extract from ranges if no versions array
            ranges = affected.get("ranges", [])
            for version_range in ranges:
                events = version_range.get("events", [])
                for event in events:
                    if "introduced" in event and event["introduced"] != "0":
                        # Use the introduced version if it's specific
                        introduced_version = event["introduced"]
                        if _is_valid_version_format(introduced_version):
                            logger.info(f"OSV suggested introduced version {introduced_version} for {package_name}")

                            # Validate if group_id is available
                            if group_id and maven_resolver.version_exists(group_id, artifact_id, introduced_version):
                                logger.info(f"Validated {group_id}:{artifact_id}:{introduced_version} exists in Maven Central")
                                return introduced_version
                            elif not group_id:
                                logger.warning(f"Cannot validate version {introduced_version} - group_id not available")
                                return introduced_version
                            else:
                                logger.warning(f"Introduced version {introduced_version} does NOT exist in Maven Central")
                                # Continue to other strategies

        # Strategy 2: Parse version from details/summary text (fallback)
        details = vuln_data.get("details", "")
        summary = vuln_data.get("summary", "")

        version_patterns = [
            # Range patterns (most specific first)
            r"(\d+\.\d+(?:\.\d+)*(?:-\w+)?)\s+through\s+(\d+\.\d+(?:\.\d+)*)",  # "2.0-beta9 through 2.15.0"
            r"from\s+(\d+\.\d+(?:\.\d+)*)\s+to\s+(\d+\.\d+(?:\.\d+)*)",  # "from 2.0 to 2.15.0"
            r"between\s+(\d+\.\d+(?:\.\d+)*)\s+and\s+(\d+\.\d+(?:\.\d+)*)",  # "between 2.0 and 2.15.0"
            # Fixed version patterns (fallback)
            r"before\s+(\d+\.\d+(?:\.\d+)*)",  # "before 2.9.9.1"
            r"prior\s+to\s+(\d+\.\d+(?:\.\d+)*)",  # "prior to 2.9.9"
            r"versions?\s+(\d+\.\d+(?:\.\d+)*)\s+and\s+earlier",  # "version 2.9.9 and earlier"
            r"up\s+to\s+(\d+\.\d+(?:\.\d+)*)",  # "up to 2.9.9"
        ]

        text_to_search = f"{details} {summary}".lower()
        for pattern in version_patterns:
            match = re.search(pattern, text_to_search)
            if match:
                # Check if this is a range pattern (2 groups) or single version pattern (1 group)
                if len(match.groups()) == 2:
                    # Range pattern: start_version through end_version
                    start_version, end_version = match.groups()
                    vulnerable_version = _get_version_from_range(end_version)
                    if vulnerable_version:
                        logger.info(
                            f"Extracted version {vulnerable_version} from range {start_version}-{end_version} for {package_name}"
                        )
                        # Validate if group_id is available
                        if group_id:
                            if maven_resolver.version_exists(group_id, artifact_id, vulnerable_version):
                                logger.info("Validated text-extracted version exists in Maven Central")
                                return vulnerable_version
                            else:
                                logger.warning(f"Text-extracted version {vulnerable_version} does NOT exist in Maven Central")
                                # Continue to next pattern
                                continue
                        else:
                            return vulnerable_version
                else:
                    # Single version pattern: version that fixes the vulnerability
                    fixed_version = match.group(1)
                    vulnerable_version = _get_vulnerable_version_before(fixed_version)
                    if vulnerable_version:
                        logger.info(f"Extracted version {vulnerable_version} from text analysis for {package_name}")
                        # Validate if group_id is available
                        if group_id:
                            if maven_resolver.version_exists(group_id, artifact_id, vulnerable_version):
                                logger.info("Validated text-extracted version exists in Maven Central")
                                return vulnerable_version
                            else:
                                logger.warning(f"Text-extracted version {vulnerable_version} does NOT exist in Maven Central")
                                # Continue to next pattern
                                continue
                        else:
                            return vulnerable_version

        # Strategy 3: Last resort - try to use MavenVersionResolver to find ANY valid version
        if group_id:
            logger.warning("All version extraction strategies failed validation. Attempting last-resort resolution...")
            try:
                version_info = maven_resolver.resolve_version(
                    group_id,
                    artifact_id,
                    target_version=None,  # No target, just get latest
                    strategy="latest"
                )
                logger.warning(f"Using latest available version as last resort: {version_info.version}")
                logger.warning("This may not be a vulnerable version! Manual verification recommended.")
                return version_info.version
            except Exception as e:
                logger.error(f"Last-resort resolution failed: {e}")

        logger.error(f"Could not extract ANY valid vulnerable version for {package_name} from OSV data or Maven Central")
        logger.error("OSV data quality issue detected - no versions in OSV match Maven Central")
        raise ValueError(f"No valid Maven version found for package {package_name} in OSV vulnerability data")

    except Exception as e:
        logger.warning(f"Error extracting version for {package_name}: {e}")
        raise e


def _get_version_from_range(end_version: str) -> str | None:
    """
    Select a suitable vulnerable version from a version range.

    Args:
        start_version: First vulnerable version (e.g., "2.0-beta9")
        end_version: Last version before fix (e.g., "2.15.0")

    Returns:
        A good vulnerable version from the range, preferring stable releases
    """
    try:
        # Clean up version strings and normalize
        def normalize_version(version: str) -> tuple:
            # Remove pre-release suffixes like "-beta9", "-alpha", etc.
            clean_version = re.sub(r"-\w+.*$", "", version)
            parts = clean_version.split(".")
            return tuple(int(p) for p in parts)

        try:
            end_parts = normalize_version(end_version)
        except ValueError:
            return None

        # For the end version, pick the previous minor/patch version
        # This is a generic approach that works for any package
        if len(end_parts) >= 3:  # major.minor.patch
            major, minor, patch = end_parts[0], end_parts[1], end_parts[2]
            if patch > 0:
                return f"{major}.{minor}.{patch - 1}"
            elif minor > 0:
                return f"{major}.{minor - 1}.1"
            else:
                return f"{max(1, major - 1)}.99.1"
        elif len(end_parts) == 2:  # major.minor
            major, minor = end_parts[0], end_parts[1]
            if minor > 0:
                return f"{major}.{minor - 1}.1"
            else:
                return f"{max(1, major - 1)}.99.1"
        else:
            return None

    except Exception:
        return None


def _select_best_version_from_list(versions: list) -> str | None:
    """
    Select the best version from a list of actual vulnerable versions.
    Prefers stable releases and recent versions.
    Converts Debian package versions to Maven-compatible versions.

    Args:
        versions: List of version strings from OSV data

    Returns:
        Selected version string or None
    """
    if not versions:
        return None

    # Filter out invalid/empty versions and convert Debian to Maven versions
    maven_compatible_versions = []
    for v in versions:
        if v and isinstance(v, str):
            # Convert Debian package version to Maven version (e.g., "1.28-1" -> "1.28")
            maven_version = _convert_debian_to_maven_version(v)
            if maven_version and _is_valid_version_format(maven_version):
                maven_compatible_versions.append(maven_version)

    if not maven_compatible_versions:
        return None

    # Remove duplicates while preserving order
    unique_versions = []
    seen = set()
    for v in maven_compatible_versions:
        if v not in seen:
            unique_versions.append(v)
            seen.add(v)

    # Prefer non-beta/alpha versions
    stable_versions = [v for v in unique_versions if not re.search(r"-(alpha|beta|rc|snapshot)", v.lower())]

    if not stable_versions:
        # Fall back to last available version (latest)
        return unique_versions[-1]

    # Smart version selection: prefer mature middle versions over bleeding-edge latest
    # This avoids API churn in brand-new releases while avoiding ancient deprecated APIs

    # Group versions by major.minor (e.g., "2.5", "6.3")
    version_groups = {}
    for v in stable_versions:
        parts = v.split('.')
        if len(parts) >= 2:
            try:
                major_minor = f"{parts[0]}.{parts[1]}"
                if major_minor not in version_groups:
                    version_groups[major_minor] = []
                version_groups[major_minor].append(v)
            except (ValueError, IndexError):
                # Skip malformed versions
                continue

    if not version_groups:
        # Fallback if grouping fails
        return stable_versions[-1]

    # Sort major.minor keys numerically
    try:
        major_minor_keys = sorted(version_groups.keys(),
                                 key=lambda x: [int(p) for p in x.split('.')])
    except ValueError:
        # Fallback if sorting fails
        return stable_versions[-1]

    # Selection strategy based on number of version lines
    num_lines = len(major_minor_keys)

    if num_lines == 1:
        # Only one major.minor line: pick latest patch version
        selected_key = major_minor_keys[0]
    elif num_lines == 2:
        # Two lines: prefer the older, more stable one
        # (e.g., prefer 5.3.x over 6.0.x if both exist)
        selected_key = major_minor_keys[0]
    else:
        # Multiple lines: pick the SECOND-TO-LAST major.minor (mature but not ancient)
        # This avoids both bleeding-edge (latest) and ancient (oldest)
        # Example: If we have 2.0, 2.1, 2.3, 2.5, 6.0, 6.1, 6.2, 6.3
        #          Pick 6.2 (second-to-last) - mature 6.x but not bleeding-edge 6.3
        selected_key = major_minor_keys[-2]

    # Within the selected major.minor, pick the latest patch version
    selected_versions = version_groups[selected_key]
    return selected_versions[-1]


def _convert_debian_to_maven_version(debian_version: str) -> str | None:
    """
    Convert Debian package version to Maven-compatible version.

    Examples:
        "1.28-1" -> "1.28"
        "1.28-1+deb11u1" -> "1.28"
        "2.0+ds-1" -> "2.0"
        "1.33-2" -> "1.33"
        "20230618" -> "20230618" (unchanged for date-based versions)

    Args:
        debian_version: Debian package version string

    Returns:
        Maven-compatible version string or None if conversion fails
    """
    if not debian_version or not isinstance(debian_version, str):
        return None

    # Handle date-based versions (like org.json) - keep as is
    if re.match(r"^\d{8}$", debian_version.strip()):
        return debian_version.strip()

    # Remove Debian-specific suffixes
    # Pattern matches: -1, -1+deb11u1, +ds-1, etc.
    maven_version = re.sub(r"[-+].*$", "", debian_version.strip())

    # Validate the result is a proper version
    if maven_version and re.match(r"^\d+\.\d+(?:\.\d+)*$", maven_version):
        return maven_version

    # If the cleaned version doesn't match standard format, try to extract just the version part
    version_match = re.match(r"^(\d+\.\d+(?:\.\d+)*)", debian_version.strip())
    if version_match:
        return version_match.group(1)

    return None


def _is_valid_version_format(version: str) -> bool:
    """
    Check if a version string has a valid format.
    Supports semantic versions and date-based versions.

    Args:
        version: Version string to validate

    Returns:
        True if version format is valid
    """
    if not version or not isinstance(version, str):
        return False

    version = version.strip()

    # Date-based version pattern (e.g., org.json uses YYYYMMDD format)
    if re.match(r"^\d{8}$", version):
        return True

    # Basic semantic version pattern: digits.digits[.digits][optional suffix]
    pattern = r"^\d+\.\d+(?:\.\d+)*(?:-[\w\.-]+)?$"
    return bool(re.match(pattern, version))


def _get_vulnerable_version_before(fixed_version: str) -> str | None:
    """
    Get a reasonable vulnerable version before the fixed version.
    This is a fallback function - should only be used when OSV versions array is unavailable.
    """
    logger.warning(
        f"Using fallback version generation for fixed version {fixed_version} - this may produce non-existent versions"
    )

    try:
        # Parse version components
        version_match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", fixed_version)
        if not version_match:
            return None

        major, minor, patch = version_match.groups()
        major, minor = int(major), int(minor)
        patch = int(patch) if patch else 0

        # Generate a vulnerable version slightly before the fixed version
        if patch > 0:
            return f"{major}.{minor}.{patch - 1}"
        elif minor > 0:
            return f"{major}.{minor - 1}.0"
        else:
            return f"{major - 1}.0.0" if major > 1 else "1.0.0"

    except Exception:
        return None
