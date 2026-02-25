# Copyright (c) 2025 Dynatrace LLC. All rights reserved.
#
# This software and associated documentation files (the "Software") are being
# made available by Dynatrace LLC for the sole purpose of illustrating the
# implementation of certain algorithms which are published. Permission is
# hereby granted, free of charge, to any person obtaining a copy of the
# Software, to view and use the Software for internal, non-production,
# non-commercial purposes only. Without limiting the foregoing, the Software
# may not (i) be used to process live data or train, fine-tune, enrich or
# improve any machine learning or foundation model or other artificial
# intelligence model or system or (ii) distributed, sublicensed, modified, used
# to provide a service, or sold either alone or as part of or in combination
# with any other software. The Software shall at all times be considered the
# proprietary property of Dynatrace LLC.
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
from typing import Any

import httpx

from forge.models import CVETask

logger = logging.getLogger(__name__)

_MAX_CONCURRENCY = 10

# OSV ecosystem → programming language mapping.
# These are the standard ecosystem identifiers used by OSV/GHSA.
# See: https://ossf.github.io/osv-schema/#affectedpackage-field
_ECOSYSTEM_TO_LANGUAGE: dict[str, str] = {
    "PyPI": "python",
    "npm": "javascript",
    "Maven": "java",
    "Packagist": "php",
    "crates.io": "rust",
    "Go": "go",
    "NuGet": "csharp",
    "RubyGems": "ruby",
    "Hex": "elixir",
    "Pub": "dart",
    "SwiftURL": "swift",
    "CocoaPods": "swift",
    "Hackage": "haskell",
    "CRAN": "r",
    "GHC": "haskell",
}


class OSVEnricher:
    """Enriches CVETask instances with advisory data from osv.dev.

    Queries the OSV REST API by CVE ID and populates affected versions,
    fix versions, fix commit URLs, advisory URLs, and the primary OSV/GHSA
    identifier. Zero LLM token cost — runs before any model calls.
    """

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        base_url: str = "https://api.osv.dev/v1",
    ) -> None:
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")

    async def enrich(self, task: CVETask) -> bool:
        """Fetch OSV data for a single CVE and mutate the task in-place.

        Args:
            task: CVE task to enrich with advisory data.

        Returns:
            True if enrichment succeeded, False on any error (404, timeout, etc.).
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await self._enrich_one(client, task)

    async def _enrich_one(self, client: httpx.AsyncClient, task: CVETask) -> bool:
        """Fetch and apply OSV data for a single task.

        Returns True on success, False on any failure.
        """
        url = f"{self._base_url}/vulns/{task.cve_id}"

        try:
            response = await client.get(url)
        except httpx.TimeoutException:
            logger.warning("OSV request timed out for %s", task.cve_id)
            return False
        except httpx.HTTPError as exc:
            logger.warning("OSV request failed for %s: %s", task.cve_id, exc)
            return False

        if response.status_code == 404:
            logger.debug("No OSV record for %s", task.cve_id)
            return False

        if response.status_code != 200:
            logger.warning(
                "OSV returned status %d for %s",
                response.status_code,
                task.cve_id,
            )
            return False

        try:
            data = response.json()
        except ValueError:
            logger.warning("Invalid JSON from OSV for %s", task.cve_id)
            return False

        self._apply(task, data)
        logger.debug("Enriched %s from OSV (osv_id=%s)", task.cve_id, task.osv_id)
        return True

    def _apply(self, task: CVETask, data: dict[str, Any]) -> None:
        """Apply parsed OSV data to the CVETask fields."""
        affected = data.get("affected", [])
        references = data.get("references", [])

        task.osv_id = self._extract_osv_id(data)
        task.affected_versions = self._extract_affected_versions(affected)
        task.fix_versions = self._extract_fix_versions(affected)
        task.fix_commit_url = self._extract_fix_commit_url(references)
        task.advisory_urls = self._extract_advisory_urls(references)
        task.advisory_summary = data.get("summary", "")

        # Extract ecosystem and package name for technology identification
        eco, pkg = self._extract_ecosystem_and_package(affected)
        if eco:
            lang = _ECOSYSTEM_TO_LANGUAGE.get(eco, "")
            if lang and not task.language:
                task.language = lang
                logger.debug("OSV ecosystem %s → language=%s for %s", eco, lang, task.cve_id)
        if pkg and not task.vulnerable_package:
            task.vulnerable_package = pkg

    @staticmethod
    def _extract_ecosystem_and_package(
        affected: list[dict[str, Any]],
    ) -> tuple[str, str]:
        """Extract the first ecosystem and package name from OSV affected data.

        Returns:
            (ecosystem, package_name) tuple; either may be empty string.
        """
        for entry in affected:
            package = entry.get("package", {})
            ecosystem = package.get("ecosystem", "")
            name = package.get("name", "")
            if ecosystem or name:
                return ecosystem, name
        return "", ""

    @staticmethod
    def _extract_osv_id(vuln_data: dict[str, Any]) -> str | None:
        """Extract the primary OSV/GHSA identifier.

        Args:
            vuln_data: Full OSV vulnerability record.

        Returns:
            GHSA ID if found in aliases, otherwise the top-level ``id``, or None.
        """
        aliases: list[str] = vuln_data.get("aliases", [])
        for alias in aliases:
            if alias.startswith("GHSA-"):
                return alias

        primary_id: str = vuln_data.get("id", "")
        if primary_id.startswith("GHSA-"):
            return primary_id

        return primary_id or None

    @staticmethod
    def _extract_affected_versions(
        affected: list[dict[str, Any]],
    ) -> list[str]:
        """Parse version ranges into human-readable constraint strings.

        Iterates ``affected[].ranges[].events[]`` and pairs ``introduced``
        with ``fixed`` or ``last_affected`` markers to produce strings like
        ``>=1.0.0,<1.4.3``.

        Args:
            affected: The ``affected`` array from an OSV record.

        Returns:
            Deduplicated list of version range strings.
        """
        ranges: list[str] = []

        for entry in affected:
            for range_obj in entry.get("ranges", []):
                ranges.extend(_parse_range_events(range_obj.get("events", [])))

            explicit = entry.get("versions", [])
            if explicit:
                ranges.extend(explicit)

        return _dedupe(ranges)

    @staticmethod
    def _extract_fix_versions(
        affected: list[dict[str, Any]],
    ) -> list[str]:
        """Extract fixed versions from range events.

        Args:
            affected: The ``affected`` array from an OSV record.

        Returns:
            Deduplicated list of fix version strings.
        """
        fixes: list[str] = []

        for entry in affected:
            for range_obj in entry.get("ranges", []):
                for event in range_obj.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        fixes.append(fixed)

        return _dedupe(fixes)

    @staticmethod
    def _extract_fix_commit_url(
        references: list[dict[str, str]],
    ) -> str | None:
        """Find the best fix commit URL from references.

        Prefers GitHub commit URLs among ``FIX`` type references.

        Args:
            references: The ``references`` array from an OSV record.

        Returns:
            Fix commit URL, or None if not found.
        """
        fix_urls: list[str] = []

        for ref in references:
            if ref.get("type") == "FIX":
                url = ref.get("url", "")
                if url:
                    fix_urls.append(url)

        if not fix_urls:
            return None

        for url in fix_urls:
            if "github.com" in url and "/commit/" in url:
                return url

        return fix_urls[0]

    @staticmethod
    def _extract_advisory_urls(
        references: list[dict[str, str]],
    ) -> list[str]:
        """Extract advisory URLs from references.

        Args:
            references: The ``references`` array from an OSV record.

        Returns:
            List of advisory URLs (ADVISORY and WEB types).
        """
        urls: list[str] = []

        for ref in references:
            ref_type = ref.get("type", "")
            if ref_type in ("ADVISORY", "WEB"):
                url = ref.get("url", "")
                if url:
                    urls.append(url)

        return _dedupe(urls)


def _parse_range_events(events: list[dict[str, str]]) -> list[str]:
    """Convert a list of OSV range events into version constraint strings.

    Events come in sequential pairs: an ``introduced`` event followed by a
    ``fixed`` or ``last_affected`` event. Each pair is translated into a
    constraint string:

    - ``introduced=0`` + ``fixed=1.4.3`` → ``<1.4.3``
    - ``introduced=1.0`` + ``fixed=1.4.3`` → ``>=1.0,<1.4.3``
    - ``introduced=1.0`` + ``last_affected=1.3.9`` → ``>=1.0,<=1.3.9``
    - ``introduced=1.0`` with no closing event → ``>=1.0``
    """
    constraints: list[str] = []
    pending_introduced: str | None = None

    for event in events:
        if "introduced" in event:
            if pending_introduced is not None:
                constraints.append(_format_introduced(pending_introduced))
            pending_introduced = event["introduced"]

        elif "fixed" in event:
            fixed = event["fixed"]
            if pending_introduced is not None:
                constraints.append(_format_range(pending_introduced, fixed, exclusive=True))
                pending_introduced = None
            else:
                constraints.append(f"<{fixed}")

        elif "last_affected" in event:
            last = event["last_affected"]
            if pending_introduced is not None:
                constraints.append(_format_range(pending_introduced, last, exclusive=False))
                pending_introduced = None
            else:
                constraints.append(f"<={last}")

    if pending_introduced is not None:
        constraints.append(_format_introduced(pending_introduced))

    return constraints


def _format_introduced(version: str) -> str:
    """Format a lone introduced marker as a lower-bound constraint."""
    if version == "0":
        return ">=0"
    return f">={version}"


def _format_range(introduced: str, upper: str, *, exclusive: bool) -> str:
    """Format a version range from introduced to upper bound.

    Args:
        introduced: Lower bound version.
        upper: Upper bound version.
        exclusive: True for ``<upper`` (fixed), False for ``<=upper`` (last_affected).
    """
    op = "<" if exclusive else "<="

    if introduced == "0":
        return f"{op}{upper}"

    return f">={introduced},{op}{upper}"


def _dedupe(items: list[str]) -> list[str]:
    """Return deduplicated list preserving insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
