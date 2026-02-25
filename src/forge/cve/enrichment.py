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

import json
import logging
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path("data/cache")
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BATCH_SIZE = 30
NVD_TIMEOUT = 15.0
EPSS_TIMEOUT = 15.0


class EnrichmentCache:
    """JSON file cache for EPSS and CVSS scores."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._epss_path = self._cache_dir / "epss.json"
        self._cvss_path = self._cache_dir / "cvss.json"
        self._epss: dict[str, float] = self._load(self._epss_path)
        self._cvss: dict[str, float] = self._load(self._cvss_path)

    @staticmethod
    def _load(path: Path) -> dict[str, float]:
        """Load a JSON cache file, returning empty dict if missing."""
        if path.exists():
            return dict(json.loads(path.read_text()))
        return {}

    def _save_epss(self) -> None:
        self._epss_path.write_text(json.dumps(self._epss, indent=2))

    def _save_cvss(self) -> None:
        self._cvss_path.write_text(json.dumps(self._cvss, indent=2))

    def get_epss(self, cve_id: str) -> float | None:
        """Get cached EPSS score for a CVE."""
        return self._epss.get(cve_id)

    def get_cvss(self, cve_id: str) -> float | None:
        """Get cached CVSS score for a CVE."""
        return self._cvss.get(cve_id)

    def put_epss_batch(self, scores: dict[str, float]) -> None:
        """Cache multiple EPSS scores and persist to disk."""
        self._epss.update(scores)
        self._save_epss()

    def put_cvss(self, cve_id: str, score: float) -> None:
        """Cache a CVSS score and persist to disk."""
        self._cvss[cve_id] = score
        self._save_cvss()


async def fetch_epss_batch(
    cve_ids: list[str],
    *,
    timeout: float = EPSS_TIMEOUT,
) -> dict[str, float]:
    """Fetch EPSS scores for multiple CVEs from the FIRST API.

    Args:
        cve_ids: List of CVE identifiers.
        timeout: HTTP request timeout in seconds.

    Returns:
        Mapping of CVE ID to EPSS probability score.
    """
    if not cve_ids:
        return {}

    results: dict[str, float] = {}
    async with httpx.AsyncClient(timeout=timeout) as client:
        for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
            batch = cve_ids[i : i + EPSS_BATCH_SIZE]
            cve_param = ",".join(batch)
            try:
                response = await client.get(EPSS_API_URL, params={"cve": cve_param})
                response.raise_for_status()
                data = response.json()
                for entry in data.get("data", []):
                    results[entry["cve"]] = float(entry["epss"])
            except httpx.HTTPError:
                logger.warning("EPSS batch fetch failed for %d CVEs, skipping", len(batch))

    logger.info("Fetched EPSS scores for %d / %d CVEs", len(results), len(cve_ids))
    return results


async def fetch_cvss(
    cve_id: str,
    *,
    timeout: float = NVD_TIMEOUT,
    api_key: str | None = None,
) -> float | None:
    """Fetch CVSS v3.1 Base Score from the NVD API.

    Args:
        cve_id: CVE identifier.
        timeout: HTTP request timeout in seconds.
        api_key: Optional NVD API key for higher rate limits.

    Returns:
        CVSS v3.1 Base Score, or None if unavailable.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        try:
            response = await client.get(NVD_API_URL, params={"cveId": cve_id})
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError:
            logger.warning("NVD fetch failed for %s", cve_id)
            return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            return float(metric_list[0]["cvssData"]["baseScore"])

    return None


async def enrich_scores(
    cve_ids: list[str],
    cache: EnrichmentCache,
    *,
    nvd_api_key: str | None = None,
) -> dict[str, tuple[float | None, float | None]]:
    """Enrich CVEs with EPSS and CVSS scores, using cache where available.

    Args:
        cve_ids: List of CVE identifiers to enrich.
        cache: Cache instance for reading/writing scores.
        nvd_api_key: Optional NVD API key.

    Returns:
        Mapping of CVE ID to (epss_score, cvss_score) tuples.
    """
    results: dict[str, tuple[float | None, float | None]] = {}
    epss_missing: list[str] = []
    cvss_missing: list[str] = []

    for cve_id in cve_ids:
        epss = cache.get_epss(cve_id)
        cvss = cache.get_cvss(cve_id)
        results[cve_id] = (epss, cvss)
        if epss is None:
            epss_missing.append(cve_id)
        if cvss is None:
            cvss_missing.append(cve_id)

    if epss_missing:
        fetched = await fetch_epss_batch(epss_missing)
        cache.put_epss_batch(fetched)
        for cve_id, score in fetched.items():
            existing_cvss = results[cve_id][1]
            results[cve_id] = (score, existing_cvss)

    for cve_id in cvss_missing:
        cvss_score = await fetch_cvss(cve_id, api_key=nvd_api_key)
        if cvss_score is not None:
            cache.put_cvss(cve_id, cvss_score)
            existing_epss = results[cve_id][0]
            results[cve_id] = (existing_epss, cvss_score)

    cached_count = len(cve_ids) - len(epss_missing)
    logger.info(
        "Enrichment complete: %d CVEs (%d EPSS cached, %d CVSS cached)",
        len(cve_ids),
        cached_count,
        len(cve_ids) - len(cvss_missing),
    )
    return results
