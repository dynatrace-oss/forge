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
import time
from pathlib import Path
from typing import Any

import httpx

from forge.models import TechniqueMapping

logger = logging.getLogger(__name__)

_EPSS_API = "https://api.first.org/data/v1/epss"
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_BATCH_SIZE = 30  # EPSS API supports batch queries
_REQUEST_TIMEOUT = 30.0
_NVD_DELAY = 6.5  # seconds between NVD requests (rate limit: ~5 per 30s)
_NVD_MAX_RETRIES = 4  # retry count for 429/5xx errors
_NVD_SAVE_INTERVAL = 10  # save cache every N successful fetches


class ScoreEnricher:
    """Fetch and cache EPSS / CVSS scores for CVE identifiers.

    Cache files are simple ``{cve_id: score}`` JSON dicts, matching the
    existing layout in ``data/cache/epss.json`` and ``data/cache/cvss.json``.
    """

    def __init__(self, cache_dir: Path) -> None:
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def enrich_epss(self, cve_ids: list[str]) -> dict[str, float]:
        """Return EPSS scores, fetching missing ones from api.first.org."""
        cache_path = self._cache_dir / "epss.json"
        cache = _load_cache(cache_path)

        missing = [c for c in cve_ids if c not in cache]
        if missing:
            logger.info("Fetching EPSS scores for %d CVEs", len(missing))
            fetched = self._fetch_epss_batch(missing)
            cache.update(fetched)
            _save_cache(cache_path, cache)

        return {c: cache[c] for c in cve_ids if c in cache}

    @staticmethod
    def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
        results: dict[str, float] = {}
        for i in range(0, len(cve_ids), _BATCH_SIZE):
            batch = cve_ids[i : i + _BATCH_SIZE]
            params = {"cve": ",".join(batch)}
            try:
                with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
                    resp = client.get(_EPSS_API, params=params)
                    resp.raise_for_status()
                data = resp.json().get("data", [])
                for item in data:
                    results[item["cve"]] = float(item["epss"])
            except httpx.HTTPError:
                logger.warning(
                    "EPSS fetch failed for batch starting at %d",
                    i,
                    exc_info=True,
                )
        return results

    def enrich_cvss(self, cve_ids: list[str]) -> dict[str, float]:
        """Return CVSS v3.1 base scores, fetching missing ones from NVD.

        Uses incremental cache saves so progress persists even if the
        process is interrupted during the long NVD fetch.
        """
        cache_path = self._cache_dir / "cvss.json"
        cache = _load_cache(cache_path)

        missing = [c for c in cve_ids if c not in cache]
        if missing:
            logger.info("Fetching CVSS scores for %d CVEs", len(missing))
            fetched = _fetch_cvss_with_backoff(missing, cache, cache_path)
            cache.update(fetched)
            _save_cache(cache_path, cache)

        return {c: cache[c] for c in cve_ids if c in cache}


def _fetch_cvss_with_backoff(
    cve_ids: list[str],
    cache: dict[str, float],
    cache_path: Path,
) -> dict[str, float]:
    """Fetch CVSS scores one-by-one with NVD rate limiting and retry.

    The NVD API allows ~5 requests per 30 seconds without an API key.
    This function sleeps between requests and retries on 429/5xx with
    exponential backoff.  Cache is saved incrementally so progress
    persists across interruptions.
    """
    results: dict[str, float] = {}
    total = len(cve_ids)
    fetched_since_save = 0

    with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
        for idx, cve_id in enumerate(cve_ids):
            if idx > 0:
                time.sleep(_NVD_DELAY)

            score = _nvd_single_fetch(client, cve_id)
            if score is not None:
                results[cve_id] = score
                cache[cve_id] = score
                fetched_since_save += 1

            if fetched_since_save >= _NVD_SAVE_INTERVAL:
                _save_cache(cache_path, cache)
                fetched_since_save = 0

            if (idx + 1) % 25 == 0 or idx == total - 1:
                logger.info(
                    "CVSS progress: %d/%d fetched, %d scored",
                    idx + 1,
                    total,
                    len(results),
                )

    return results


def _nvd_single_fetch(client: httpx.Client, cve_id: str) -> float | None:
    """Fetch a single CVSS score with retry on 429 / server errors."""
    for attempt in range(_NVD_MAX_RETRIES):
        try:
            resp = client.get(_NVD_API, params={"cveId": cve_id})
            if resp.status_code == 429:  # noqa: PLR2004
                wait = 2 ** (attempt + 2)  # 4, 8, 16, 32 seconds
                logger.warning(
                    "NVD 429 for %s — retrying in %ds (attempt %d/%d)",
                    cve_id,
                    wait,
                    attempt + 1,
                    _NVD_MAX_RETRIES,
                )
                time.sleep(wait)
                continue
            resp.raise_for_status()

            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                return None
            metrics = vulns[0].get("cve", {}).get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                entries = metrics.get(key, [])
                if entries:
                    return float(entries[0]["cvssData"]["baseScore"])
            return None  # no CVSS v3 data present

        except httpx.HTTPStatusError as exc:
            if exc.response.status_code >= 500:  # noqa: PLR2004
                wait = 2 ** (attempt + 1)
                logger.warning(
                    "NVD %d for %s — retrying in %ds",
                    exc.response.status_code,
                    cve_id,
                    wait,
                )
                time.sleep(wait)
                continue
            logger.warning("CVSS fetch failed for %s", cve_id, exc_info=True)
            return None
        except httpx.HTTPError:
            logger.warning("CVSS fetch failed for %s", cve_id, exc_info=True)
            return None

    logger.warning("CVSS fetch exhausted retries for %s", cve_id)
    return None


def _load_cache(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    data: dict[str, float] = json.loads(text)
    return data


def _save_cache(path: Path, data: dict[str, float]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# Default location for the pre-built CWE enrichment knowledge base.
_DEFAULT_CWE_KB_PATH = Path("data/cache/cwe/cwe_enrichment.json")


class CWEEnricher:
    """Map CWE IDs to CAPEC attack patterns, ATT&CK techniques, oracle
    criteria, exploit strategies, and failure modes.

    Loads from a JSON knowledge base (``data/cache/cwe/cwe_enrichment.json``
    by default).  The KB ships with curated mappings for the top-25 web-app
    CWEs found in the CVE-GENIE dataset.  Unknown CWEs degrade gracefully to
    empty lists.
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = cache_dir or _DEFAULT_CWE_KB_PATH.parent
        self._kb_path = self._cache_dir / "cwe_enrichment.json"
        self._kb: dict[str, Any] | None = None

    def get_techniques(self, cwe_id: str) -> list[TechniqueMapping]:
        """Return CAPEC + ATT&CK technique mappings for *cwe_id*."""
        entry = self._lookup(cwe_id)
        if entry is None:
            return []
        return [TechniqueMapping(**t) for t in entry.get("techniques", [])]

    def get_cwe_name(self, cwe_id: str) -> str:
        """Return human-readable CWE name, or empty string if unknown."""
        entry = self._lookup(cwe_id)
        if entry is None:
            return ""
        name: str = entry.get("name", "")
        return name

    def _lookup(self, cwe_id: str) -> dict[str, Any] | None:
        """Look up a CWE entry from the knowledge base."""
        kb = self._load_kb()
        return kb.get(cwe_id)

    def _load_kb(self) -> dict[str, Any]:
        """Load the knowledge base JSON, caching in memory."""
        if self._kb is not None:
            return self._kb

        if not self._kb_path.exists():
            logger.warning(
                "CWE enrichment KB not found at %s — CWE enrichment disabled",
                self._kb_path,
            )
            self._kb = {}
            return self._kb

        raw = json.loads(self._kb_path.read_text(encoding="utf-8"))
        # Strip metadata key
        self._kb = {k: v for k, v in raw.items() if not k.startswith("_")}
        logger.info(
            "Loaded CWE enrichment KB with %d entries from %s",
            len(self._kb),
            self._kb_path,
        )
        return self._kb
