#!/usr/bin/env python3
# Copyright 2025 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_OUTPUT_PATH = _PROJECT_ROOT / "data" / "cache" / "technology_map.json"
_EVAL_CVES_PATH = _PROJECT_ROOT / "data" / "test" / "evaluation_cves.json"
_NVD_CACHE_DIR = _PROJECT_ROOT / "data" / "cache" / "nvd_cpe"
_OSV_CACHE_DIR = _PROJECT_ROOT / "data" / "cache" / "osv_tech"

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_API_URL = "https://api.osv.dev/v1/vulns"
_REQUEST_TIMEOUT = 30.0

# Rate limiting: NVD allows 5 requests/30s without API key
_NVD_DELAY = 6.5  # seconds between NVD requests

# Standard OSV ecosystem → language mapping
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


def _fetch_nvd_cpe(cve_id: str, client: httpx.Client, cache_dir: Path) -> list[dict[str, str]]:
    """Fetch CPE entries for a single CVE from NVD, with disk caching."""
    cache_file = cache_dir / f"{cve_id}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())  # type: ignore[no-any-return]
        except (ValueError, OSError):
            pass

    try:
        resp = client.get(_NVD_API_URL, params={"cveId": cve_id})
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return []

    entries = _extract_cpe_from_nvd(data)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(entries, indent=2))
    return entries


def _extract_cpe_from_nvd(raw: dict[str, Any]) -> list[dict[str, str]]:
    """Extract CPE vendor:product:version from NVD configurations."""
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    vulns = raw.get("vulnerabilities", [])
    if not vulns:
        return entries

    cve_data = vulns[0].get("cve", {})
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                cpe_uri = match.get("criteria", "")
                parts = cpe_uri.split(":")
                if len(parts) < 6:
                    continue
                vendor, product = parts[3], parts[4]
                if vendor == "*" or product == "*":
                    continue
                key = (vendor, product)
                if key in seen:
                    continue
                seen.add(key)
                entries.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "version": parts[5] if len(parts) > 5 else "*",
                    }
                )
    return entries


def _fetch_osv_tech(cve_id: str, client: httpx.Client, cache_dir: Path) -> tuple[str, str]:
    """Fetch ecosystem and package name from OSV for a CVE."""
    cache_file = cache_dir / f"{cve_id}.json"
    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text())
            return cached.get("ecosystem", ""), cached.get("package", "")
        except (ValueError, OSError):
            pass

    try:
        resp = client.get(f"{_OSV_API_URL}/{cve_id}")
        if resp.status_code == 404:
            # CVE not in OSV
            result = {"ecosystem": "", "package": ""}
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(result))
            return "", ""
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OSV fetch failed for %s: %s", cve_id, exc)
        return "", ""

    ecosystem = ""
    package = ""
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem"):
            ecosystem = pkg["ecosystem"]
            package = pkg.get("name", "")
            break

    result = {"ecosystem": ecosystem, "package": package}
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(result))
    return ecosystem, package


def _load_cve_ids() -> list[str]:
    """Load CVE IDs from the evaluation dataset or config files."""
    # Try evaluation_cves.json first (600-CVE dataset)
    if _EVAL_CVES_PATH.exists():
        data = json.loads(_EVAL_CVES_PATH.read_text())
        return [entry["cve_id"] for entry in data]

    # Fall back to validation and amortization test files
    cve_ids: list[str] = []
    for txt_file in (_PROJECT_ROOT / "data" / "config").glob("*.txt"):
        for line in txt_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("CVE-"):
                cve_ids.append(line)
    return list(dict.fromkeys(cve_ids))  # deduplicate, preserve order


def build_technology_map(cve_ids: list[str], *, offline: bool = False) -> dict[str, Any]:
    """Build the technology map from NVD CPE + OSV ecosystem data."""
    tech_map: dict[str, dict[str, str]] = {}
    stats = {"total_cves": len(cve_ids), "cpe_hits": 0, "osv_hits": 0, "mapped": 0}

    with httpx.Client(timeout=_REQUEST_TIMEOUT, follow_redirects=True) as client:
        for i, cve_id in enumerate(cve_ids):
            if (i + 1) % 50 == 0:
                logger.info("Processing %d/%d CVEs...", i + 1, len(cve_ids))

            # Fetch CPE entries
            if not offline or (_NVD_CACHE_DIR / f"{cve_id}.json").exists():
                cpe_entries = _fetch_nvd_cpe(cve_id, client, _NVD_CACHE_DIR)
                if cpe_entries:
                    stats["cpe_hits"] += 1

                # Rate limit NVD API (only for non-cached requests)
                if not (_NVD_CACHE_DIR / f"{cve_id}.json").exists():
                    time.sleep(_NVD_DELAY)
            else:
                cpe_entries = []

            # Fetch OSV ecosystem
            osv_eco, osv_pkg = "", ""
            if not offline or (_OSV_CACHE_DIR / f"{cve_id}.json").exists():
                osv_eco, osv_pkg = _fetch_osv_tech(cve_id, client, _OSV_CACHE_DIR)
                if osv_eco:
                    stats["osv_hits"] += 1

            # Build mapping for each CPE vendor:product
            for entry in cpe_entries:
                key = f"{entry['vendor']}:{entry['product']}"
                if key in tech_map:
                    continue

                language = _ECOSYSTEM_TO_LANGUAGE.get(osv_eco, "")
                framework = entry["product"]

                tech_map[key] = {
                    "language": language,
                    "framework": framework,
                    "ecosystem": osv_eco,
                    "package": osv_pkg,
                    "vendor": entry["vendor"],
                    "product": entry["product"],
                }
                stats["mapped"] += 1

    output: dict[str, Any] = {
        "_meta": {
            "version": 1,
            "source": "NVD CPE + OSV ecosystem",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "stats": stats,
        },
    }
    output.update(tech_map)
    return output


def main() -> None:
    """Download NVD/OSV data and generate technology map."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Use cached data only")
    parser.add_argument("--output", type=Path, default=_OUTPUT_PATH, help="Output JSON path")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")

    cve_ids = _load_cve_ids()
    if not cve_ids:
        logger.error("No CVE IDs found. Run curate_dataset.py first or add CVE lists.")
        return

    logger.info("Building technology map for %d CVEs", len(cve_ids))
    tech_map = build_technology_map(cve_ids, offline=args.offline)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(tech_map, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    meta = tech_map["_meta"]
    logger.info(
        "Wrote %d vendor:product mappings to %s (CPE hits: %d, OSV hits: %d)",
        meta["stats"]["mapped"],
        args.output,
        meta["stats"]["cpe_hits"],
        meta["stats"]["osv_hits"],
    )


if __name__ == "__main__":
    main()
