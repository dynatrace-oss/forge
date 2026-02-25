#!/usr/bin/env python3
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
import sys
import time
from collections import Counter
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from forge2.cve.enricher import ScoreEnricher
from forge2.cve.loader import CVEGENIELoader, languages_from_patches
from forge2.cve.selector import DiversitySelector
from forge2.models import CVESource

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("curate")

DATA_PATH = ROOT / "data" / "CVE Genie Data.json"
OUTPUT_PATH = ROOT / "data" / "test" / "evaluation_cves.json"
CACHE_DIR = ROOT / "data" / "cache"
COUNT = 600
SEED = 42


def main() -> None:
    logger.info("Loading CVE-GENIE data from %s", DATA_PATH)
    loader = CVEGENIELoader(DATA_PATH)
    pool = loader.load_web_suitable()
    logger.info("Pool: %d web-suitable CVEs", len(pool))

    selector = DiversitySelector(seed=SEED)
    selected = selector.select(pool, count=COUNT)
    logger.info("Selected %d CVEs (seed=%d)", len(selected), SEED)

    cve_ids = [cve.cve_id for cve in selected]
    enricher = ScoreEnricher(cache_dir=CACHE_DIR)

    logger.info("Fetching EPSS scores...")
    t0 = time.monotonic()
    epss = enricher.enrich_epss(cve_ids)
    logger.info("EPSS: %d/%d scored (%.1fs)", len(epss), len(cve_ids), time.monotonic() - t0)

    logger.info("Fetching CVSS scores (this may take a while)...")
    t0 = time.monotonic()
    cvss = enricher.enrich_cvss(cve_ids)
    logger.info("CVSS: %d/%d scored (%.1fs)", len(cvss), len(cve_ids), time.monotonic() - t0)

    print("\n" + "=" * 60)
    print("DATA COMPLETENESS VALIDATION")
    print("=" * 60)
    validate_completeness(selected, epss, cvss)

    print("\n" + "=" * 60)
    print("DIVERSITY REPORT")
    print("=" * 60)
    generate_diversity_report(selected, epss, cvss)

    save_evaluation_cves(selected, epss, cvss)
    logger.info("Done. Artifacts saved.")


def validate_completeness(
    selected: list[CVESource],
    epss: dict[str, float],
    cvss: dict[str, float],
) -> None:
    """Check data completeness for all selected CVEs."""
    total = len(selected)

    # Description present
    has_desc = sum(1 for c in selected if c.description.strip())
    print(f"\nDescription present:       {has_desc}/{total} ({100 * has_desc / total:.1f}%)")

    # CWE tags present
    has_cwe = sum(1 for c in selected if c.cwes)
    print(f"CWE tags present:          {has_cwe}/{total} ({100 * has_cwe / total:.1f}%)")

    # Patch commits with diffs
    has_patches = sum(1 for c in selected if c.patch_commits)
    has_diffs = sum(
        1
        for c in selected
        if any(p.diff_content and p.diff_content.strip() for p in c.patch_commits)
    )
    print(f"Patch commits present:     {has_patches}/{total} ({100 * has_patches / total:.1f}%)")
    print(f"Patch diffs present:       {has_diffs}/{total} ({100 * has_diffs / total:.1f}%)")

    # Security advisories
    has_advisories = sum(1 for c in selected if c.security_advisories)
    print(
        f"Security advisories:       {has_advisories}/{total} ({100 * has_advisories / total:.1f}%)"
    )

    # EPSS/CVSS coverage
    has_epss = sum(1 for c in selected if c.cve_id in epss)
    has_cvss = sum(1 for c in selected if c.cve_id in cvss)
    print(f"EPSS scores:               {has_epss}/{total} ({100 * has_epss / total:.1f}%)")
    print(f"CVSS scores:               {has_cvss}/{total} ({100 * has_cvss / total:.1f}%)")

    # CVE-GENIE success (already reproduced)
    has_success = sum(1 for c in selected if c.successful)
    print(f"CVE-GENIE reproduced:      {has_success}/{total} ({100 * has_success / total:.1f}%)")

    # Report gaps
    missing_desc = [c.cve_id for c in selected if not c.description.strip()]
    missing_diffs = [
        c.cve_id
        for c in selected
        if not any(p.diff_content and p.diff_content.strip() for p in c.patch_commits)
    ]
    missing_adv = [c.cve_id for c in selected if not c.security_advisories]

    if missing_desc:
        tail = "..." if len(missing_desc) > 10 else ""
        print(f"\n  Missing descriptions: {missing_desc[:10]}{tail}")
    if missing_diffs:
        tail = "..." if len(missing_diffs) > 10 else ""
        print(f"  Missing diffs ({len(missing_diffs)}): {missing_diffs[:10]}{tail}")
    if missing_adv:
        print(f"  Missing advisories ({len(missing_adv)}): first 5 = {missing_adv[:5]}")


def generate_diversity_report(
    selected: list[CVESource],
    epss: dict[str, float],
    cvss: dict[str, float],
) -> None:
    """Produce a diversity summary showing distributions."""
    total = len(selected)

    # ---- CWE distribution (top 25) ----
    cwe_counts: Counter[str] = Counter()
    for c in selected:
        for cwe in c.cwes:
            cwe_counts[cwe.id] += 1

    print(f"\nCWE Distribution (top 25 of {len(cwe_counts)} unique CWEs):")
    print(f"  {'CWE':<12} {'Count':>5}  {'%':>5}  Name")
    print(f"  {'---':<12} {'-----':>5}  {'---':>5}  ----")
    for cwe_id, count in cwe_counts.most_common(25):
        # Find the name from the first entry that has this CWE
        name = ""
        for c in selected:
            for cwe in c.cwes:
                if cwe.id == cwe_id:
                    name = cwe.value[:40]
                    break
            if name:
                break
        print(f"  {cwe_id:<12} {count:>5}  {100 * count / total:>5.1f}  {name}")

    # ---- Language distribution ----
    lang_counts: Counter[str] = Counter()
    for c in selected:
        langs = languages_from_patches(c.patch_commits)
        for lang in langs:
            lang_counts[lang] += 1

    print(f"\nLanguage Distribution ({len(lang_counts)} languages):")
    for lang, count in lang_counts.most_common():
        print(f"  {lang:<15} {count:>4} CVEs ({100 * count / total:>5.1f}%)")

    # ---- CVE-GENIE success ----
    has_success = sum(1 for c in selected if c.successful)
    print("\nCVE-GENIE Reproduction:")
    print(f"  Reproduced: {has_success}/{total} ({100 * has_success / total:.1f}%)")
    print(f"  Not yet:    {total - has_success}/{total}")

    # ---- EPSS coverage ----
    has_epss = sum(1 for c in selected if c.cve_id in epss)
    epss_vals = [epss[c.cve_id] for c in selected if c.cve_id in epss]
    print("\nEPSS Coverage:")
    print(f"  Scored: {has_epss}/{total} ({100 * has_epss / total:.1f}%)")
    if epss_vals:
        print(f"  Mean:   {sum(epss_vals) / len(epss_vals):.4f}")
        print(f"  Min:    {min(epss_vals):.4f}")
        print(f"  Max:    {max(epss_vals):.4f}")

    # ---- CVSS coverage ----
    has_cvss = sum(1 for c in selected if c.cve_id in cvss)
    cvss_vals = [cvss[c.cve_id] for c in selected if c.cve_id in cvss]
    print("\nCVSS Coverage:")
    print(f"  Scored: {has_cvss}/{total} ({100 * has_cvss / total:.1f}%)")
    if cvss_vals:
        print(f"  Mean:   {sum(cvss_vals) / len(cvss_vals):.1f}")
        print(f"  Min:    {min(cvss_vals):.1f}")
        print(f"  Max:    {max(cvss_vals):.1f}")

        # CVSS severity distribution
        low = sum(1 for v in cvss_vals if v < 4.0)
        med = sum(1 for v in cvss_vals if 4.0 <= v < 7.0)
        high = sum(1 for v in cvss_vals if 7.0 <= v < 9.0)
        crit = sum(1 for v in cvss_vals if v >= 9.0)
        print(f"  Low (0-3.9):      {low:>4}")
        print(f"  Medium (4-6.9):   {med:>4}")
        print(f"  High (7-8.9):     {high:>4}")
        print(f"  Critical (9-10):  {crit:>4}")


def save_evaluation_cves(
    selected: list[CVESource],
    epss: dict[str, float],
    cvss: dict[str, float],
) -> None:
    """Save selected CVEs with metadata to evaluation_cves.json."""
    entries = []
    for cve in selected:
        entry: dict[str, object] = {
            "cve_id": cve.cve_id,
            "cwes": [{"id": c.id, "value": c.value} for c in cve.cwes],
            "description_length": len(cve.description),
            "patch_commits": len(cve.patch_commits),
            "has_diffs": any(p.diff_content and p.diff_content.strip() for p in cve.patch_commits),
            "security_advisories": len(cve.security_advisories),
            "cve_genie_reproduced": cve.successful,
        }
        if cve.cve_id in epss:
            entry["epss_score"] = epss[cve.cve_id]
        if cve.cve_id in cvss:
            entry["cvss_score"] = cvss[cve.cve_id]
        entries.append(entry)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    logger.info("Saved %d CVEs to %s", len(entries), OUTPUT_PATH)


if __name__ == "__main__":
    main()
