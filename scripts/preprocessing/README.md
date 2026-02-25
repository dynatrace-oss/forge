# FORGE Preprocessing Scripts

One-time data preparation scripts that run **before** evaluation. These scripts
build the evaluation dataset, CWE enrichment data, and technology mapping used
at runtime by the FORGE pipeline.

## Quick Reference

| Script | Purpose | When to use |
|--------|---------|-------------|
| `curate_dataset.py` | Build evaluation CVE dataset from CVE-GENIE | One-time — before first evaluation run |
| `generate_cwe_enrichment.py` | Generate CWE enrichment JSON from MITRE data | One-time — or when CWE/CAPEC data updates |
| `generate_technology_map.py` | Build CPE → technology mapping from NVD/OSV | One-time — or when adding new CVEs to dataset |

## Usage

### Dataset Curation

Loads CVE-GENIE data, runs diversity selection across languages/CWE types,
enriches with EPSS/CVSS scores, and saves the curated 600-CVE evaluation dataset.

```bash
uv run python scripts/preprocessing/curate_dataset.py
```

**Input:** `data/CVE Genie Data.json`
**Output:** `data/test/evaluation_cves.json`

### CWE Enrichment

Downloads MITRE CWE (view 1000) and CAPEC (view 2000) CSV data, parses them,
and produces a complete CWE enrichment JSON with names, techniques,
oracle criteria, exploit strategies, and failure modes.

```bash
python scripts/preprocessing/generate_cwe_enrichment.py          # download + generate
python scripts/preprocessing/generate_cwe_enrichment.py --offline # use cached CSVs only
```

**Output:** `data/cache/cwe/cwe_enrichment.json`
**Consumed by:** `forge2.intel.compiler` (CWE-conditioned prompt injection)

### Technology Mapping

Fetches NVD CPE configurations and OSV affected-package metadata, then builds
a lookup table mapping `vendor:product` keys to `{language, framework, ecosystem}`.

```bash
python scripts/preprocessing/generate_technology_map.py          # fetch + generate
python scripts/preprocessing/generate_technology_map.py --offline # use cached data only
```

**Input:** `data/test/evaluation_cves.json` (the curated dataset)
**Output:** `data/cache/technology_map.json`
**Consumed by:** `forge2.intel.compiler._infer_tech_from_cpe()` (high-confidence CPE lookup)

## Notes

- These scripts require network access for downloading MITRE/NVD/OSV data (use `--offline` to skip)
- NVD API rate limit: 5 requests/30s without API key (scripts include delay handling)
- All outputs are cached and re-runnable — subsequent runs overwrite previous output
- The curate script requires `forge2` package imports (run with `uv run`)
