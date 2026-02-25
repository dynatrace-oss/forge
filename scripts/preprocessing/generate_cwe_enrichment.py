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
import csv
import io
import json
import logging
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_RAW_DIR = _PROJECT_ROOT / "data" / "cache" / "cwe" / "raw"
_OUTPUT_PATH = _PROJECT_ROOT / "data" / "cache" / "cwe" / "cwe_enrichment.json"

_CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
_CAPEC_CSV_URL = "https://capec.mitre.org/data/csv/2000.csv.zip"
_CWE_CSV_LOCAL = _RAW_DIR / "cwe_1000.csv"
_CAPEC_CSV_LOCAL = _RAW_DIR / "capec_2000.csv"

_REQUEST_TIMEOUT = 60.0


def _download_csv_zip(url: str, dest: Path) -> None:
    """Download a zip archive and extract the single CSV inside it."""
    logger.info("Downloading %s", url)
    with httpx.Client(timeout=_REQUEST_TIMEOUT, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
        if not csv_names:
            raise RuntimeError(f"No CSV found in {url}")
        data = zf.read(csv_names[0])

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    logger.info("Saved %s (%d bytes)", dest, len(data))


def ensure_csvs(*, offline: bool = False) -> tuple[Path, Path]:
    """Return paths to CWE and CAPEC CSVs, downloading if needed."""
    if not offline or not _CWE_CSV_LOCAL.exists():
        _download_csv_zip(_CWE_CSV_URL, _CWE_CSV_LOCAL)
    if not offline or not _CAPEC_CSV_LOCAL.exists():
        _download_csv_zip(_CAPEC_CSV_URL, _CAPEC_CSV_LOCAL)
    return _CWE_CSV_LOCAL, _CAPEC_CSV_LOCAL


# MITRE CSVs use :: as a record delimiter within fields.
_DELIMITED_RE = re.compile(r"::")


def _parse_delimited_records(raw: str) -> list[dict[str, str]]:
    """Parse ``::KEY:VAL::KEY:VAL::`` delimited records into dicts."""
    records: list[dict[str, str]] = []
    if not raw.strip():
        return records
    # Split top-level records on "::" followed by field marker
    tokens = _DELIMITED_RE.split(raw)
    current: dict[str, str] = {}
    for token in tokens:
        token = token.strip()
        if not token:
            if current:
                records.append(current)
                current = {}
            continue
        # Each token may be "KEY:VALUE"
        parts = token.split(":", 1)
        if len(parts) == 2:
            key, value = parts[0].strip(), parts[1].strip()
            if key:
                current[key] = value
    if current:
        records.append(current)
    return records


def _parse_consequence_field(raw: str) -> list[dict[str, str]]:
    """Parse Common Consequences field into structured list."""
    results: list[dict[str, str]] = []
    # Split on :: boundaries, grouping by SCOPE...IMPACT...NOTE patterns
    chunks = raw.split("::")
    current: dict[str, str] = {}
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            if current:
                results.append(current)
                current = {}
            continue
        if chunk.startswith("SCOPE:"):
            if "scope" in current and "impact" in current:
                results.append(current)
                current = {}
            scope_val = chunk[6:].strip()
            existing = current.get("scope", "")
            current["scope"] = f"{existing}, {scope_val}" if existing else scope_val
        elif chunk.startswith("IMPACT:"):
            current["impact"] = chunk[7:].strip()
        elif chunk.startswith("NOTE:"):
            current["note"] = chunk[5:].strip()
    if current:
        results.append(current)
    return results


def _parse_capec_ids(raw: str) -> list[str]:
    """Extract CAPEC IDs from Related Attack Patterns field."""
    return re.findall(r"(\d+)", raw)


def _parse_mitigations(raw: str) -> list[dict[str, str]]:
    """Parse Potential Mitigations into phase + strategy + description dicts.

    MITRE CSV encodes mitigations as ``::`` delimited records where each
    record contains ``KEY:VALUE`` pairs separated by ``:`` within the
    record.  Example single record::

        PHASE:Implementation:STRATEGY:Input Validation:DESCRIPTION:Use allow-lists...

    We split on ``::`` to get records, then extract known keys
    (PHASE, STRATEGY, DESCRIPTION) from each record by scanning for
    the key markers.
    """
    results: list[dict[str, str]] = []
    keys = ("PHASE", "STRATEGY", "DESCRIPTION")

    for chunk in raw.split("::"):
        chunk = chunk.strip()
        if not chunk:
            continue

        record: dict[str, str] = {}
        # Find positions of each known key marker within the chunk
        positions: list[tuple[int, str]] = []
        for key in keys:
            marker = f"{key}:"
            idx = chunk.find(marker)
            if idx >= 0:
                positions.append((idx, key))
        positions.sort()

        # Extract values between consecutive markers
        for i, (pos, key) in enumerate(positions):
            start = pos + len(key) + 1  # skip "KEY:"
            end = positions[i + 1][0] if i + 1 < len(positions) else len(chunk)
            val = chunk[start:end].rstrip(":").strip()
            if val:
                record[key.lower()] = val

        if record.get("description"):
            results.append(record)

    return results


def load_cwe_csv(path: Path) -> dict[str, dict[str, Any]]:
    """Load CWE Research Concepts CSV into a dict keyed by CWE-{id}."""
    result: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe_id_num = row.get("CWE-ID", "").strip()
            if not cwe_id_num:
                continue
            cwe_id = f"CWE-{cwe_id_num}"
            result[cwe_id] = {
                "id": cwe_id,
                "name": row.get("Name", "").strip(),
                "abstraction": row.get("Weakness Abstraction", "").strip(),
                "status": row.get("Status", "").strip(),
                "description": row.get("Description", "").strip(),
                "consequences": _parse_consequence_field(row.get("Common Consequences", "")),
                "capec_ids": _parse_capec_ids(row.get("Related Attack Patterns", "")),
                "mitigations": _parse_mitigations(row.get("Potential Mitigations", "")),
            }
    logger.info("Loaded %d CWE entries from %s", len(result), path)
    return result


def load_capec_csv(path: Path) -> dict[str, dict[str, Any]]:
    """Load CAPEC CSV into a dict keyed by CAPEC ID (numeric string)."""
    result: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # CAPEC CSV has a quirky "'ID" column name
            capec_id = row.get("'ID", row.get("ID", "")).strip()
            if not capec_id:
                continue
            # Parse ATT&CK techniques from Taxonomy Mappings
            tax_raw = row.get("Taxonomy Mappings", "")
            attack_entries = re.findall(
                r"TAXONOMY NAME:ATTACK:ENTRY ID:([^:]+):ENTRY NAME:([^:]+)",
                tax_raw,
            )
            # Parse related CWEs
            related_cwes_raw = row.get("Related Weaknesses", "")
            related_cwes = re.findall(r"(\d+)", related_cwes_raw)

            result[capec_id] = {
                "id": capec_id,
                "name": row.get("Name", "").strip(),
                "severity": row.get("Typical Severity", "").strip(),
                "attack_techniques": [
                    {"attack_id": f"T{tid.strip()}", "attack_name": tname.strip()}
                    for tid, tname in attack_entries
                ],
                "related_cwes": [f"CWE-{c}" for c in related_cwes],
            }
    logger.info("Loaded %d CAPEC entries from %s", len(result), path)
    return result


def build_technique_mappings(
    capec_ids: list[str],
    capec_db: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    """Build technique mapping list from CAPEC IDs."""
    mappings: list[dict[str, str]] = []
    seen: set[str] = set()

    for cid in capec_ids:
        entry = capec_db.get(cid)
        if entry is None:
            continue
        capec_name = entry["name"]
        attack_techniques = entry["attack_techniques"]

        if attack_techniques:
            for at in attack_techniques:
                key = f"CAPEC-{cid}:{at['attack_id']}"
                if key not in seen:
                    seen.add(key)
                    mappings.append(
                        {
                            "capec_id": f"CAPEC-{cid}",
                            "capec_name": capec_name,
                            "attack_id": at["attack_id"],
                            "attack_name": at["attack_name"],
                        }
                    )
        else:
            key = f"CAPEC-{cid}:"
            if key not in seen:
                seen.add(key)
                mappings.append(
                    {
                        "capec_id": f"CAPEC-{cid}",
                        "capec_name": capec_name,
                        "attack_id": "",
                        "attack_name": "",
                    }
                )

    return mappings[:10]  # Cap at 10 per CWE


def generate_exploit_strategies(
    cwe_entry: dict[str, Any],
) -> list[str]:
    """Generate exploit strategy descriptions from CWE consequences + description."""
    # Generate from consequences
    strategies: list[str] = []
    description = cwe_entry.get("description", "")
    if description:
        # Summarize the vulnerability as first strategy
        desc_short = description[:200].rstrip(".")
        strategies.append(f"Exploit the weakness: {desc_short}")

    for cons in cwe_entry.get("consequences", []):
        impact = cons.get("impact", "")
        scope = cons.get("scope", "")
        if impact:
            strategies.append(f"Target {scope.lower()} via {impact.lower()}")

    return strategies[:6] if strategies else ["Analyze and exploit the identified weakness"]



def generate_failure_modes(
    cwe_entry: dict[str, Any],
) -> list[dict[str, str]]:
    """Generate failure modes from CWE mitigations (inverted)."""
    modes: list[dict[str, str]] = []
    for mit in cwe_entry.get("mitigations", []):
        desc = mit.get("description", "")
        if not desc or len(desc) < 20:
            continue
        # Invert: if mitigation is X, failure mode is "X blocks exploitation"
        desc_short = desc[:150].rstrip(".")
        strategy = mit.get("strategy", "")
        symptom = f"Exploit blocked by mitigation: {desc_short}"
        diagnosis = f"Application implements {strategy or 'defense'}: {desc_short}"
        fix = "Try bypass techniques or look for incomplete implementation of this defense"
        modes.append(
            {
                "symptom": symptom[:200],
                "diagnosis": diagnosis[:200],
                "fix_suggestion": fix,
            }
        )

    return modes[:5] if modes else []


def generate_oracle_criteria(
    cwe_entry: dict[str, Any],
) -> list[dict[str, Any]]:
    """Generate L1-L5 oracle criteria for LLM guidance.

    Generates generic criteria from the CWE's consequence scopes and
    impacts.  ALL criteria have ``automated: false`` — they are injected
    into the exploit agent's system prompt as descriptive guidance, NOT
    regex-matched by the inline oracle.
    """
    # Generate generic criteria from consequences
    consequences = cwe_entry.get("consequences", [])
    impacts: list[str] = []
    scopes: list[str] = []
    for c in consequences:
        if c.get("impact"):
            impacts.append(c["impact"])
        if c.get("scope"):
            scopes.extend(s.strip() for s in c["scope"].split(","))

    impact_str = impacts[0] if impacts else "trigger the vulnerability"
    scope_str = scopes[0].lower() if scopes else "application"
    name = cwe_entry.get("name", "Unknown Weakness")

    return [
        {
            "level": 1,
            "name": "Vulnerability Triggered",
            "description": (
                f"The {name} weakness was triggered — targeted probe caused "
                "observable change in application behavior"
            ),
            "indicators": [
                f"Identified vulnerable input point for {name}",
                "Application error or anomalous response from crafted payload",
                "Behavioral difference confirms vulnerability presence",
            ],
            "automated": False,
        },
        {
            "level": 2,
            "name": "Exploitation Achieved",
            "description": (
                f"Exploitation of {name} yielded sensitive"
                f" information or confirmed {scope_str} impact"
            ),
            "indicators": [
                "Sensitive data or internal state exposed",
                f"{scope_str.title()} boundary violated",
                f"Demonstrated {impact_str.lower()}",
            ],
            "automated": False,
        },
        {
            "level": 3,
            "name": "Full Compromise",
            "description": f"Complete exploitation of {name} — full attack chain demonstrated",
            "indicators": [
                "End-to-end exploit chain successful",
                "Maximum impact achieved for this weakness class",
                "Attacker-controlled code execution or data exfiltration",
            ],
            "automated": False,
        },
    ]


def build_enrichment(
    cwe_db: dict[str, dict[str, Any]],
    capec_db: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the full enrichment JSON from CWE and CAPEC data."""
    output: dict[str, Any] = {
        "_meta": {
            "version": 2,
            "source": "MITRE CWE CSV (Research Concepts v1000) + CAPEC CSV (v2000)",
            "generated": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cwe_count": 0,
            "capec_count": len(capec_db),
        },
    }

    count = 0
    for cwe_id, entry in sorted(cwe_db.items(), key=lambda x: int(x[0].split("-")[1])):
        # Build technique mappings from CAPEC
        techniques = build_technique_mappings(entry["capec_ids"], capec_db)

        # Generate oracle criteria
        oracle_criteria = generate_oracle_criteria(entry)

        # Generate exploit strategies
        exploit_strategies = generate_exploit_strategies(entry)

        # Generate failure modes
        failure_modes = generate_failure_modes(entry)

        output[cwe_id] = {
            "name": entry["name"],
            "techniques": techniques,
            "oracle_criteria": oracle_criteria,
            "exploit_strategies": exploit_strategies,
            "failure_modes": failure_modes,
        }
        count += 1

    output["_meta"]["cwe_count"] = count
    return output


def main() -> None:
    """Download MITRE data and generate CWE enrichment JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip download, use cached CSVs only",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_OUTPUT_PATH,
        help=f"Output JSON path (default: {_OUTPUT_PATH})",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    # Download or load CSVs
    cwe_csv, capec_csv = ensure_csvs(offline=args.offline)

    # Parse CSVs
    cwe_db = load_cwe_csv(cwe_csv)
    capec_db = load_capec_csv(capec_csv)

    logger.info(
        "Building enrichment for %d CWEs with %d CAPEC entries",
        len(cwe_db),
        len(capec_db),
    )

    # Build enrichment
    enrichment = build_enrichment(cwe_db, capec_db)

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(enrichment, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    meta = enrichment["_meta"]
    logger.info(
        "Wrote %d CWE entries to %s (CAPEC: %d)",
        meta["cwe_count"],
        args.output,
        meta["capec_count"],
    )


if __name__ == "__main__":
    main()
