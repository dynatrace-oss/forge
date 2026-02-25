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

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from forge.models import ExploitAttempt
from forge.pipeline.results_store import CSV_COLUMNS, ResultsStore


def _make_attempt(**overrides: object) -> ExploitAttempt:
    """Build a minimal ExploitAttempt with sensible defaults."""
    defaults: dict[str, object] = {
        "cve_id": "CVE-2025-00001",
        "cwe_ids": ["CWE-22"],
        "language": "python",
        "condition": "cwe_conditioned",
        "exploitation_level": 3,
        "timestamp": datetime(2026, 4, 15, tzinfo=UTC),
    }
    defaults.update(overrides)
    return ExploitAttempt(**defaults)  # type: ignore[arg-type]


class TestResultsStoreCSV:
    """Verify results.csv no longer contains error_message."""

    def test_csv_columns_match_spec(self, tmp_path: Path) -> None:
        store = ResultsStore(tmp_path)
        store.save(_make_attempt())

        with store.get_results_path().open(newline="") as f:
            reader = csv.DictReader(f)
            assert list(reader.fieldnames or []) == CSV_COLUMNS

    def test_csv_one_row_per_line(self, tmp_path: Path) -> None:
        """Each row occupies exactly one line (no embedded newlines)."""
        store = ResultsStore(tmp_path)
        msg = "Compose up failed:\n  Container foo  Creating\n  exit 1"
        store.save(_make_attempt(error_message=msg))

        lines = store.get_results_path().read_text().splitlines()
        assert len(lines) == 2  # header + 1 data row


class TestResultsStoreErrors:
    """Verify errors.jsonl receives error details."""

    def test_error_written_to_jsonl(self, tmp_path: Path) -> None:
        store = ResultsStore(tmp_path)
        store.save(
            _make_attempt(
                error_message="Health check failed",
                error_category="benchmark_start_failure",
            )
        )

        records = [json.loads(line) for line in store.get_errors_path().read_text().splitlines()]
        assert len(records) == 1
        rec = records[0]
        assert rec["cve_id"] == "CVE-2025-00001"
        assert rec["condition"] == "cwe_conditioned"
        assert rec["error_category"] == "benchmark_start_failure"
        assert rec["error_message"] == "Health check failed"
