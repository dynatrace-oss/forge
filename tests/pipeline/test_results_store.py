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
