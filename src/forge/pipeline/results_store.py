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
import logging
import re
from pathlib import Path

from forge.models import ExploitAttempt

logger = logging.getLogger(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

DEFAULT_RESULTS_DIR = Path("data/results")

CSV_COLUMNS = [
    "cve_id",
    "cwe_ids",
    "language",
    "framework",
    "condition",
    "strategy_pack_id",
    "run_index",
    "seed",
    "model",
    "build_prompt_tokens",
    "build_completion_tokens",
    "build_total_tokens",
    "build_llm_calls",
    "exploit_prompt_tokens",
    "exploit_completion_tokens",
    "exploit_total_tokens",
    "exploit_llm_calls",
    "total_tokens",
    "estimated_cost_usd",
    "build_success",
    "build_retries",
    "app_healthy",
    "deploy_retries",
    "error_category",
    "exploit_completed",
    "early_stopped",
    "turns_used",
    "max_exploitation_level",
    "binary_success",
    "exploitation_level",
    "oracle_confidence",
    "detection_rules_count",
    "cvss_score",
    "epss_score",
    "osv_enriched",
    "wall_clock_seconds",
    "otel_trace_id",
    "timestamp",
    "artifact_dir",
]


class ResultsStore:
    """Stores experiment results to CSV files."""

    def __init__(self, results_dir: Path | None = None) -> None:
        self._results_dir = results_dir or DEFAULT_RESULTS_DIR
        self._results_dir.mkdir(parents=True, exist_ok=True)
        self._results_file = self._results_dir / "results.csv"
        self._errors_file = self._results_dir / "errors.jsonl"
        self._ensure_header()

    def _ensure_header(self) -> None:
        """Create the CSV file with header if it doesn't exist."""
        if not self._results_file.exists():
            with self._results_file.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()

    def save(self, attempt: ExploitAttempt) -> None:
        """Append one ExploitAttempt as a row in the results CSV."""
        row = {
            "cve_id": attempt.cve_id,
            "cwe_ids": ",".join(attempt.cwe_ids),
            "language": attempt.language,
            "framework": attempt.framework or "",
            "condition": attempt.condition,
            "strategy_pack_id": attempt.strategy_pack_id or "",
            "run_index": attempt.run_index,
            "seed": attempt.seed,
            "model": attempt.model,
            "build_prompt_tokens": attempt.build_prompt_tokens,
            "build_completion_tokens": attempt.build_completion_tokens,
            "build_total_tokens": attempt.build_total_tokens,
            "build_llm_calls": attempt.build_llm_calls,
            "exploit_prompt_tokens": attempt.exploit_prompt_tokens,
            "exploit_completion_tokens": attempt.exploit_completion_tokens,
            "exploit_total_tokens": attempt.exploit_total_tokens,
            "exploit_llm_calls": attempt.exploit_llm_calls,
            "total_tokens": attempt.total_tokens,
            "estimated_cost_usd": f"{attempt.estimated_cost_usd:.6f}",
            "build_success": attempt.build_success,
            "build_retries": attempt.build_retries,
            "app_healthy": attempt.app_healthy,
            "deploy_retries": attempt.deploy_retries,
            "error_category": attempt.error_category,
            "exploit_completed": attempt.exploit_completed,
            "early_stopped": attempt.early_stopped,
            "turns_used": attempt.turns_used,
            "max_exploitation_level": attempt.max_exploitation_level,
            "binary_success": attempt.binary_success,
            "exploitation_level": attempt.exploitation_level,
            "oracle_confidence": f"{attempt.oracle_confidence:.4f}",
            "detection_rules_count": attempt.detection_rules_generated,
            "cvss_score": (f"{attempt.cvss_score:.1f}" if attempt.cvss_score is not None else ""),
            "epss_score": (f"{attempt.epss_score:.6f}" if attempt.epss_score is not None else ""),
            "osv_enriched": attempt.osv_enriched,
            "wall_clock_seconds": f"{attempt.wall_clock_seconds:.2f}",
            "otel_trace_id": attempt.otel_trace_id,
            "timestamp": attempt.timestamp.isoformat(),
            "artifact_dir": attempt.artifact_dir or "",
        }

        with self._results_file.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writerow(row)

        if attempt.error_message:
            self._append_error(attempt)

        logger.info(
            "Saved result: %s %s level=%d tokens=%d",
            attempt.cve_id,
            attempt.condition,
            attempt.exploitation_level,
            attempt.total_tokens,
        )

    def _append_error(self, attempt: ExploitAttempt) -> None:
        """Write error details to errors.jsonl, one JSON object per line."""
        msg = _ANSI_RE.sub("", attempt.error_message or "").strip()
        record = {
            "cve_id": attempt.cve_id,
            "condition": attempt.condition,
            "run_index": attempt.run_index,
            "error_category": attempt.error_category,
            "timestamp": attempt.timestamp.isoformat(),
            "error_message": msg,
        }
        with self._errors_file.open("a") as f:
            f.write(json.dumps(record) + "\n")

    def get_results_path(self) -> Path:
        """Return the path to the results CSV file."""
        return self._results_file

    def get_errors_path(self) -> Path:
        """Return the path to the errors JSONL file."""
        return self._errors_file

    def get_completed_keys(self) -> set[str]:
        """Return set of completed (cve_id, condition, run_index) keys for resume support.

        Each key is formatted as 'cve_id|condition|run_index'.
        """
        keys: set[str] = set()
        if not self._results_file.exists():
            return keys

        with self._results_file.open(newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = f"{row['cve_id']}|{row['condition']}|{row['run_index']}"
                keys.add(key)

        return keys
