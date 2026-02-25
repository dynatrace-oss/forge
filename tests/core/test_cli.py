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
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from forge.cli import main


class TestSelectCommand:
    def test_select_produces_output_file(self, tmp_path: Path) -> None:
        output = tmp_path / "selected.json"
        data_path = Path("data/CVE Genie Data.json")
        if not data_path.exists():
            pytest.skip("CVE-GENIE data not available")

        runner = CliRunner()
        result = runner.invoke(main, ["select", "--count", "10", "--output", str(output)])
        assert result.exit_code == 0, result.output
        assert output.exists()

        selected = json.loads(output.read_text())
        assert len(selected) == 10
        assert all("cve_id" in s for s in selected)


class TestStatsCommand:
    def test_stats_reads_results_csv(self, tmp_path: Path) -> None:
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        csv_path = results_dir / "results.csv"

        # Write a minimal results CSV
        fieldnames = [
            "cve_id",
            "exploitation_level",
            "estimated_cost_usd",
            "wall_clock_seconds",
            "exploit_completed",
        ]
        with csv_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(
                {
                    "cve_id": "CVE-2024-0001",
                    "exploitation_level": "3",
                    "estimated_cost_usd": "0.50",
                    "wall_clock_seconds": "30.0",
                    "exploit_completed": "True",
                }
            )
            writer.writerow(
                {
                    "cve_id": "CVE-2024-0002",
                    "exploitation_level": "0",
                    "estimated_cost_usd": "0.25",
                    "wall_clock_seconds": "15.0",
                    "exploit_completed": "True",
                }
            )

        runner = CliRunner()
        result = runner.invoke(main, ["stats", "--results-dir", str(results_dir)])
        assert result.exit_code == 0, result.output
        assert "2 rows" in result.output
        assert "$0.75" in result.output
        assert "L0" in result.output
        assert "L3" in result.output


class TestRunCommand:
    def test_run_requires_exactly_one_source(self) -> None:
        runner = CliRunner()
        # No source at all
        result = runner.invoke(main, ["run"])
        assert result.exit_code != 0

    def test_run_single_cve_with_mocked_pipeline(self) -> None:
        runner = CliRunner()
        with (
            patch("forge.cli._run_batch", new_callable=AsyncMock) as mock_batch,
            patch("forge.config.load_config") as mock_cfg,
        ):
            mock_cfg.return_value = None  # won't be used since _run_batch is mocked
            mock_batch.return_value = None
            result = runner.invoke(main, ["run", "CVE-2024-9999"])

        # The run command should at least parse args and call _run_batch
        # (config loading happens via lazy import inside the command)
        assert result.exit_code == 0 or mock_batch.called


def _make_mock_pipeline_result(cve_id: str) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "status": "completed",
        "exploitation_level": 2,
        "tokens": {"estimated_cost_usd": 0.50},
        "wall_clock_seconds": 30.0,
    }


class TestResolveCveSources:
    """Tests for _resolve_cve_sources CWE lookup."""

    def test_cve_list_mode_preserves_cwes(self, tmp_path: Path) -> None:
        """CVE IDs found in CVE-GENIE should have their CWE tags populated."""
        data_path = Path("data/CVE Genie Data.json")
        if not data_path.exists():
            pytest.skip("CVE-GENIE data not available")

        # Pick the first CVE that has CWEs
        raw = json.loads(data_path.read_text())
        cve_with_cwes: str | None = None
        for cve_id, blob in raw.items():
            cwes = blob.get("cwe", [])
            if cwes and any(c.get("id", "n/a") != "n/a" for c in cwes):
                cve_with_cwes = cve_id
                break
        assert cve_with_cwes is not None, "No CVE with CWEs found in dataset"

        # Write a cve-list file
        cve_list_file = tmp_path / "cves.txt"
        cve_list_file.write_text(cve_with_cwes + "\n")

        from forge.cli import _resolve_cve_sources

        results = _resolve_cve_sources(
            cve_id=None, batch=None, cve_list=str(cve_list_file), seed=42
        )
        assert len(results) == 1
        assert results[0]["cve_id"] == cve_with_cwes
        assert len(results[0]["cwes"]) > 0, "CWE list should be populated from CVE-GENIE"


class TestPipelineResultToAttempt:
    """Verify per-agent token columns are populated correctly."""

    def test_build_and_exploit_tokens_separated(self) -> None:
        """build_* columns should come from intel+generator, exploit_* from exploit agent."""
        from forge.agents.base import AgentResult
        from forge.agents.orchestrator import AgentRole, PipelineResult, PipelineStatus
        from forge.cli import _pipeline_result_to_attempt
        from forge.models import CVETask, TokenUsage

        intel_tokens = TokenUsage(
            prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=2
        )
        gen_tokens = TokenUsage(
            prompt_tokens=200, completion_tokens=100, total_tokens=300, llm_calls=3
        )
        exploit_tokens = TokenUsage(
            prompt_tokens=1000, completion_tokens=500, total_tokens=1500, llm_calls=10
        )
        detector_tokens = TokenUsage(
            prompt_tokens=80, completion_tokens=40, total_tokens=120, llm_calls=1
        )

        total = intel_tokens + gen_tokens + exploit_tokens + detector_tokens

        pipeline_result = PipelineResult(
            cve_id="CVE-2024-TEST",
            status=PipelineStatus.COMPLETED,
            exploitation_level=3,
            tokens=total,
            agent_results={
                AgentRole.INTEL: AgentResult(tokens=intel_tokens),
                AgentRole.GENERATOR: AgentResult(tokens=gen_tokens),
                AgentRole.EXPLOIT: AgentResult(tokens=exploit_tokens),
                AgentRole.DETECTOR: AgentResult(tokens=detector_tokens),
            },
        )
        task = CVETask(
            cve_id="CVE-2024-TEST",
            cwe_ids=["CWE-89"],
            language="python",
        )

        attempt = _pipeline_result_to_attempt(pipeline_result, task)

        # build = intel + generator
        assert attempt.build_prompt_tokens == 300  # 100 + 200
        assert attempt.build_completion_tokens == 150  # 50 + 100
        assert attempt.build_total_tokens == 450  # 150 + 300
        assert attempt.build_llm_calls == 5  # 2 + 3

        # exploit = exploit agent only
        assert attempt.exploit_prompt_tokens == 1000
        assert attempt.exploit_completion_tokens == 500
        assert attempt.exploit_total_tokens == 1500
        assert attempt.exploit_llm_calls == 10

        # total = all agents combined
        assert attempt.total_tokens == total.total_tokens


class TestSavePerCveArtifact:
    """Tests for _save_per_cve_artifact including OTEL span export."""

    def test_saves_result_json(self, tmp_path: Path) -> None:
        from forge.agents.orchestrator import PipelineResult

        result = PipelineResult(cve_id="CVE-2024-0001")
        from forge.cli import _save_per_cve_artifact

        _save_per_cve_artifact(result, tmp_path)
        artifact = tmp_path / "CVE-2024-0001" / "result.json"
        assert artifact.exists()
        data = json.loads(artifact.read_text())
        assert data["cve_id"] == "CVE-2024-0001"

    def test_saves_otel_spans_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from forge.agents.orchestrator import PipelineResult

        result = PipelineResult(cve_id="CVE-2024-0002", otel_trace_id="abc123")

        # Mock export_and_clear_otel_spans to return test data
        mock_spans = [
            {"name": "litellm.completion", "duration_ms": 500.0, "attributes": {"model": "test"}},
        ]
        monkeypatch.setattr(
            "forge.pipeline.llm_client.export_and_clear_otel_spans",
            lambda: mock_spans,
        )

        from forge.cli import _save_per_cve_artifact

        _save_per_cve_artifact(result, tmp_path)

        otel_path = tmp_path / "CVE-2024-0002" / "otel_spans.json"
        assert otel_path.exists()
        spans = json.loads(otel_path.read_text())
        assert len(spans) == 1
        assert spans[0]["name"] == "litellm.completion"

    def test_otel_trace_id_wired_to_csv(self) -> None:
        from forge.agents.orchestrator import PipelineResult, PipelineStatus
        from forge.cli import _pipeline_result_to_attempt
        from forge.models import CVETask

        result = PipelineResult(
            cve_id="CVE-2024-0003",
            status=PipelineStatus.COMPLETED,
            otel_trace_id="trace-abc-123",
        )
        task = CVETask(cve_id="CVE-2024-0003", cwe_ids=["CWE-89"], language="python")
        attempt = _pipeline_result_to_attempt(result, task)
        assert attempt.otel_trace_id == "trace-abc-123"
