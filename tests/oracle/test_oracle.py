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

import pytest

from forge.oracle.models import OracleEvidence
from forge.oracle.oracle import ExploitOracle, _compute_confidence, format_snapshot
from forge.sandbox.models import SandboxSnapshot


def _make_evidence(
    level: int, confidence: float = 0.85, source: str = "exploit_output"
) -> OracleEvidence:
    return OracleEvidence(
        source=source,
        description=f"Test evidence L{level}",
        level_match=level,
        confidence=confidence,
        provenance="client",
    )


class TestFormatSnapshot:
    def test_empty_snapshot(self) -> None:
        snapshot = SandboxSnapshot()
        result = format_snapshot(snapshot)
        assert "empty" in result.lower()

    def test_files_created(self) -> None:
        snapshot = SandboxSnapshot(files_created=["/tmp/pwned", "/tmp/marker.txt"])
        result = format_snapshot(snapshot)
        assert "FILES CREATED" in result
        assert "/tmp/pwned" in result
        assert "/tmp/marker.txt" in result

    def test_processes(self) -> None:
        snapshot = SandboxSnapshot(processes=[{"raw": "nc -lvp 4444"}])
        result = format_snapshot(snapshot)
        assert "PROCESSES" in result
        assert "nc -lvp 4444" in result

    def test_app_logs(self) -> None:
        snapshot = SandboxSnapshot(app_logs="Error: segfault\nConnection reset")
        result = format_snapshot(snapshot)
        assert "APPLICATION LOGS" in result
        assert "segfault" in result

    def test_combined_snapshot(self) -> None:
        snapshot = SandboxSnapshot(
            files_created=["/tmp/pwned"],
            processes=[{"raw": "bash -i"}],
            app_logs="500 Internal Server Error",
        )
        result = format_snapshot(snapshot)
        assert "FILES CREATED" in result
        assert "PROCESSES" in result
        assert "APPLICATION LOGS" in result

    def test_long_logs_truncated(self) -> None:
        lines = [f"log line {i}" for i in range(100)]
        snapshot = SandboxSnapshot(app_logs="\n".join(lines))
        result = format_snapshot(snapshot)
        assert "last 50 lines" in result


class TestComputeConfidence:
    def test_no_evidence(self) -> None:
        assert _compute_confidence([], 0) == pytest.approx(0.0)

    def test_no_exploitation_is_confident(self) -> None:
        assert _compute_confidence([], 0) == pytest.approx(0.0)
        evidence = [_make_evidence(0)]
        assert _compute_confidence(evidence, 0) == pytest.approx(1.0)

    def test_single_high_confidence_evidence(self) -> None:
        evidence = [_make_evidence(3, confidence=0.9)]
        conf = _compute_confidence(evidence, 3)
        assert conf > 0.0

    def test_multiple_sources_bonus(self) -> None:
        evidence = [
            _make_evidence(3, confidence=0.9, source="exploit_output"),
            _make_evidence(3, confidence=0.9, source="filesystem"),
        ]
        conf = _compute_confidence(evidence, 3)
        # Two unique sources should give higher confidence
        single = _compute_confidence([evidence[0]], 3)
        assert conf > single


class TestExploitOracle:
    def test_verdict_from_evidence(self) -> None:
        oracle = ExploitOracle()
        evidence = [
            _make_evidence(3, confidence=0.9),
            _make_evidence(2, confidence=0.8),
        ]
        verdict = oracle.evaluate(evidence)
        assert verdict.binary_success is True
        assert verdict.exploitation_level == 3

    def test_empty_evidence_is_l0(self) -> None:
        oracle = ExploitOracle()
        verdict = oracle.evaluate([])
        assert verdict.binary_success is False
        assert verdict.exploitation_level == 0

    def test_low_confidence_evidence_filtered(self) -> None:
        oracle = ExploitOracle()
        evidence = [_make_evidence(3, confidence=0.3)]
        verdict = oracle.evaluate(evidence)
        # Below 0.5 confidence threshold
        assert verdict.exploitation_level == 0
