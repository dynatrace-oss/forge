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

import pytest

from forge.intel.knowledge import (
    CRYSTALLIZATION_THRESHOLD,
    KnowledgeStore,
    normalize_technique,
)


@pytest.fixture()
def store(tmp_path):
    return KnowledgeStore(knowledge_dir=tmp_path / "knowledge")


class TestKnowledgeStore:
    def test_record_attempt_creates_entry(self, store):
        result = store.record_attempt(
            cwe_id="CWE-79",
            cve_id="CVE-2024-1234",
            max_level=3,
            cwe_name="XSS",
        )
        assert result.total_attempts == 1
        assert result.total_successes == 1
        assert result.avg_max_level == pytest.approx(3.0)
        assert result.confirmations == 1

    def test_crystallization(self, store):
        for i in range(CRYSTALLIZATION_THRESHOLD):
            result = store.record_attempt(
                cwe_id="CWE-79",
                cve_id=f"CVE-2024-{i:04d}",
                max_level=3,
            )
        assert result.crystallized


class TestRecordEscalation:
    def test_record_escalation_creates_path(self, store):
        """Record L1→L3 escalation for CWE-89.  Verify EscalationPath created."""
        store.record_escalation(
            cwe_id="CWE-89",
            cve_id="CVE-2024-1234",
            from_level=1,
            to_level=3,
            techniques=["sqli_union"],
        )
        knowledge = store.get("CWE-89")
        assert knowledge is not None
        assert len(knowledge.escalation_paths) == 1
        path = knowledge.escalation_paths[0]
        assert path.from_level == 1
        assert path.to_level == 3
        assert path.techniques == ["sqli_union"]
        assert path.success_count == 1
        assert "CVE-2024-1234" in path.cve_ids


class TestNormalizeTechnique:
    """Tests for normalize_technique() canonical name mapping."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("SQL injection via UNION SELECT", "sqli"),
            ("  ", "unknown"),
        ],
    )
    def test_normalize(self, raw: str, expected: str) -> None:
        assert normalize_technique(raw) == expected


class TestTechniqueConsolidation:
    """Verify that synonym variations consolidate into one entry."""

    def test_synonyms_consolidate_in_record_attempt(self, store):
        """Different SQL injection names merge into one technique."""
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0001",
            max_level=3,
            techniques_used=["SQL injection via UNION"],
        )
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0002",
            max_level=2,
            techniques_used=["union-based SQLi"],
        )
        knowledge = store.get("CWE-89")
        assert knowledge is not None
        # Both should consolidate into one "sqli" technique
        assert len(knowledge.techniques) == 1
        assert knowledge.techniques[0].name == "sqli"
        assert knowledge.techniques[0].success_count == 2


class TestLanguageAwareness:
    """Language-aware technique tracking and prompt formatting."""

    def test_record_attempt_tracks_language(self, store: KnowledgeStore) -> None:
        """When language is provided, technique records per-language success."""
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0001",
            max_level=3,
            techniques_used=["sqli"],
            language="python",
        )
        knowledge = store.get("CWE-89")
        assert knowledge is not None
        assert len(knowledge.techniques) == 1
        tech = knowledge.techniques[0]
        assert tech.language_success == {"python": 1}

    def test_language_accumulates_across_attempts(self, store: KnowledgeStore) -> None:
        """Multiple attempts in same language increment the counter."""
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0001",
            max_level=3,
            techniques_used=["sqli"],
            language="python",
        )
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0002",
            max_level=2,
            techniques_used=["sqli"],
            language="python",
        )
        knowledge = store.get("CWE-89")
        assert knowledge is not None
        tech = knowledge.techniques[0]
        assert tech.language_success["python"] == 2

    def test_multiple_languages_tracked(self, store: KnowledgeStore) -> None:
        """Different languages tracked separately on the same technique."""
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0001",
            max_level=3,
            techniques_used=["sqli"],
            language="python",
        )
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0002",
            max_level=2,
            techniques_used=["sqli"],
            language="java",
        )
        knowledge = store.get("CWE-89")
        assert knowledge is not None
        tech = knowledge.techniques[0]
        assert tech.language_success == {"python": 1, "java": 1}

    def test_no_language_records_empty_stats(self, store: KnowledgeStore) -> None:
        """Without language, language_success stays empty (backward compat)."""
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0001",
            max_level=3,
            techniques_used=["sqli"],
        )
        knowledge = store.get("CWE-89")
        assert knowledge is not None
        assert knowledge.techniques[0].language_success == {}

    def test_failed_attempt_does_not_track_language(self, store: KnowledgeStore) -> None:
        """Failed attempts (max_level=0) don't increment language_success."""
        store.record_attempt(
            cwe_id="CWE-89",
            cve_id="CVE-2024-0001",
            max_level=0,
            techniques_used=["sqli"],
            language="python",
        )
        knowledge = store.get("CWE-89")
        assert knowledge is not None
        tech = knowledge.techniques[0]
        assert tech.language_success == {}
        assert tech.failure_count == 1

    def test_format_for_prompt_annotates_language(self, store: KnowledgeStore) -> None:
        """format_for_prompt shows [verified for X] when language matches."""
        # Record enough attempts to reach confidence threshold
        for i in range(3):
            store.record_attempt(
                cwe_id="CWE-89",
                cve_id=f"CVE-2024-{i:04d}",
                max_level=3,
                techniques_used=["sqli"],
                language="python",
            )
        result = store.format_for_prompt("CWE-89", language="python")
        assert "[verified for python]" in result

    def test_format_for_prompt_no_annotation_for_other_language(
        self,
        store: KnowledgeStore,
    ) -> None:
        """format_for_prompt omits annotation when language doesn't match."""
        for i in range(3):
            store.record_attempt(
                cwe_id="CWE-89",
                cve_id=f"CVE-2024-{i:04d}",
                max_level=3,
                techniques_used=["sqli"],
                language="python",
            )
        result = store.format_for_prompt("CWE-89", language="java")
        assert "[verified for" not in result

    def test_format_for_prompt_language_boosts_ordering(
        self,
        store: KnowledgeStore,
    ) -> None:
        """Language-matched techniques sort before non-matched ones."""
        # Record xss technique with python success
        store.record_attempt(
            cwe_id="CWE-79",
            cve_id="CVE-2024-0001",
            max_level=3,
            techniques_used=["xss"],
            language="python",
        )
        # Record rce technique with java success (higher overall rate)
        store.record_attempt(
            cwe_id="CWE-79",
            cve_id="CVE-2024-0002",
            max_level=3,
            techniques_used=["rce"],
            language="java",
        )
        # Bump confirmations for confidence
        store.record_attempt(
            cwe_id="CWE-79",
            cve_id="CVE-2024-0003",
            max_level=3,
        )
        result = store.format_for_prompt("CWE-79", language="python")
        # xss should appear before rce because it has python success
        xss_pos = result.find("xss")
        rce_pos = result.find("rce")
        assert xss_pos < rce_pos, f"xss@{xss_pos} should be before rce@{rce_pos}"
