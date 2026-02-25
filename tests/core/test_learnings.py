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

from pathlib import Path

from forge.learnings import ErrorCategory, Learning, LearningStore


class TestLearningStore:
    def test_record_and_query(self, tmp_path: Path) -> None:
        store = LearningStore(store_dir=tmp_path)
        store.record(
            Learning(
                phase="build",
                error_category=ErrorCategory.PACKAGE_NOT_FOUND,
                language="python",
                cve_id="CVE-2025-1111",
                error_summary="numpy not found",
                fix_summary="Added numpy to requirements",
                success=True,
            )
        )
        store.record(
            Learning(
                phase="deploy",
                error_category=ErrorCategory.HEALTH_CHECK_FAILURE,
                language="php",
                cve_id="CVE-2025-2222",
                error_summary="404 on /health",
                fix_summary="Added /health route",
                success=True,
            )
        )

        assert store.count() == 2

        # Query by phase
        build_learnings = store.query(phase="build")
        assert len(build_learnings) == 1
        assert build_learnings[0].cve_id == "CVE-2025-1111"

        # Query by language
        php_learnings = store.query(language="php")
        assert len(php_learnings) == 1

        # Query all
        all_learnings = store.query()
        assert len(all_learnings) == 2

    def test_freeze_and_load(self, tmp_path: Path) -> None:
        store = LearningStore(store_dir=tmp_path)
        store.record(
            Learning(
                phase="build",
                error_category=ErrorCategory.PORT_MISMATCH,
                language="go",
                success=False,
            )
        )

        frozen_path = store.freeze("1")
        assert frozen_path.exists()

        frozen_store = LearningStore.from_frozen(frozen_path)
        assert frozen_store.frozen is True
        assert frozen_store.count() == 1

        # Frozen store can query
        results = frozen_store.query(language="go")
        assert len(results) == 1


class TestQueryRelated:
    """Tests for LearningStore.query_related with cross-CWE sibling lookup."""

    def test_returns_exact_cwe_matches_first(self, tmp_path: Path) -> None:
        """Exact CWE matches come before sibling matches."""
        store = LearningStore(store_dir=tmp_path)
        # CWE-89 learning (exact)
        store.record(
            Learning(
                phase="exploit",
                error_category=ErrorCategory.EXPLOIT_SUCCESS_PATTERN,
                cwe_id="CWE-89",
                cve_id="CVE-2024-0001",
                error_summary="UNION SQLi worked",
                fix_summary="UNION SELECT",
                success=True,
            )
        )
        # CWE-564 learning (sibling — both under CWE-943)
        store.record(
            Learning(
                phase="exploit",
                error_category=ErrorCategory.EXPLOIT_SUCCESS_PATTERN,
                cwe_id="CWE-564",
                cve_id="CVE-2024-0002",
                error_summary="Hibernate injection worked",
                fix_summary="HQL injection",
                success=True,
            )
        )

        results = store.query_related("CWE-89", max_results=10)
        assert len(results) == 2
        # Exact match first
        assert results[0].cwe_id == "CWE-89"
        assert results[1].cwe_id == "CWE-564"


class TestExploitLearningRecorded:
    """Phase 5.3: Exploit learning recording."""

    def test_exploit_learning_recorded(self, tmp_path: Path) -> None:
        """Record exploit learning with phase='exploit' and technique."""
        store = LearningStore(store_dir=tmp_path)
        store.record(
            Learning(
                phase="exploit",
                error_category=ErrorCategory.EXPLOIT_SUCCESS_PATTERN,
                cwe_id="CWE-89",
                cve_id="CVE-2025-1234",
                error_summary="Reached L3 with techniques: UNION SELECT",
                fix_summary="UNION SELECT",
                success=True,
            )
        )
        results = store.query(phase="exploit", cwe_id="CWE-89")
        assert len(results) == 1
        assert results[0].phase == "exploit"
        assert results[0].success is True
        assert "L3" in results[0].error_summary


class TestGenerationLearningRecorded:
    """Phase 5.3: Generation learning recording."""

    def test_generation_success_learning(self, tmp_path: Path) -> None:
        """Generator succeeds → learning recorded with phase='generation'."""
        store = LearningStore(store_dir=tmp_path)
        store.record(
            Learning(
                phase="generation",
                error_category=ErrorCategory.EXPLOIT_SUCCESS_PATTERN,
                cwe_id="CWE-89",
                cve_id="CVE-2025-4444",
                language="python",
                error_summary="App generated in 1 attempt(s), framework=flask",
                fix_summary="flask",
                success=True,
            )
        )
        results = store.query(phase="generation")
        assert len(results) == 1
        assert results[0].success is True
        assert "flask" in results[0].error_summary
