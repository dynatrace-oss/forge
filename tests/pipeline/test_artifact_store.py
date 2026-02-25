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

import json
from pathlib import Path

import pytest

from forge.pipeline.artifact_store import ArtifactStore


@pytest.fixture()
def store(tmp_path: Path) -> ArtifactStore:
    return ArtifactStore(results_dir=tmp_path)


class TestAppIndex:
    def test_save_and_find_exact_match(self, store: ArtifactStore, tmp_path: Path) -> None:
        """save_app_index + find_similar_app round-trips for exact (language, framework)."""
        # First, save some project files
        store.save_build(
            "CVE-2024-1234",
            "forge",
            0,
            {"app.py": "print('hello')", "Dockerfile": "FROM python:3.12"},
        )
        store.save_app_index("CVE-2024-1234", "forge", 0, "python", "flask")

        # Find should return the saved files
        files = store.find_similar_app("python", "flask")
        assert "app.py" in files
        assert "Dockerfile" in files
        assert files["app.py"] == "print('hello')"

    def test_find_returns_empty_on_no_match(self, store: ArtifactStore) -> None:
        """find_similar_app returns empty dict when no matching technology exists."""
        files = store.find_similar_app("java", "spring")
        assert files == {}

    def test_skip_index_when_no_language_or_framework(self, store: ArtifactStore) -> None:
        """save_app_index is a no-op when both language and framework are empty."""
        store.save_app_index("CVE-X", "forge", 0, "", "")
        assert not store.find_similar_app("", "")

    def test_index_file_is_valid_json(self, store: ArtifactStore, tmp_path: Path) -> None:
        """The _app_index.json is valid JSON with expected structure."""
        store.save_build("CVE-A", "forge", 0, {"app.py": "x"})
        store.save_app_index("CVE-A", "forge", 0, "java", "spring")

        index_path = tmp_path / "_app_index.json"
        assert index_path.exists()
        data = json.loads(index_path.read_text())
        assert "java:spring" in data
        assert data["java:spring"]["cve_id"] == "CVE-A"
        assert data["java:spring"]["condition"] == "forge"
        assert data["java:spring"]["run_index"] == 0
