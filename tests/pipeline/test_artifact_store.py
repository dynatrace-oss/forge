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
