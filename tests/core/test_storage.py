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

import pytest

from forge.config import PathsConfig
from forge.storage import StorageManager


@pytest.fixture()
def storage(tmp_path: Path) -> StorageManager:
    return StorageManager(
        results=tmp_path / "results",
        generated_apps=tmp_path / "generated-apps",
        knowledge=tmp_path / "knowledge",
        cache=tmp_path / "cache",
        prompts=tmp_path / "prompts",
    )


class TestStorageManager:
    @pytest.mark.parametrize(
        ("method_name", "arg", "expected_name", "parent_attr"),
        [
            pytest.param("results_dir", "CVE-2024-1234", "CVE-2024-1234", "results", id="results"),
        ],
    )
    def test_subdir(
        self,
        storage: StorageManager,
        method_name: str,
        arg: str,
        expected_name: str,
        parent_attr: str,
    ) -> None:
        path = getattr(storage, method_name)(arg)
        assert path.name == expected_name
        assert path.parent == getattr(storage, parent_attr)

    def test_cache_dir(self, storage: StorageManager) -> None:
        assert storage.cache_dir() == storage.cache

    def test_from_config(self, tmp_path: Path) -> None:
        paths = PathsConfig(
            results=str(tmp_path / "r"),
            generated_apps=str(tmp_path / "g"),
            knowledge=str(tmp_path / "k"),
            cache=str(tmp_path / "c"),
            prompts=str(tmp_path / "p"),
        )
        sm = StorageManager.from_config(paths)
        assert sm.results == tmp_path / "r"
        assert sm.generated_apps == tmp_path / "g"
        assert sm.knowledge == tmp_path / "k"
        assert sm.cache == tmp_path / "c"
        assert sm.prompts == tmp_path / "p"
