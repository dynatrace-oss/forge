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
