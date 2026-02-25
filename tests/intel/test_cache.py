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

import time

import pytest

from forge.intel.cache import CacheEntry, RawCache, SourceType


@pytest.fixture()
def cache(tmp_path):
    return RawCache(cache_dir=tmp_path / "raw", default_ttl=3600)


class TestRawCache:
    def test_put_and_get(self, cache):
        data = {"description": "test vulnerability", "severity": "high"}
        cache.put(SourceType.NVD, "CVE-2024-1234", data)
        result = cache.get(SourceType.NVD, "CVE-2024-1234")
        assert result == data

    def test_get_expired_returns_none(self, cache):
        data = {"test": True}
        cache.put(SourceType.NVD, "CVE-2024-5678", data, ttl_seconds=1)
        # Manually backdate the metadata
        meta_path = cache._meta_path(SourceType.NVD, "CVE-2024-5678")
        entry = CacheEntry.model_validate_json(meta_path.read_text())
        entry.stored_at = time.time() - 10
        meta_path.write_text(entry.model_dump_json())
        assert cache.get(SourceType.NVD, "CVE-2024-5678") is None
