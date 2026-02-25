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
import logging
import time
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path("data/cache")
DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 days


class SourceType(StrEnum):
    """Types of raw intelligence sources stored in cache."""

    NVD = "nvd"
    GITHUB_ADVISORY = "github-advisory"
    PATCH_DIFF = "patch-diff"
    EXPLOIT_DB = "exploitdb"
    CONTAINER_INFO = "container-info"
    TECH_STACK = "tech-stack"
    SOURCE_FILE = "source-file"


class CacheEntry(BaseModel):
    """Metadata for a cached raw intelligence item."""

    source: SourceType
    key: str
    stored_at: float = Field(default_factory=time.time)
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    size_bytes: int = 0

    @property
    def expired(self) -> bool:
        return (time.time() - self.stored_at) > self.ttl_seconds


class RawCache:
    """Tier 1 raw intelligence cache with TTL-based expiration.

    Stores raw API responses (NVD JSON, advisories, patch diffs, etc.)
    on disk. Items are immutable once cached — a fresh fetch replaces
    expired entries entirely.

    Directory layout::

        data/cache/
            nvd/{cve_id}.json
            github-advisory/{cve_id}.json
            patch-diff/{cve_id}.patch
            exploitdb/{cve_id}.json
            container-info/{cve_id}.json
            tech-stack/{cve_id}.json
            source-file/{cve_id}/{filename}.json
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        *,
        default_ttl: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._dir = cache_dir or DEFAULT_CACHE_DIR
        self._default_ttl = default_ttl

    def get(self, source: SourceType, key: str) -> dict[str, Any] | None:
        """Retrieve a cached item if it exists and is not expired.

        Returns None if the item is missing or expired.
        """
        data_path = self._data_path(source, key)
        meta_path = self._meta_path(source, key)

        if not data_path.exists() or not meta_path.exists():
            return None

        try:
            entry = CacheEntry.model_validate_json(meta_path.read_text())
        except (ValueError, OSError):
            logger.warning("Corrupt cache metadata: %s", meta_path)
            return None

        if entry.expired:
            logger.debug("Cache expired: %s/%s", source, key)
            return None

        try:
            result: dict[str, Any] = json.loads(data_path.read_text())
            return result
        except (ValueError, OSError):
            logger.warning("Corrupt cache data: %s", data_path)
            return None

    def put(
        self,
        source: SourceType,
        key: str,
        data: dict[str, Any],
        *,
        ttl_seconds: int | None = None,
    ) -> Path:
        """Store a raw intelligence item in the cache.

        Returns the path to the stored data file.
        """
        data_path = self._data_path(source, key)
        meta_path = self._meta_path(source, key)

        data_path.parent.mkdir(parents=True, exist_ok=True)

        content = json.dumps(data, indent=2)
        data_path.write_text(content)

        entry = CacheEntry(
            source=source,
            key=key,
            ttl_seconds=ttl_seconds or self._default_ttl,
            size_bytes=len(content.encode()),
        )
        meta_path.write_text(entry.model_dump_json(indent=2))

        logger.debug(
            "Cached %s/%s (%d bytes, TTL=%ds)",
            source,
            key,
            entry.size_bytes,
            entry.ttl_seconds,
        )
        return data_path

    def has(self, source: SourceType, key: str) -> bool:
        """Check if a non-expired cache entry exists."""
        return self.get(source, key) is not None

    def invalidate(self, source: SourceType, key: str) -> bool:
        """Remove a cache entry. Returns True if it existed."""
        data_path = self._data_path(source, key)
        meta_path = self._meta_path(source, key)

        removed = False
        for path in (data_path, meta_path):
            if path.exists():
                path.unlink()
                removed = True

        if removed:
            logger.debug("Invalidated cache: %s/%s", source, key)
        return removed

    def list_keys(self, source: SourceType) -> list[str]:
        """List all non-expired keys for a given source type."""
        source_dir = self._dir / source.value
        if not source_dir.exists():
            return []

        keys: list[str] = []
        for meta_file in source_dir.glob("*.meta.json"):
            try:
                entry = CacheEntry.model_validate_json(meta_file.read_text())
                if not entry.expired:
                    keys.append(entry.key)
            except (ValueError, OSError):
                continue
        return sorted(keys)

    def _data_path(self, source: SourceType, key: str) -> Path:
        safe_key = key.replace("/", "_").replace("\\", "_")
        return self._dir / source.value / f"{safe_key}.json"

    def _meta_path(self, source: SourceType, key: str) -> Path:
        safe_key = key.replace("/", "_").replace("\\", "_")
        return self._dir / source.value / f"{safe_key}.meta.json"
