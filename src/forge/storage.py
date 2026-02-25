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

import logging
from pathlib import Path

from pydantic import BaseModel

from forge.config import PathsConfig

logger = logging.getLogger(__name__)


class StorageManager(BaseModel):
    """Configurable base paths for all FORGE data artifacts.

    Reads paths from ``ForgeConfig.paths`` (a ``PathsConfig`` instance).
    All paths are relative to a configurable base directory.
    """

    results: Path = Path("data/results")
    generated_apps: Path = Path("data/generated-apps")
    knowledge: Path = Path("data/knowledge")
    cache: Path = Path("data/cache")
    prompts: Path = Path("data/prompts")

    @classmethod
    def from_config(cls, paths: PathsConfig) -> "StorageManager":
        """Create a StorageManager from a ``PathsConfig`` instance."""
        return cls(
            results=Path(paths.results),
            generated_apps=Path(paths.generated_apps),
            knowledge=Path(paths.knowledge),
            cache=Path(paths.cache),
            prompts=Path(paths.prompts),
        )

    def results_dir(self, cve_id: str) -> Path:
        """Return ``data/results/CVE-XXXX-XXXX/``."""
        return self.results / cve_id

    def generated_app_dir(self, cve_id: str) -> Path:
        """Return ``data/generated-apps/CVE-XXXX-XXXX/``."""
        return self.generated_apps / cve_id

    # Knowledge sub-directories

    def knowledge_dir(self, kind: str) -> Path:
        """Return ``data/knowledge/{kind}/``.

        Supported kinds: cookbook, detection, experience, exploitation,
        learnings, graph.
        """
        return self.knowledge / kind

    def cache_dir(self) -> Path:
        """Return ``data/cache/``."""
        return self.cache

    def ensure_dirs(self) -> None:
        """Create the full directory tree for all storage paths."""
        dirs = [
            self.results,
            self.generated_apps,
            self.knowledge_dir("exploitation"),
            self.knowledge_dir("learnings"),
            self.knowledge_dir("experience"),
            self.cache,
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
        logger.debug("Ensured storage directories exist under %s", self.results.parent)
