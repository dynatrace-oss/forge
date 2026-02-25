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
