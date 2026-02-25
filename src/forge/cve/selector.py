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
import math
import random
from collections import defaultdict

from forge.cve.loader import languages_from_patches
from forge.models import CVESource

logger = logging.getLogger(__name__)


class DiversitySelector:
    """Stratified diversity sampling from a CVE pool.

    Stratifies by CWE type × primary language × project type, then
    allocates slots proportionally to stratum size.
    """

    def __init__(self, seed: int = 42) -> None:
        self._seed = seed

    def select(
        self,
        pool: list[CVESource],
        count: int = 500,
        *,
        project_types: dict[str, str] | None = None,
    ) -> list[CVESource]:
        """Select a diverse subset stratified by CWE × language × project type.

        Args:
            pool: Full set of web-suitable CVE entries.
            count: Target number of entries to select.
            project_types: Optional repo-URL → category mapping
                (e.g. from ``results/project_types.json``).

        Returns:
            Deterministically selected subset in stable CVE-ID order.
        """
        if count >= len(pool):
            return sorted(pool, key=lambda e: e.cve_id)

        strata = self._build_strata(pool, project_types)
        selected = self._proportional_sample(strata, count)

        return sorted(selected, key=lambda e: e.cve_id)

    @staticmethod
    def _stratum_key(
        entry: CVESource,
        project_types: dict[str, str] | None,
    ) -> str:
        """Build a composite stratum key: ``CWE|language|project_type``."""
        # Primary CWE — first tag
        cwe = entry.cwes[0].id if entry.cwes else "NONE"

        # Primary language — most common from patches
        langs = languages_from_patches(entry.patch_commits)
        lang = min(langs) if langs else "Unknown"

        # Project type — look up first patch URL's repo
        ptype = "unknown"
        if project_types:
            ptype = _lookup_project_type(entry, project_types)

        return f"{cwe}|{lang}|{ptype}"

    def _build_strata(
        self,
        pool: list[CVESource],
        project_types: dict[str, str] | None,
    ) -> dict[str, list[CVESource]]:
        strata: dict[str, list[CVESource]] = defaultdict(list)
        for entry in pool:
            key = self._stratum_key(entry, project_types)
            strata[key].append(entry)
        logger.debug("Built %d strata from %d entries", len(strata), len(pool))
        return dict(strata)

    def _proportional_sample(
        self,
        strata: dict[str, list[CVESource]],
        count: int,
    ) -> list[CVESource]:
        """Allocate *count* slots proportionally across strata.

        Uses largest-remainder method (Hamilton's method) for fair
        integer allocation, then samples within each stratum.
        """
        total = sum(len(v) for v in strata.values())
        rng = random.Random(self._seed)

        # Compute ideal fractional allocation per stratum.
        allocations: dict[str, int] = {}
        remainders: list[tuple[str, float]] = []
        allocated = 0

        for key, entries in strata.items():
            ideal = (len(entries) / total) * count
            floor_val = math.floor(ideal)
            # Cannot allocate more than stratum size.
            floor_val = min(floor_val, len(entries))
            allocations[key] = floor_val
            allocated += floor_val
            # Only accrue remainder if stratum has capacity left.
            if floor_val < len(entries):
                remainders.append((key, ideal - floor_val))

        # Distribute remaining slots by largest remainder.
        remainders.sort(key=lambda x: -x[1])
        for key, _ in remainders:
            if allocated >= count:
                break
            if allocations[key] < len(strata[key]):
                allocations[key] += 1
                allocated += 1

        # Sample within each stratum.
        selected: list[CVESource] = []
        for key in sorted(strata.keys()):
            n = allocations[key]
            entries = strata[key]
            if n >= len(entries):
                selected.extend(entries)
            else:
                selected.extend(rng.sample(entries, n))

        return selected


def _lookup_project_type(
    entry: CVESource,
    project_types: dict[str, str],
) -> str:
    """Resolve the project type for a CVE from its patch commit URLs."""
    for pc in entry.patch_commits:
        url = pc.url
        # Extract "owner/repo" from GitHub URLs.
        parts = url.split("github.com/")
        if len(parts) < 2:
            continue
        segments = parts[1].split("/")
        if len(segments) >= 2:
            repo_key = f"{segments[0]}/{segments[1]}"
            if repo_key in project_types:
                return project_types[repo_key]
    return "unknown"
