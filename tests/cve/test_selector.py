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

from forge.cve.selector import DiversitySelector
from forge.models import CVESource, CWETag, PatchCommit


def _make_entry(
    cve_id: str,
    cwe_id: str = "CWE-79",
    *,
    filename: str = "app.py",
) -> CVESource:
    """Build a minimal ``CVESource`` for selector tests."""
    return CVESource(
        cve_id=cve_id,
        description=f"Test entry {cve_id}",
        cwes=[CWETag(id=cwe_id, value=cwe_id)],
        patch_commits=[
            PatchCommit(
                url=f"https://github.com/owner/repo/commit/{cve_id}",
                diff_content=f"Filename: src/{filename}:\n@@ -1,1 +1,2 @@\n",
            ),
        ],
    )


def _make_pool() -> list[CVESource]:
    """Create a 20-entry pool with varied CWEs and languages."""
    entries: list[CVESource] = []
    cwes = ["CWE-79"] * 8 + ["CWE-89"] * 5 + ["CWE-22"] * 4 + ["CWE-78"] * 3
    files = (
        ["views.js"] * 4
        + ["views.py"] * 4  # CWE-79
        + ["db.py"] * 3
        + ["db.php"] * 2  # CWE-89
        + ["fs.go"] * 2
        + ["fs.rb"] * 2  # CWE-22
        + ["cmd.java"] * 2
        + ["cmd.py"] * 1  # CWE-78
    )
    for i, (cwe, fn) in enumerate(zip(cwes, files, strict=True)):
        entries.append(_make_entry(f"CVE-2024-{i:04d}", cwe, filename=fn))
    return entries


class TestDiversitySelector:
    def test_determinism_same_seed(self) -> None:
        pool = _make_pool()
        s1 = DiversitySelector(seed=42).select(pool, count=10)
        s2 = DiversitySelector(seed=42).select(pool, count=10)
        assert [e.cve_id for e in s1] == [e.cve_id for e in s2]

    def test_stratification_covers_top_cwes(self) -> None:
        pool = _make_pool()
        selected = DiversitySelector(seed=42).select(pool, count=15)
        selected_cwes = {e.cwes[0].id for e in selected}
        # All 4 CWE types should be represented.
        assert selected_cwes == {"CWE-79", "CWE-89", "CWE-22", "CWE-78"}

    def test_pool_smaller_than_count_returns_all(self) -> None:
        pool = _make_pool()
        selected = DiversitySelector(seed=42).select(pool, count=100)
        assert len(selected) == len(pool)
