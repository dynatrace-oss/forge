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
