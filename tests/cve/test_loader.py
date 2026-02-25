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

from forge.cve.loader import CVEGENIELoader

# -- Fixtures ---------------------------------------------------------------

SAMPLE_DATASET: dict[str, object] = {
    "CVE-2024-1111": {
        "published_date": "2024-01-01T00:00:00.000Z",
        "description": "SQL injection in login form.",
        "cwe": [{"id": "CWE-89", "value": "SQL Injection"}],
        "patch_commits": [
            {
                "url": "https://github.com/owner/repo/commit/abc123",
                "content": "Filename: app/routes.py:\n@@ -10,3 +10,5 @@\n",
            }
        ],
        "sw_version": "1.0.0",
        "sw_version_wget": "https://github.com/owner/repo/archive/refs/tags/v1.0.0.zip",
        "sec_adv": [{"url": "https://advisory.example.com/1", "content": "Advisory text."}],
    },
    "CVE-2024-2222": {
        "published_date": "2024-02-01T00:00:00.000Z",
        "description": "Buffer overflow in native parser.",
        "cwe": [{"id": "CWE-787", "value": "Out-of-bounds Write"}],
        "patch_commits": [
            {
                "url": "https://github.com/owner/native/commit/def456",
                "content": "Filename: src/parser.c:\n@@ -1,3 +1,5 @@\n",
            }
        ],
        "sw_version": "2.0.0",
        "sw_version_wget": None,
        "sec_adv": [],
    },
    "CVE-2024-3333": {
        "published_date": "2024-03-01T00:00:00.000Z",
        "description": "XSS in comment form.",
        "cwe": [{"id": "CWE-79", "value": "Cross-site Scripting"}],
        "patch_commits": [
            {
                "url": "https://github.com/owner/web/commit/ghi789",
                "content": "Filename: views/comment.js:\n@@ -5,2 +5,4 @@\n",
            }
        ],
        "sw_version": "3.0.0",
        "sw_version_wget": None,
        "sec_adv": [],
    },
    "CVE-2024-4444": {
        "published_date": "2024-04-01T00:00:00.000Z",
        "description": "Unknown vuln with no CWE tag.",
        "cwe": [{"id": "n/a", "value": "n/a"}],
        "patch_commits": [],
        "sw_version": "",
        "sw_version_wget": None,
        "sec_adv": [],
    },
}


@pytest.fixture()
def sample_data_path(tmp_path: Path) -> Path:
    path = tmp_path / "cve_data.json"
    path.write_text(json.dumps(SAMPLE_DATASET), encoding="utf-8")
    return path


# -- Tests -------------------------------------------------------------------


class TestCVEGENIELoader:
    def test_load_all_parses_every_entry(self, sample_data_path: Path) -> None:
        loader = CVEGENIELoader(sample_data_path)
        entries = loader.load_all()
        assert len(entries) == 4

    def test_parse_entry_fields(self, sample_data_path: Path) -> None:
        loader = CVEGENIELoader(sample_data_path)
        entries = {e.cve_id: e for e in loader.load_all()}
        sql = entries["CVE-2024-1111"]

        assert sql.description == "SQL injection in login form."
        assert len(sql.cwes) == 1
        assert sql.cwes[0].id == "CWE-89"
        assert len(sql.patch_commits) == 1
        assert sql.patch_commits[0].url.endswith("abc123")
        assert sql.patch_commits[0].diff_content is not None
        assert sql.sw_version == "1.0.0"
        assert len(sql.security_advisories) == 1

    def test_load_web_suitable_excludes_native_and_no_cwe(
        self,
        sample_data_path: Path,
    ) -> None:
        loader = CVEGENIELoader(sample_data_path)
        filtered = loader.load_web_suitable()
        ids = {e.cve_id for e in filtered}

        # SQL injection (CWE-89, Python) and XSS (CWE-79, JS) pass.
        assert "CVE-2024-1111" in ids
        assert "CVE-2024-3333" in ids
        # Native-only buffer overflow (CWE-787, .c file) excluded.
        assert "CVE-2024-2222" not in ids
        # No valid CWE (n/a) excluded.
        assert "CVE-2024-4444" not in ids


class TestGetCwes:
    """Tests for CVEGENIELoader.get_cwes() per-CVE lookup."""

    @pytest.mark.parametrize(
        ("cve_id", "expected_len"),
        [
            pytest.param("CVE-2024-1111", 1, id="known_cve"),
        ],
    )
    def test_get_cwes(self, sample_data_path: Path, cve_id: str, expected_len: int) -> None:
        loader = CVEGENIELoader(sample_data_path)
        cwes = loader.get_cwes(cve_id)
        assert len(cwes) == expected_len
