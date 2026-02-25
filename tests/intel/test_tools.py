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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forge.intel.cache import RawCache, SourceType
from forge.intel.compiler import ExistingPoC
from forge.tools.intel_tools import (
    _SKIP_PATTERNS,
    FetchCVEAdvisory,
    _filter_security_relevant,
    _parse_nvd_response,
)


@pytest.fixture()
def cache(tmp_path):
    return RawCache(cache_dir=tmp_path / "raw")


class TestParseNVDResponse:
    def test_full_response(self):
        raw = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"lang": "en", "value": "SQL injection in search"}],
                        "weaknesses": [
                            {
                                "description": [{"value": "CWE-89"}],
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                                }
                            ],
                        },
                        "references": [{"url": "https://example.com/advisory"}],
                    },
                }
            ],
        }
        result = _parse_nvd_response(raw, "CVE-2024-5678")
        assert result["description"] == "SQL injection in search"
        assert result["cwe_ids"] == ["CWE-89"]
        assert result["cvss_score"] == pytest.approx(9.8)
        assert result["severity"] == "critical"
        assert len(result["references"]) == 1


class TestFetchCVEAdvisory:
    @pytest.mark.asyncio()
    async def test_fetches_and_caches(self, cache):
        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"lang": "en", "value": "test vuln"}],
                        "weaknesses": [],
                        "metrics": {},
                        "references": [],
                    },
                }
            ],
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value=nvd_data)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("forge.tools.intel_tools.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            tool = FetchCVEAdvisory(cache)
            result = await tool.execute({"cve_id": "CVE-2024-9999"})

        assert not result.error
        data = json.loads(result.content)
        assert data["description"] == "test vuln"
        # Should be cached now
        assert cache.has(SourceType.NVD, "CVE-2024-9999")


class TestExistingPoCNullFields:
    """Regression test for BUG 1: GitHub API returns description=null."""

    @pytest.mark.parametrize(
        ("kwargs", "field", "expected"),
        [
            pytest.param(
                {"source": "github", "url": "https://x", "description": None},
                "description",
                "",
                id="none_description",
            ),
        ],
    )
    def test_none_coerced_to_empty(self, kwargs, field, expected):
        poc = ExistingPoC(**kwargs)
        assert getattr(poc, field) == expected


class TestSkipPatterns:
    """Tests for _SKIP_PATTERNS filtering build artifacts."""

    @pytest.mark.parametrize(
        "path",
        [
            "web/dist/assets/index-50d6fa6f.js",
        ],
        ids=[
            "hashed-js",
        ],
    )
    def test_skips_build_artifacts(self, path: str) -> None:
        assert _SKIP_PATTERNS.search(path), f"Expected {path!r} to be skipped"

    @pytest.mark.parametrize(
        "path",
        [
            "src/auth/login.py",
        ],
        ids=["python-source"],
    )
    def test_keeps_source_files(self, path: str) -> None:
        assert not _SKIP_PATTERNS.search(path), f"Expected {path!r} to be kept"

    def test_filter_security_relevant_removes_artifacts(self) -> None:
        """_filter_security_relevant drops build artifacts but keeps source."""
        file_diffs = [
            ("web/dist/assets/index-50d6fa6f.js", ["-minified_code"]),
            ("web/src/views/SettingsView.vue", ["-real_code"]),
            ("node_modules/foo/bar.js", ["-dep_code"]),
        ]
        result = _filter_security_relevant(file_diffs)
        assert len(result) == 1
        assert result[0][0] == "web/src/views/SettingsView.vue"


class TestParseCPEFromNVD:
    """Test CPE extraction from NVD configurations block."""

    def test_extracts_vendor_product_version(self) -> None:
        raw = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"lang": "en", "value": "Struts RCE"}],
                        "weaknesses": [{"description": [{"value": "CWE-502"}]}],
                        "metrics": {},
                        "references": [],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "operator": "OR",
                                        "negate": False,
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:apache:struts"
                                                ":2.5.30:*:*:*:*:*:*:*",
                                            },
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:apache:struts"
                                                ":2.5.31:*:*:*:*:*:*:*",
                                            },
                                        ],
                                    }
                                ]
                            }
                        ],
                    },
                }
            ],
        }
        result = _parse_nvd_response(raw, "CVE-2023-50164")
        assert len(result["cpe_entries"]) == 1  # deduplicated by vendor:product
        entry = result["cpe_entries"][0]
        assert entry["vendor"] == "apache"
        assert entry["product"] == "struts"
        assert entry["version"] == "2.5.30"

    def test_empty_configurations(self) -> None:
        raw: dict[str, object] = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [],
                        "weaknesses": [],
                        "metrics": {},
                        "references": [],
                    },
                }
            ],
        }
        result = _parse_nvd_response(raw, "CVE-2024-0002")
        assert result["cpe_entries"] == []
