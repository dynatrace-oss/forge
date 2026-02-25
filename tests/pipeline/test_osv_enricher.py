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

from typing import Any

import httpx

from forge.models import CVETask
from forge.pipeline.osv_enricher import OSVEnricher

SAMPLE_OSV_RESPONSE: dict[str, Any] = {
    "id": "PYSEC-2024-1234",
    "aliases": ["CVE-2025-27520", "GHSA-33pc-xm42-35pf"],
    "summary": "BentoML deserialization vulnerability allows RCE",
    "details": "A deserialization issue in BentoML before 1.4.3...",
    "affected": [
        {
            "package": {"name": "bentoml", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.4.3"},
                    ],
                }
            ],
            "versions": ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.4.2"],
        }
    ],
    "references": [
        {"type": "FIX", "url": "https://github.com/bentoml/BentoML/commit/abc123"},
        {"type": "FIX", "url": "https://some-other.site/fix"},
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-33pc-xm42-35pf"},
        {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-27520"},
        {"type": "PACKAGE", "url": "https://pypi.org/project/bentoml/"},
    ],
    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
}


def _mock_transport(
    success_cves: dict[str, dict[str, Any]] | None = None,
    *,
    malformed: bool = False,
    timeout: bool = False,
) -> httpx.MockTransport:
    """Build a mock transport that routes by CVE ID in the URL path."""
    cve_map = success_cves or {}

    def handler(request: httpx.Request) -> httpx.Response:
        if timeout:
            raise httpx.TimeoutException("mock timeout")

        url_path = str(request.url)
        for cve_id, response_data in cve_map.items():
            if cve_id in url_path:
                if malformed:
                    return httpx.Response(200, text="<<<not json>>>")
                return httpx.Response(200, json=response_data)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _make_task(cve_id: str = "CVE-2025-27520") -> CVETask:
    return CVETask(cve_id=cve_id)


class TestEnrichOne:
    async def test_enrich_success(self) -> None:
        task = _make_task("CVE-2025-27520")
        transport = _mock_transport({"CVE-2025-27520": SAMPLE_OSV_RESPONSE})
        enricher = OSVEnricher()

        async with httpx.AsyncClient(transport=transport) as client:
            result = await enricher._enrich_one(client, task)

        assert result is True
        assert task.osv_id == "GHSA-33pc-xm42-35pf"
        assert task.advisory_summary == "BentoML deserialization vulnerability allows RCE"
        assert "<1.4.3" in task.affected_versions
        assert "1.4.3" in task.fix_versions
        assert task.fix_commit_url == "https://github.com/bentoml/BentoML/commit/abc123"
        assert "https://github.com/advisories/GHSA-33pc-xm42-35pf" in task.advisory_urls
        assert "https://nvd.nist.gov/vuln/detail/CVE-2025-27520" in task.advisory_urls
        assert "1.0.0" in task.affected_versions
        assert "1.4.2" in task.affected_versions
        # Ecosystem → language extraction (Phase 1: technology identification)
        assert task.language == "python"
        assert task.vulnerable_package == "bentoml"


class TestOsvContext:
    def test_enriched_task(self) -> None:
        task = _make_task()
        task.osv_id = "GHSA-33pc-xm42-35pf"
        task.affected_versions = ["<1.4.3"]
        task.fix_versions = ["1.4.3"]
        task.fix_commit_url = "https://github.com/bentoml/BentoML/commit/abc123"
        task.advisory_urls = ["https://github.com/advisories/GHSA-33pc-xm42-35pf"]
        task.advisory_summary = "RCE via deserialization"

        ctx = task.osv_context()
        assert ctx["osv_enriched"] is True
        assert ctx["affected_versions"] == ["<1.4.3"]
        assert ctx["fix_versions"] == ["1.4.3"]
        assert ctx["fix_commit_url"] == "https://github.com/bentoml/BentoML/commit/abc123"
        assert ctx["advisory_urls"] == ["https://github.com/advisories/GHSA-33pc-xm42-35pf"]
        assert ctx["advisory_summary"] == "RCE via deserialization"
