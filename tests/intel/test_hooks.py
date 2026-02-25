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

import pytest

from forge.intel.cache import RawCache, SourceType
from forge.intel.compiler import ReportCompiler
from forge.intel.hooks import IntelHooks
from forge.intel.knowledge import KnowledgeStore
from forge.models import CVETask


@pytest.fixture()
def intel_stack(tmp_path):
    cache = RawCache(cache_dir=tmp_path / "raw")
    compiler = ReportCompiler(cache, compiled_dir=tmp_path / "compiled")
    knowledge = KnowledgeStore(knowledge_dir=tmp_path / "knowledge")
    hooks = IntelHooks(cache, compiler, knowledge)
    return cache, compiler, knowledge, hooks


@pytest.fixture()
def sample_task():
    return CVETask(
        cve_id="CVE-2024-1234",
        cwe_ids=["CWE-79", "CWE-89"],
        description="Test vulnerability",
        vulnerable_package="django",
        vulnerable_version="4.1.0",
    )


class TestIntelHooks:
    def test_on_cve_load_with_cached_data(self, intel_stack, sample_task):
        cache, _, _, hooks = intel_stack
        cache.put(
            SourceType.NVD,
            "CVE-2024-1234",
            {
                "description": "test",
                "cwe_ids": ["CWE-79"],
                "severity": "high",
                "cvss_score": 7.5,
            },
        )
        result = hooks.on_cve_load(sample_task)
        assert result is not None
        assert result.cve_id == "CVE-2024-1234"
        assert "nvd" in result.sources_used

    def test_on_cve_load_returns_none_when_empty(self, intel_stack, sample_task):
        """Empty store returns None — Intel Agent must gather data."""
        _, _, _, hooks = intel_stack
        result = hooks.on_cve_load(sample_task)
        assert result is None

    def test_on_cve_load_recompiles_stale_tech_stack(self, intel_stack, sample_task):
        """Cached report with empty tech_stack is recompiled when raw data
        contains keywords that newer compiler tiers can infer from."""
        cache, compiler, _, hooks = intel_stack
        # Seed NVD cache with a description containing 'Django' keyword.
        cache.put(
            SourceType.NVD,
            "CVE-2024-1234",
            {
                "description": "A vulnerability in Django allows XSS",
                "cwe_ids": ["CWE-79"],
                "severity": "high",
                "cvss_score": 7.5,
            },
        )
        # First call compiles and saves the report.
        first = hooks.on_cve_load(sample_task)
        assert first is not None
        assert first.tech_stack.language == "python"

        # Simulate a stale cached report by overwriting the saved file
        # with an empty tech_stack (as if saved by older compiler code).
        first.tech_stack.language = ""
        first.tech_stack.framework = ""
        compiler.save(first)

        # Second call should detect the stale tech_stack and recompile.
        second = hooks.on_cve_load(sample_task)
        assert second is not None
        assert second.tech_stack.language == "python"

    def test_on_cve_load_keeps_cached_when_tech_present(self, intel_stack, sample_task):
        """Cached report with populated tech_stack is returned as-is."""
        cache, _, _, hooks = intel_stack
        cache.put(
            SourceType.NVD,
            "CVE-2024-1234",
            {
                "description": "A vulnerability in Flask",
                "cwe_ids": ["CWE-79"],
                "severity": "medium",
                "cvss_score": 5.0,
            },
        )
        first = hooks.on_cve_load(sample_task)
        assert first is not None
        assert first.tech_stack.language == "python"
        assert first.tech_stack.framework == "flask"

        # Second load returns the same cached report without recompiling.
        second = hooks.on_cve_load(sample_task)
        assert second is not None
        assert second.tech_stack.language == "python"
        assert second.tech_stack.framework == "flask"

    def test_on_exploit_complete_updates_knowledge(self, intel_stack, sample_task):
        _, _, knowledge, hooks = intel_stack
        hooks.on_exploit_complete(
            sample_task,
            max_level=3,
            techniques_used=["reflected XSS"],
        )
        # Both CWEs should have knowledge
        k79 = knowledge.get("CWE-79")
        k89 = knowledge.get("CWE-89")
        assert k79 is not None
        assert k89 is not None
        assert k79.total_attempts == 1
        assert k79.total_successes == 1
