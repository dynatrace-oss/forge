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

from unittest.mock import MagicMock

import pytest

from forge.agents.base import AgentConfig
from forge.agents.intel import IntelAgent
from forge.intel.cache import RawCache, SourceType
from forge.intel.compiler import ReportCompiler
from forge.intel.hooks import IntelHooks
from forge.intel.knowledge import KnowledgeStore
from forge.models import CVETask
from forge.pipeline.llm_client import LLMClient

_INTEL_CONFIG = AgentConfig(
    name="intel",
    system_prompt="Gather CVE intelligence.",
    max_turns=10,
)


@pytest.fixture()
def intel_stack(tmp_path):
    cache = RawCache(cache_dir=tmp_path / "raw")
    compiler = ReportCompiler(cache, compiled_dir=tmp_path / "compiled")
    knowledge = KnowledgeStore(knowledge_dir=tmp_path / "knowledge")
    hooks = IntelHooks(cache, compiler, knowledge)
    return cache, compiler, knowledge, hooks


@pytest.fixture()
def mock_llm():
    llm = MagicMock(spec=LLMClient)
    return llm


class TestIntelAgentParseOutput:
    def test_parse_json_output(self, mock_llm, intel_stack):
        cache, compiler, _, hooks = intel_stack
        agent = IntelAgent(mock_llm, cache, compiler, hooks, config=_INTEL_CONFIG)
        output = agent.parse_output(
            'Here is my analysis:\n{"root_cause": "unsanitized input", "confidence": 0.9}'
        )
        assert output["root_cause"] == "unsanitized input"


class TestIntelAgentCompileReport:
    def test_compile_report_delegates_to_hooks(self, mock_llm, intel_stack):
        cache, compiler, _, hooks = intel_stack
        cache.put(
            SourceType.NVD,
            "CVE-2024-1234",
            {"description": "test", "cwe_ids": ["CWE-89"], "severity": "high"},
        )
        agent = IntelAgent(mock_llm, cache, compiler, hooks, config=_INTEL_CONFIG)
        task = CVETask(cve_id="CVE-2024-1234", cwe_ids=["CWE-89"])
        report = agent.compile_report(task)
        assert report.cve_id == "CVE-2024-1234"
        assert "nvd" in report.sources_used
