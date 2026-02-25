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
