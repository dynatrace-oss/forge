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

from pathlib import Path

import pytest

from forge.pipeline.prompt_engine import PromptEngine

PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "prompts"


@pytest.fixture()
def engine() -> PromptEngine:
    return PromptEngine(PROMPTS_DIR)


class TestPromptEngineInit:
    def test_loads_agent_and_fragment_templates(self, engine: PromptEngine) -> None:
        prompts = engine.list_prompts()
        assert len(prompts) >= 5
        assert "agents/intel" in prompts
        assert "agents/exploit" in prompts
        assert "agents/planner" in prompts
        assert "agents/detector" in prompts
        assert "agents/generator" in prompts


class TestAgentPrompts:
    @pytest.mark.parametrize(
        ("template_name", "expected_keywords"),
        [
            pytest.param("agents/exploit", ["Exploit Agent", "exploitation_level"], id="exploit"),
        ],
    )
    def test_agent_prompt_renders(
        self, engine: PromptEngine, template_name: str, expected_keywords: list[str]
    ) -> None:
        result = engine.render(template_name)
        for keyword in expected_keywords:
            assert keyword in result


class TestPromptEngineRaw:
    def test_raw_returns_unrendered(self, engine: PromptEngine) -> None:
        raw = engine.raw("agents/intel")
        assert "Intel Agent" in raw


class TestPromptEngineHas:
    @pytest.mark.parametrize(
        ("template", "expected"),
        [
            pytest.param("agents/intel", True, id="existing"),
        ],
    )
    def test_has(self, engine: PromptEngine, template: str, expected: bool) -> None:
        assert engine.has(template) is expected
