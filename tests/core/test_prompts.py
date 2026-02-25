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
