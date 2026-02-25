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
import yaml

from forge.config import ForgeConfig, load_config


class TestForgeConfigDefaults:
    def test_default_config_has_all_agents(self) -> None:
        config = ForgeConfig()
        assert config.agents.intel.model == "gpt-4.1"
        assert config.agents.exploit.max_turns == 10  # default
        assert config.agents.planner.temperature == 0.0
        assert config.agents.detector.prompt_template == ""
        assert config.agents.generator.temperature == 0.0


class TestLoadConfigFromYaml:
    def test_loads_from_file(self, tmp_path: Path) -> None:
        data = {
            "agents": {
                "intel": {"model": "o3", "max_turns": 15},
                "exploit": {"max_turns": 50, "temperature": 0.1},
            },
            "budget": {"max_cost_per_cve": 10.0},
        }
        config_file = tmp_path / "forge.yaml"
        config_file.write_text(yaml.dump(data))
        config = load_config(config_file)

        assert config.agents.intel.model == "o3"
        assert config.agents.intel.max_turns == 15
        assert config.agents.exploit.max_turns == 50
        assert config.agents.exploit.temperature == 0.1
        assert config.budget.max_cost_per_cve == 10.0
        # Defaults for unspecified fields
        assert config.agents.planner.model == "gpt-4.1"

    def test_missing_file_uses_defaults(self, tmp_path: Path) -> None:
        config = load_config(tmp_path / "nonexistent.yaml")
        assert config.agents.intel.model == "gpt-4.1"
        assert config.budget.max_cost_per_cve == 5.0


@pytest.mark.parametrize(
    ("yaml_data", "env_var", "env_value", "accessor", "expected"),
    [
        pytest.param(
            {"agents": {"exploit": {"model": "gpt-4.1"}}},
            "FORGE_AGENT_EXPLOIT_MODEL",
            "claude-sonnet-4-20250514",
            lambda c: c.agents.exploit.model,
            "claude-sonnet-4-20250514",
            id="agent_model_override",
        ),
    ],
)
def test_env_var_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    yaml_data: dict,
    env_var: str,
    env_value: str,
    accessor: object,
    expected: object,
) -> None:
    config_file = tmp_path / "forge.yaml"
    config_file.write_text(yaml.dump(yaml_data))
    monkeypatch.setenv(env_var, env_value)
    config = load_config(config_file)
    assert callable(accessor)
    assert accessor(config) == expected
