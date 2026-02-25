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
