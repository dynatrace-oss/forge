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

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("data/config/forge.yaml")


class AgentSettings(BaseModel):
    """Per-agent settings from forge.yaml.

    ``max_continues`` and ``max_nudges`` override the global
    ``BaseAgentSettings`` values when set.  ``None`` means inherit
    from the global ``base_agent`` section.
    """

    model: str = "gpt-4.1"
    max_turns: int = 10
    temperature: float = 0.0
    prompt_template: str = ""
    max_continues: int | None = None
    max_nudges: int | None = None
    max_tokens: int = 4096
    """Maximum output tokens per LLM call.  Raise for agents that
    produce large tool payloads (e.g. generator writing full projects)."""
    max_generation_attempts: int = 2
    """Maximum build-verify-retry cycles for the generator agent.
    Only used by GeneratorAgent; ignored for other agents."""


class AgentsConfig(BaseModel):
    """All agent settings."""

    intel: AgentSettings = Field(default_factory=AgentSettings)
    generator: AgentSettings = Field(default_factory=AgentSettings)
    planner: AgentSettings = Field(default_factory=AgentSettings)
    exploit: AgentSettings = Field(default_factory=AgentSettings)
    detector: AgentSettings = Field(default_factory=AgentSettings)


class BaseAgentSettings(BaseModel):
    """Shared base-agent turn-loop settings."""

    max_nudges: int = 2
    max_continues: int = 5
    nudge_message: str = (
        "You MUST use your tools to make progress. Do not respond with text \u2014 call a tool."
    )
    continue_message: str = "Continue working on the task. Use your tools to make progress."
    final_json_message: str = "Provide your final assessment as JSON with the required fields."

    def with_overrides(self, agent_settings: AgentSettings) -> "BaseAgentSettings":
        """Return a copy with per-agent overrides applied.

        Only overrides fields that are explicitly set (not None) on
        the agent settings. Fields left as None inherit from the
        global base_agent defaults.
        """
        overrides: dict[str, Any] = {}
        if agent_settings.max_continues is not None:
            overrides["max_continues"] = agent_settings.max_continues
        if agent_settings.max_nudges is not None:
            overrides["max_nudges"] = agent_settings.max_nudges
        if not overrides:
            return self
        return self.model_copy(update=overrides)


class ResourceLimits(BaseModel):
    """Container resource limits."""

    memory: str = "2g"
    cpus: int = 2


class SandboxConfig(BaseModel):
    """Sandbox execution settings."""

    health_check_retries: int = 3
    default_timeout: int = 120
    """Default timeout (seconds) for podman commands and sandbox operations."""
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)


class BudgetConfig(BaseModel):
    """Cost-cap settings."""

    max_cost_per_cve: float = 5.0


class LLMConfig(BaseModel):
    """Global LLM call settings (retry behaviour, etc.)."""

    max_retries: int = 3
    """Maximum retries on transient API errors (429, 5xx)."""
    base_retry_delay: float = 2.0
    """Base delay in seconds for exponential backoff between retries."""


class CacheConfig(BaseModel):
    """Intel cache settings."""

    ttl_seconds: int = 7 * 24 * 3600
    """Default cache TTL in seconds (default: 7 days = 604800)."""


class ResolverConfig(BaseModel):
    """LLM-based package resolver settings."""

    model: str = "bedrock/us.meta.llama4-maverick-17b-instruct-v1:0"
    """Model for package resolution LLM calls."""

    max_turns: int = 2
    """Maximum LLM turns (1 = direct answer, 2 = allows one web search)."""


class OracleConfig(BaseModel):
    """Oracle settings — LLM critic model for Tier 2 evaluation."""

    critic_model: str = "gpt-5-mini"


class CoachingConfig(BaseModel):
    """Coaching trigger thresholds — loaded from forge.yaml coaching section."""

    stuck_at_l0_turns: int = 8
    stuck_at_l1_l2_turns: int = 3
    stuck_at_l2_l3_turns: int = 4
    consecutive_error_turns: int = 3
    max_coaching_repeats: int = 3
    grace_turns_after_l3: int = 3
    grace_turns_after_l2: int = 5


class PathsConfig(BaseModel):
    """Directory paths for data artifacts."""

    results: str = "data/results"
    generated_apps: str = "data/generated-apps"
    knowledge: str = "data/knowledge"
    cache: str = "data/cache"
    prompts: str = "data/prompts"


class ForgeConfig(BaseModel):
    """Root configuration for FORGE — loaded from forge.yaml."""

    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    base_agent: BaseAgentSettings = Field(default_factory=BaseAgentSettings)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    coaching: CoachingConfig = Field(default_factory=CoachingConfig)
    oracle: OracleConfig = Field(default_factory=OracleConfig)
    resolver: ResolverConfig = Field(default_factory=ResolverConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)


def load_config(path: Path | None = None) -> ForgeConfig:
    """Load ForgeConfig from a YAML file.

    Resolution order for the config path:
    1. Explicit *path* argument.
    2. ``FORGE_CONFIG_PATH`` environment variable.
    3. Default ``data/config/forge.yaml``.

    After loading the YAML, individual fields may be overridden via
    environment variables (e.g. ``FORGE_AGENT_EXPLOIT_MODEL``).
    """
    config_path = path or Path(os.environ.get("FORGE_CONFIG_PATH", str(DEFAULT_CONFIG_PATH)))

    if config_path.exists():
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
        logger.info("Loaded config from %s", config_path)
    else:
        logger.warning("Config file not found at %s, using defaults", config_path)
        raw = {}

    config = ForgeConfig.model_validate(raw)
    _apply_env_overrides(config)
    return config


def _apply_env_overrides(config: ForgeConfig) -> None:
    """Override config fields from environment variables.

    Supported overrides:
    - ``FORGE_AGENT_{NAME}_MODEL`` — per-agent model name
    - ``FORGE_BUDGET_MAX_COST`` — max cost per CVE
    """
    agent_names = ["intel", "generator", "planner", "exploit", "detector"]
    for name in agent_names:
        env_key = f"FORGE_AGENT_{name.upper()}_MODEL"
        env_val = os.environ.get(env_key)
        if env_val:
            getattr(config.agents, name).model = env_val
            logger.info("Override %s = %s", env_key, env_val)

    cost_override = os.environ.get("FORGE_BUDGET_MAX_COST")
    if cost_override:
        config.budget.max_cost_per_cve = float(cost_override)
        logger.info("Override FORGE_BUDGET_MAX_COST = %s", cost_override)
