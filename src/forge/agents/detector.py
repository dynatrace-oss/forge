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
from pathlib import Path
from typing import Any

import jinja2
import yaml

from forge.agents.base import AgentConfig, AgentResult, BaseAgent
from forge.config import BaseAgentSettings
from forge.models import CWEModule
from forge.pipeline.llm_client import LLMClient
from forge.signals.query import SpanQuery
from forge.tools.base import Tool, ToolRegistry, safe_json_loads
from forge.tools.detection_tools import register_detection_tools

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path("data/prompts/agents/detector.yaml")
_prompt_cache: dict[str, str] = {}


def _load_prompts() -> dict[str, str]:
    """Load detector prompt templates from YAML (cached after first call)."""
    if _prompt_cache:
        return _prompt_cache
    if not _PROMPT_PATH.exists():
        raise FileNotFoundError(f"Detector prompts not found: {_PROMPT_PATH}")
    with _PROMPT_PATH.open() as f:
        data: dict[str, Any] = yaml.safe_load(f)
    for key in ("final_json_message", "user_input", "continue_prompt", "cwe_context"):
        _prompt_cache[key] = str(data[key])
    return _prompt_cache


def _render(template_key: str, **context: Any) -> str:
    """Render a detector prompt template with Jinja2."""
    prompts = _load_prompts()
    env = jinja2.Environment(undefined=jinja2.Undefined)
    template = env.from_string(prompts[template_key])
    return template.render(**context).strip()


class DetectorAgent(BaseAgent):
    """Detector Agent — generates Sigma/Snort rules from OTEL spans.

    Only runs when exploitation reached L1+. Queries the SpanCollector
    for exploitation signals and uses templates + validation to produce
    detection rules.

    Accepts an optional ``CWEModule`` to inject CWE-specific detection
    guidance into the system prompt.
    """

    def __init__(
        self,
        llm: LLMClient,
        span_query: SpanQuery,
        config: AgentConfig,
        *,
        cwe_module: CWEModule | None = None,
        base_config: BaseAgentSettings | None = None,
        cost_budget: float = 0.0,
        detection_kb_dir: Path | None = None,
    ) -> None:
        registry = ToolRegistry()
        all_tools: list[Tool] = register_detection_tools(
            span_query,
            kb_dir=detection_kb_dir,
        )
        for tool in all_tools:
            registry.register(tool)

        super().__init__(config, llm, registry, base_config=base_config, cost_budget=cost_budget)
        self._span_query = span_query
        self._cwe_module = cwe_module
        self._detection_kb_dir = detection_kb_dir

        # Override the generic final JSON demand with a detector-specific one
        # so the last-chance demand at turn exhaustion names the exact keys.
        prompts = _load_prompts()
        self._base_config = self._base_config.model_copy(
            update={"final_json_message": prompts["final_json_message"]},
        )

        # If a CWE module is provided, inject CWE-specific context into
        # the system prompt so the detector gets targeted guidance.
        if cwe_module is not None:
            cwe_context = _build_cwe_context(
                cwe_module,
                detection_kb_dir=detection_kb_dir,
            )
            if cwe_context:
                self.config = config.model_copy(
                    update={"system_prompt": config.system_prompt + "\n\n" + cwe_context},
                )

    def format_input(self, input_data: dict[str, Any]) -> str:
        """Format the detector agent's input as a user message."""
        level = input_data.get("exploitation_level", 0)
        cve_id = self._span_query.cve_id
        total_spans = len(self._span_query.all_spans())

        cwe_ids = ""
        intel_report = input_data.get("intel_report")
        if intel_report and isinstance(intel_report, dict):
            cwe_list = intel_report.get("cwe_ids", [])
            if cwe_list:
                cwe_ids = ", ".join(str(c) for c in cwe_list)

        return _render(
            "user_input",
            cve_id=cve_id,
            level=level,
            total_spans=total_spans,
            cwe_ids=cwe_ids,
        )

    def parse_output(self, content: str) -> dict[str, Any]:
        """Parse the detector agent's final output."""
        result: dict[str, Any] = {"rules": []}

        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                parsed: dict[str, Any] = safe_json_loads(content[start:end])
                if "sigma_rule" in parsed:
                    result["sigma_rule"] = parsed["sigma_rule"]
                    result["rules"].append(parsed["sigma_rule"])
                if "snort_rule" in parsed:
                    result["snort_rule"] = parsed["snort_rule"]
                    result["rules"].append(parsed["snort_rule"])
                if "summary" in parsed:
                    result["summary"] = parsed["summary"]
        except ValueError:
            result["raw_output"] = content
            if "title:" in content:
                result["rules"].append(content)

        return result

    def should_stop(self, content: str) -> bool:
        """Only stop when the LLM produces JSON with detection rules."""
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = safe_json_loads(content[start:end])
                if "sigma_rule" in parsed or "snort_rule" in parsed:
                    return True
        except ValueError:
            pass
        return False

    def _get_continue_prompt(self) -> str:
        """Prompt the detector agent to produce structured JSON output."""
        return _load_prompts()["continue_prompt"]

    async def run(self, input_data: dict[str, Any]) -> AgentResult:
        """Run the detection rule generation loop."""
        result = await super().run(input_data)
        result.output["cve_id"] = self._span_query.cve_id
        result.output["trace_id"] = self._span_query.trace_id
        result.output["total_spans"] = len(self._span_query.all_spans())
        return result


def _build_cwe_context(
    cwe_module: CWEModule,
    *,
    detection_kb_dir: Path | None = None,
) -> str:
    """Build CWE-specific detection guidance from a CWEModule.

    Loads the detection strategy from the detection KB if available.
    """
    cwe_id = cwe_module.cwe_id
    cwe_name = cwe_module.cwe_name

    # Load detection strategy from KB if available
    detection_strategy = ""
    if detection_kb_dir is not None:
        cwe_num = cwe_id.upper().replace("CWE-", "")
        meta_path = detection_kb_dir / f"cwe-{cwe_num}" / "meta.yaml"
        if meta_path.exists():
            try:
                meta = yaml.safe_load(meta_path.read_text())
                detection_strategy = meta.get("detection_strategy", "")
            except (yaml.YAMLError, OSError):
                pass

    return _render(
        "cwe_context",
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        detection_strategy=detection_strategy,
    )
