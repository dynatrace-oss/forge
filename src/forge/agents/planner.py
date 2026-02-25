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

import json
import logging
from typing import Any

from forge.agents.base import AgentConfig, BaseAgent
from forge.pipeline.llm_client import LLMClient
from forge.tools.base import safe_json_loads

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """Planner Agent -- pure reasoning agent, no tools.

    Receives the Intel Agent's report and produces a structured
    attack plan with primary strategy, escalation paths, and fallbacks.
    The Exploit Agent uses this plan to guide its exploitation loop.
    """

    def __init__(
        self,
        llm: LLMClient,
        config: AgentConfig,
        *,
        cost_budget: float = 0.0,
    ) -> None:
        super().__init__(config, llm, cost_budget=cost_budget)

    def format_input(self, input_data: dict[str, Any]) -> str:
        """Format the intel report as the planner's input message."""
        intel_report = input_data.get("intel_report", {})

        lines = ["Create an attack plan based on this intelligence report:", ""]

        if isinstance(intel_report, dict):
            cve_id = intel_report.get("cve_id", "unknown")
            lines.append(f"CVE: {cve_id}")

            root_cause = intel_report.get("root_cause", "")
            if root_cause:
                lines.append(f"Root cause: {root_cause}")

            cwe_ids = intel_report.get("cwe_ids", [])
            if cwe_ids:
                lines.append(f"CWE: {', '.join(str(c) for c in cwe_ids)}")

            attack_surface = intel_report.get("attack_surface", {})
            if attack_surface:
                endpoints = attack_surface.get("endpoints", [])
                if endpoints:
                    lines.append(f"Endpoints: {', '.join(str(e) for e in endpoints)}")
                inputs = attack_surface.get("inputs", [])
                if inputs:
                    lines.append(f"Input vectors: {', '.join(str(i) for i in inputs)}")

            patch_analysis = intel_report.get("patch_analysis", {})
            if patch_analysis:
                lines.append(f"\nPatch analysis: {json.dumps(patch_analysis, indent=2)}")

            tech_stack = intel_report.get("tech_stack", {})
            if tech_stack:
                lines.append(f"\nTech stack: {json.dumps(tech_stack, indent=2)}")

            existing_pocs = intel_report.get("existing_pocs", [])
            if existing_pocs:
                lines.append(f"\nExisting PoCs: {json.dumps(existing_pocs, indent=2)}")
        else:
            lines.append(str(intel_report))

        # Inject prior knowledge from the KB (CWE knowledge, learnings,
        # cross-CVE intelligence) so the planner can reference known
        # escalation paths and technique success rates.
        prior = input_data.get("prior_knowledge", "")
        if prior:
            lines.append(f"\nPrior Knowledge (from previous CVE assessments):\n{prior}")

        lines.append(
            "\nProduce a JSON attack plan with: primary_strategy, "
            "escalation_paths, fallback_strategies, key_targets, estimated_difficulty."
        )
        return "\n".join(lines)

    def parse_output(self, content: str) -> dict[str, Any]:
        """Parse the planner's output into a structured attack plan."""
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                parsed: dict[str, Any] = safe_json_loads(content[start:end])
                return parsed
        except ValueError:
            pass

        return {"raw_output": content}
