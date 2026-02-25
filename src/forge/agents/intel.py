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

import logging
from typing import Any

from forge.agents.base import AgentConfig, BaseAgent
from forge.intel.cache import RawCache
from forge.intel.compiler import IntelReport, ReportCompiler
from forge.intel.hooks import IntelHooks
from forge.models import CVETask
from forge.pipeline.llm_client import LLMClient
from forge.sandbox.protocols import SandboxSession
from forge.tools.base import ToolRegistry, safe_json_loads
from forge.tools.intel_tools import register_intel_tools

logger = logging.getLogger(__name__)


class IntelAgent(BaseAgent):
    """Intel Agent — gathers CVE intelligence using 6 tools.

    Runs for up to ``config.max_turns`` turns, calling intel tools to
    populate the raw cache. After the agent finishes, the orchestrator
    calls ``IntelHooks.on_intel_complete()`` to compile the Tier 2 report.
    """

    def __init__(
        self,
        llm: LLMClient,
        cache: RawCache,
        compiler: ReportCompiler,
        hooks: IntelHooks,
        config: AgentConfig,
        *,
        session: SandboxSession | None = None,
        cost_budget: float = 0.0,
    ) -> None:
        registry = ToolRegistry()
        for tool in register_intel_tools(cache, session):
            registry.register(tool)

        super().__init__(config, llm, registry, cost_budget=cost_budget)

        self._compiler = compiler
        self._hooks = hooks

    def format_input(self, input_data: dict[str, Any]) -> str:
        """Format a CVETask dict as the initial user message."""
        cve_id = input_data.get("cve_id", "unknown")
        description = input_data.get("description", "")
        cwe_ids = input_data.get("cwe_ids", [])
        fix_commit_url = input_data.get("fix_commit_url", "")
        advisory_urls = input_data.get("advisory_urls", [])

        lines = [f"Assess CVE: {cve_id}"]

        if description:
            lines.append(f"\nDescription: {description}")
        if cwe_ids:
            lines.append(f"CWE: {', '.join(cwe_ids)}")
        if fix_commit_url:
            lines.append(f"Fix commit: {fix_commit_url}")
        if advisory_urls:
            lines.append(f"Advisories: {', '.join(advisory_urls)}")

        lines.append(
            "\nGather intelligence using your tools, then output a JSON summary of your findings."
        )
        return "\n".join(lines)

    def parse_output(self, content: str) -> dict[str, Any]:
        """Parse the agent's final text output into structured data."""
        try:
            # Try to extract JSON from the output
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                result: dict[str, Any] = safe_json_loads(content[start:end])
                return result
        except (ValueError):
            pass

        return {"raw_output": content}

    def should_stop(self, content: str) -> bool:
        """Accept output if it contains JSON or if enough tools were used.

        Intel Agent is less strict than Exploit/Detector — we accept
        any JSON output or allow stopping after 3+ tool calls (it has
        gathered meaningful data at that point).
        """
        # Always accept if we have structured JSON output
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                safe_json_loads(content[start:end])
                return True
        except (ValueError):
            pass
        # Accept if we've gathered enough raw data (3+ tool calls)
        return len(self._tool_calls) >= 3

    def _get_continue_prompt(self) -> str:
        """Prompt the intel agent to keep gathering data."""
        return (
            "You haven't gathered enough intelligence yet. "
            "Continue using your tools: try fetch_cve_advisory, "
            "search_exploit_db, analyze_container, or discover_tech_stack. "
            "When done, output a JSON summary of your findings."
        )

    def compile_report(self, task: CVETask) -> IntelReport:
        """Compile the Tier 2 report after the agent has run.

        Called by the orchestrator after ``run()`` completes. Uses
        the hooks to compile from cached raw data.
        """
        return self._hooks.on_intel_complete(task)
