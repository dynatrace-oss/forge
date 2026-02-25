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
import re
from typing import Literal

from forge.detection.models import ConfidenceTier, ExploitArtifacts, SigmaRule
from forge.models import Message, TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.pipeline.prompt_engine import PromptEngine

logger = logging.getLogger(__name__)

_YAML_BLOCK_RE = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.DOTALL)

SigmaLevel = Literal["low", "medium", "high", "critical"]

_CONFIDENCE_TO_SIGMA_LEVEL: dict[ConfidenceTier, SigmaLevel] = {
    ConfidenceTier.LOW: "low",
    ConfidenceTier.MEDIUM: "medium",
    ConfidenceTier.HIGH: "high",
    ConfidenceTier.CRITICAL: "critical",
}


class SigmaGenerator:
    """Generate Sigma detection rules from exploitation artifacts via LLM."""

    def __init__(self, llm: LLMClient, prompts: PromptEngine) -> None:
        self._llm = llm
        self._prompts = prompts

    async def generate(
        self,
        artifacts: ExploitArtifacts,
    ) -> tuple[SigmaRule, TokenUsage]:
        """Generate a Sigma rule for the given exploitation artifacts.

        Args:
            artifacts: Structured exploitation artifacts.

        Returns:
            Tuple of (SigmaRule, token usage from LLM call).
        """
        context = _build_context(artifacts)

        system = self._prompts.render("detection/sigma_system")
        user = self._prompts.render("detection/sigma_user", **context)

        messages = [
            Message(role="system", content=system),
            Message(role="user", content=user),
        ]

        response, tokens = await self._llm.chat(
            messages,
            temperature=0.0,
            max_tokens=2048,
            phase="detection",
        )

        rule = _parse_sigma_response(response, artifacts)
        return rule, tokens


def _build_context(
    artifacts: ExploitArtifacts,
) -> dict[str, object]:
    """Build Jinja2 template context from artifacts."""
    return {
        "cve_id": artifacts.cve_id,
        "cwe_id": artifacts.cwe_id,
        "exploitation_level": artifacts.exploitation_level,
        "confidence_tier": artifacts.confidence_tier.value,
        "http_exchanges": [e.model_dump() for e in artifacts.http_exchanges],
        "file_artifacts": [f.model_dump() for f in artifacts.file_artifacts],
        "payloads": artifacts.payloads,
        "network_connections": artifacts.network_connections,
        "crash_signals": artifacts.crash_signals,
        "log_patterns": artifacts.log_patterns,
        "detection_indicators": [],
    }


def _parse_sigma_response(
    response: str,
    artifacts: ExploitArtifacts,
) -> SigmaRule:
    """Extract Sigma rule YAML from LLM response."""
    raw_rule = _extract_yaml_block(response)
    sigma_level = _CONFIDENCE_TO_SIGMA_LEVEL.get(artifacts.confidence_tier, "medium")

    return SigmaRule(
        cve_id=artifacts.cve_id,
        cwe_id=artifacts.cwe_id,
        title=f"Exploitation Attempt - {artifacts.cve_id}",
        description=f"Detects exploitation attempt for {artifacts.cve_id} ({artifacts.cwe_id})",
        confidence_tier=artifacts.confidence_tier,
        exploitation_level=artifacts.exploitation_level,
        raw_rule=raw_rule,
        sigma_level=sigma_level,
    )


def _extract_yaml_block(text: str) -> str:
    """Extract YAML content from a markdown code block."""
    match = _YAML_BLOCK_RE.search(text)
    if match:
        return match.group(1).strip()
    # Fallback: if no code block, treat entire response as YAML
    stripped = text.strip()
    if stripped.startswith("title:") or stripped.startswith("id:"):
        return stripped
    return stripped
