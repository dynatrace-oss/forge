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
import re

from forge.detection.models import ConfidenceTier, ExploitArtifacts, SnortRule
from forge.models import Message, TokenUsage
from forge.pipeline.llm_client import LLMClient
from forge.pipeline.prompt_engine import PromptEngine

logger = logging.getLogger(__name__)

_RULE_BLOCK_RE = re.compile(r"```\s*\n?(alert\s+.*?)```", re.DOTALL)
_BARE_ALERT_RE = re.compile(r"^(alert\s+\S+\s+.+;)\s*$", re.MULTILINE)

_CONFIDENCE_TO_CLASSTYPE: dict[ConfidenceTier, str] = {
    ConfidenceTier.LOW: "web-application-attack",
    ConfidenceTier.MEDIUM: "web-application-attack",
    ConfidenceTier.HIGH: "attempted-admin",
    ConfidenceTier.CRITICAL: "successful-admin",
}

_SID_BASE = 9_000_000


class SnortGenerator:
    """Generate Snort/Suricata detection rules from exploitation artifacts via LLM."""

    def __init__(self, llm: LLMClient, prompts: PromptEngine) -> None:
        self._llm = llm
        self._prompts = prompts

    async def generate(
        self,
        artifacts: ExploitArtifacts,
        *,
        sid: int = 0,
    ) -> tuple[SnortRule, TokenUsage]:
        """Generate a Snort rule for the given exploitation artifacts.

        Args:
            artifacts: Structured exploitation artifacts.
            sid: Snort rule SID. If 0, auto-assigned from SID_BASE + hash.

        Returns:
            Tuple of (SnortRule, token usage from LLM call).
        """
        context = _build_context(artifacts)

        system = self._prompts.render("detection/snort_system")
        user = self._prompts.render("detection/snort_user", **context)

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

        rule_sid = sid or _auto_sid(artifacts.cve_id)
        rule = _parse_snort_response(response, artifacts, rule_sid)
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
        "payloads": artifacts.payloads,
        "network_connections": artifacts.network_connections,
        "crash_signals": artifacts.crash_signals,
        "detection_indicators": [],
    }


def _parse_snort_response(
    response: str,
    artifacts: ExploitArtifacts,
    sid: int,
) -> SnortRule:
    """Extract Snort rule from LLM response."""
    raw_rule = _extract_rule(response)
    classtype = _CONFIDENCE_TO_CLASSTYPE.get(artifacts.confidence_tier, "web-application-attack")

    return SnortRule(
        cve_id=artifacts.cve_id,
        cwe_id=artifacts.cwe_id,
        title=f"ET EXPLOIT {artifacts.cve_id} Exploitation Attempt",
        description=f"Detects network-level exploitation attempt for {artifacts.cve_id}",
        confidence_tier=artifacts.confidence_tier,
        exploitation_level=artifacts.exploitation_level,
        raw_rule=raw_rule,
        classtype=classtype,
        sid=sid,
    )


def _extract_rule(text: str) -> str:
    """Extract Snort rule from a markdown code block or bare text."""
    match = _RULE_BLOCK_RE.search(text)
    if match:
        return match.group(1).strip()
    bare = _BARE_ALERT_RE.search(text)
    if bare:
        return bare.group(1).strip()
    return text.strip()


def _auto_sid(cve_id: str) -> int:
    """Derive a deterministic SID from a CVE ID."""
    return _SID_BASE + (hash(cve_id) % 99_999)
