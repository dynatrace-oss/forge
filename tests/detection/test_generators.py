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

from unittest.mock import AsyncMock

import pytest

from forge.detection.models import ConfidenceTier, ExploitArtifacts, HttpExchange
from forge.detection.sigma_gen import (
    SigmaGenerator,
    _parse_sigma_response,
)
from forge.detection.snort_gen import (
    SnortGenerator,
)
from forge.models import TokenUsage
from forge.pipeline.prompt_engine import PromptEngine


@pytest.fixture()
def sample_artifacts() -> ExploitArtifacts:
    return ExploitArtifacts(
        cve_id="CVE-2024-1234",
        cwe_id="CWE-79",
        exploitation_level=3,
        confidence_tier=ConfidenceTier.MEDIUM,
        http_exchanges=[
            HttpExchange(
                method="POST",
                url="http://localhost:8080/search",
                status_code=200,
                request_body="q=<script>alert(1)</script>",
            ),
        ],
        payloads=["# exploit.py\nrequests.post(...)"],
        log_patterns=["ERROR: XSS payload detected"],
    )


@pytest.fixture()
def prompts() -> PromptEngine:
    return PromptEngine()


@pytest.mark.anyio()
async def test_sigma_generator_generate(
    sample_artifacts: ExploitArtifacts,
    prompts: PromptEngine,
) -> None:
    mock_llm = AsyncMock()
    mock_response = (
        "```yaml\ntitle: CVE-2024-1234 XSS\nid: 12345678-1234-1234-1234-123456789abc\n"
        "status: experimental\nlogsource:\n  category: webserver\ndetection:\n"
        '  selection:\n    cs-uri-query|contains: "<script>"\n  condition: selection\n'
        "level: medium\n```"
    )
    mock_llm.chat = AsyncMock(
        return_value=(mock_response, TokenUsage(prompt_tokens=100, completion_tokens=50))
    )

    gen = SigmaGenerator(mock_llm, prompts)
    rule, tokens = await gen.generate(sample_artifacts)

    assert rule.cve_id == "CVE-2024-1234"
    assert "CVE-2024-1234 XSS" in rule.raw_rule
    assert tokens.prompt_tokens == 100
    mock_llm.chat.assert_called_once()


def test_parse_sigma_response(sample_artifacts: ExploitArtifacts) -> None:
    response = (
        "```yaml\ntitle: Test Rule\nlogsource:\n  product: web\n"
        "detection:\n  selection:\n    field: value\n  condition: selection\n"
        "level: medium\n```"
    )
    rule = _parse_sigma_response(response, sample_artifacts)
    assert rule.cve_id == "CVE-2024-1234"
    assert rule.cwe_id == "CWE-79"
    assert rule.sigma_level == "medium"
    assert rule.confidence_tier == ConfidenceTier.MEDIUM
    assert "title: Test Rule" in rule.raw_rule


@pytest.mark.anyio()
async def test_snort_generator_generate(
    sample_artifacts: ExploitArtifacts,
    prompts: PromptEngine,
) -> None:
    mock_llm = AsyncMock()
    mock_response = (
        "```\nalert http $EXTERNAL_NET any -> $HOME_NET any "
        '(msg:"ET EXPLOIT CVE-2024-1234"; flow:established,to_server; '
        'http.uri; content:"/search"; fast_pattern; '
        'http.content_type; content:"application/x-www-form-urlencoded"; '
        'content:"<script>"; sid:9000001; rev:1;)\n```'
    )
    mock_llm.chat = AsyncMock(
        return_value=(mock_response, TokenUsage(prompt_tokens=80, completion_tokens=60))
    )

    gen = SnortGenerator(mock_llm, prompts)
    rule, tokens = await gen.generate(sample_artifacts)

    assert rule.cve_id == "CVE-2024-1234"
    assert "ET EXPLOIT" in rule.raw_rule
    assert tokens.completion_tokens == 60
    mock_llm.chat.assert_called_once()
