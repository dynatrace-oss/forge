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
