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

import pytest

from forge.pipeline.llm_client import (
    LLMClient,
    _estimate_cost,
    _extract_provider_prefix,
    _get_context_limit,
    _is_reasoning_model,
)


class TestBedrockProviderPrefix:
    @pytest.mark.parametrize(
        ("model", "expected_prefix"),
        [
            pytest.param(
                "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                "bedrock",
                id="bedrock-sonnet",
            ),
            pytest.param(
                "bedrock/us.meta.llama4-maverick-17b-instruct-v1:0",
                "bedrock",
                id="bedrock-llama-maverick",
            ),
            pytest.param(
                "bedrock/mistral.mistral-large-2402-v1:0",
                "bedrock",
                id="bedrock-mistral",
            ),
        ],
    )
    def test_extract_prefix_bedrock(self, model: str, expected_prefix: str) -> None:
        assert _extract_provider_prefix(model) == expected_prefix


class TestBedrockResolveModel:
    def test_bare_model_gets_bedrock_prefix(self) -> None:
        client = LLMClient(
            "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            enable_otel=False,
        )
        resolved = client._resolve_model("us.anthropic.claude-haiku-4-5-20251001-v1:0")
        assert resolved == "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"

    def test_qualified_model_unchanged(self) -> None:
        client = LLMClient(
            "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            enable_otel=False,
        )
        model = "bedrock/us.meta.llama4-scout-17b-instruct-v1:0"
        assert client._resolve_model(model) == model


class TestBedrockCostLookup:
    def test_sonnet_cost(self) -> None:
        cost = _estimate_cost(
            "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            prompt_tokens=1_000_000,
            completion_tokens=1_000_000,
        )
        # $3.00/1M input + $15.00/1M output = $18.00
        assert cost == pytest.approx(18.0, abs=0.01)

    def test_haiku_cost(self) -> None:
        cost = _estimate_cost(
            "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
            prompt_tokens=1_000_000,
            completion_tokens=1_000_000,
        )
        # $1.00/1M input + $5.00/1M output = $6.00
        assert cost == pytest.approx(6.0, abs=0.01)

    def test_llama_maverick_cost(self) -> None:
        cost = _estimate_cost(
            "bedrock/us.meta.llama4-maverick-17b-instruct-v1:0",
            prompt_tokens=1_000_000,
            completion_tokens=1_000_000,
        )
        # $0.50/1M input + $0.77/1M output = $1.27
        assert cost == pytest.approx(1.27, abs=0.01)


class TestBedrockContextWindow:
    def test_sonnet_context(self) -> None:
        assert _get_context_limit("bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0") == 200_000

    def test_llama_scout_context(self) -> None:
        assert _get_context_limit("bedrock/us.meta.llama4-scout-17b-instruct-v1:0") == 10_000_000

    def test_llama_maverick_context(self) -> None:
        assert _get_context_limit("bedrock/us.meta.llama4-maverick-17b-instruct-v1:0") == 1_000_000

    def test_mistral_context(self) -> None:
        assert _get_context_limit("bedrock/mistral.mistral-large-2402-v1:0") == 128_000


class TestBedrockNotReasoningModel:
    @pytest.mark.parametrize(
        "model",
        [
            pytest.param(
                "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                id="bedrock-sonnet",
            ),
            pytest.param(
                "bedrock/us.meta.llama4-maverick-17b-instruct-v1:0",
                id="bedrock-llama",
            ),
            pytest.param(
                "bedrock/mistral.mistral-large-2402-v1:0",
                id="bedrock-mistral",
            ),
        ],
    )
    def test_bedrock_models_not_reasoning(self, model: str) -> None:
        assert _is_reasoning_model(model) is False
