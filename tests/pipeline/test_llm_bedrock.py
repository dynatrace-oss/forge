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
