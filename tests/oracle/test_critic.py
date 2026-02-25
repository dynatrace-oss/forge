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

"""Tests for the LLM oracle critic — verdict parsing, narrative stripping, integration."""

from unittest.mock import AsyncMock

import pytest

from forge.oracle.inline_oracle import DefaultInlineOracle
from forge.oracle.llm_critic import (
    LLMOracleCritic,
    _extract_fields_from_raw,
    _parse_verdict,
    _strip_narrative,
    _verdict_from_dict,
)
from forge.sandbox.models import SandboxSnapshot


class TestParseVerdict:
    def test_valid_json(self) -> None:
        raw = '{"level": 3, "confidence": 0.9, "reasoning": "RCE via exit code"}'
        v = _parse_verdict(raw)
        assert v.level == 3
        assert v.confidence == pytest.approx(0.9)
        assert "RCE" in v.reasoning


class TestVerdictFromDict:
    def test_all_fields(self) -> None:
        d = {"level": 2, "confidence": 0.8, "reasoning": "data leak"}
        v = _verdict_from_dict(d)
        assert v.level == 2
        assert v.confidence == pytest.approx(0.8)
        assert v.reasoning == "data leak"

    def test_defaults_for_missing_keys(self) -> None:
        v = _verdict_from_dict({})
        assert v.level == 0
        assert v.confidence == pytest.approx(0.5)
        assert v.reasoning == ""

    def test_string_level_converted(self) -> None:
        v = _verdict_from_dict({"level": "3", "confidence": "0.9"})
        assert v.level == 3
        assert v.confidence == pytest.approx(0.9)


class TestExtractFieldsFromRaw:
    def test_extracts_level_and_confidence(self) -> None:
        raw = '{"level": 2, "confidence": 0.85, "reasoning": "The attack...'
        v = _extract_fields_from_raw(raw)
        assert v is not None
        assert v.level == 2
        assert v.confidence == pytest.approx(0.85)
        assert v.reasoning == "recovered_from_truncated_response"

    def test_extracts_level_only(self) -> None:
        raw = '{"level": 3, ...'
        v = _extract_fields_from_raw(raw)
        assert v is not None
        assert v.level == 3
        assert v.confidence == pytest.approx(0.5)  # default when no confidence

    def test_returns_none_for_no_level(self) -> None:
        raw = "totally unparseable gibberish"
        assert _extract_fields_from_raw(raw) is None

    def test_handles_quoted_level(self) -> None:
        raw = '{"level": "2", "confidence": "0.7"}'
        v = _extract_fields_from_raw(raw)
        assert v is not None
        assert v.level == 2
        assert v.confidence == pytest.approx(0.7)


class TestParseVerdictTruncation:
    """Regression tests for Maverick Tier 2 critic truncated JSON."""

    def test_truncated_reasoning_recovered(self) -> None:
        raw = '{"level": 2, "confidence": 0.8, "reasoning": "The attacker successfully'
        v = _parse_verdict(raw)
        assert v.level == 2
        assert v.confidence == pytest.approx(0.8)

    def test_truncated_after_confidence(self) -> None:
        raw = '{"level": 3, "confidence": 0.9, "reasoning": "RCE via'
        v = _parse_verdict(raw)
        assert v.level == 3
        assert v.confidence == pytest.approx(0.9)

    def test_completely_broken_json_uses_field_regex(self) -> None:
        raw = (
            "Here is my analysis: level is 2, confidence 0.75. "
            '{"level": 2, "confidence": 0.75 extra junk'
        )
        v = _parse_verdict(raw)
        assert v.level == 2
        assert v.confidence == pytest.approx(0.75)

    def test_valid_json_still_works(self) -> None:
        raw = '{"level": 3, "confidence": 0.95, "reasoning": "Complete RCE"}'
        v = _parse_verdict(raw)
        assert v.level == 3
        assert v.confidence == pytest.approx(0.95)
        assert "Complete RCE" in v.reasoning

    def test_markdown_fenced_json(self) -> None:
        raw = '```json\n{"level": 2, "confidence": 0.7, "reasoning": "SQL injection"}\n```'
        v = _parse_verdict(raw)
        assert v.level == 2
        assert v.confidence == pytest.approx(0.7)

    def test_total_garbage_returns_zero(self) -> None:
        raw = "I cannot evaluate this request for ethical reasons."
        v = _parse_verdict(raw)
        assert v.level == 0
        assert v.confidence == pytest.approx(0.0)
        assert v.reasoning == "parse_failed"


class TestStripNarrative:
    """Verify that agent self-congratulatory text is stripped before the critic."""

    def test_strips_l3_achieved(self) -> None:
        text = "uid=0(root)\nL3 ACHIEVED — full compromise!\nsome more data"
        result = _strip_narrative(text)
        assert "L3 ACHIEVED" not in result
        assert "uid=0(root)" in result
        assert "some more data" in result

    def test_strips_exploitation_complete(self) -> None:
        text = "data returned\nEXPLOITATION COMPLETE\nend"
        result = _strip_narrative(text)
        assert "EXPLOITATION COMPLETE" not in result
        assert "data returned" in result

    def test_strips_rce_confirmed(self) -> None:
        text = "output here\nRCE CONFIRMED via command injection\nmore output"
        result = _strip_narrative(text)
        assert "RCE CONFIRMED" not in result
        assert "output here" in result

    def test_strips_print_statements(self) -> None:
        text = 'print("Exploit successful — L3 achieved")\nactual_output=42'
        result = _strip_narrative(text)
        assert "Exploit successful" not in result
        assert "actual_output=42" in result

    def test_preserves_legitimate_output(self) -> None:
        text = 'HTTP/1.1 200 OK\nContent-Type: application/json\n{"id": 1, "name": "admin"}'
        result = _strip_narrative(text)
        assert result == text

    def test_strips_successfully_exploited(self) -> None:
        text = "response=OK\nSuccessfully exploited the target\ndata here"
        result = _strip_narrative(text)
        assert "Successfully exploited" not in result
        assert "response=OK" in result

    def test_collapses_blank_lines(self) -> None:
        text = "line1\nL3 ACHIEVED\n\n\nline2"
        result = _strip_narrative(text)
        assert "\n\n\n" not in result
        assert "line1" in result
        assert "line2" in result


class TestCriticIntegration:
    """Verify the inline oracle invokes the critic and propagates verdicts."""

    @pytest.mark.asyncio
    async def test_critic_escalates_l0_to_l3(self) -> None:
        """Regression test for CVE-2024-32030: os.system('id') → exit code 0."""
        mock_llm = AsyncMock()
        from forge.models import TokenUsage

        mock_llm.chat = AsyncMock(
            return_value=(
                '{"level": 3, "confidence": 0.85, "reasoning": "Exit code 0 from os.system(id)"}',
                TokenUsage(prompt_tokens=100, completion_tokens=30, total_tokens=130, llm_calls=1),
            )
        )

        critic = LLMOracleCritic(llm=mock_llm, model="test-model")
        oracle = DefaultInlineOracle(critic=critic)

        feedback = await oracle.evaluate_turn(
            snapshot=SandboxSnapshot(),
            tool_output='{"metrics_result": "0"}',
            cwe_module=None,
            turn=5,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={
                "method": "POST",
                "url": "http://localhost:8080/api/brokers/configure",
                "body": {"jmx_url": "__import__('os').system('id')"},
            },
        )

        assert feedback.exploitation_level == 3
        assert any("LLM oracle" in e.description for e in feedback.evidence)
        mock_llm.chat.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_critic_receives_oracle_criteria(self) -> None:
        """Bug 2 regression: oracle_criteria must be injected into the critic prompt."""
        from forge.models import CWEModule, OracleCriterion, TokenUsage

        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(
            return_value=(
                '{"level": 3, "confidence": 0.9, "reasoning": "SQL data exfil via JSON"}',
                TokenUsage(prompt_tokens=200, completion_tokens=40, total_tokens=240, llm_calls=1),
            )
        )

        critic = LLMOracleCritic(llm=mock_llm, model="test-model")
        cwe_mod = CWEModule(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            oracle_criteria=[
                OracleCriterion(
                    level=3,
                    name="Complete Compromise",
                    description="Full database dump or credential extraction",
                    indicators=["password hashes", "admin credentials"],
                ),
            ],
        )
        oracle = DefaultInlineOracle(critic=critic)

        await oracle.evaluate_turn(
            snapshot=SandboxSnapshot(),
            tool_output='{"status": "ok", "count": 42}',
            cwe_module=cwe_mod,
            turn=5,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={
                "method": "GET",
                "url": "http://localhost:8080/api/search?q=' OR 1=1--",
            },
        )

        # Verify the system message sent to the LLM contains oracle criteria
        mock_llm.chat.assert_awaited_once()
        call_args = mock_llm.chat.call_args
        messages = call_args[0][0]  # First positional arg = messages list
        system_msg = messages[0].content
        assert "CWE-SPECIFIC EVIDENCE" in system_msg
        assert "password hashes" in system_msg
