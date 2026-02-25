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
    _compact_messages,
    _estimate_message_tokens,
    _is_reasoning_model,
    _strip_unsupported_params,
    export_and_clear_otel_spans,
)


class TestIsReasoningModel:
    @pytest.mark.parametrize(
        "model",
        [
            pytest.param("o3", id="o3"),
        ],
    )
    def test_detects_reasoning_models(self, model: str) -> None:
        assert _is_reasoning_model(model) is True


class TestStripUnsupportedParams:
    @pytest.mark.parametrize(
        ("model", "expect_stripped"),
        [
            pytest.param("gpt-5-mini", True, id="reasoning_model"),
        ],
    )
    def test_strip_unsupported_params(self, model: str, expect_stripped: bool) -> None:
        kwargs = {
            "model": model,
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.0,
            "seed": 42,
            "max_tokens": 4096,
        }
        result = _strip_unsupported_params(kwargs)
        if expect_stripped:
            assert "temperature" not in result
            assert "seed" not in result
        else:
            assert result["temperature"] == pytest.approx(0.0)
            assert result["seed"] == pytest.approx(42)


class TestResolveModel:
    def test_bare_model_gets_prefix_from_default(self) -> None:
        client = LLMClient("github_copilot/claude-sonnet-4.5", enable_otel=False)
        assert client._resolve_model("gpt-5-mini") == "github_copilot/gpt-5-mini"


class TestCompactMessages:
    """Tests for _compact_messages() — context window management."""

    def test_compact_preserves_tool_call_pairing(self) -> None:
        """Compact with tight budget should keep or drop tool_call groups together."""
        messages: list[dict[str, object]] = [
            {"role": "system", "content": "System prompt."},
            {"role": "user", "content": "Do something."},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {"name": "tool_a", "arguments": "{}"},
                    },
                    {
                        "id": "call_2",
                        "function": {"name": "tool_b", "arguments": "{}"},
                    },
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "result_1"},
            {"role": "tool", "tool_call_id": "call_2", "content": "result_2"},
            {"role": "assistant", "content": "Done."},
        ]
        result = _compact_messages(messages, "gpt-4.1")

        assistant_tc_ids: set[str] = set()
        tool_response_ids: set[str] = set()
        for msg in result:
            if msg.get("role") == "assistant":
                for tc in msg.get("tool_calls", []):
                    assistant_tc_ids.add(tc["id"])
            if msg.get("role") == "tool":
                tool_response_ids.add(msg["tool_call_id"])

        assert tool_response_ids.issubset(assistant_tc_ids), (
            f"Orphan tool responses: {tool_response_ids - assistant_tc_ids}"
        )
        if assistant_tc_ids:
            assert assistant_tc_ids.issubset(tool_response_ids), (
                f"Orphan tool_calls: {assistant_tc_ids - tool_response_ids}"
            )

    def test_compact_handles_oversized_system_prompt(self) -> None:
        """System message content of 500K chars should be truncated to fit."""
        big_content = "A" * 500_000
        messages = [
            {"role": "system", "content": big_content},
            {"role": "user", "content": "hello"},
        ]
        # Use a model with 128K context so the 500K-char prompt exceeds
        # the 80% budget and triggers compaction phases.
        result = _compact_messages(messages, "gpt-4o")
        estimated = _estimate_message_tokens(result)
        budget = int(128_000 * 0.80)
        assert estimated <= budget, (
            f"After compaction, estimated {estimated} tokens exceeds budget {budget}"
        )

    def test_compact_phase1_truncates_large_tool_results(self) -> None:
        """Tool messages with >1000 char results should be truncated in phase 1."""
        big_result = "x" * 5000
        messages: list[dict[str, object]] = [
            {"role": "system", "content": "System prompt."},
            {"role": "user", "content": "Do something."},
        ]
        for i in range(80):
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call_{i}",
                            "function": {"name": "tool_a", "arguments": "{}"},
                        },
                    ],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": f"call_{i}",
                    "content": big_result,
                }
            )

        # Use gpt-4o (128K context) so 80 tool results of 5000 chars each
        # (~133K tokens) exceed the 80% budget and trigger phase-1 truncation.
        result = _compact_messages(messages, "gpt-4o")
        truncated_count = 0
        for msg in result:
            if msg.get("role") == "tool":
                content = str(msg.get("content", ""))
                if len(content) < 5000:
                    truncated_count += 1
        assert truncated_count > 0, "No tool results were truncated"


class TestExportOtelSpans:
    """Tests for export_and_clear_otel_spans()."""

    def test_returns_empty_when_no_exporter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns empty list when OTEL exporter is not initialized."""
        import forge.pipeline.llm_client as mod

        monkeypatch.setattr(mod, "_otel_exporter", None)
        assert export_and_clear_otel_spans() == []

    def test_exports_and_clears_spans(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Exports spans as dicts and clears the exporter."""
        from unittest.mock import MagicMock

        import forge.pipeline.llm_client as mod

        # Create a mock span matching the OTEL ReadableSpan interface
        mock_ctx = MagicMock()
        mock_ctx.trace_id = 0x1234ABCD
        mock_ctx.span_id = 0x5678EF

        mock_span = MagicMock()
        mock_span.name = "litellm.completion"
        mock_span.get_span_context.return_value = mock_ctx
        mock_span.start_time = 1_000_000_000  # 1s in nanoseconds
        mock_span.end_time = 2_500_000_000  # 2.5s
        mock_span.attributes = {"model": "claude-sonnet", "gen_ai.usage.prompt_tokens": 100}
        mock_span.status = MagicMock()
        mock_span.status.status_code = MagicMock()
        mock_span.status.status_code.name = "OK"

        mock_exporter = MagicMock()
        mock_exporter.get_finished_spans.return_value = [mock_span]
        monkeypatch.setattr(mod, "_otel_exporter", mock_exporter)

        result = export_and_clear_otel_spans()

        assert len(result) == 1
        span = result[0]
        assert span["name"] == "litellm.completion"
        assert span["duration_ms"] == pytest.approx(1500.0)
        assert span["status"] == "OK"
        assert span["attributes"]["model"] == "claude-sonnet"
        assert span["attributes"]["gen_ai.usage.prompt_tokens"] == 100
        assert span["trace_id"]  # non-empty hex
        assert span["span_id"]  # non-empty hex

        # Verify exporter was cleared
        mock_exporter.clear.assert_called_once()
