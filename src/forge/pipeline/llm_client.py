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

import asyncio
import functools
import logging
import re
from pathlib import Path
from typing import Any

import litellm
import yaml
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from forge.models import Message, TokenUsage

logger = logging.getLogger(__name__)

# Retry settings for transient LLM API errors (429, 5xx)
_MAX_RETRIES = 3
_BASE_DELAY = 2.0  # seconds
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# Models that use internal reasoning and reject temperature/seed params.
# GPT-5 family (gpt-5, gpt-5-mini, gpt-5-nano) and o-series (o3, o4-mini)
# only accept temperature=1 (the default). Passing any other value raises
# litellm.UnsupportedParamsError.
_REASONING_MODEL_RE = re.compile(
    r"(?:^|/)(?:gpt-5|o[34])",  # matches gpt-5*, o3*, o4* after optional provider/
)

# Module-level singleton for OTEL — avoids "Overriding TracerProvider" warnings
# when multiple LLMClient instances are created (one per agent).
_otel_exporter: InMemorySpanExporter | None = None
_otel_initialized = False


class LLMClient:
    """Thin LiteLLM wrapper with OTEL token tracking.

    All LLM calls go through this client. Token usage is captured via
    OTEL InMemorySpanExporter and can be extracted per-phase.
    """

    def __init__(
        self,
        default_model: str = "github_copilot/claude-sonnet-4.5",
        *,
        enable_otel: bool = True,
        max_retries: int = _MAX_RETRIES,
        base_retry_delay: float = _BASE_DELAY,
    ) -> None:
        self.default_model = default_model
        self._provider_prefix = _extract_provider_prefix(default_model)
        self._max_retries = max_retries
        self._base_retry_delay = base_retry_delay

        if enable_otel:
            _setup_otel_singleton()

    @staticmethod
    def _get_exporter() -> InMemorySpanExporter | None:
        """Return the shared OTEL exporter (if initialized)."""
        return _otel_exporter

    def _resolve_model(self, model: str) -> str:
        """Apply provider prefix from default_model to bare model names.

        When a secondary model (e.g. compaction_model="gpt-5-mini") is used
        without a provider prefix, litellm routes it to the native API which
        may require a separate API key. This method infers the provider from
        the primary model and prepends it so the same credentials work.

        Examples:
            default_model="github_copilot/claude-sonnet-4.5", model="gpt-5-mini"
            → "github_copilot/gpt-5-mini"

            model="openai/gpt-5-mini" → unchanged (already has prefix)
            default_model="claude-sonnet-4.5", model="gpt-5-mini" → unchanged
        """
        if "/" in model:
            return model  # already has a provider prefix
        if self._provider_prefix:
            resolved = f"{self._provider_prefix}/{model}"
            logger.debug(
                "Resolved bare model %r → %r (prefix from default_model)",
                model,
                resolved,
            )
            return resolved
        return model

    async def chat(
        self,
        messages: list[Message],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        seed: int | None = None,
        max_tokens: int = 4096,
        phase: str = "unknown",
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, TokenUsage]:
        """Send a chat completion request and return response + token usage.

        Args:
            messages: Conversation messages.
            model: LLM model name (defaults to self.default_model).
            temperature: Sampling temperature.
            seed: Random seed for reproducibility.
            max_tokens: Maximum response tokens.
            phase: Pipeline phase tag ("build" or "exploit") for OTEL.
            metadata: Additional metadata for OTEL spans.

        Returns:
            Tuple of (response content, token usage).
        """
        model = self._resolve_model(model or self.default_model)

        # Build litellm messages
        litellm_messages = [{"role": m.role, "content": m.content} for m in messages]

        # Prepare metadata for OTEL tagging
        otel_metadata = {
            "trace_name": f"forge-{phase}",
            "tags": [phase],
            **(metadata or {}),
        }

        try:
            response = await self._call_with_retry(
                model=model,
                messages=litellm_messages,
                temperature=temperature,
                seed=seed,
                max_tokens=max_tokens,
                metadata=otel_metadata,
            )
        except Exception:
            logger.exception("LLM call failed for model=%s phase=%s", model, phase)
            raise

        # Extract response content
        if not response.choices:
            logger.error("LLM returned empty choices for model=%s phase=%s", model, phase)
            raise RuntimeError(f"LLM returned no choices (model={model}, phase={phase})")
        content = response.choices[0].message.content or ""

        # Extract token usage
        usage = response.usage
        tokens = TokenUsage(
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            total_tokens=usage.total_tokens if usage else 0,
            llm_calls=1,
            estimated_cost_usd=_estimate_cost(
                model, usage.prompt_tokens or 0, usage.completion_tokens or 0
            )
            if usage
            else 0.0,
        )

        logger.debug(
            "LLM call: model=%s phase=%s tokens=%d",
            model,
            phase,
            tokens.total_tokens,
        )

        return content, tokens

    async def complete(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | None = None,
        temperature: float = 0.0,
        seed: int | None = None,
        max_tokens: int = 4096,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[Any, TokenUsage]:
        """Low-level completion with tool-calling support.

        Unlike ``chat()``, this accepts raw message dicts and preserves
        ``tool_calls`` in the response. Used by the agent framework.

        Includes automatic message compaction: if the estimated token
        count exceeds the model's context window, older tool results
        are truncated to fit.

        Args:
            tool_choice: Override tool_choice (``"auto"`` | ``"required"``
                | ``"none"``).  Defaults to ``"auto"`` when tools are present.

        Returns:
            Tuple of (raw litellm response, token usage).
        """
        resolved = self._resolve_model(model or self.default_model)

        # Guard against context-window overflow: estimate token count
        # and compact messages if necessary.
        messages = _compact_messages(messages, resolved)

        kwargs: dict[str, Any] = {
            "model": resolved,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if seed is not None:
            kwargs["seed"] = seed
        if tools and tool_choice != "none":
            # Defense-in-depth: when tool_choice="none" is explicitly
            # requested, omit tools entirely from the request.  Some
            # providers (e.g. GitHub Copilot) return empty choices when
            # tools are present alongside tool_choice="none".
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice or "auto"
        if metadata:
            kwargs["metadata"] = metadata

        n_tools = len(tools) if tools else 0
        effective_tc = kwargs.get("tool_choice", "n/a")
        logger.debug(
            "complete(): model=%s, n_messages=%d, n_tools=%d, tool_choice=%s, temp=%.1f",
            resolved,
            len(messages),
            n_tools,
            effective_tc,
            temperature,
        )

        response = await self._call_with_retry(**kwargs)

        if not response.choices:
            # Retry once — some providers transiently return empty choices.
            logger.warning(
                "LLM returned no choices (model=%s), retrying once after %.1fs",
                resolved,
                self._base_retry_delay,
            )
            await asyncio.sleep(self._base_retry_delay)
            response = await self._call_with_retry(**kwargs)
            if not response.choices:
                raise RuntimeError(f"LLM returned no choices after retry (model={resolved})")

        # Log response shape so we can diagnose tool-call issues
        msg = response.choices[0].message
        has_tc = bool(getattr(msg, "tool_calls", None))
        content_len = len(msg.content or "") if msg.content else 0
        finish = getattr(response.choices[0], "finish_reason", "?")
        logger.debug(
            "complete() response: finish=%s, has_tool_calls=%s, content_len=%d",
            finish,
            has_tc,
            content_len,
        )

        # Detect output truncation — this is the #1 cause of empty
        # tool-call arguments.  Log at WARNING so it's visible in
        # production runs (not just DEBUG).
        if finish == "length":
            logger.warning(
                "LLM response truncated (finish_reason=length, max_tokens=%d). "
                "Tool call arguments may be missing or incomplete.",
                max_tokens,
            )

        usage = response.usage
        tokens = TokenUsage(
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            total_tokens=usage.total_tokens if usage else 0,
            llm_calls=1,
            estimated_cost_usd=_estimate_cost(
                resolved, usage.prompt_tokens or 0, usage.completion_tokens or 0
            )
            if usage
            else 0.0,
        )

        return response, tokens

    async def _call_with_retry(self, **kwargs: Any) -> Any:
        """Call litellm.acompletion with exponential backoff for transient errors.

        Automatically strips ``temperature`` and ``seed`` for reasoning models
        (GPT-5 family, o-series) that reject those parameters.
        """
        kwargs = _strip_unsupported_params(kwargs)
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                return await litellm.acompletion(**kwargs)
            except Exception as exc:
                last_exc = exc
                status = getattr(exc, "status_code", None)
                if status not in _RETRYABLE_STATUS_CODES or attempt >= self._max_retries:
                    raise

                delay = self._base_retry_delay * (2**attempt)
                logger.warning(
                    "LLM call failed (status=%s), retry %d/%d in %.1fs: %s",
                    status,
                    attempt + 1,
                    self._max_retries,
                    delay,
                    str(exc)[:100],
                )
                await asyncio.sleep(delay)

        # Should not reach here, but satisfy type checker
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected retry loop exit")


def export_and_clear_otel_spans() -> list[dict[str, Any]]:
    """Export all OTEL spans as JSON-serializable dicts, then clear the exporter.

    Each span dict includes: name, trace_id, span_id, start/end timestamps,
    duration_ms, status, and all LiteLLM attributes (model, tokens, cost).

    Call this after each CVE run to persist LLM-level telemetry before the
    in-memory exporter is cleared for the next CVE.
    """
    if _otel_exporter is None:
        return []

    finished = _otel_exporter.get_finished_spans()
    exported: list[dict[str, Any]] = []

    for span in finished:
        ctx = span.get_span_context()
        start_ns: int = span.start_time or 0
        end_ns: int = span.end_time or 0
        duration_ms = (end_ns - start_ns) / 1_000_000 if end_ns > start_ns else 0.0

        # Extract attributes, converting to plain Python types
        attrs: dict[str, Any] = {}
        if span.attributes:
            for k, v in span.attributes.items():
                attrs[k] = v

        exported.append(
            {
                "name": span.name,
                "trace_id": format(ctx.trace_id, "032x") if ctx else "",
                "span_id": format(ctx.span_id, "016x") if ctx else "",
                "start_time_unix_nano": start_ns,
                "end_time_unix_nano": end_ns,
                "duration_ms": round(duration_ms, 2),
                "status": span.status.status_code.name if span.status else "UNSET",
                "attributes": attrs,
            }
        )

    _otel_exporter.clear()
    logger.debug("Exported %d OTEL spans", len(exported))
    return exported


def _is_reasoning_model(model: str) -> bool:
    """Check if a model uses internal reasoning and rejects temperature/seed."""
    return _REASONING_MODEL_RE.search(model) is not None


def _setup_otel_singleton() -> None:
    """Configure OTEL once at module level.

    Multiple LLMClient instances share the same TracerProvider and
    InMemorySpanExporter, avoiding the "Overriding TracerProvider"
    warning that fires when ``trace.set_tracer_provider`` is called
    more than once per process.
    """
    global _otel_exporter, _otel_initialized  # noqa: PLW0603
    if _otel_initialized:
        return
    _otel_initialized = True

    _otel_exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_otel_exporter))
    trace.set_tracer_provider(provider)

    if "otel" not in (litellm.callbacks or []):
        litellm.callbacks = litellm.callbacks or []
        litellm.callbacks.append("otel")

    # Bedrock rejects requests that omit `tools` when the conversation
    # history contains tool_use blocks (e.g. final JSON demand after
    # exploitation).  `modify_params` tells litellm to add a dummy tool
    # to satisfy Bedrock's validation.  Other providers ignore it.
    litellm.modify_params = True

    logger.info("OTEL InMemorySpanExporter configured (singleton)")


def _extract_provider_prefix(model: str) -> str:
    """Extract the provider prefix from a litellm model string.

    LiteLLM uses ``provider/model_name`` routing (e.g.
    ``github_copilot/claude-sonnet-4.5``).  This returns everything before the
    last ``/`` so we can apply the same prefix to secondary models.

    Returns empty string if no prefix is present.
    """
    if "/" not in model:
        return ""
    return model.rsplit("/", maxsplit=1)[0]


def _strip_unsupported_params(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Remove temperature and seed for reasoning models that reject them.

    GPT-5 family and o-series models only accept temperature=1 (default).
    Passing any other value raises UnsupportedParamsError. Rather than
    setting litellm.drop_params globally (which masks real errors),
    we surgically remove the offending params for known reasoning models.
    """
    model = kwargs.get("model", "")
    if not _is_reasoning_model(model):
        return kwargs

    cleaned = dict(kwargs)
    dropped: list[str] = []

    if "temperature" in cleaned:
        dropped.append(f"temperature={cleaned.pop('temperature')}")
    if "seed" in cleaned:
        dropped.append(f"seed={cleaned.pop('seed')}")

    if dropped:
        logger.info(
            "Stripped unsupported params for reasoning model %s: %s",
            model,
            ", ".join(dropped),
        )

    return cleaned

_DEFAULT_COST: tuple[float, float] = (3.0, 15.0)
_DEFAULT_CONTEXT_WINDOW: int = 128_000

# Relative path — works when CWD is the repo root.  Callers that need an
# absolute path can set _MODELS_YAML_PATH before the first LLM call.
_MODELS_YAML_PATH: Path = Path("data/config/models.yaml")


@functools.cache
def _load_model_config() -> dict[str, Any]:
    """Load model pricing and context windows from models.yaml (cached)."""
    path = _MODELS_YAML_PATH
    if not path.exists():
        logger.debug("models.yaml not found at %s, using built-in defaults", path)
        return {}
    try:
        data: Any = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            return {}
        logger.debug(
            "llm.models_config | loaded=%d models from %s",
            len(data.get("models", {})),
            path,
        )
        return dict(data)
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load models.yaml: %s", exc)
        return {}


def _get_model_costs(model_name: str) -> tuple[float, float]:
    """Return (input_cost, output_cost) per 1M tokens for a model."""
    cfg = _load_model_config()
    models = cfg.get("models", {})
    entry = models.get(model_name, {})
    if entry:
        return (
            float(entry.get("cost_per_1m_input", _DEFAULT_COST[0])),
            float(entry.get("cost_per_1m_output", _DEFAULT_COST[1])),
        )
    defaults = cfg.get("defaults", {})
    return (
        float(defaults.get("cost_per_1m_input", _DEFAULT_COST[0])),
        float(defaults.get("cost_per_1m_output", _DEFAULT_COST[1])),
    )


def _get_model_context_window(model_name: str) -> int:
    """Return context window size for a model."""
    cfg = _load_model_config()
    models = cfg.get("models", {})
    entry = models.get(model_name, {})
    if entry:
        return int(entry.get("context_window", _DEFAULT_CONTEXT_WINDOW))
    defaults = cfg.get("defaults", {})
    return int(defaults.get("context_window", _DEFAULT_CONTEXT_WINDOW))

_CHARS_PER_TOKEN = 3.0


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate USD cost for a completion call."""
    model_name = model.split("/")[-1] if "/" in model else model
    costs = _get_model_costs(model_name)
    return (prompt_tokens * costs[0] + completion_tokens * costs[1]) / 1_000_000


def _get_context_limit(model: str) -> int:
    """Return the approximate context window for a model."""
    model_name = model.split("/")[-1] if "/" in model else model
    return _get_model_context_window(model_name)


def _estimate_message_tokens(messages: list[dict[str, Any]]) -> int:
    """Rough estimate of token count for a message list."""
    total_chars = 0
    for msg in messages:
        content = msg.get("content") or ""
        total_chars += len(content)
        # Tool call arguments count too
        for tc in msg.get("tool_calls", []):
            fn = tc.get("function", {})
            total_chars += len(fn.get("arguments", ""))
    return int(total_chars / _CHARS_PER_TOKEN)


def _compact_messages(
    messages: list[dict[str, Any]],
    model: str,
) -> list[dict[str, Any]]:
    """Truncate tool result messages to fit within the context window.

    Strategy: keep system + first user message intact.  When estimated
    tokens exceed 80% of the context limit, truncate the *content* of
    tool-role messages (oldest first) to 500 chars each.  If still over,
    drop the oldest tool messages entirely (preserving the assistant
    message's tool_call_ids by inserting a stub response).

    This is a last-resort safety net — ideally individual tools should
    bound their output sizes, but this protects against edge cases.
    """
    limit = _get_context_limit(model)
    budget = int(limit * 0.80)  # 80% — leave room for completion + tools schema
    estimated = _estimate_message_tokens(messages)

    if estimated <= budget:
        return messages

    logger.warning(
        "Compaction phase 1: ~%d tokens exceeds budget (%d) for %s — truncating tool results",
        estimated,
        budget,
        model,
    )

    # Phase 1: truncate long tool results
    compacted = list(messages)
    before = len(compacted)
    for i, msg in enumerate(compacted):
        if msg.get("role") == "tool" and len(msg.get("content", "")) > 1000:
            compacted[i] = {
                **msg,
                "content": msg["content"][:500] + "\n[... truncated to fit context window]",
            }

    estimated = _estimate_message_tokens(compacted)
    logger.info("Compaction phase 1: %d -> %d messages", before, len(compacted))
    if estimated <= budget:
        return compacted

    # Phase 2: aggressively truncate ALL tool results to 200 chars
    before = len(compacted)
    for i, msg in enumerate(compacted):
        if msg.get("role") == "tool":
            compacted[i] = {
                **msg,
                "content": msg["content"][:200] + "\n[truncated]",
            }

    estimated = _estimate_message_tokens(compacted)
    logger.info("Compaction phase 2: %d -> %d messages", before, len(compacted))
    if estimated <= budget:
        return compacted

    # Phase 3: drop oldest assistant+tool exchanges, keep system + last 20 messages.
    # Maintain tool_call_id pairing: if an assistant message with tool_calls is
    # kept, ensure all matching tool responses are also kept (and vice versa).
    before = len(compacted)
    system_msgs = [m for m in compacted if m.get("role") == "system"]
    other_msgs = [m for m in compacted if m.get("role") != "system"]
    kept = system_msgs + other_msgs[-20:]

    # Fix tool_call pairing: collect required tool_call_ids from kept assistant
    # messages and ensure matching tool responses are present.
    kept = _repair_tool_call_pairing(kept)

    logger.info(
        "Compaction phase 3: %d -> %d messages (dropped %d)",
        before,
        len(kept),
        before - len(kept),
    )

    estimated = _estimate_message_tokens(kept)
    if estimated <= budget:
        return kept

    # Phase 4: system/user content itself is too large (e.g. 671K token
    # system prompt with embedded generated files).  Truncate the longest
    # system and user message content fields to fit.
    logger.warning(
        "Compaction phase 4: still ~%d tokens after phase 3, truncating system/user content",
        estimated,
    )

    non_su_chars = sum(
        len(msg.get("content", "") or "")
        for msg in kept
        if msg.get("role") not in ("system", "user")
    )
    available_chars = int(budget * _CHARS_PER_TOKEN) - non_su_chars
    su_indices = [i for i, m in enumerate(kept) if m.get("role") in ("system", "user")]
    max_chars_per_msg = max(available_chars // max(len(su_indices), 1), 500)
    for i in su_indices:
        content = kept[i].get("content", "")
        if len(content) > max_chars_per_msg:
            kept[i] = {
                **kept[i],
                "content": content[:max_chars_per_msg]
                + "\n[... content truncated to fit context window]",
            }

    logger.info(
        "Compaction phase 4: %d messages, estimated ~%d tokens",
        len(kept),
        _estimate_message_tokens(kept),
    )
    return kept


def _repair_tool_call_pairing(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ensure tool_call_id pairing integrity in a message list.

    For each assistant message with ``tool_calls``, verify that matching
    tool response messages exist.  For each tool response, verify that
    a prior assistant message requested that tool_call_id.  Drop orphans.
    """
    # Collect all tool_call_ids from assistant messages
    provided_ids: set[str] = set()
    for msg in messages:
        if msg.get("role") == "assistant":
            for tc in msg.get("tool_calls", []):
                tc_id = tc.get("id", "")
                if tc_id:
                    provided_ids.add(tc_id)

    # Collect all tool_call_ids from tool response messages
    responded_ids: set[str] = set()
    for msg in messages:
        if msg.get("role") == "tool":
            tc_id = msg.get("tool_call_id", "")
            if tc_id:
                responded_ids.add(tc_id)

    # Drop assistant messages whose tool_calls have no matching responses
    needed_ids: set[str] = set()
    result: list[dict[str, Any]] = []
    for msg in messages:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            tc_ids = {tc.get("id", "") for tc in msg["tool_calls"]}
            if tc_ids and not tc_ids.intersection(responded_ids):
                # No matching tool responses — drop this assistant message
                continue
            needed_ids.update(tc_ids)
        result.append(msg)

    # Drop tool messages whose tool_call_id has no matching assistant message
    final: list[dict[str, Any]] = []
    for msg in result:
        if msg.get("role") == "tool":
            tc_id = msg.get("tool_call_id", "")
            if tc_id and tc_id not in needed_ids and tc_id not in provided_ids:
                continue
        final.append(msg)

    return final
