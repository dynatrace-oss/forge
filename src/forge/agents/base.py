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

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from forge.config import BaseAgentSettings
from forge.models import TokenUsage
from forge.pipeline.budget import BudgetTracker
from forge.pipeline.llm_client import LLMClient, _compact_messages
from forge.tools.base import ToolCall, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)


class AgentConfig(BaseModel):
    """Configuration for an agent instance."""

    name: str
    system_prompt: str
    max_turns: int
    model: str = "gpt-4.1"
    temperature: float = 0.0
    max_tokens: int = 4096 # default max tokens; can be overridden per-agent


class AgentResult(BaseModel):
    """Result of running an agent through its turn loop."""

    output: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    turns_used: int = 0
    tokens: TokenUsage = Field(default_factory=TokenUsage)
    wall_clock_seconds: float = 0.0


class BaseAgent(ABC):
    """
    Implements the core turn loop: call LLM → if tool calls, execute
    and loop → if text, parse structured output and return.
    Subclasses define ``format_input``, ``parse_output``, and optionally
    ``on_tool_result`` for per-call side effects (oracle, coaching).
    """

    def __init__(
        self,
        config: AgentConfig,
        llm: LLMClient,
        tools: ToolRegistry | None = None,
        base_config: BaseAgentSettings | None = None,
        *,
        cost_budget: float = 0.0,
        accumulated_cost: float = 0.0,
    ) -> None:
        self.config = config
        self.llm = llm
        self.tools = tools or ToolRegistry()
        self._base_config = base_config or BaseAgentSettings()
        self._messages: list[dict[str, Any]] = []
        self._tool_calls: list[ToolCall] = []
        self._tool_results: list[ToolResult] = []
        self._partial_tokens: TokenUsage = TokenUsage()
        self._last_tool_duration_ms: float = 0.0
        self._cost_budget = cost_budget
        self._accumulated_cost = accumulated_cost
        self._budget_tracker: BudgetTracker | None = None

    async def run(self, input_data: dict[str, Any]) -> AgentResult:
        """Execute the agent turn loop and return structured result.

        Two mechanisms prevent the LLM from ignoring its tools:

        1. **Force-tool on first turn**: When tools are registered, the first
           LLM call uses ``tool_choice="required"`` so the model *must* call
           at least one tool before it can produce text output.
        2. **Nudge on text-before-tools**: If the model somehow returns text
           without having made any tool calls, we inject a system nudge and
           retry up to ``max_nudges`` times before accepting the text output.
        """
        start = time.monotonic()
        agent_name = self.config.name

        self._messages = [{"role": "system", "content": self.config.system_prompt}]
        self._tool_calls = []
        self._tool_results = []
        total_tokens = TokenUsage()

        user_msg = self.format_input(input_data)
        self._messages.append({"role": "user", "content": user_msg})

        has_tools = len(self.tools) > 0
        nudge_count = 0
        continue_count = 0
        force_tool_attempts = 0
        max_force_tool_attempts = 2
        tool_names = self.tools.list_names() if has_tools else []

        logger.info(
            "[%s] Starting turn loop (max_turns=%d, tools=%s, model=%s)",
            agent_name,
            self.config.max_turns,
            tool_names,
            self.config.model,
        )
        logger.debug(
            "[%s] User message (%d chars): %.200s...",
            agent_name,
            len(user_msg),
            user_msg,
        )

        turns_used = 0
        for turn in range(self.config.max_turns):
            turns_used = turn + 1

            # Force the model to call a tool until it produces at least one
            # *successful* (non-error) tool call, up to a retry limit.
            any_tool_ok = any(not r.error for r in self._tool_results)
            force_tool = (
                has_tools and not any_tool_ok and force_tool_attempts < max_force_tool_attempts
            )
            if force_tool:
                force_tool_attempts += 1
            tc_mode = "required" if force_tool else "auto"
            logger.info(
                "[%s] Turn %d/%d — calling LLM (tool_choice=%s, msg_count=%d)",
                agent_name,
                turns_used,
                self.config.max_turns,
                tc_mode if has_tools else "n/a",
                len(self._messages),
            )
            response, tokens = await self._call_llm(
                tool_choice="required" if force_tool else None,
            )
            total_tokens = total_tokens + tokens
            self._partial_tokens = total_tokens

            # Cost cap enforcement: accumulate cost and check budget.
            self._accumulated_cost += tokens.estimated_cost_usd
            if self._budget_tracker is not None:
                self._budget_tracker.record(tokens)
            budget_exhausted = (
                self._budget_tracker.is_exhausted
                if self._budget_tracker is not None
                else (self._cost_budget > 0 and self._accumulated_cost >= self._cost_budget)
            )
            if budget_exhausted:
                budget_label = (
                    f"${self._budget_tracker.accumulated_cost:.2f} >= "
                    f"${self._budget_tracker.total_budget:.2f}"
                    if self._budget_tracker is not None
                    else f"${self._accumulated_cost:.2f} >= ${self._cost_budget:.2f}"
                )
                logger.warning(
                    "[%s] Cost cap reached: %s budget after turn %d",
                    agent_name,
                    budget_label,
                    turns_used,
                )
                # Emit final JSON demand before terminating
                self._messages.append(
                    {"role": "user", "content": self._base_config.final_json_message}
                )
                try:
                    final_resp, final_tok = await self._call_llm(tool_choice="none")
                    total_tokens = total_tokens + final_tok
                    # Fix L1: record final demand tokens to tracker
                    self._accumulated_cost += final_tok.estimated_cost_usd
                    if self._budget_tracker is not None:
                        self._budget_tracker.record(final_tok)
                    final_text = final_resp.choices[0].message.content or ""
                    if final_text.strip():
                        output = self.parse_output(final_text)
                        return AgentResult(
                            output=output,
                            tool_calls=self._tool_calls,
                            tool_results=self._tool_results,
                            turns_used=turns_used,
                            tokens=total_tokens,
                            wall_clock_seconds=time.monotonic() - start,
                        )
                except Exception:
                    logger.warning(
                        "[%s] Final JSON demand after cost cap failed",
                        agent_name,
                        exc_info=True,
                    )
                # Fall through to return whatever we have
                last_text = ""
                for msg in reversed(self._messages):
                    if msg.get("role") == "assistant" and msg.get("content"):
                        last_text = str(msg["content"])
                        break
                output = self.parse_output(last_text) if last_text else {}
                return AgentResult(
                    output=output,
                    tool_calls=self._tool_calls,
                    tool_results=self._tool_results,
                    turns_used=turns_used,
                    tokens=total_tokens,
                    wall_clock_seconds=time.monotonic() - start,
                )

            logger.debug(
                "[%s] Turn %d — LLM response tokens: prompt=%d completion=%d total=%d",
                agent_name,
                turns_used,
                tokens.prompt_tokens,
                tokens.completion_tokens,
                tokens.total_tokens,
            )

            message = response.choices[0].message

            if getattr(message, "tool_calls", None):
                tc_names = [tc.function.name for tc in message.tool_calls]
                logger.info(
                    "[%s] Turn %d — LLM requested %d tool call(s): %s",
                    agent_name,
                    turns_used,
                    len(message.tool_calls),
                    tc_names,
                )
                self._messages.append(_assistant_msg_to_dict(message))

                # Process ALL tool calls — even if one fails, every
                # tool_call_id MUST get a response message.  Otherwise
                # the next LLM call rejects the conversation as malformed.
                for tc in message.tool_calls:
                    try:
                        tool_call = ToolCall.from_openai(tc)
                    except Exception as parse_exc:
                        # ToolCall parsing failed (malformed JSON args).
                        # Fabricate a ToolCall so we can still send a
                        # response message for this tool_call_id.
                        logger.warning(
                            "[%s] Failed to parse tool call %s: %s",
                            agent_name,
                            tc.id,
                            parse_exc,
                        )
                        tool_call = ToolCall(
                            id=tc.id,
                            name=getattr(tc.function, "name", "unknown"),
                            arguments={},
                        )
                        result = ToolResult(
                            tool_call_id=tc.id,
                            content=f"Error parsing tool arguments: {parse_exc}",
                            error=True,
                        )
                        self._tool_calls.append(tool_call)
                        self._tool_results.append(result)
                        self._messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": result.content,
                            }
                        )
                        continue

                    self._tool_calls.append(tool_call)

                    # Check if a subclass wants to abort remaining tools
                    # (e.g., exploit agent grace period expired mid-batch).
                    if self.should_abort_remaining_tools():
                        logger.info(
                            "[%s] Aborting tool %s — agent requested stop",
                            agent_name,
                            tool_call.name,
                        )
                        result = ToolResult(
                            tool_call_id=tool_call.id,
                            content="Execution skipped — agent budget exhausted",
                            error=True,
                        )
                        tool_call.output = result.content
                        tool_call.error = result.error
                        self._tool_results.append(result)
                        self._messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": result.content,
                            }
                        )
                        continue

                    logger.info(
                        "[%s] Executing tool: %s (args=%s)",
                        agent_name,
                        tool_call.name,
                        json.dumps(tool_call.arguments)[:500],
                    )

                    t0 = time.monotonic()
                    result = await self.tools.execute(tool_call)
                    self._last_tool_duration_ms = (time.monotonic() - t0) * 1000
                    # Attach output to the tool call for paired serialization
                    tool_call.output = result.content
                    tool_call.error = result.error
                    self._tool_results.append(result)

                    logger.info(
                        "[%s] Tool %s completed in %.0fms (error=%s, result_len=%d)",
                        agent_name,
                        tool_call.name,
                        self._last_tool_duration_ms,
                        result.error,
                        len(result.content),
                    )
                    if result.error:
                        # Log error tool results at WARNING with content preview
                        # so build failures and similar issues are visible at INFO+
                        logger.warning(
                            "[%s] Tool %s FAILED: %.800s",
                            agent_name,
                            tool_call.name,
                            result.content,
                        )
                    else:
                        logger.debug(
                            "[%s] Tool %s result: %.500s",
                            agent_name,
                            tool_call.name,
                            result.content,
                        )

                    self._messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": result.content,
                        }
                    )

                    await self.on_tool_result(tool_call, result, turn)

                continue

            # LLM returned text — decide whether to accept or nudge.
            content: str = message.content or ""
            logger.info(
                "[%s] Turn %d — LLM returned text (%d chars, tool_calls_so_far=%d)",
                agent_name,
                turns_used,
                len(content),
                len(self._tool_calls),
            )
            logger.debug(
                "[%s] Turn %d — LLM text: %.500s",
                agent_name,
                turns_used,
                content,
            )

            # Case 1: No tool calls at all — strong nudge to use tools.
            if (
                has_tools
                and len(self._tool_calls) == 0
                and nudge_count < self._base_config.max_nudges
            ):
                nudge_count += 1
                logger.warning(
                    "[%s] Returned text without tool calls (nudge %d/%d), retrying",
                    agent_name,
                    nudge_count,
                    self._base_config.max_nudges,
                )
                self._messages.append({"role": "assistant", "content": content.rstrip()})
                self._messages.append(
                    {
                        "role": "user",
                        "content": self._base_config.nudge_message,
                    }
                )
                continue

            # Case 2: Agent has tools and has used some, but should_stop()
            # says the output isn't complete yet — inject continuation prompt.
            if (
                has_tools
                and len(self._tool_calls) > 0
                and not self.should_stop(content)
                and continue_count < self._base_config.max_continues
            ):
                continue_count += 1
                logger.info(
                    "[%s] should_stop=False (continue %d/%d), injecting continuation prompt",
                    agent_name,
                    continue_count,
                    self._base_config.max_continues,
                )
                self._messages.append({"role": "assistant", "content": content.rstrip()})
                # On the last continue, demand structured JSON output
                if continue_count >= self._base_config.max_continues:
                    self._messages.append(
                        {
                            "role": "user",
                            "content": self._base_config.final_json_message,
                        }
                    )
                else:
                    self._messages.append({"role": "user", "content": self._get_continue_prompt()})
                continue

            # Case 3: Accept text as final output.
            self._messages.append({"role": "assistant", "content": content.rstrip()})
            output = self.parse_output(content)
            logger.info(
                "[%s] Finished: %d turns, %d tool calls, %d tokens, %.1fs",
                agent_name,
                turns_used,
                len(self._tool_calls),
                total_tokens.total_tokens,
                time.monotonic() - start,
            )

            return AgentResult(
                output=output,
                tool_calls=self._tool_calls,
                tool_results=self._tool_results,
                turns_used=turns_used,
                tokens=total_tokens,
                wall_clock_seconds=time.monotonic() - start,
            )

        logger.warning(
            "[%s] Exhausted %d turns without final text output (tool_calls=%d, tokens=%d, %.1fs)",
            agent_name,
            self.config.max_turns,
            len(self._tool_calls),
            total_tokens.total_tokens,
            time.monotonic() - start,
        )

        # Prevents common failure where coaching/continue loops burn
        # all turns and parse_output gets non-JSON text.
        if has_tools and len(self._tool_calls) > 0:
            self._messages.append(
                {
                    "role": "user",
                    "content": self._base_config.final_json_message,
                }
            )
            try:
                final_resp, final_tokens = await self._call_llm(tool_choice="none")
                total_tokens = total_tokens + final_tokens
                # Fix L2: record exhausted-turns final demand to tracker
                self._accumulated_cost += final_tokens.estimated_cost_usd
                if self._budget_tracker is not None:
                    self._budget_tracker.record(final_tokens)
                final_content = final_resp.choices[0].message.content or ""
                if final_content.strip():
                    logger.info(
                        "[%s] Final JSON demand produced %d chars",
                        agent_name,
                        len(final_content),
                    )
                    output = self.parse_output(final_content)
                    return AgentResult(
                        output=output,
                        tool_calls=self._tool_calls,
                        tool_results=self._tool_results,
                        turns_used=turns_used + 1,
                        tokens=total_tokens,
                        wall_clock_seconds=time.monotonic() - start,
                    )
            except Exception:
                logger.warning("[%s] Final JSON demand LLM call failed", agent_name, exc_info=True)

        last_content = ""
        for msg in reversed(self._messages):
            if msg.get("role") == "assistant" and msg.get("content"):
                last_content = str(msg["content"])
                break

        output = self.parse_output(last_content) if last_content else {}

        return AgentResult(
            output=output,
            tool_calls=self._tool_calls,
            tool_results=self._tool_results,
            turns_used=turns_used,
            tokens=total_tokens,
            wall_clock_seconds=time.monotonic() - start,
        )

    def _apply_compaction(self) -> None:
        """Apply message compaction in-place, pruning old messages.

        Shared by BaseAgent._call_llm and ExploitAgent._call_llm so
        compaction logic isn't duplicated across agent types.
        """
        model = self.llm._resolve_model(self.config.model)
        before_count = len(self._messages)
        self._messages = _compact_messages(self._messages, model)
        if len(self._messages) < before_count:
            logger.info(
                "[%s] Compaction fired: %d -> %d messages",
                self.config.name,
                before_count,
                len(self._messages),
            )

    async def _call_llm(
        self,
        tool_choice: str | None = None,
    ) -> tuple[Any, TokenUsage]:
        """Call LLM with current messages and tool schemas.

        Before each call, applies compaction to ``self._messages`` so that
        the agent's message history is pruned (not just the API call payload).
        This prevents monotonic message growth across turns.

        Args:
            tool_choice: Override for ``tool_choice`` (``"required"``,
                ``"auto"``, ``"none"``).  ``None`` uses the LLM client
                default (``"auto"`` when tools are present).
        """
        self._apply_compaction()

        tool_schemas = self.tools.to_openai_schemas() if len(self.tools) > 0 else None
        n_tools = len(tool_schemas) if tool_schemas else 0
        logger.debug(
            "[%s] _call_llm: model=%s, tool_choice=%s, n_tools=%d, n_messages=%d",
            self.config.name,
            self.config.model,
            tool_choice or "auto",
            n_tools,
            len(self._messages),
        )
        response, tokens = await self.llm.complete(
            messages=self._messages,
            model=self.config.model,
            tools=tool_schemas,
            tool_choice=tool_choice,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        return response, tokens

    def inject_system_message(self, content: str) -> None:
        """Inject a system message into the conversation (for coaching)."""
        self._messages.append({"role": "system", "content": content})

    @property
    def messages(self) -> list[dict[str, Any]]:
        """Return a copy of the conversation history for logging/debugging."""
        return list(self._messages)

    def set_budget_tracker(self, tracker: BudgetTracker) -> None:
        """Wire a shared BudgetTracker for pipeline-wide cost tracking.

        When set, the turn loop records every LLM call to the tracker
        and checks ``tracker.is_exhausted`` for the cost cap.
        """
        self._budget_tracker = tracker

    @property
    def accumulated_cost(self) -> float:
        """Return the total cost accumulated across turns."""
        return self._accumulated_cost

    @abstractmethod
    def format_input(self, input_data: dict[str, Any]) -> str:
        """Format input data as a user message string."""
        ...

    @abstractmethod
    def parse_output(self, content: str) -> dict[str, Any]:
        """Parse LLM's final text output into structured data."""
        ...

    def should_stop(self, content: str) -> bool:
        """
        Override in subclasses to enforce that the agent must produce
        a specific output format (e.g., JSON with exploitation_level)
        before it's allowed to exit the turn loop.  Default: always
        accept text as final.

        Only called when the agent has tools and has already made at
        least one tool call (the zero-tool-call case is handled by the
        nudge mechanism).
        """
        return True

    def should_abort_remaining_tools(self) -> bool:
        """Whether to skip executing remaining tool calls in a batch.

        When the LLM returns multiple tool calls in a single response,
        they are processed sequentially.  If a subclass sets a stop
        condition (e.g., grace period expired), remaining tool calls in
        the batch should be skipped rather than executed.

        Override in subclasses; default returns False (execute all).
        """
        return False

    def _get_continue_prompt(self) -> str:
        """Return the prompt injected when ``should_stop`` returns False"""
        return self._base_config.continue_message

    async def on_tool_result(  # noqa: B027
        self, tool_call: ToolCall, result: ToolResult, turn: int
    ) -> None:
        """Hook called after each tool execution"""


def _assistant_msg_to_dict(message: Any) -> dict[str, Any]:
    """Convert a litellm assistant message to a dict for message history.

    Strips trailing whitespace from content because the GitHub Copilot
    API rejects messages whose final assistant content ends with trailing
    whitespace (``invalid_request_body``).
    """
    raw_content: str = message.content or ""
    msg: dict[str, Any] = {"role": "assistant", "content": raw_content.rstrip()}
    if getattr(message, "tool_calls", None):
        msg["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": (
                        tc.function.arguments
                        if isinstance(tc.function.arguments, str)
                        else json.dumps(tc.function.arguments)
                    ),
                },
            }
            for tc in message.tool_calls
        ]
    return msg
