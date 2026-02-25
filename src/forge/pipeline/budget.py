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
import math

from forge.models import TokenUsage

logger = logging.getLogger(__name__)


class BudgetTracker:
    """Single source of truth for pipeline-wide cost tracking.

    Shared across all agents in a pipeline run.  Each agent records
    token usage after every LLM call; budget checks read from this
    tracker instead of per-agent accumulators.

    When ``total_budget <= 0``, the tracker operates in unlimited mode:
    ``remaining`` returns infinity and ``is_exhausted`` returns False.
    """

    __slots__ = ("_total_budget", "_accumulated_cost", "_total_tokens")

    def __init__(self, total_budget: float = 0.0) -> None:
        self._total_budget = total_budget
        self._accumulated_cost = 0.0
        self._total_tokens = TokenUsage()

    @property
    def total_budget(self) -> float:
        return self._total_budget

    @property
    def accumulated_cost(self) -> float:
        return self._accumulated_cost

    @property
    def remaining(self) -> float:
        """Remaining budget in USD.  Returns inf when no budget is set."""
        if self._total_budget <= 0:
            return math.inf
        return max(self._total_budget - self._accumulated_cost, 0.0)

    @property
    def is_exhausted(self) -> bool:
        """True when accumulated cost meets or exceeds the budget."""
        if self._total_budget <= 0:
            return False
        return self._accumulated_cost >= self._total_budget

    @property
    def total_tokens(self) -> TokenUsage:
        return self._total_tokens

    def record(self, tokens: TokenUsage) -> None:
        """Record token usage from an LLM call."""
        self._accumulated_cost += tokens.estimated_cost_usd
        self._total_tokens = self._total_tokens + tokens
