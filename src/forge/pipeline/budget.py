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
