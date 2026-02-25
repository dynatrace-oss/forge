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

import math

import pytest

from forge.models import TokenUsage
from forge.pipeline.budget import BudgetTracker


class TestBudgetTracker:
    def test_initial_state(self) -> None:
        tracker = BudgetTracker(total_budget=5.0)
        assert tracker.total_budget == pytest.approx(5.0)
        assert tracker.accumulated_cost == pytest.approx(0.0)
        assert tracker.remaining == pytest.approx(5.0)
        assert tracker.is_exhausted is False
        assert tracker.total_tokens.total_tokens == 0

    def test_record_accumulates_cost_and_tokens(self) -> None:
        tracker = BudgetTracker(total_budget=10.0)
        t1 = TokenUsage(total_tokens=100, llm_calls=1, estimated_cost_usd=2.0)
        t2 = TokenUsage(total_tokens=200, llm_calls=1, estimated_cost_usd=3.0)
        tracker.record(t1)
        tracker.record(t2)
        assert tracker.accumulated_cost == pytest.approx(5.0)
        assert tracker.remaining == pytest.approx(5.0)
        assert tracker.total_tokens.total_tokens == 300
        assert tracker.total_tokens.llm_calls == 2

    def test_is_exhausted_at_budget(self) -> None:
        tracker = BudgetTracker(total_budget=1.0)
        tracker.record(TokenUsage(total_tokens=50, estimated_cost_usd=1.0))
        assert tracker.is_exhausted is True
        assert tracker.remaining == pytest.approx(0.0)

    def test_is_exhausted_over_budget(self) -> None:
        tracker = BudgetTracker(total_budget=1.0)
        tracker.record(TokenUsage(total_tokens=50, estimated_cost_usd=1.5))
        assert tracker.is_exhausted is True
        assert tracker.remaining == pytest.approx(0.0)

    def test_unlimited_mode_when_no_budget(self) -> None:
        tracker = BudgetTracker(total_budget=0.0)
        tracker.record(TokenUsage(total_tokens=9999, estimated_cost_usd=100.0))
        assert tracker.is_exhausted is False
        assert tracker.remaining == math.inf
        assert tracker.accumulated_cost == pytest.approx(100.0)

    @pytest.mark.parametrize(
        ("budget", "cost", "expected_exhausted"),
        [
            pytest.param(5.0, 4.99, False, id="just-under"),
            pytest.param(5.0, 5.0, True, id="exact-match"),
            pytest.param(5.0, 5.01, True, id="just-over"),
        ],
    )
    def test_exhaustion_boundary(
        self, budget: float, cost: float, expected_exhausted: bool
    ) -> None:
        tracker = BudgetTracker(total_budget=budget)
        tracker.record(TokenUsage(total_tokens=1, estimated_cost_usd=cost))
        assert tracker.is_exhausted is expected_exhausted
