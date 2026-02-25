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
