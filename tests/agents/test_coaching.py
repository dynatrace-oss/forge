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

from forge.agents.coaching import CoachingConfig, CoachingTracker, CoachingType


@pytest.fixture
def tracker() -> CoachingTracker:
    return CoachingTracker(
        CoachingConfig(
            stuck_at_l0_turns=3,
            stuck_at_l1_l2_turns=2,
            stuck_at_l2_l3_turns=2,
            consecutive_error_turns=2,
        )
    )


class TestCoachingTracker:
    def test_no_coaching_initially(self, tracker: CoachingTracker) -> None:
        assert tracker.check_coaching(0, 0) is None

    @pytest.mark.parametrize(
        ("level", "num_turns", "expected_type"),
        [
            (0, 4, CoachingType.RECONNAISSANCE),
        ],
        ids=["0-4-reconnaissance"],
    )
    def test_stuck_triggers_coaching(
        self,
        tracker: CoachingTracker,
        level: int,
        num_turns: int,
        expected_type: CoachingType,
    ) -> None:
        for _ in range(num_turns):
            tracker.record_turn(level, False)
        msg = tracker.check_coaching(level, num_turns)
        assert msg is not None and msg.coaching_type == expected_type

    def test_error_recovery_priority(self, tracker: CoachingTracker) -> None:
        for _ in range(3):
            tracker.record_turn(0, True)
        msg = tracker.check_coaching(0, 3, recent_errors=["e1", "e2"])
        assert msg is not None and msg.coaching_type == CoachingType.ERROR_RECOVERY

    def test_progress_resets_stuck(self, tracker: CoachingTracker) -> None:
        tracker.record_turn(0, False)
        tracker.record_turn(0, False)
        tracker.record_turn(1, False)  # progress resets
        assert tracker.check_coaching(1, 3) is None  # only 0 stuck turns at L1


class TestCoachingTermination:
    def test_coaching_terminates_after_max_repeats(self) -> None:
        """Set max_repeats=3.  Fire same trigger enough times.  should_terminate becomes True."""
        tracker = CoachingTracker(CoachingConfig(stuck_at_l0_turns=1, max_coaching_repeats=3))
        assert tracker.should_terminate is False

        fired = 0
        for turn in range(20):
            tracker.record_turn(0, False)
            msg = tracker.check_coaching(0, turn * 2)
            if msg is not None:
                fired += 1
            if fired >= 3:
                break

        assert tracker.should_terminate is True
        assert tracker.coaching_counts.get("reconnaissance", 0) >= 3
