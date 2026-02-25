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

from forge.oracle.models import InlineOracleFeedback, OracleEvidence, OracleVerdict

__all__ = [
    "CriticVerdict",
    "DefaultInlineOracle",
    "InlineOracleFeedback",
    "LLMOracleCritic",
    "OracleEvidence",
    "OracleVerdict",
]


def __getattr__(name: str) -> object:
    """Lazy imports to avoid circular dependency with models."""
    if name == "DefaultInlineOracle":
        from forge.oracle.inline_oracle import DefaultInlineOracle

        return DefaultInlineOracle
    if name == "LLMOracleCritic":
        from forge.oracle.llm_critic import LLMOracleCritic

        return LLMOracleCritic
    if name == "CriticVerdict":
        from forge.oracle.llm_critic import CriticVerdict

        return CriticVerdict
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
