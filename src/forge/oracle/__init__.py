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
