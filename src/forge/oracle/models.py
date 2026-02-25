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
from typing import Literal

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

EvidenceSource = Literal[
    "filesystem",
    "process",
    "app_log",
    "http_response",
    "exploit_output",
    "template_criteria",
    "ground_truth",
]

EvidenceProvenance = Literal["server", "client", "unknown"]

ErrorClassification = Literal[
    "none",  # No error — exploit executed
    "connection_refused",  # App not reachable
    "wrong_endpoint",  # 404 or wrong URL
    "wrong_payload_format",  # App rejected the payload format
    "partial_trigger",  # Vulnerability partially triggered
    "fundamental",  # Wrong approach entirely
    "infrastructure",  # Sandbox/container issue
]


class OracleEvidence(BaseModel):
    """Evidence supporting an exploitation level classification."""

    source: EvidenceSource
    description: str
    level_match: int = Field(ge=0, le=3)
    indicator_matched: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: EvidenceProvenance = "unknown"


class OracleVerdict(BaseModel):
    """Result of oracle evaluation for a single exploit attempt."""

    binary_success: bool = False
    exploitation_level: int = Field(default=0, ge=0, le=3)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: list[OracleEvidence] = Field(default_factory=list)
    tier_used: Literal["effect", "template", "ground_truth", "llm"] = "effect"


class InlineOracleFeedback(BaseModel):
    """Feedback produced after each exploit tool call (R3).

    Provides per-turn progress signal so the LLM can course-correct
    instead of repeating failing approaches blindly.
    """

    turn: int
    exploitation_level: int = Field(default=0, ge=0, le=3)
    progress_delta: int = 0  # Change from previous turn's level
    error_classification: ErrorClassification = "none"
    connection_status: str = "unknown"  # "healthy", "crashed", "timeout", "refused"
    response_analysis: str = ""  # Brief analysis of last tool output
    suggested_fix: str | None = None  # Specific fix if error is correctable
    evidence: list[OracleEvidence] = Field(default_factory=list)  # Raw evidence for accumulation
