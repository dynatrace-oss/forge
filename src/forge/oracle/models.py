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
