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
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ConfidenceTier(StrEnum):
    """Detection rule confidence based on exploitation depth.

    Higher exploitation levels produce more specific indicators,
    yielding higher-confidence detection rules.
    """

    LOW = "low"  # Level 1: generic connection patterns
    MEDIUM = "medium"  # Level 2: exploitation achieved
    HIGH = "high"  # Level 3: full compromise
    CRITICAL = "critical"  # Level 3 with high oracle confidence


class HttpExchange(BaseModel):
    """A single HTTP request/response observed during exploitation."""

    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_snippet: str = ""


class FileArtifact(BaseModel):
    """A file created or modified during exploitation."""

    path: str
    action: Literal["created", "modified"]
    content_snippet: str = ""


class ExploitArtifacts(BaseModel):
    """Structured exploitation artifacts extracted from raw results.

    Aggregates all observable indicators from an exploit attempt
    into a form suitable for detection rule generation.
    """

    cve_id: str
    cwe_id: str = ""
    exploitation_level: int = Field(default=0, ge=0, le=3)
    confidence_tier: ConfidenceTier = ConfidenceTier.LOW

    http_exchanges: list[HttpExchange] = Field(default_factory=list)
    file_artifacts: list[FileArtifact] = Field(default_factory=list)
    payloads: list[str] = Field(default_factory=list)
    network_connections: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    crash_signals: list[str] = Field(default_factory=list)
    log_patterns: list[str] = Field(default_factory=list)


class ValidationError(BaseModel):
    """A single validation error found in a detection rule."""

    field: str
    message: str
    source: str = "schema"


class DetectionRule(BaseModel):
    """Base class for generated detection rules."""

    cve_id: str
    cwe_id: str = ""
    title: str = ""
    description: str = ""
    confidence_tier: ConfidenceTier = ConfidenceTier.LOW
    exploitation_level: int = Field(default=0, ge=0, le=3)
    raw_rule: str = ""
    validation_errors: list[ValidationError] = Field(default_factory=list)


class SigmaRule(DetectionRule):
    """A generated Sigma detection rule."""

    sigma_level: Literal["low", "medium", "high", "critical"] = "medium"
    logsource_product: str = ""
    logsource_category: str = ""


class SnortRule(DetectionRule):
    """A generated Snort/Suricata detection rule."""

    classtype: str = "web-application-attack"
    sid: int = 0
    protocol: str = "tcp"
