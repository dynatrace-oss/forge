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

from forge.detection.models import (
    ConfidenceTier,
    DetectionRule,
    ExploitArtifacts,
    FileArtifact,
    HttpExchange,
    SigmaRule,
    SnortRule,
    ValidationError,
)

__all__ = [
    "ConfidenceTier",
    "DetectionRule",
    "ExploitArtifacts",
    "FileArtifact",
    "HttpExchange",
    "SigmaRule",
    "SnortRule",
    "SigmaGenerator",
    "SnortGenerator",
    "ValidationError",
    "collect_artifacts",
    "validate_sigma",
    "validate_snort",
]


def __getattr__(name: str) -> object:
    """Lazy imports for heavy modules."""
    if name == "collect_artifacts":
        from forge.detection.artifacts import collect_artifacts

        return collect_artifacts
    if name == "SigmaGenerator":
        from forge.detection.sigma_gen import SigmaGenerator

        return SigmaGenerator
    if name == "SnortGenerator":
        from forge.detection.snort_gen import SnortGenerator

        return SnortGenerator
    if name == "validate_sigma":
        from forge.detection.validator import validate_sigma

        return validate_sigma
    if name == "validate_snort":
        from forge.detection.validator import validate_snort

        return validate_snort
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
