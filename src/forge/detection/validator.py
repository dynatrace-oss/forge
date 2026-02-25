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
import re

import idstools.rule  # type: ignore[import-untyped]
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule as PySigmaRule

from forge.detection.models import SigmaRule, SnortRule
from forge.detection.models import ValidationError as VError

logger = logging.getLogger(__name__)

_SNORT_SID_RE = re.compile(r"sid:\s*(\d+)")
_SNORT_MSG_RE = re.compile(r'msg:\s*"[^"]*"')


def validate_sigma(rule: SigmaRule) -> list[VError]:
    """Validate a Sigma rule using pySigma.

    Delegates all structural and semantic checks to the pySigma library
    (``SigmaRule.from_yaml``).  Returns a list of validation errors;
    an empty list means the rule is valid.
    """
    raw = rule.raw_rule.strip()
    if not raw:
        return [VError(field="raw_rule", message="Empty rule")]

    try:
        PySigmaRule.from_yaml(raw)
    except SigmaError as exc:
        return [VError(field="raw_rule", message=str(exc), source="pysigma")]
    except Exception as exc:  # noqa: BLE001
        return [VError(field="raw_rule", message=f"Parse error: {exc}", source="pysigma")]

    return []


def validate_snort(rule: SnortRule) -> list[VError]:
    """Validate a Snort rule using idstools.

    ``idstools.rule.parse()`` returns ``None`` for unparseable rules.
    After a successful parse we verify the presence of *sid* and *msg*
    fields which are required for production deployment.
    """
    raw = rule.raw_rule.strip()
    if not raw:
        return [VError(field="raw_rule", message="Empty rule")]

    # Normalise line continuations before parsing
    normalised = raw.replace("\\\n", " ")

    parsed = idstools.rule.parse(normalised)
    if parsed is None:
        return [
            VError(field="raw_rule", message="idstools: rule is unparseable", source="idstools")
        ]

    errors: list[VError] = []
    if not _SNORT_SID_RE.search(normalised):
        errors.append(
            VError(field="sid", message="Rule must contain sid:<number>", source="idstools")
        )
    if not _SNORT_MSG_RE.search(normalised):
        errors.append(VError(field="msg", message='Rule must contain msg:"..."', source="idstools"))

    return errors
