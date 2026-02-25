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
