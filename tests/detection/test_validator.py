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

from forge.detection.models import SigmaRule, SnortRule
from forge.detection.validator import validate_sigma, validate_snort

VALID_SIGMA = """\
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains: "<script>"
  condition: selection
level: medium
"""

SIGMA_NO_TITLE = """\
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri|contains: "/api/"
  condition: selection
level: medium
"""

SIGMA_NO_DETECTION = """\
title: Missing Detection
status: experimental
logsource:
  category: webserver
level: medium
"""

SIGMA_INVALID_YAML = "title: [broken yaml\n  - missing: close"


class TestValidateSigma:
    def test_valid_sigma_passes(self) -> None:
        rule = SigmaRule(cve_id="CVE-2024-0001", raw_rule=VALID_SIGMA)
        errors = validate_sigma(rule)
        assert errors == []

    def test_empty_rule_fails(self) -> None:
        rule = SigmaRule(cve_id="CVE-2024-0001", raw_rule="")
        errors = validate_sigma(rule)
        assert len(errors) == 1
        assert "Empty rule" in errors[0].message

    def test_missing_title_fails(self) -> None:
        rule = SigmaRule(cve_id="CVE-2024-0001", raw_rule=SIGMA_NO_TITLE)
        errors = validate_sigma(rule)
        assert len(errors) >= 1
        assert errors[0].source == "pysigma"

    def test_missing_detection_fails(self) -> None:
        rule = SigmaRule(cve_id="CVE-2024-0001", raw_rule=SIGMA_NO_DETECTION)
        errors = validate_sigma(rule)
        assert len(errors) >= 1
        assert errors[0].source == "pysigma"

    def test_invalid_yaml_fails(self) -> None:
        rule = SigmaRule(cve_id="CVE-2024-0001", raw_rule=SIGMA_INVALID_YAML)
        errors = validate_sigma(rule)
        assert len(errors) >= 1

    @pytest.mark.parametrize(
        "raw_rule",
        [
            pytest.param("just a string", id="plain-text"),
            pytest.param("42", id="number"),
        ],
    )
    def test_non_rule_yaml_fails(self, raw_rule: str) -> None:
        rule = SigmaRule(cve_id="CVE-2024-0001", raw_rule=raw_rule)
        errors = validate_sigma(rule)
        assert len(errors) >= 1


VALID_SNORT = (
    "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 "
    '(msg:"CVE-2024-1234 XSS"; flow:established,to_server; '
    'content:"/search"; http_uri; sid:9000001; rev:1;)'
)

SNORT_NO_SID = (
    "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 "
    '(msg:"Test Rule"; content:"/api"; http_uri; rev:1;)'
)

SNORT_NO_MSG = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (content:"/api"; http_uri; sid:9000002; rev:1;)'
)


class TestValidateSnort:
    def test_valid_snort_passes(self) -> None:
        rule = SnortRule(cve_id="CVE-2024-0001", raw_rule=VALID_SNORT)
        errors = validate_snort(rule)
        assert errors == []

    def test_empty_rule_fails(self) -> None:
        rule = SnortRule(cve_id="CVE-2024-0001", raw_rule="")
        errors = validate_snort(rule)
        assert len(errors) == 1
        assert "Empty rule" in errors[0].message

    def test_unparseable_rule_fails(self) -> None:
        rule = SnortRule(cve_id="CVE-2024-0001", raw_rule="this is not a rule")
        errors = validate_snort(rule)
        assert len(errors) >= 1
        assert errors[0].source == "idstools"

    def test_missing_sid_flagged(self) -> None:
        rule = SnortRule(cve_id="CVE-2024-0001", raw_rule=SNORT_NO_SID)
        errors = validate_snort(rule)
        sid_errors = [e for e in errors if e.field == "sid"]
        assert len(sid_errors) >= 1

    def test_missing_msg_flagged(self) -> None:
        rule = SnortRule(cve_id="CVE-2024-0001", raw_rule=SNORT_NO_MSG)
        errors = validate_snort(rule)
        msg_errors = [e for e in errors if e.field == "msg"]
        assert len(msg_errors) >= 1

    def test_line_continuation_normalised(self) -> None:
        multiline = (
            "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \\\n"
            '(msg:"Test"; content:"/api"; sid:9000003; rev:1;)'
        )
        rule = SnortRule(cve_id="CVE-2024-0001", raw_rule=multiline)
        errors = validate_snort(rule)
        assert errors == []
