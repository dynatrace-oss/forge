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

from pathlib import Path

import pytest
import yaml

from forge.detection.kb_updater import DetectionKBUpdater
from forge.detection.models import SigmaRule

_VALID_SIGMA_RAW = """\
title: Test Generated Rule
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains: "' OR 1=1"
  condition: selection
level: medium
"""

_VALID_SNORT_RAW = (
    "alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS "
    '(msg:"Test generated Snort rule"; '
    'content:"|27| OR 1=1"; http_uri; '
    "sid:9999001; rev:1;)"
)

_INVALID_SIGMA_RAW = "not: valid\nyaml: data"  # Missing title, logsource, detection


@pytest.fixture()
def kb_dir(tmp_path: Path) -> Path:
    """Create a detection KB directory with a curated CWE-89 entry."""
    d = tmp_path / "detection"
    cwe89 = d / "cwe-89" / "sigma"
    cwe89.mkdir(parents=True)
    # Write a curated meta.yaml
    meta = d / "cwe-89" / "meta.yaml"
    meta.write_text(
        yaml.dump(
            {
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "detection_strategy": "Match SQL metacharacters",
                "tier_coverage": ["web"],
                "source": "curated",
                "last_updated": "2026-04-01",
            },
            default_flow_style=False,
        )
    )
    return d


class TestSuccessfulRuleAdded:
    def test_valid_sigma_rule_written_to_kb(self, kb_dir: Path) -> None:
        """Generate valid Sigma rule for CWE-89. Verify file written."""
        updater = DetectionKBUpdater(kb_dir)
        rule = SigmaRule(
            cve_id="CVE-2025-0001",
            cwe_id="CWE-89",
            title="sqli_union_select",
            raw_rule=_VALID_SIGMA_RAW,
        )
        written = updater.update("CWE-89", [rule])
        assert len(written) == 1
        assert written[0].name.startswith("generated_")
        assert written[0].suffix == ".yml"
        assert written[0].exists()


class TestInvalidRuleNotAdded:
    def test_invalid_sigma_not_written(self, kb_dir: Path) -> None:
        """Invalid Sigma rule (missing required fields) is rejected."""
        updater = DetectionKBUpdater(kb_dir)
        rule = SigmaRule(
            cve_id="CVE-2025-0003",
            cwe_id="CWE-89",
            title="bad_rule",
            raw_rule=_INVALID_SIGMA_RAW,
        )
        written = updater.update("CWE-89", [rule])
        assert len(written) == 0


class TestGeneratedRulesTagged:
    def test_sigma_rule_contains_source_generated(self, kb_dir: Path) -> None:
        """Written Sigma rule YAML contains ``source: generated``."""
        updater = DetectionKBUpdater(kb_dir)
        rule = SigmaRule(
            cve_id="CVE-2025-0005",
            cwe_id="CWE-89",
            title="tagged_rule",
            raw_rule=_VALID_SIGMA_RAW,
        )
        written = updater.update("CWE-89", [rule])
        assert len(written) == 1
        content = yaml.safe_load(written[0].read_text())
        assert content["source"] == "generated"
        assert content["quality"] == pytest.approx(1.0)


class TestNewCWEDirectory:
    def test_update_creates_cwe_directory(self, kb_dir: Path) -> None:
        """Updating a CWE that doesn't exist yet creates its directory."""
        updater = DetectionKBUpdater(kb_dir)
        rule = SigmaRule(
            cve_id="CVE-2025-0010",
            cwe_id="CWE-999",
            title="new_cwe_rule",
            raw_rule=_VALID_SIGMA_RAW,
        )
        written = updater.update("CWE-999", [rule])
        assert len(written) == 1
        assert (kb_dir / "cwe-999" / "sigma").exists()
        assert (kb_dir / "cwe-999" / "meta.yaml").exists()
