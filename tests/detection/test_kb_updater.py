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
