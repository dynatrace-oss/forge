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

_KB_DIR = Path("data/knowledge/detection")

pytestmark = pytest.mark.skipif(
    not _KB_DIR.exists(),
    reason="requires forge-artifacts knowledge base (clone dynatrace-oss/forge-artifacts)",
)

_TOP_10_CWES = [
    "CWE-79",
    "CWE-89",
    "CWE-22",
    "CWE-78",
    "CWE-94",
    "CWE-502",
    "CWE-918",
    "CWE-352",
    "CWE-611",
    "CWE-77",
]

_TIER_PREFIXES = {
    "web": "web_",
    "host": "linux_",
    "network": "network_",
    "application": "app_",
}


def _cwe_dir(cwe_id: str) -> Path:
    """Return KB directory for a CWE, e.g., CWE-89 -> cwe-89."""
    num = cwe_id.split("-")[1]
    return _KB_DIR / f"cwe-{num}"


class TestKBStructure:
    def test_index_yaml_exists(self) -> None:
        assert (_KB_DIR / "index.yaml").exists()

    def test_index_yaml_valid(self) -> None:
        data = yaml.safe_load((_KB_DIR / "index.yaml").read_text())
        assert isinstance(data, dict)
        assert "cwes" in data
        assert "tiers" in data
        assert len(data["cwes"]) == 10

    @pytest.mark.parametrize("cwe_id", ["CWE-89"], ids=["CWE-89"])
    def test_cwe_directory_exists(self, cwe_id: str) -> None:
        cwe = _cwe_dir(cwe_id)
        assert cwe.is_dir(), f"Missing KB directory: {cwe}"
        assert (cwe / "meta.yaml").exists(), f"Missing meta.yaml in {cwe}"
        assert (cwe / "sigma").is_dir(), f"Missing sigma/ dir in {cwe}"
        assert (cwe / "snort").is_dir(), f"Missing snort/ dir in {cwe}"


class TestSigmaRulesValidYaml:
    """1.2: All Sigma rules must be valid YAML."""

    @pytest.fixture()
    def all_sigma_rules(self) -> list[tuple[Path, dict]]:
        rules: list[tuple[Path, dict]] = []
        for yml in sorted(_KB_DIR.rglob("sigma/*.yml")):
            data = yaml.safe_load(yml.read_text())
            rules.append((yml, data))
        return rules

    def test_sigma_rules_valid_yaml(self, all_sigma_rules: list[tuple[Path, dict]]) -> None:
        assert len(all_sigma_rules) > 0, "No Sigma rules found in KB"
        for path, data in all_sigma_rules:
            assert isinstance(data, dict), f"Not a YAML mapping: {path}"


class TestSnortRulesValid:
    """1.3: Snort rules must have valid syntax."""

    @pytest.fixture()
    def all_snort_rules(self) -> list[tuple[Path, list[str]]]:
        results: list[tuple[Path, list[str]]] = []
        for path in sorted(_KB_DIR.rglob("snort/*.rules")):
            lines = [
                ln.strip()
                for ln in path.read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            results.append((path, lines))
        return results

    def test_snort_rules_valid_syntax(self, all_snort_rules: list[tuple[Path, list[str]]]) -> None:
        assert len(all_snort_rules) > 0, "No Snort rules found in KB"
        for path, lines in all_snort_rules:
            for rule in lines:
                assert rule.startswith("alert"), f"Rule doesn't start with 'alert': {path}"
                assert "sid:" in rule, f"Missing 'sid:' in rule: {path}"
                assert "msg:" in rule, f"Missing 'msg:' in rule: {path}"
                assert "content:" in rule or "pcre:" in rule, (
                    f"No content:/pcre: match in rule: {path}"
                )


class TestAllTiers:
    """1.5: All 4 tiers represented in KB."""

    def test_all_tiers_represented(self) -> None:
        found_tiers: set[str] = set()
        for yml in sorted(_KB_DIR.rglob("sigma/*.yml")):
            name = yml.name
            for tier, prefix in _TIER_PREFIXES.items():
                if name.startswith(prefix):
                    found_tiers.add(tier)
        expected = {"web", "host", "network", "application"}
        missing = expected - found_tiers
        assert not missing, f"Missing tiers: {sorted(missing)}"
