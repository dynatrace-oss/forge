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

import json
from pathlib import Path

import pytest

from forge.cve.enricher import CWEEnricher
from forge.models import TechniqueMapping


@pytest.fixture()
def enricher() -> CWEEnricher:
    """CWEEnricher using the shipped knowledge base."""
    kb_path = Path("data/cache/cwe/cwe_enrichment.json")
    if not kb_path.exists():
        pytest.skip("CWE enrichment KB not available")
    return CWEEnricher(cache_dir=kb_path.parent)


@pytest.fixture()
def enricher_with_tmp_kb(tmp_path: Path) -> CWEEnricher:
    """CWEEnricher with a minimal temporary knowledge base."""
    kb = {
        "CWE-89": {
            "name": "SQL Injection",
            "techniques": [
                {
                    "capec_id": "CAPEC-66",
                    "capec_name": "SQL Injection",
                    "attack_id": "T1190",
                    "attack_name": "Exploit Public-Facing Application",
                }
            ],
        }
    }
    kb_path = tmp_path / "cwe_enrichment.json"
    kb_path.write_text(json.dumps(kb), encoding="utf-8")
    return CWEEnricher(cache_dir=tmp_path)


class TestCWEEnricherTechniques:
    def test_cwe_89_has_capec_mapping(self, enricher: CWEEnricher) -> None:
        """CWE-89 (SQLi) returns CAPEC-66 (SQL Injection) in techniques."""
        techniques = enricher.get_techniques("CWE-89")
        assert len(techniques) > 0
        capec_ids = [t.capec_id for t in techniques]
        assert "CAPEC-66" in capec_ids
        assert all(isinstance(t, TechniqueMapping) for t in techniques)


class TestCWEEnricherCaching:
    def test_cache_persistence(self, enricher_with_tmp_kb: CWEEnricher) -> None:
        """Enrich once, verify data loads from cached JSON."""
        techniques = enricher_with_tmp_kb.get_techniques("CWE-89")
        assert len(techniques) == 1
        assert techniques[0].capec_id == "CAPEC-66"

        # Second call uses in-memory cache
        techniques2 = enricher_with_tmp_kb.get_techniques("CWE-89")
        assert techniques == techniques2
