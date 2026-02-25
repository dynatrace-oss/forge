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
