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

"""Tests for CWEModuleFactory."""

import json
from pathlib import Path

import pytest

from forge.cve.cwe_module_factory import CWEModuleFactory
from forge.cve.enricher import CWEEnricher
from forge.models import CWEModule


@pytest.fixture()
def enricher(tmp_path: Path) -> CWEEnricher:
    """CWEEnricher backed by a minimal temporary KB."""
    kb = {
        "CWE-89": {
            "name": "SQL Injection",
            "techniques": [
                {
                    "capec_id": "CAPEC-66",
                    "capec_name": "SQL Injection",
                    "attack_id": "T1190",
                    "attack_name": "Exploit Public-Facing Application",
                },
                {
                    "capec_id": "CAPEC-7",
                    "capec_name": "Blind SQL Injection",
                    "attack_id": "T1190",
                    "attack_name": "Exploit Public-Facing Application",
                },
            ],
        }
    }
    kb_path = tmp_path / "cwe_enrichment.json"
    kb_path.write_text(json.dumps(kb), encoding="utf-8")
    return CWEEnricher(cache_dir=tmp_path)


@pytest.fixture()
def factory(enricher: CWEEnricher) -> CWEModuleFactory:
    return CWEModuleFactory(enricher)


class TestCWEModuleFactory:
    def test_build_cwe_89_module(self, factory: CWEModuleFactory) -> None:
        """Factory produces CWEModule with non-empty escalation paths."""
        module = factory.build("CWE-89")
        assert isinstance(module, CWEModule)
        assert module.cwe_id == "CWE-89"
        assert module.cwe_name == "SQL Injection"
        assert len(module.escalation_paths) > 0

    def test_module_caching(self, factory: CWEModuleFactory) -> None:
        """Same CWE requested twice returns same instance."""
        m1 = factory.build("CWE-89")
        m2 = factory.build("CWE-89")
        assert m1 is m2  # exact same object due to cache

    def test_unknown_cwe_returns_empty_module(self, factory: CWEModuleFactory) -> None:
        """Unknown CWE still returns a valid (empty) CWEModule."""
        module = factory.build("CWE-999999")
        assert isinstance(module, CWEModule)
        assert module.cwe_id == "CWE-999999"
        assert module.escalation_paths == []
