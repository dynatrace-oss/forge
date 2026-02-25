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
