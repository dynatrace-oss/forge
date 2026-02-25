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

from forge.cve.enricher import CWEEnricher
from forge.models import CWEModule

logger = logging.getLogger(__name__)


class CWEModuleFactory:
    """Build :class:`CWEModule` instances from :class:`CWEEnricher` data.

    >>> factory = CWEModuleFactory(enricher)
    >>> module = factory.build("CWE-89")
    """

    def __init__(self, enricher: CWEEnricher) -> None:
        self._enricher = enricher
        self._cache: dict[str, CWEModule] = {}

    def build(self, cwe_id: str) -> CWEModule:
        """Build (or return cached) :class:`CWEModule` for *cwe_id*.

        Parameters
        ----------
        cwe_id:
            CWE identifier, e.g. ``"CWE-89"``.

        Returns
        -------
        CWEModule
            Module with CWE identity and CAPEC/ATT&CK escalation paths.
        """
        if cwe_id in self._cache:
            return self._cache[cwe_id]

        module = self._build_fresh(cwe_id)
        self._cache[cwe_id] = module

        logger.info(
            "Built CWEModule for %s: %d escalation paths",
            cwe_id,
            len(module.escalation_paths),
        )
        return module

    def _build_fresh(self, cwe_id: str) -> CWEModule:
        """Construct a new CWEModule from enricher data."""
        enricher = self._enricher
        cwe_name = enricher.get_cwe_name(cwe_id) or cwe_id

        # Escalation paths: CAPEC attack pattern chain
        techniques = enricher.get_techniques(cwe_id)
        escalation_paths = [
            f"{t.capec_id} ({t.capec_name}) \u2192 {t.attack_id} ({t.attack_name})"
            if t.attack_id
            else f"{t.capec_id} ({t.capec_name})"
            for t in techniques
        ]

        return CWEModule(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            escalation_paths=escalation_paths,
        )
