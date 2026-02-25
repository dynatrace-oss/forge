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
