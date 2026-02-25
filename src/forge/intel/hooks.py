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
from pathlib import Path

from forge.intel.cache import RawCache
from forge.intel.compiler import IntelReport, ReportCompiler
from forge.intel.knowledge import KnowledgeStore
from forge.models import CVETask

logger = logging.getLogger(__name__)


class IntelHooks:
    """Lifecycle hooks that wire the 4-tier intelligence store together.

    Called by the orchestrator at key pipeline events to coordinate
    cache, compiler, knowledge, and graph updates.
    """

    def __init__(
        self,
        cache: RawCache,
        compiler: ReportCompiler,
        knowledge: KnowledgeStore,
    ) -> None:
        self._cache = cache
        self._compiler = compiler
        self._knowledge = knowledge

    @classmethod
    def from_paths(
        cls,
        cache_dir: Path,
        compiled_dir: Path,
        knowledge_dir: Path,
        *,
        cache_ttl_seconds: int | None = None,
    ) -> "IntelHooks":
        """Create the full intel stack from explicit directory paths.

        This is the preferred construction method when using ``StorageManager``::

            hooks = IntelHooks.from_paths(
                cache_dir=storage.cache_dir(),
                compiled_dir=storage.cache_dir() / "compiled",
                knowledge_dir=storage.knowledge_dir("exploitation"),
            )

        Args:
            cache_ttl_seconds: Override default cache TTL (default: 7 days).
        """
        cache_kwargs: dict[str, int] = {}
        if cache_ttl_seconds is not None:
            cache_kwargs["default_ttl"] = cache_ttl_seconds
        cache = RawCache(cache_dir=cache_dir, **cache_kwargs)
        compiler = ReportCompiler(cache, compiled_dir=compiled_dir)
        knowledge = KnowledgeStore(knowledge_dir=knowledge_dir)
        return cls(cache, compiler, knowledge)

    @property
    def cache(self) -> RawCache:
        """Access the Tier 1 raw cache."""
        return self._cache

    @property
    def compiler(self) -> ReportCompiler:
        """Access the Tier 2 report compiler."""
        return self._compiler

    @property
    def knowledge(self) -> KnowledgeStore:
        """Access the Tier 3 CWE knowledge store."""
        return self._knowledge

    def on_cve_load(self, task: CVETask) -> IntelReport | None:
        """Called when a CVE is selected for assessment.

        Checks for an existing compiled report. If found and fresh,
        returns it. Recompiles when the cached report is stale (e.g.
        missing ``tech_stack.language`` that newer compiler logic can
        infer). Returns None if no raw data is cached yet (Intel Agent
        must gather it first).
        """
        existing = self._compiler.load(task.cve_id)
        if existing and existing.sources_used:
            # Recompile stale reports that are missing tech_stack data
            # which newer compiler tiers (CPE / description inference)
            # can now populate.
            if not existing.tech_stack.language:
                refreshed = self._compiler.compile(task.cve_id)
                if refreshed.tech_stack.language:
                    logger.info(
                        "Recompiled stale intel report for %s: inferred language=%s",
                        task.cve_id,
                        refreshed.tech_stack.language,
                    )
                    self._compiler.save(refreshed)
                    return refreshed
            logger.debug(
                "Found existing intel report for %s (sources=%s)",
                task.cve_id,
                existing.sources_used,
            )
            return existing

        report = self._compiler.compile(task.cve_id)
        if not report.sources_used:
            logger.debug(
                "No cached raw data for %s — Intel Agent must gather it",
                task.cve_id,
            )
            return None

        self._compiler.save(report)
        return report

    def on_intel_complete(self, task: CVETask) -> IntelReport:
        """Called after the Intel Agent finishes gathering data.

        Compiles (or recompiles) the Tier 2 report from all cached
        raw data and updates the knowledge graph.
        """
        report = self._compiler.compile(task.cve_id)
        self._compiler.save(report)
        logger.info(
            "Compiled intel report for %s: confidence=%.2f, sources=%s",
            task.cve_id,
            report.confidence,
            report.sources_used,
        )
        return report

    def on_exploit_complete(
        self,
        task: CVETask,
        max_level: int,
        techniques_used: list[str] | None = None,
    ) -> None:
        """Called after exploitation finishes.

        Updates Tier 3 CWE knowledge with the outcome.
        """
        language = task.language or ""
        for cwe_id in task.cwe_ids:
            self._knowledge.record_attempt(
                cwe_id=cwe_id,
                cve_id=task.cve_id,
                max_level=max_level,
                techniques_used=techniques_used,
                cwe_name=cwe_id,
                language=language,
            )

        logger.info(
            "Updated CWE knowledge for %s: level=%d, techniques=%s",
            task.cve_id,
            max_level,
            techniques_used or [],
        )
