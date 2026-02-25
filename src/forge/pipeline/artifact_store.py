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
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _safe_child(base: Path, untrusted: str) -> Path:
    """Resolve an untrusted relative path and verify it stays inside *base*.

    Raises ValueError if the resolved path escapes the base directory
    (e.g. via ``../`` sequences in LLM-generated filenames).
    """
    resolved = (base / untrusted).resolve()
    base_resolved = base.resolve()
    if not str(resolved).startswith(str(base_resolved) + "/") and resolved != base_resolved:
        raise ValueError(f"Path traversal blocked: {untrusted!r} resolves outside {base}")
    return resolved


class ArtifactStore:
    """Persists per-run artifacts (generated code, exploit scripts, logs) to disk.

    Directory layout per run:
        {results_dir}/{cve_id}/{condition}/run_{run_index}/
            app/           — generated project files (Dockerfile, source code, etc.)
            exploit/       — exploit scripts (exploit.py, etc.)
            build.log      — container build log
            deploy.log     — container/app logs from deploy phase
    """

    def __init__(self, results_dir: Path) -> None:
        self._results_dir = results_dir

    def save_build(
        self,
        cve_id: str,
        condition: str,
        run_index: int,
        project_files: dict[str, str],
        build_log: str = "",
    ) -> Path:
        """Save build artifacts (project files and build log).

        Returns the artifact directory path.
        """
        run_dir = self._run_dir(cve_id, condition, run_index)
        app_dir = run_dir / "app"
        app_dir.mkdir(parents=True, exist_ok=True)

        for filepath, content in project_files.items():
            file_path = _safe_child(app_dir, filepath)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)

        if build_log:
            (run_dir / "build.log").write_text(build_log)

        logger.debug(
            "Saved %d build artifacts for %s/%s/run_%d",
            len(project_files),
            cve_id,
            condition,
            run_index,
        )
        return run_dir

    def save_exploit(
        self,
        cve_id: str,
        condition: str,
        run_index: int,
        exploit_files: dict[str, str],
        execution_log: str = "",
    ) -> None:
        """Save exploit artifacts (scripts and execution log)."""
        run_dir = self._run_dir(cve_id, condition, run_index)
        exploit_dir = run_dir / "exploit"
        exploit_dir.mkdir(parents=True, exist_ok=True)

        for filepath, content in exploit_files.items():
            file_path = _safe_child(exploit_dir, filepath)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)

        if execution_log:
            (exploit_dir / "execution.log").write_text(execution_log)

        logger.debug(
            "Saved %d exploit artifacts for %s/%s/run_%d",
            len(exploit_files),
            cve_id,
            condition,
            run_index,
        )

    def save_deploy_log(
        self,
        cve_id: str,
        condition: str,
        run_index: int,
        container_logs: str,
    ) -> None:
        """Save deploy/container logs."""
        run_dir = self._run_dir(cve_id, condition, run_index)
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "deploy.log").write_text(container_logs)

    def save_detection(
        self,
        cve_id: str,
        condition: str,
        run_index: int,
        rule_type: str,
        rule_content: str,
    ) -> Path:
        """Save a detection rule (Sigma or Snort) to the detection/ subdirectory.

        Args:
            cve_id: CVE identifier.
            condition: Experiment condition label.
            run_index: Repetition index.
            rule_type: "sigma" or "snort".
            rule_content: Raw rule text.

        Returns:
            Path to the saved rule file.
        """
        detection_dir = self._run_dir(cve_id, condition, run_index) / "detection"
        detection_dir.mkdir(parents=True, exist_ok=True)

        ext = "yml" if rule_type == "sigma" else "rules"
        out_path = detection_dir / f"{rule_type}.{ext}"
        out_path.write_text(rule_content)

        logger.debug(
            "Saved %s detection rule for %s/%s/run_%d",
            rule_type,
            cve_id,
            condition,
            run_index,
        )
        return out_path

    def load_project_files(
        self,
        cve_id: str,
        condition: str,
        run_index: int,
    ) -> dict[str, str]:
        """Load previously saved project files for a run.

        Returns empty dict if no artifacts exist.
        """
        app_dir = self._run_dir(cve_id, condition, run_index) / "app"
        if not app_dir.exists():
            return {}

        files: dict[str, str] = {}
        for file_path in app_dir.rglob("*"):
            if file_path.is_file():
                relative = file_path.relative_to(app_dir)
                files[str(relative)] = file_path.read_text()
        return files

    def get_artifact_dir(
        self,
        cve_id: str,
        condition: str,
        run_index: int,
    ) -> Path:
        """Return the artifact directory path for a run (may not exist yet)."""
        return self._run_dir(cve_id, condition, run_index)

    def save_app_index(
        self,
        cve_id: str,
        condition: str,
        run_index: int,
        language: str,
        framework: str,
    ) -> None:
        """Update the technology-to-app index for cross-CVE reuse.

        Records that the app at ``(cve_id, condition, run_index)`` was built
        for the given ``(language, framework)`` pair.  Later runs targeting
        the same technology can call :meth:`find_similar_app` to retrieve
        the full project files as a reference template.

        The index is stored as ``_app_index.json`` in the results root.
        Uses exact ``language:framework`` keys — no fuzzy matching.
        """
        if not language and not framework:
            return

        index_path = self._results_dir / "_app_index.json"
        index: dict[str, Any] = {}
        if index_path.exists():
            try:
                index = json.loads(index_path.read_text())
            except (json.JSONDecodeError, OSError):
                logger.warning("Corrupt app index at %s, resetting", index_path)

        key = f"{language}:{framework}"
        index[key] = {
            "cve_id": cve_id,
            "condition": condition,
            "run_index": run_index,
        }

        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(json.dumps(index, indent=2))
        logger.debug(
            "App index updated: %s → %s/%s/run_%d",
            key,
            cve_id,
            condition,
            run_index,
        )

    def find_similar_app(
        self,
        language: str,
        framework: str,
    ) -> dict[str, str]:
        """Find a previously generated app for the same (language, framework).

        Returns the full project files dict if an exact match exists in the
        app index.  Returns an empty dict if no match is found or the
        referenced files no longer exist on disk.

        This enables cross-CVE app reuse: if CVE-A already generated a
        working Java/Spring app, CVE-B (also Java/Spring) gets those files
        as a reference template for its generator.
        """
        if not language and not framework:
            return {}

        index_path = self._results_dir / "_app_index.json"
        if not index_path.exists():
            return {}

        try:
            index: dict[str, Any] = json.loads(index_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

        key = f"{language}:{framework}"
        entry = index.get(key)
        if entry is None:
            return {}

        cve_id = entry.get("cve_id", "")
        condition = entry.get("condition", "")
        run_index = entry.get("run_index", 0)

        files = self.load_project_files(cve_id, condition, run_index)
        if files:
            logger.info(
                "Found reference app for %s: %s/%s/run_%d (%d files)",
                key,
                cve_id,
                condition,
                run_index,
                len(files),
            )
        return files

    def _run_dir(self, cve_id: str, condition: str, run_index: int) -> Path:
        return self._results_dir / cve_id / condition / f"run_{run_index}"
