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
import logging
from typing import Any

from forge.generator.verification import AppVerifier, VerificationResult
from forge.models import AppManifest, GeneratedApp
from forge.tools.base import Tool, ToolResult

logger = logging.getLogger(__name__)


class AddVulnerability(Tool):
    """Inject a vulnerability pattern into existing app code."""

    def __init__(self, app_state: dict[str, str]) -> None:
        self._app_state = app_state

    @property
    def name(self) -> str:
        return "add_vulnerability"

    @property
    def description(self) -> str:
        return (
            "Inject a vulnerability pattern into an existing app file. "
            "Provide the target file, CWE ID, endpoint route, complexity "
            "level, and the vulnerable code snippet to inject."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Target file to modify (must exist in app)",
                },
                "cwe_id": {
                    "type": "string",
                    "description": "CWE to inject (e.g., CWE-89)",
                },
                "endpoint": {
                    "type": "string",
                    "description": "Route/endpoint where vulnerability is accessible",
                },
                "complexity": {
                    "type": "string",
                    "description": "Complexity level: L1, L2, or L3",
                    "enum": ["L1", "L2", "L3"],
                },
                "code_snippet": {
                    "type": "string",
                    "description": "The vulnerable code to inject into the file",
                },
            },
            "required": ["file_path", "cwe_id", "endpoint", "code_snippet"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        file_path: str = arguments["file_path"]
        cwe_id: str = arguments["cwe_id"]
        endpoint: str = arguments["endpoint"]
        complexity: str = arguments.get("complexity", "L1")
        code_snippet: str = arguments["code_snippet"]

        if file_path not in self._app_state:
            return ToolResult(
                content=f"File not found in app: {file_path}. "
                f"Available files: {sorted(self._app_state.keys())}",
                error=True,
            )

        existing = self._app_state[file_path]
        self._app_state[file_path] = existing + "\n" + code_snippet

        return ToolResult(
            content=json.dumps(
                {
                    "modified": file_path,
                    "cwe_id": cwe_id,
                    "endpoint": endpoint,
                    "complexity": complexity,
                    "file_size": len(self._app_state[file_path]),
                }
            ),
        )


class WriteAppFiles(Tool):
    """Write multiple application files in a single call.

    Accepts an array of ``{path, content}`` objects (preferred) or a
    legacy dictionary of file paths to file contents (backward compat).
    All files are written atomically to the app state.
    """

    def __init__(self, app_state: dict[str, str]) -> None:
        self._app_state = app_state

    @property
    def name(self) -> str:
        return "write_app_files"

    @property
    def description(self) -> str:
        return (
            "Write multiple app files at once. Pass an array of "
            "{path, content} objects. Use this to create or overwrite "
            "all project files in a single call."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "description": (
                        "Array of files to write. Each entry has a 'path' "
                        "(relative file path) and 'content' (full file text)."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Relative file path (e.g., 'app.py', 'Dockerfile')",
                            },
                            "content": {
                                "type": "string",
                                "description": "Complete file contents",
                            },
                        },
                        "required": ["path", "content"],
                    },
                },
            },
            "required": ["files"],
        }

    # Lockfiles that should never be committed — they are generated by
    # the package manager during ``docker build`` and the LLM should
    # not attempt to create them.  If it does, we silently strip them.
    _LOCKFILE_NAMES: frozenset[str] = frozenset(
        {
            "go.sum",
            "Cargo.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "composer.lock",
            "Gemfile.lock",
            "poetry.lock",
            "Pipfile.lock",
        }
    )

    @staticmethod
    def _normalize_files(raw: Any) -> dict[str, str]:
        """Convert files arg to a path->content dict.

        Accepts:
          - list[{path, content}]  (new array schema)
          - dict[str, str]         (legacy dict schema — backward compat)
          - JSON string of either form
        """
        # Handle JSON-string wrapping (LLM double-serialization).
        # The LLM may wrap the array in 1 or 2 extra string layers.
        # Unwrap up to 2 levels so we reach the underlying list/dict.
        for _depth in range(2):
            if not isinstance(raw, str):
                break
            try:
                raw = json.loads(raw)
            except ValueError as exc:
                raise TypeError(
                    f"files must be an array or dict, got unparseable string: {exc}"
                ) from exc

        # New array format: [{path: "...", content: "..."}, ...]
        if isinstance(raw, list):
            result: dict[str, str] = {}
            for i, entry in enumerate(raw):
                if not isinstance(entry, dict):
                    raise TypeError(
                        f"files[{i}] must be an object with 'path' and 'content', "
                        f"got {type(entry).__name__}"
                    )
                path = entry.get("path")
                content = entry.get("content")
                if not path:
                    raise TypeError(f"files[{i}] missing required 'path' field")
                if content is None:
                    raise TypeError(f"files[{i}] missing required 'content' field")
                if not isinstance(content, str):
                    content = json.dumps(content, indent=2)
                result[str(path)] = content
            return result

        # Legacy dict format: {"app.py": "...", "Dockerfile": "..."}
        if isinstance(raw, dict):
            coerced: dict[str, str] = {}
            for path, content in raw.items():
                if not isinstance(content, str):
                    content = json.dumps(content, indent=2)
                coerced[str(path)] = content
            return coerced

        raise TypeError(f"files must be an array or dict, got {type(raw).__name__}")

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        raw_files = arguments.get("files")
        if not raw_files:
            return ToolResult(
                content=(
                    'Error: files is empty. You MUST pass the "files" parameter '
                    "as an array of {path, content} objects. "
                    'Example: {"files": ['
                    '{"path": "Dockerfile", "content": "FROM python:3.12-slim\\n..."}, '
                    '{"path": "app.py", "content": "from flask import Flask\\n..."}]}'
                ),
                error=True,
            )

        try:
            files = self._normalize_files(raw_files)
        except TypeError as exc:
            return ToolResult(content=f"Error: {exc}", error=True)

        if not files:
            return ToolResult(
                content=(
                    "Error: files resolved to empty. Provide at least one file with "
                    '"path" and "content" fields.'
                ),
                error=True,
            )

        # Strip lockfiles the LLM should not produce
        stripped: list[str] = []
        for path in list(files):
            basename = path.rsplit("/", maxsplit=1)[-1]
            if basename in self._LOCKFILE_NAMES:
                stripped.append(path)
                del files[path]

        if stripped:
            logger.warning(
                "Stripped %d lockfile(s) from LLM output: %s",
                len(stripped),
                ", ".join(stripped),
            )

        if not files:
            return ToolResult(
                content="Error: all provided files were lockfiles and were stripped. "
                "Please provide actual source files instead.",
                error=True,
            )

        for path, content in files.items():
            self._app_state[path] = content

        msg = f"Wrote {len(files)} files:\n"
        msg += "\n".join(f"  - {p}" for p in sorted(files))
        if stripped:
            msg += (
                f"\nNOTE: Stripped lockfile(s): {', '.join(stripped)}. "
                "These are auto-generated by the package manager during "
                "docker build — do NOT include them. Your Dockerfile must "
                "generate them (e.g. `go mod tidy`, `composer install`, "
                "`npm install`). Ensure your COPY commands do NOT reference "
                "these files."
            )
            stripped_basenames = {p.rsplit("/", maxsplit=1)[-1] for p in stripped}
            if "go.sum" in stripped_basenames:
                msg += (
                    "\nGo CRITICAL: Your Dockerfile MUST copy ALL source "
                    "files BEFORE running `go mod tidy`. The correct "
                    "pattern is: `COPY . .` then "
                    "`RUN go mod tidy && CGO_ENABLED=0 go build -o server .` "
                    "in a single layer. `go mod tidy` scans .go source "
                    "files to resolve imports — it CANNOT run before "
                    "source files are copied."
                )
        return ToolResult(content=msg)


class ValidateApp(Tool):
    """Build, deploy, and test the generated application."""

    def __init__(
        self,
        verifier: AppVerifier,
        app_state: dict[str, str],
    ) -> None:
        self._verifier = verifier
        self._app_state = app_state
        # Set by GeneratorAgent before the turn loop so that in-loop
        # validate_app calls enforce package fidelity.
        self.expected_package: str = ""

    @property
    def name(self) -> str:
        return "validate_app"

    @property
    def description(self) -> str:
        return (
            "Build, deploy, and validate the current generated application. "
            "Checks: Docker build succeeds, container starts, health endpoint "
            "responds, and vulnerable endpoint is accessible. Returns a "
            "structured report with pass/fail for each stage."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {},
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        if not self._app_state:
            return ToolResult(
                content="No app files exist yet. Use write_app_files first.",
                error=True,
            )

        if "Dockerfile" not in self._app_state:
            return ToolResult(
                content="Missing Dockerfile. The app cannot be built without it.",
                error=True,
            )

        manifest = _extract_manifest(self._app_state)
        app = GeneratedApp(
            cve_id=manifest.cve_id,
            project_files=dict(self._app_state),
            manifest=manifest,
        )

        try:
            result: VerificationResult = await self._verifier.verify(
                app, expected_package=self.expected_package
            )
        except Exception as exc:
            logger.warning("Verification raised exception: %s", exc)
            return ToolResult(
                content=json.dumps(
                    {
                        "success": False,
                        "error": str(exc),
                        "build_ok": False,
                        "deploy_ok": False,
                        "health_ok": False,
                        "vuln_present": False,
                    }
                ),
                error=True,
            )

        return ToolResult(
            content=json.dumps(
                {
                    "success": result.success,
                    "build_ok": result.build_ok,
                    "deploy_ok": result.deploy_ok,
                    "health_ok": result.health_ok,
                    "vuln_present": result.vuln_present,
                    "failure_reason": result.failure_reason,
                    "details": result.details,
                }
            ),
            error=not result.success,
        )


def register_generator_tools(
    verifier: AppVerifier,
    app_state: dict[str, str],
) -> list[Tool]:
    """Register all generator tools (with verifier)."""
    return [
        AddVulnerability(app_state),
        WriteAppFiles(app_state),
        ValidateApp(verifier, app_state),
    ]


def register_generator_tools_no_verifier(
    app_state: dict[str, str],
) -> list[Tool]:
    """Register the generator tools that do not require a verifier.

    Used at construction time when no sandbox is available yet.
    The orchestrator later calls ``GeneratorAgent.set_verifier()`` to
    add the ``ValidateApp`` tool once a verification sandbox exists.
    """
    return [
        AddVulnerability(app_state),
        WriteAppFiles(app_state),
    ]


def _extract_manifest(app_state: dict[str, str]) -> AppManifest:
    """Best-effort manifest extraction from current app files.

    Scans file content for route patterns to locate the vulnerable
    endpoint. Falls back to "/" if nothing is detected.
    """
    vuln_endpoint = "/"
    framework = "flask"
    language = "python"

    if "app.js" in app_state or "package.json" in app_state:
        framework = "express"
        language = "javascript"
    elif "pom.xml" in app_state:
        framework = "spring"
        language = "java"
    elif "composer.json" in app_state:
        framework = "laravel"
        language = "php"
    elif any(f.endswith("settings.py") for f in app_state):
        framework = "django"
        language = "python"

    # Scan for non-health endpoints
    for content in app_state.values():
        for line in content.splitlines():
            low = line.lower().strip()
            if "route" in low or "path" in low or "get(" in low or "post(" in low:  # noqa: SIM102
                if "/health" not in low and "/" in low:
                    start = low.find('"/')
                    if start == -1:
                        start = low.find("'/")
                    if start >= 0:
                        end = low.find('"', start + 1)
                        if end == -1:
                            end = low.find("'", start + 1)
                        if end > start:
                            candidate = low[start + 1 : end]
                            if candidate != "/" and candidate != "/health":
                                vuln_endpoint = candidate
                                break

    return AppManifest(
        cve_id="unknown",
        cwe="unknown",
        language=language,
        framework=framework,
        vulnerable_endpoint=vuln_endpoint,
    )
