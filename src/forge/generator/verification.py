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
import re

from pydantic import BaseModel

from forge.models import AppManifest, GeneratedApp
from forge.sandbox.protocols import SandboxSession

logger = logging.getLogger(__name__)

# Packages that are used at runtime (Dockerfile CMD, entry points) rather
# than imported in source code.  Flagging these would be a false positive.
_RUNTIME_ONLY: frozenset[str] = frozenset(
    {
        # Python
        "gunicorn",
        "uvicorn",
        "waitress",
        "gevent",
        "eventlet",
        "pip",
        "setuptools",
        "wheel",
        "cython",
        # Node
        "nodemon",
        "ts-node",
        "typescript",
        "tsc",
        # Go (no common runtime-only deps)
    }
)

# Well-known service ports that indicate a fake server when the app only
# needs its own HTTP port (e.g. 8080).  If a generated app is also
# listening on port 6379, it almost certainly spun up a fake Redis.
_SUSPICIOUS_SERVICE_PORTS: dict[int, str] = {
    6379: "Redis",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    11211: "Memcached",
    9092: "Kafka",
    5672: "RabbitMQ",
    2181: "ZooKeeper",
}

# Patterns in source code that indicate fabrication — fake/mock services,
# raw TCP echo servers, hardcoded vulnerability responses.
_FABRICATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?:def|func|function|class)\s+(?:start|create|launch|run)\s*(?:Fake|Mock|Dummy)\w*",
            re.IGNORECASE,
        ),
        "Fake/Mock service function or class definition",
    ),
    (
        re.compile(
            r"(?:class\s+(?:Fake|Mock|Dummy)\w*(?:Redis|Server|DB|Database|Broker|Service))",
            re.IGNORECASE,
        ),
        "Fake/Mock service class",
    ),
    (
        re.compile(
            r"""sendall\s*\(\s*b?['"]?\+OK""",
            re.IGNORECASE,
        ),
        "TCP server responding +OK unconditionally (fake Redis pattern)",
    ),
    (
        re.compile(
            r"socket\.socket\s*\(.*\).*\.bind\s*\(.*\).*\.listen\s*\(",
            re.DOTALL,
        ),
        "Raw TCP socket server (likely fake service)",
    ),
]


def check_dependency_usage(
    files: dict[str, str],
    language: str,
) -> list[str]:
    """Check that declared dependencies are actually imported in source code.

    Returns a list of dependency names that are declared in the project's
    dependency manifest but never imported.  An empty list means all
    declared deps appear to be used (or the language is not supported).

    This catches the "fabricated vulnerability" anti-pattern where the
    generator lists a vulnerable library in the manifest but builds a
    mock/simulated version instead of actually using it.
    """
    lang = language.lower()
    if lang in ("python", "py"):
        return _check_python(files)
    if lang in ("javascript", "typescript", "js", "ts", "node"):
        return _check_node(files)
    if lang in ("go", "golang"):
        return _check_go(files)
    return []


def check_vulnerable_package_present(
    files: dict[str, str],
    language: str,
    expected_package: str,
) -> str:
    """Check that the expected vulnerable package is declared in the dependency file.

    Returns an empty string if the package is found (or no check was possible),
    or a human-readable error message if the package is missing.

    This is the critical gate: if the generator doesn't install the actual
    vulnerable package, the exploit is meaningless — it's testing generic
    code, not the real vulnerability.
    """
    if not expected_package:
        return ""  # No package to check

    lang = language.lower()
    pkg_lower = expected_package.lower()

    # Check the appropriate dependency file based on language
    if lang in ("python", "py"):
        content = files.get("requirements.txt", "")
        if not content:
            content = files.get("pyproject.toml", "")
        if not content:
            return ""  # Can't verify without a dependency file
        # Normalize: PyPI uses hyphens, Python uses underscores
        pkg_normalized = pkg_lower.replace("-", "_")
        content_normalized = content.lower().replace("-", "_")
        if pkg_normalized not in content_normalized and pkg_lower not in content.lower():
            return (
                f"MISSING VULNERABLE PACKAGE — '{expected_package}' is not "
                f"declared in requirements.txt or pyproject.toml. You MUST "
                f"add it as a dependency and import/use it in your code."
            )

    elif lang in ("javascript", "typescript", "js", "ts", "node"):
        content = files.get("package.json", "")
        if not content:
            return ""
        try:
            pkg_data = json.loads(content)
        except json.JSONDecodeError:
            return ""
        all_deps: dict[str, str] = {}
        for section in ("dependencies", "devDependencies"):
            section_deps = pkg_data.get(section, {})
            if isinstance(section_deps, dict):
                all_deps.update(section_deps)
        dep_names_lower = [d.lower() for d in all_deps]
        if pkg_lower not in dep_names_lower:
            # Also check for scoped package match (e.g. "@scope/pkg" matches "pkg")
            base_names = [d.split("/")[-1].lower() for d in all_deps]
            if pkg_lower not in base_names:
                return (
                    f"MISSING VULNERABLE PACKAGE — '{expected_package}' is not "
                    f"declared in package.json dependencies. You MUST add it "
                    f"and require/import it in your application code."
                )

    elif lang in ("go", "golang"):
        content = files.get("go.mod", "")
        if not content:
            return ""
        if pkg_lower not in content.lower():
            return (
                f"MISSING VULNERABLE PACKAGE — '{expected_package}' is not "
                f"declared in go.mod. You MUST add it as a require directive "
                f"and import it in your Go source files."
            )

    elif lang in ("java", "kotlin", "scala"):
        # Check pom.xml or build.gradle
        content = files.get("pom.xml", "") or files.get("build.gradle", "")
        if not content:
            return ""
        if pkg_lower not in content.lower():
            return (
                f"MISSING VULNERABLE PACKAGE — '{expected_package}' is not "
                f"declared in pom.xml/build.gradle. You MUST add it as a "
                f"dependency."
            )

    elif lang in ("ruby", "rb"):
        content = files.get("Gemfile", "")
        if not content:
            return ""
        if pkg_lower not in content.lower():
            return (
                f"MISSING VULNERABLE PACKAGE — '{expected_package}' is not "
                f"declared in Gemfile. You MUST add it as a gem dependency."
            )

    elif lang in ("php",):
        content = files.get("composer.json", "")
        if not content:
            return ""
        if pkg_lower not in content.lower():
            return (
                f"MISSING VULNERABLE PACKAGE — '{expected_package}' is not "
                f"declared in composer.json. You MUST add it as a dependency."
            )

    elif lang in ("rust",):
        content = files.get("Cargo.toml", "")
        if not content:
            return ""
        if pkg_lower not in content.lower():
            return (
                f"MISSING VULNERABLE PACKAGE — '{expected_package}' is not "
                f"declared in Cargo.toml. You MUST add it as a dependency."
            )

    return ""


def check_fabrication_patterns(files: dict[str, str]) -> list[str]:
    """Scan source files for patterns that indicate fabricated services.

    Returns a list of human-readable descriptions of fabrication patterns
    found.  An empty list means no suspicious patterns were detected.

    This complements ``check_dependency_usage`` by catching cases where
    the real library *is* imported but a parallel fake service is also
    created (e.g., startFakeRedis alongside ``import redis``).
    """
    source_blob = "\n".join(
        content
        for path, content in files.items()
        if path.endswith((".py", ".js", ".ts", ".go", ".rb", ".php", ".java"))
        and "/vendor/" not in path
        and "/node_modules/" not in path
    )
    if not source_blob:
        return []

    findings: list[str] = []
    for pattern, description in _FABRICATION_PATTERNS:
        match = pattern.search(source_blob)
        if match:
            snippet = match.group(0)[:80]
            findings.append(f"{description}: `{snippet}`")
    return findings


def _check_python(files: dict[str, str]) -> list[str]:
    """Check Python requirements.txt against .py imports."""
    deps = _parse_requirements_txt(files)
    if not deps:
        return []

    source_blob = _concat_sources(files, (".py",))
    if not source_blob:
        return []

    unused: list[str] = []
    for dep in deps:
        # Normalize: PyPI uses hyphens, Python uses underscores
        import_name = dep.replace("-", "_").lower()
        # Check for: import X, from X import, from X.sub import
        pattern = rf"(?:^|\s)(?:import|from)\s+{re.escape(import_name)}\b"
        if not re.search(pattern, source_blob, re.IGNORECASE | re.MULTILINE):
            unused.append(dep)
    return unused


def _check_node(files: dict[str, str]) -> list[str]:
    """Check package.json dependencies against JS/TS imports."""
    deps = _parse_package_json(files)
    if not deps:
        return []

    source_blob = _concat_sources(files, (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))
    if not source_blob:
        return []

    unused: list[str] = []
    for dep in deps:
        # require('dep') or require("dep") or from 'dep' or from "dep"
        # Also matches scoped packages like @scope/dep
        escaped = re.escape(dep)
        pattern = rf"""(?:require\s*\(\s*['"]|from\s+['"]){escaped}[/'"]"""
        if not re.search(pattern, source_blob):
            unused.append(dep)
    return unused


def _check_go(files: dict[str, str]) -> list[str]:
    """Check go.mod require directives against .go imports."""
    deps = _parse_go_mod(files)
    if not deps:
        return []

    source_blob = _concat_sources(files, (".go",))
    if not source_blob:
        return []

    unused: list[str] = []
    for dep in deps:
        # Go imports use the full module path or a sub-path
        if dep not in source_blob:
            unused.append(dep)
    return unused


def _parse_requirements_txt(files: dict[str, str]) -> list[str]:
    """Extract package names from requirements.txt."""
    content = files.get("requirements.txt", "")
    if not content:
        return []

    deps: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip version specifiers: ==, >=, <=, ~=, !=, <, >
        name = re.split(r"[=<>!~;@\[]", line)[0].strip()
        if name and name.lower() not in _RUNTIME_ONLY:
            deps.append(name)
    return deps


def _parse_package_json(files: dict[str, str]) -> list[str]:
    """Extract dependency names from package.json."""
    content = files.get("package.json", "")
    if not content:
        return []
    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        return []

    deps: list[str] = []
    for section in ("dependencies",):
        section_deps = pkg.get(section, {})
        if isinstance(section_deps, dict):
            for name in section_deps:
                if name.lower() not in _RUNTIME_ONLY:
                    deps.append(name)
    return deps


def _parse_go_mod(files: dict[str, str]) -> list[str]:
    """Extract module paths from go.mod require directives."""
    content = files.get("go.mod", "")
    if not content:
        return []

    deps: list[str] = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require:
            # "github.com/go-redis/redis/v8 v8.11.5"
            parts = stripped.split()
            if parts:
                deps.append(parts[0])
        elif stripped.startswith("require "):
            # Single-line require: "require github.com/foo v1.0.0"
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append(parts[1])
    return deps


def _concat_sources(files: dict[str, str], extensions: tuple[str, ...]) -> str:
    """Concatenate all source files matching the given extensions."""
    parts: list[str] = []
    for path, content in files.items():
        if any(path.endswith(ext) for ext in extensions):
            # Skip Dockerfile, test files, vendor files
            if "/vendor/" in path or "/node_modules/" in path:
                continue
            parts.append(content)
    return "\n".join(parts)


class VerificationResult(BaseModel):
    """Outcome of verifying a generated vulnerable application."""

    success: bool
    build_ok: bool = False
    deploy_ok: bool = False
    health_ok: bool = False
    vuln_present: bool = False
    failure_reason: str | None = None
    details: str | None = None


class AppVerifier:
    """Verify generated app builds, deploys, and contains vulnerability."""

    def __init__(self, sandbox: SandboxSession) -> None:
        self._sandbox = sandbox

    async def verify(
        self,
        app: GeneratedApp,
        *,
        expected_package: str = "",
    ) -> VerificationResult:
        """Full verification pipeline.

        Sequence: vulnerable-pkg-check -> dep-usage -> pattern-scan ->
        build -> deploy -> port-scan -> health -> vuln-endpoint.
        """
        # Static check: the generated app MUST declare the expected vulnerable
        # package in its dependency manifest.  This is the strongest signal —
        # if the package is missing, the app is testing generic code, not the
        # real vulnerability.
        pkg_error = check_vulnerable_package_present(
            app.project_files,
            app.manifest.language,
            expected_package,
        )
        if pkg_error:
            logger.warning(
                "Vulnerable package check failed for %s: %s",
                app.cve_id,
                pkg_error,
            )
            return VerificationResult(
                success=False,
                failure_reason=pkg_error,
            )

        # Static check: declared dependencies must be imported in source code.
        # Catches fabricated vulnerability
        unused_deps = check_dependency_usage(app.project_files, app.manifest.language)
        if unused_deps:
            dep_list = ", ".join(unused_deps)
            logger.warning(
                "Dependency-usage check failed: %s declared but never imported",
                dep_list,
            )
            return VerificationResult(
                success=False,
                failure_reason=(
                    f"FABRICATION DETECTED — these dependencies are declared "
                    f"in the manifest but never imported in source code: "
                    f"{dep_list}. You MUST import and use the REAL library, "
                    f"not build mocked/simulated code."
                ),
            )

        # Static check: source code patterns indicating fake/mock services.
        fabrication_findings = check_fabrication_patterns(app.project_files)
        if fabrication_findings:
            findings_str = "; ".join(fabrication_findings)
            logger.warning("Fabrication pattern scan found: %s", findings_str)
            return VerificationResult(
                success=False,
                failure_reason=(
                    f"FABRICATION DETECTED — source code contains fake/mock "
                    f"service patterns: {findings_str}. Remove all fake "
                    f"servers and use the REAL vulnerable library instead."
                ),
            )

        # Deploy the app (build + start)
        deploy_result = await self._sandbox.deploy(
            app.project_files,
            health_path=app.manifest.health_endpoint,
        )
        if not deploy_result.success:
            error_msg = deploy_result.error or ""
            # Distinguish build failures from runtime/health failures
            # so the LLM knows whether to fix Dockerfile or app code.
            build_failed = "Build failed" in error_msg or "No Dockerfile" in error_msg
            health_failed = "Health check failed" in error_msg
            if build_failed:
                return VerificationResult(
                    success=False,
                    build_ok=False,
                    deploy_ok=False,
                    failure_reason="Docker build failed — fix Dockerfile or dependencies",
                    details=error_msg[-2000:],
                )
            if health_failed:
                return VerificationResult(
                    success=False,
                    build_ok=True,
                    deploy_ok=True,
                    health_ok=False,
                    failure_reason=(
                        "Container started but app crashed or health "
                        "endpoint returned non-200 — fix the application "
                        "code, not the Dockerfile"
                    ),
                    details=error_msg[-2000:],
                )
            # Pod creation or container start failure
            return VerificationResult(
                success=False,
                build_ok=True,
                deploy_ok=False,
                failure_reason="Container failed to start",
                details=error_msg[-2000:],
            )

        # Health check
        health_ok = await self._check_health(
            app.manifest.health_endpoint,
        )
        if not health_ok:
            return VerificationResult(
                success=False,
                build_ok=True,
                deploy_ok=True,
                health_ok=False,
                failure_reason="Health check failed",
            )

        # Port scan: detect fake services listening on unexpected ports
        fake_services = await self._check_fake_services(app.manifest.health_port)
        if fake_services:
            services_str = ", ".join(fake_services)
            logger.warning("Fake service port scan found: %s", services_str)
            return VerificationResult(
                success=False,
                build_ok=True,
                deploy_ok=True,
                health_ok=True,
                failure_reason=(
                    f"FABRICATION DETECTED — container is listening on "
                    f"unexpected service ports: {services_str}. The app "
                    f"should only listen on its own HTTP port "
                    f"({app.manifest.health_port}). Remove fake services "
                    f"and use external real services instead."
                ),
            )

        # Vulnerability presence check
        vuln_present = await self._check_vulnerability_present(app.manifest)
        return VerificationResult(
            success=vuln_present,
            build_ok=True,
            deploy_ok=True,
            health_ok=True,
            vuln_present=vuln_present,
            failure_reason=None if vuln_present else "Vulnerable endpoint not responding",
        )

    async def _check_health(self, endpoint: str) -> bool:
        """HTTP GET to health endpoint, expect 200."""
        try:
            resp = await self._sandbox.http_request("GET", endpoint)
            return resp.status_code == 200
        except (OSError, RuntimeError):
            logger.warning("Health check failed for %s", endpoint)
            return False

    async def _check_vulnerability_present(self, manifest: AppManifest) -> bool:
        """Basic check that the vulnerable endpoint exists and responds."""
        try:
            resp = await self._sandbox.http_request("GET", manifest.vulnerable_endpoint)
            # Any non-5xx response means the endpoint exists
            return resp.status_code < 500
        except (OSError, RuntimeError):
            logger.warning(
                "Vulnerability check failed for %s",
                manifest.vulnerable_endpoint,
            )
            return False

    async def _check_fake_services(self, expected_port: int) -> list[str]:
        """Run ``ss -tlnp`` inside the container to detect fake services.

        Returns a list of descriptions for suspicious listeners (ports
        that match known service ports like Redis 6379, MySQL 3306, etc.).
        An empty list means no fake services were detected.

        This catches the pattern where the generator creates an in-process
        fake Redis/DB/Kafka that accepts all commands unconditionally.
        """
        try:
            result = await self._sandbox.exec("ss -tlnp", timeout=5)
            output = result.stdout if result.stdout else ""
        except (OSError, RuntimeError):
            logger.debug("ss -tlnp failed in container — skipping port scan")
            return []

        findings: list[str] = []
        for line in output.splitlines():
            # Parse ss output lines like:
            # LISTEN 0  128  *:6379  *:*  users:(("fake_redis",pid=42,...))
            port_match = re.search(r"[*:]+:(\d+)\s", line)
            if not port_match:
                continue
            port = int(port_match.group(1))
            if port == expected_port:
                continue  # This is the app's own HTTP port
            service_name = _SUSPICIOUS_SERVICE_PORTS.get(port)
            if service_name:
                findings.append(f"port {port} ({service_name})")
        return findings
