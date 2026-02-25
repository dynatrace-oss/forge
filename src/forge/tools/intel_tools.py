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
import re
from typing import Any

import httpx

from forge.intel.cache import RawCache, SourceType
from forge.sandbox.protocols import SandboxSession
from forge.tools.base import Tool, ToolResult

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 30.0
_HUNK_FUNC_RE = re.compile(r"@@[^@]+@@\s*(.*)")


async def _fetch_github_readme(
    client: httpx.AsyncClient,
    full_name: str,
) -> str:
    """Fetch the raw README from a GitHub repo (best-effort).

    Uses the ``raw.githubusercontent.com`` CDN to avoid API rate limits.
    Returns empty string on any failure.
    """
    for filename in ("README.md", "readme.md", "README.rst", "README"):
        raw_url = f"https://raw.githubusercontent.com/{full_name}/main/{filename}"
        try:
            resp = await client.get(raw_url, timeout=10)
            if resp.status_code == 200:
                return resp.text
        except httpx.HTTPError:
            continue
    return ""


class FetchCVEAdvisory(Tool):
    """Fetch NVD + GitHub Advisory data for a CVE."""

    @property
    def name(self) -> str:
        return "fetch_cve_advisory"

    @property
    def description(self) -> str:
        return (
            "Fetch CVE advisory data from NVD and GitHub Advisory Database. "
            "Returns CVE description, CVSS score, CWE IDs, affected versions, "
            "and reference URLs."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier (e.g., CVE-2024-1234)",
                },
            },
            "required": ["cve_id"],
        }

    def __init__(self, cache: RawCache) -> None:
        self._cache = cache

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cve_id: str = arguments["cve_id"]

        cached = self._cache.get(SourceType.NVD, cve_id)
        if cached:
            return ToolResult(content=json.dumps(cached, indent=2))

        try:
            data = await self._fetch_nvd(cve_id)
            self._cache.put(SourceType.NVD, cve_id, data)
            return ToolResult(content=json.dumps(data, indent=2))
        except Exception as exc:
            return ToolResult(
                content=f"Failed to fetch advisory for {cve_id}: {exc}",
                error=True,
            )

    async def _fetch_nvd(self, cve_id: str) -> dict[str, Any]:
        """Fetch CVE data from NVD 2.0 API."""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.get(url)
            response.raise_for_status()
            raw = response.json()

        return _parse_nvd_response(raw, cve_id)


class FetchPatchDiff(Tool):
    """Fetch the git diff from a vulnerability fix commit."""

    @property
    def name(self) -> str:
        return "fetch_patch_diff"

    @property
    def description(self) -> str:
        return (
            "Fetch the git diff from a fix commit URL. Returns changed files, "
            "functions, and vulnerable code context for white-box analysis."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier for cache key",
                },
                "commit_url": {
                    "type": "string",
                    "description": "GitHub commit URL (e.g., https://github.com/org/repo/commit/abc123)",
                },
            },
            "required": ["cve_id", "commit_url"],
        }

    def __init__(self, cache: RawCache) -> None:
        self._cache = cache

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cve_id: str = arguments["cve_id"]
        commit_url: str = arguments["commit_url"]

        cached = self._cache.get(SourceType.PATCH_DIFF, cve_id)
        if cached:
            return ToolResult(content=json.dumps(cached, indent=2))

        try:
            data = await self._fetch_diff(commit_url)
            self._cache.put(SourceType.PATCH_DIFF, cve_id, data)
            return ToolResult(content=json.dumps(data, indent=2))
        except Exception as exc:
            return ToolResult(
                content=f"Failed to fetch patch for {cve_id}: {exc}",
                error=True,
            )

    async def _fetch_diff(self, commit_url: str) -> dict[str, Any]:
        """Fetch diff from a GitHub commit URL.

        For large diffs (>50KB), only security-relevant files and a bounded
        number of changed lines are kept to avoid context-window overflow.
        """
        diff_url = commit_url.rstrip("/") + ".diff"
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.get(diff_url)
            response.raise_for_status()
            diff_text = response.text

        return _parse_diff(diff_text)


class SearchExploits(Tool):
    """Search for existing exploits and PoCs across OSV and GitHub."""

    @property
    def name(self) -> str:
        return "search_exploits"

    @property
    def description(self) -> str:
        return (
            "Search OSV and GitHub for existing proof-of-concept "
            "exploits for a CVE. Returns known PoC repos with README "
            "excerpts, advisory references, and known techniques."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier to search for",
                },
            },
            "required": ["cve_id"],
        }

    def __init__(self, cache: RawCache) -> None:
        self._cache = cache

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cve_id: str = arguments["cve_id"]

        cached = self._cache.get(SourceType.EXPLOIT_DB, cve_id)
        if cached:
            return ToolResult(content=json.dumps(cached, indent=2))

        try:
            data = await self._search(cve_id)
            self._cache.put(SourceType.EXPLOIT_DB, cve_id, data)
            return ToolResult(content=json.dumps(data, indent=2))
        except Exception as exc:
            return ToolResult(
                content=f"Exploit search failed for {cve_id}: {exc}",
                error=True,
            )

    async def _search(self, cve_id: str) -> dict[str, Any]:
        """Search GitHub and OSV for PoCs and vulnerability data."""
        exploits: list[dict[str, str]] = []

        # 1. OSV API — structured vulnerability data
        try:
            osv_data = await self._search_osv(cve_id)
            for entry in osv_data:
                exploits.append(entry)
        except Exception as exc:
            logger.debug("OSV search failed for %s: %s", cve_id, exc)

        # 2. GitHub repos — community PoCs
        try:
            gh_data = await self._search_github(cve_id)
            for entry in gh_data:
                exploits.append(entry)
        except Exception as exc:
            logger.debug("GitHub search failed for %s: %s", cve_id, exc)

        return {"cve_id": cve_id, "exploits": exploits}

    @staticmethod
    async def _search_osv(cve_id: str) -> list[dict[str, str]]:
        """Query OSV API for vulnerability details and references."""
        url = f"https://api.osv.dev/v1/vulns/{cve_id}"
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.get(url)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            data = response.json()

        results: list[dict[str, str]] = []
        # Extract GHSA references and advisories
        for ref in data.get("references", []):
            ref_url = ref.get("url", "")
            ref_type = ref.get("type", "")
            if ref_type in ("ADVISORY", "FIX", "ARTICLE") and ref_url:
                results.append(
                    {
                        "source": "osv",
                        "url": ref_url,
                        "description": f"OSV {ref_type.lower()} reference",
                        "technique": "",
                    }
                )

        # Extract affected package info for context
        for affected in data.get("affected", []):
            pkg = affected.get("package", {})
            pkg_name = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", "")
            if pkg_name:
                results.append(
                    {
                        "source": "osv",
                        "url": "",
                        "description": f"Affects {ecosystem}/{pkg_name}",
                        "technique": "",
                    }
                )

        return results

    @staticmethod
    async def _search_github(cve_id: str) -> list[dict[str, str]]:
        """Search GitHub for PoC repos and fetch their README content."""
        url = "https://api.github.com/search/repositories"
        params = {"q": cve_id, "sort": "stars", "per_page": "5"}
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            raw = response.json()

            results: list[dict[str, str]] = []
            for item in raw.get("items", []):
                full_name = item.get("full_name", "")
                poc_entry: dict[str, str] = {
                    "source": "github",
                    "url": item.get("html_url", ""),
                    "description": item.get("description") or "",
                    "technique": "",
                }

                # Fetch README for PoC details (best-effort, capped at 4KB)
                if full_name:
                    readme_content = await _fetch_github_readme(
                        client,
                        full_name,
                    )
                    if readme_content:
                        poc_entry["readme_excerpt"] = readme_content[:4096]

                results.append(poc_entry)
        return results


class AnalyzeContainer(Tool):
    """Inspect the running target container."""

    @property
    def name(self) -> str:
        return "analyze_container"

    @property
    def description(self) -> str:
        return (
            "Inspect the running target container to discover OS, packages, "
            "services, open ports, and configuration files. Provides the "
            "attack surface for exploitation planning."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier for cache key",
                },
                "container_id": {
                    "type": "string",
                    "description": "Container ID or name to inspect",
                },
            },
            "required": ["cve_id", "container_id"],
        }

    def __init__(self, cache: RawCache, session: SandboxSession | None = None) -> None:
        self._cache = cache
        self._session = session

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cve_id: str = arguments["cve_id"]
        container_id: str = arguments["container_id"]

        cached = self._cache.get(SourceType.CONTAINER_INFO, cve_id)
        if cached:
            return ToolResult(content=json.dumps(cached, indent=2))

        if self._session is not None:
            try:
                data = await self._inspect_container(cve_id, container_id)
            except Exception as exc:
                logger.warning("Container inspection failed: %s", exc)
                data = self._stub_data(cve_id, container_id)
        else:
            data = self._stub_data(cve_id, container_id)

        self._cache.put(SourceType.CONTAINER_INFO, cve_id, data)
        return ToolResult(content=json.dumps(data, indent=2))

    async def _inspect_container(self, cve_id: str, container_id: str) -> dict[str, Any]:
        """Use sandbox session to inspect the running container.

        Each command is run independently — if one fails, the others still
        contribute partial data (better than an all-or-nothing stub).
        """
        assert self._session is not None
        ports_output = ""
        os_info = ""
        ps_output = ""
        config_files: list[str] = []

        # Discover listening ports
        try:
            ports_result = await self._session.exec(
                "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
            )
            ports_output = ports_result.stdout if ports_result.exit_code == 0 else ""
        except Exception as exc:
            logger.debug("Port discovery failed: %s", exc)

        # Discover OS info
        try:
            os_result = await self._session.exec("cat /etc/os-release 2>/dev/null | head -5")
            os_info = os_result.stdout if os_result.exit_code == 0 else ""
        except Exception as exc:
            logger.debug("OS discovery failed: %s", exc)

        # Discover running processes
        try:
            ps_result = await self._session.exec("ps aux 2>/dev/null | head -20")
            ps_output = ps_result.stdout if ps_result.exit_code == 0 else ""
        except Exception as exc:
            logger.debug("Process discovery failed: %s", exc)

        # Discover config files
        try:
            conf_result = await self._session.exec(
                "find /app /var/www /opt -maxdepth 3 -name '*.conf' -o -name '*.yml' "
                "-o -name '*.yaml' -o -name '*.json' 2>/dev/null | head -20"
            )
            if conf_result.exit_code == 0:
                config_files = conf_result.stdout.strip().splitlines()
        except Exception as exc:
            logger.debug("Config discovery failed: %s", exc)

        return {
            "cve_id": cve_id,
            "container_id": container_id,
            "ports": ports_output,
            "os_info": os_info,
            "processes": ps_output,
            "config_files": config_files,
            "endpoints": [],
            "inputs": [],
            "protocols": ["http"],
        }

    @staticmethod
    def _stub_data(cve_id: str, container_id: str) -> dict[str, Any]:
        return {
            "cve_id": cve_id,
            "container_id": container_id,
            "endpoints": [],
            "inputs": [],
            "protocols": ["http"],
            "note": "Container inspection requires sandbox access",
        }


class ReadSourceFile(Tool):
    """Read a file from the target application."""

    @property
    def name(self) -> str:
        return "read_source_file"

    @property
    def description(self) -> str:
        return (
            "Read a source file from the target application for white-box "
            "analysis. Use this to examine vulnerable code paths identified "
            "from patch analysis."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier for cache key",
                },
                "file_path": {
                    "type": "string",
                    "description": "Path to the file inside the target container",
                },
            },
            "required": ["cve_id", "file_path"],
        }

    def __init__(self, cache: RawCache, session: SandboxSession | None = None) -> None:
        self._cache = cache
        self._session = session

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cve_id: str = arguments["cve_id"]
        file_path: str = arguments["file_path"]
        cache_key = f"{cve_id}/{file_path.replace('/', '_')}"

        cached = self._cache.get(SourceType.SOURCE_FILE, cache_key)
        if cached:
            return ToolResult(content=json.dumps(cached, indent=2))

        if self._session is not None:
            try:
                file_content = await self._session.read_file(file_path)
                data: dict[str, Any] = {
                    "cve_id": cve_id,
                    "file_path": file_path,
                    "content": file_content[:50_000],
                }
                self._cache.put(SourceType.SOURCE_FILE, cache_key, data)
                return ToolResult(content=json.dumps(data, indent=2))
            except Exception as exc:
                return ToolResult(
                    content=f"Failed to read {file_path}: {exc}",
                    error=True,
                )

        data = {
            "cve_id": cve_id,
            "file_path": file_path,
            "content": "",
            "note": "Source file reading requires sandbox access",
        }
        self._cache.put(SourceType.SOURCE_FILE, cache_key, data)
        return ToolResult(content=json.dumps(data, indent=2))


class DiscoverTechStack(Tool):
    """Enumerate the target application's technology stack."""

    @property
    def name(self) -> str:
        return "discover_tech_stack"

    @property
    def description(self) -> str:
        return (
            "Discover the target application's technology stack: language, "
            "framework, web server, database, and their versions. Essential "
            "for selecting appropriate exploitation techniques."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier for cache key",
                },
                "target_url": {
                    "type": "string",
                    "description": "Base URL of the target application",
                },
            },
            "required": ["cve_id"],
        }

    def __init__(self, cache: RawCache, session: SandboxSession | None = None) -> None:
        self._cache = cache
        self._session = session

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        cve_id: str = arguments["cve_id"]

        cached = self._cache.get(SourceType.TECH_STACK, cve_id)
        if cached:
            return ToolResult(content=json.dumps(cached, indent=2))

        if self._session is not None:
            try:
                data = await self._discover(cve_id)
            except Exception as exc:
                logger.warning("Tech stack discovery failed: %s", exc)
                data = self._stub_data(cve_id)
        else:
            data = self._stub_data(cve_id)

        self._cache.put(SourceType.TECH_STACK, cve_id, data)
        return ToolResult(content=json.dumps(data, indent=2))

    async def _discover(self, cve_id: str) -> dict[str, Any]:
        """Use sandbox session to discover the tech stack.

        Each probe is independent — failures are logged at DEBUG and
        don't prevent other probes from contributing data.
        """
        assert self._session is not None
        versions: dict[str, str] = {}
        language = ""
        framework = ""
        web_server = ""
        database = ""
        os_name = ""

        # Helper: exec with per-command resilience
        async def _safe_exec(cmd: str) -> tuple[int, str]:
            try:
                r = await self._session.exec(cmd, timeout=5)  # type: ignore[union-attr]
                return r.exit_code, r.stdout.strip()
            except Exception as exc:
                logger.debug("Exec failed for '%s': %s", cmd[:50], exc)
                return 1, ""

        # Check for common language runtimes
        for cmd, lang in [
            ("python3 --version 2>&1", "python"),
            ("node --version 2>&1", "javascript"),
            ("php --version 2>&1 | head -1", "php"),
            ("java -version 2>&1 | head -1", "java"),
            ("go version 2>&1", "go"),
            ("ruby --version 2>&1", "ruby"),
        ]:
            code, out = await _safe_exec(cmd)
            if code == 0 and out:
                language = lang
                versions[lang] = out
                break

        # Check for web servers
        for cmd, server in [
            ("nginx -v 2>&1", "nginx"),
            ("apache2 -v 2>&1 | head -1", "apache"),
        ]:
            code, out = await _safe_exec(cmd)
            if code == 0 and out:
                web_server = server
                versions[server] = out
                break

        # Check for databases
        for cmd, db in [
            ("mysql --version 2>&1", "mysql"),
            ("psql --version 2>&1", "postgresql"),
            ("sqlite3 --version 2>&1", "sqlite"),
        ]:
            code, out = await _safe_exec(cmd)
            if code == 0 and out:
                database = db
                versions[db] = out
                break

        # OS info
        code, out = await _safe_exec("cat /etc/os-release 2>/dev/null | head -2")
        if code == 0:
            os_name = out

        # Check for framework indicators
        pkg_files = [
            ("package.json", "javascript"),
            ("requirements.txt", "python"),
            ("composer.json", "php"),
            ("pom.xml", "java"),
            ("go.mod", "go"),
            ("Gemfile", "ruby"),
        ]
        for pkg_file, lang in pkg_files:
            code, out = await _safe_exec(
                f"find /app /var/www /opt -maxdepth 3 -name '{pkg_file}' 2>/dev/null | head -1",
            )
            if code == 0 and out:
                if not language:
                    language = lang
                try:
                    content = await self._session.read_file(out)
                    # Simple framework detection from package files
                    if "express" in content.lower():
                        framework = "express"
                    elif "django" in content.lower():
                        framework = "django"
                    elif "flask" in content.lower():
                        framework = "flask"
                    elif "laravel" in content.lower():
                        framework = "laravel"
                    elif "spring" in content.lower():
                        framework = "spring"
                except Exception:
                    pass
                break

        return {
            "cve_id": cve_id,
            "language": language,
            "framework": framework,
            "web_server": web_server,
            "database": database,
            "os": os_name,
            "versions": versions,
        }

    @staticmethod
    def _stub_data(cve_id: str) -> dict[str, Any]:
        return {
            "cve_id": cve_id,
            "language": "",
            "framework": "",
            "web_server": "",
            "database": "",
            "os": "",
            "versions": {},
            "note": "Tech stack discovery requires sandbox access",
        }


def register_intel_tools(cache: RawCache, session: SandboxSession | None = None) -> list[Tool]:
    """Create and return all 6 intel tools."""
    return [
        FetchCVEAdvisory(cache),
        FetchPatchDiff(cache),
        SearchExploits(cache),
        AnalyzeContainer(cache, session),
        ReadSourceFile(cache, session),
        DiscoverTechStack(cache, session),
    ]


def _parse_nvd_response(raw: dict[str, Any], cve_id: str) -> dict[str, Any]:
    """Extract structured fields from NVD API response.

    Parses the standard NVD 2.0 response including CPE match criteria
    from the ``configurations`` block, which provides vendor/product/version
    triples for the affected software.
    """
    result: dict[str, Any] = {
        "cve_id": cve_id,
        "description": "",
        "cwe_ids": [],
        "severity": "",
        "cvss_score": None,
        "affected_versions": [],
        "fix_versions": [],
        "references": [],
        "cpe_entries": [],
    }

    vulns = raw.get("vulnerabilities", [])
    if not vulns:
        return result

    cve_data = vulns[0].get("cve", {})

    # Description
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            result["description"] = desc.get("value", "")
            break

    # CWE IDs
    weaknesses = cve_data.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-"):
                result["cwe_ids"].append(cwe_val)

    # CVSS
    metrics = cve_data.get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            result["cvss_score"] = cvss_data.get("baseScore")
            result["severity"] = cvss_data.get("baseSeverity", "").lower()
            break

    # References
    refs = cve_data.get("references", [])
    for ref in refs:
        url = ref.get("url", "")
        if url:
            result["references"].append(url)

    # CPE entries from configurations (vendor/product/version triples)
    result["cpe_entries"] = _extract_cpe_entries(cve_data.get("configurations", []))

    return result


def _extract_cpe_entries(configurations: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Parse CPE match criteria from NVD configurations.

    CPE 2.3 URI format: ``cpe:2.3:part:vendor:product:version:update:edition:
    language:sw_edition:target_sw:target_hw:other``

    We extract only vulnerable entries (``vulnerable: true``) and return
    the vendor, product, and version fields.
    """
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                cpe_uri = match.get("criteria", "")
                parsed = _parse_cpe_uri(cpe_uri)
                if not parsed:
                    continue
                key = (parsed["vendor"], parsed["product"])
                if key in seen:
                    continue
                seen.add(key)
                entries.append(parsed)

    return entries


def _parse_cpe_uri(cpe_uri: str) -> dict[str, str] | None:
    """Parse a CPE 2.3 URI into vendor/product/version dict.

    Returns None if the URI is malformed or has wildcard vendor/product.
    """
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return None
    vendor = parts[3]
    product = parts[4]
    version = parts[5] if len(parts) > 5 else "*"
    if vendor == "*" or product == "*":
        return None
    return {"vendor": vendor, "product": product, "version": version}


def _parse_diff(diff_text: str) -> dict[str, Any]:
    """Extract structured data from a unified diff.

    Produces **structured vulnerable-function data** instead of raw diff
    lines.  For each security-relevant file in the patch, removed (``-``)
    lines are grouped by the enclosing function (identified via ``@@``
    hunk headers) so that downstream agents receive concise, per-function
    context rather than a flat bag of lines.

    For large diffs (>50 KB raw), applies intelligent truncation:
    1. Filters out non-security-relevant files (tests, docs, configs, assets,
       build artifacts, vendored code).
    2. Groups removed lines by (file, function) pairs.
    3. Caps each function block to 200 lines of removed code.
    4. Caps the total number of function blocks to 20.
    """
    raw_line_count = len(diff_text.splitlines())

    # Split diff into per-file sections
    file_diffs = _split_diff_by_file(diff_text)

    # For large diffs, filter out non-security-relevant files
    is_large = len(diff_text) > 50_000
    if is_large:
        file_diffs = _filter_security_relevant(file_diffs)
        logger.info(
            "Large diff (%d lines, %d bytes) truncated to %d security-relevant files",
            raw_line_count,
            len(diff_text),
            len(file_diffs),
        )

    changed_files: list[str] = []
    all_functions: list[str] = []
    # Structured per-function vulnerable code blocks
    vuln_funcs: list[dict[str, Any]] = []
    # Flat fix lines kept for backward compat summary (capped)
    fix_lines: list[str] = []

    max_func_blocks = 20
    per_func_line_limit = 200
    fix_line_limit = 200

    for file_path, lines in file_diffs:
        changed_files.append(file_path)

        # Walk hunks: track current function name from @@ headers and
        # accumulate removed lines per (file, function) pair.
        current_func = ""
        current_removed: list[str] = []

        for line in lines:
            if line.startswith("@@"):
                # New hunk — flush any accumulated block for the previous
                # function and switch to the new one.
                if current_removed and len(vuln_funcs) < max_func_blocks:
                    code = "\n".join(current_removed[:per_func_line_limit])
                    vuln_funcs.append(
                        {
                            "file_path": file_path,
                            "function_name": current_func,
                            "code": code,
                        }
                    )
                current_removed = []
                m = _HUNK_FUNC_RE.match(line)
                if m and m.group(1).strip():
                    func_ctx = m.group(1).strip()
                    current_func = func_ctx
                    if func_ctx not in all_functions:
                        all_functions.append(func_ctx)
                else:
                    current_func = ""
            elif line.startswith("-") and not line.startswith("---"):
                stripped = line[1:].strip()
                if stripped and len(stripped) > 3:
                    current_removed.append(stripped)
            elif line.startswith("+") and not line.startswith("+++"):
                stripped = line[1:].strip()
                if stripped and len(stripped) > 3 and len(fix_lines) < fix_line_limit:
                    fix_lines.append(stripped)

        # Flush the last block for this file
        if current_removed and len(vuln_funcs) < max_func_blocks:
            code = "\n".join(current_removed[:per_func_line_limit])
            vuln_funcs.append(
                {
                    "file_path": file_path,
                    "function_name": current_func,
                    "code": code,
                }
            )

    # Best-effort vulnerable function: first function from hunk headers
    vuln_function = all_functions[0] if all_functions else ""

    return {
        "changed_files": changed_files,
        "fix_description": "",
        "vulnerable_lines": [],  # deprecated — kept for backward compat
        "vulnerable_functions": vuln_funcs,
        "fix_lines": fix_lines,
        "vulnerable_function": vuln_function,
        "all_functions": all_functions[:20],
        "root_cause": "",
        "raw_diff_lines": raw_line_count,
        "truncated": is_large,
    }


# Files that are rarely security-relevant in patch diffs
_SKIP_PATTERNS = re.compile(
    r"(?:"
    r"test[s_/]|__tests__|spec[s/]|\.test\.|\.spec\."  # tests
    r"|\.md$|\.rst$|\.txt$|LICENSE|CHANGELOG"  # docs
    r"|\.lock$|package-lock|yarn\.lock|Cargo\.lock"  # lockfiles
    r"|\.png$|\.jpg$|\.gif$|\.svg$|\.ico$"  # assets
    r"|\.min\.js$|\.min\.css$|\.map$"  # minified/maps
    r"|\.github/|\.circleci/|\.travis"  # CI configs
    r"|dist/|build/|vendor/|node_modules/"  # build artifacts / vendored
    r"|-[a-f0-9]{6,}\.(js|css)$"  # hashed build output (index-50d6fa6f.js)
    r"|bundle[\./]|chunk[\./]|webpack|\.compiled\."  # bundler output
    r")",
    re.IGNORECASE,
)


def _split_diff_by_file(diff_text: str) -> list[tuple[str, list[str]]]:
    """Split a unified diff into (file_path, lines) tuples per file."""
    result: list[tuple[str, list[str]]] = []
    current_file = ""
    current_lines: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            if current_file and current_lines:
                result.append((current_file, current_lines))
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) >= 2 else ""
            current_lines = []
        else:
            current_lines.append(line)

    if current_file and current_lines:
        result.append((current_file, current_lines))

    return result


def _filter_security_relevant(
    file_diffs: list[tuple[str, list[str]]],
) -> list[tuple[str, list[str]]]:
    """Keep only files likely to contain security-relevant changes."""
    relevant = [(f, lines) for f, lines in file_diffs if not _SKIP_PATTERNS.search(f)]
    # If filtering removed everything, return all files (better than nothing)
    return relevant if relevant else file_diffs
