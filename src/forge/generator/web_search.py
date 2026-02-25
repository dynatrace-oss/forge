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

import functools
import logging
import os
import re
from html import unescape
from typing import TYPE_CHECKING

import httpx

from forge.models import Message
from forge.pipeline.prompt_engine import PromptEngine

if TYPE_CHECKING:
    from forge.pipeline.llm_client import LLMClient

logger = logging.getLogger(__name__)

_SEARCH_TIMEOUT = 5.0  # seconds
_LLM_TIMEOUT = 10.0  # seconds — query extraction (generous for cold starts)
_MAX_RESULTS = 3
_MAX_SNIPPET_LEN = 300
_MAX_TOTAL_LEN = 800

# Realistic browser User-Agent — DDG returns HTTP 202 (bot challenge) for
# obviously non-browser UAs.  Brave doesn't need it but it's harmless.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@functools.cache
def _get_query_prompt() -> str:
    """Load the query-extraction system prompt from data/prompts/."""
    return PromptEngine().raw("generator/web_search_query")


class _BuiltinPattern:
    """A known build error pattern with a canned fix hint."""

    def __init__(self, name: str, regex: re.Pattern[str], hint: str) -> None:
        self.name = name
        self.regex = regex
        self.hint = hint

    def matches(self, details: str) -> bool:
        return bool(self.regex.search(details))


_BUILTIN_PATTERNS: list[_BuiltinPattern] = [
    # Go + alpine + CGO: musl doesn't have pread64/pwrite64/off64_t
    _BuiltinPattern(
        name="go_alpine_cgo_musl",
        regex=re.compile(
            r"(pread64|pwrite64|off64_t|__REDIRECT).*(undeclared|unknown type)"
            r"|(?:undeclared|unknown type).*(pread64|pwrite64|off64_t)",
            re.IGNORECASE,
        ),
        hint=(
            "== BUILT-IN FIX (Go CGO + Alpine musl incompatibility) ==\n"
            "The build error is caused by a CGO library (e.g. go-sqlite3) that uses\n"
            "glibc-only functions (pread64, pwrite64, off64_t). Alpine uses musl libc\n"
            "which does NOT provide these functions.\n\n"
            "FIX: Use a Debian-based Go image instead of alpine:\n"
            "  FROM golang:1.22      (Debian bookworm, has glibc)\n"
            "  NOT: golang:1.22-alpine\n\n"
            "Alternatively, if the CGO dependency is only sqlite, switch to a pure-Go\n"
            "driver: modernc.org/sqlite (no CGO, works everywhere)."
        ),
    ),
    # Go: missing go.sum entries
    _BuiltinPattern(
        name="go_missing_gosum",
        regex=re.compile(
            r"missing go\.sum entry for module|"
            r"go\.sum: .*not found|"
            r"no required module provides package",
            re.IGNORECASE,
        ),
        hint=(
            "== BUILT-IN FIX (Go missing go.sum) ==\n"
            "The build failed because go.sum is missing or incomplete.\n\n"
            "FIX: In your Dockerfile, run `go mod tidy` BEFORE `go build`.\n"
            "Also COPY all .go files before running go mod tidy so it can\n"
            "resolve imports:\n"
            "  COPY . .\n"
            "  RUN go mod tidy && go build -o server .\n\n"
            "Do NOT separate `COPY go.mod` and `COPY . .` with a `go mod download`\n"
            "step unless you also copy go.sum. The simplest pattern is:\n"
            "  COPY . .\n"
            "  RUN go mod tidy && CGO_ENABLED=1 go build -o server ."
        ),
    ),
    # Node: npm ERR! could not resolve / ERESOLVE
    _BuiltinPattern(
        name="node_npm_resolve",
        regex=re.compile(r"npm ERR!.*ERESOLVE|npm ERR!.*could not resolve", re.IGNORECASE),
        hint=(
            "== BUILT-IN FIX (npm dependency resolution) ==\n"
            "npm cannot resolve conflicting peer dependencies.\n\n"
            "FIX: Add `--legacy-peer-deps` to the npm install command:\n"
            "  RUN npm install --legacy-peer-deps\n"
            "Or use `--force` as a last resort."
        ),
    ),
    # Python: ModuleNotFoundError in Dockerfile (missing requirements install)
    _BuiltinPattern(
        name="python_module_not_found",
        regex=re.compile(r"ModuleNotFoundError: No module named", re.IGNORECASE),
        hint=(
            "== BUILT-IN FIX (Python missing module) ==\n"
            "A Python import failed — the package is not installed in the container.\n\n"
            "FIX: Ensure requirements.txt lists all dependencies and the Dockerfile\n"
            "runs `pip install -r requirements.txt` BEFORE copying app code:\n"
            "  COPY requirements.txt .\n"
            "  RUN pip install --no-cache-dir -r requirements.txt\n"
            "  COPY . ."
        ),
    ),
]


def _check_builtin_patterns(details: str) -> str | None:
    """Check build error against known patterns, return a hint if matched."""
    for pattern in _BUILTIN_PATTERNS:
        if pattern.matches(details):
            logger.info(
                "[web_search] Built-in pattern matched: %s (skipping web search)",
                pattern.name,
            )
            return pattern.hint
    return None


async def _extract_query_via_llm(
    details: str,
    language: str,
    llm: "LLMClient",
    model: str,
) -> str | None:
    """Use a cheap LLM call to distil build errors into a search query."""
    # Truncate details to avoid blowing up input tokens — first 1500 chars
    # is always enough to capture the core error.
    truncated = details[:1500]

    user_msg = f"Language: {language}\nError:\n{truncated}"
    messages = [
        Message(role="system", content=_get_query_prompt()),
        Message(role="user", content=user_msg),
    ]

    try:
        content, _tokens = await llm.chat(
            messages,
            model=model,
            temperature=0.0,
            max_tokens=60,
            phase="web_search_query",
        )
    except Exception:
        logger.warning("[web_search] LLM query extraction failed", exc_info=True)
        return None

    query = content.strip().strip('"').strip("'").strip("`")
    if not query or len(query) < 5:
        logger.warning("[web_search] LLM returned empty/too-short query: %r", query)
        return None

    # Safety cap — should already be short thanks to the prompt
    return query[:120]


_SEARXNG_BASE_URL = os.environ.get("SEARXNG_URL", "http://localhost:8888")


async def _search_searxng(query: str) -> list[dict[str, str]] | None:
    """Search using a local SearXNG instance.  Returns parsed results or None.

    SearXNG is a self-hosted meta-search engine that aggregates Google, Bing,
    DuckDuckGo, Stack Overflow, and others.  No API key required.

    The base URL defaults to ``http://localhost:8888`` and can be overridden
    via the ``SEARXNG_URL`` environment variable.
    """
    try:
        async with httpx.AsyncClient(
            timeout=_SEARCH_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = await client.get(
                f"{_SEARXNG_BASE_URL}/search",
                params={"q": query, "format": "json"},
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        logger.warning("[web_search] SearXNG request failed: %s", exc)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.warning("[web_search] SearXNG returned invalid JSON")
        return None

    results: list[dict[str, str]] = []
    for item in data.get("results", [])[:_MAX_RESULTS]:
        title = item.get("title", "")
        snippet = item.get("content", "")
        if snippet:
            results.append(
                {
                    "title": title,
                    "snippet": snippet[:_MAX_SNIPPET_LEN],
                }
            )

    return results if results else None


def _parse_ddg_html(html: str) -> list[dict[str, str]]:
    """Parse DuckDuckGo HTML results page into snippets."""
    results: list[dict[str, str]] = []
    # DuckDuckGo wraps each result snippet in <a class="result__snippet">
    snippet_re = re.compile(
        r'class="result__snippet[^"]*"[^>]*>(.*?)</a>',
        re.DOTALL,
    )
    title_re = re.compile(
        r'class="result__a"[^>]*>(.*?)</a>',
        re.DOTALL,
    )
    titles = title_re.findall(html)
    snippets = snippet_re.findall(html)

    for i, snippet_html in enumerate(snippets[:_MAX_RESULTS]):
        # Strip HTML tags
        text = re.sub(r"<[^>]+>", "", snippet_html)
        text = unescape(text).strip()
        title = ""
        if i < len(titles):
            title = re.sub(r"<[^>]+>", "", titles[i])
            title = unescape(title).strip()
        if text:
            results.append({"title": title, "snippet": text[:_MAX_SNIPPET_LEN]})
    return results


async def _search_ddg(query: str) -> list[dict[str, str]] | None:
    """Search using DuckDuckGo HTML scraping (fallback)."""
    try:
        async with httpx.AsyncClient(
            timeout=_SEARCH_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": _USER_AGENT},
            )
            resp.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        logger.warning("[web_search] DDG request failed: %s", exc)
        return None

    # DDG returns HTTP 202 when it triggers bot-detection / CAPTCHA.
    if resp.status_code == 202:
        logger.warning("[web_search] DDG returned 202 (bot challenge) — skipping")
        return None

    results = _parse_ddg_html(resp.text)
    return results if results else None


def _build_hint(results: list[dict[str, str]], source: str) -> str:
    """Build a compact hint block from search results."""
    lines = [f"== WEB SEARCH RESULTS ({source}) =="]
    total_len = 0
    for r in results:
        entry = ""
        if r["title"]:
            entry += f"* {r['title']}\n"
        entry += f"  {r['snippet']}\n"
        if total_len + len(entry) > _MAX_TOTAL_LEN:
            break
        lines.append(entry)
        total_len += len(entry)
    return "\n".join(lines)


async def search_build_error(
    details: str,
    language: str,
    llm: "LLMClient",
    model: str,
) -> str | None:
    """Search for a build error fix and return a concise hint.

    Resolution order:
    1. **Built-in patterns** — zero-cost regex match for known failures
    2. **SearXNG** — self-hosted meta-search (Google/Bing/DDG/SO aggregated)
    3. **DuckDuckGo HTML** — scraping fallback

    Returns a short text block suitable for injecting into the LLM's retry
    prompt, or ``None`` if no useful results were found.

    Args:
        details: Raw build error output from ``AppVerifier.verify()``.
        language: Programming language (e.g. "Go", "Python").
        llm: LLMClient for the query-extraction call.
        model: Model identifier to use for query extraction.
    """
    # 1. Check built-in patterns first (zero cost)
    builtin = _check_builtin_patterns(details)
    if builtin:
        return builtin

    # 2. Extract a search query via LLM
    query = await _extract_query_via_llm(details, language, llm, model)
    if not query:
        logger.debug("[web_search] Could not extract search query from build error")
        return None

    logger.info("[web_search] Searching for build fix: %s", query)

    # 3. Try SearXNG (self-hosted meta-search) first
    results = await _search_searxng(query)
    if results:
        hint = _build_hint(results, "SearXNG")
        logger.info(
            "[web_search] SearXNG found %d result(s), hint length=%d",
            len(results),
            len(hint),
        )
        return hint

    # 4. Fall back to DDG
    results = await _search_ddg(query)
    if results:
        hint = _build_hint(results, "DuckDuckGo")
        logger.info(
            "[web_search] DDG found %d result(s), hint length=%d",
            len(results),
            len(hint),
        )
        return hint

    logger.info("[web_search] No results from any search engine for: %s", query)
    return None
