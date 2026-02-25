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

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from forge.generator.web_search import (
    _BUILTIN_PATTERNS,
    _check_builtin_patterns,
    _parse_ddg_html,
    _search_ddg,
    _search_searxng,
    search_build_error,
)
from forge.models import TokenUsage


def _make_mock_llm(response: str) -> Any:
    """Create a mock LLMClient that returns *response* from ``chat()``."""
    llm = AsyncMock()
    llm.chat.return_value = (
        response,
        TokenUsage(
            prompt_tokens=100,
            completion_tokens=20,
            total_tokens=120,
            llm_calls=1,
            estimated_cost_usd=0.0001,
        ),
    )
    return llm


def _make_ddg_html(snippets: list[tuple[str, str]]) -> str:
    """Build fake DDG HTML with title/snippet pairs."""
    parts: list[str] = []
    for title, snippet in snippets:
        parts.append(f'<a class="result__a" href="http://example.com">{title}</a>')
        parts.append(f'<a class="result__snippet" href="#">{snippet}</a>')
    return f"<html><body>{''.join(parts)}</body></html>"


class TestBuiltinPatterns:
    """Zero-cost built-in error pattern matching."""

    def test_go_alpine_cgo_musl_pread64(self) -> None:
        details = "sqlite3-binding.c:37644:42: error: 'pread64' undeclared here"
        hint = _check_builtin_patterns(details)
        assert hint is not None
        assert "golang:1.22" in hint
        assert "alpine" in hint.lower()

    def test_go_alpine_cgo_musl_pwrite64(self) -> None:
        details = "error: 'pwrite64' undeclared (first use in this function)"
        hint = _check_builtin_patterns(details)
        assert hint is not None
        assert "musl" in hint.lower()

    def test_go_alpine_cgo_off64_t(self) -> None:
        details = "error: unknown type name 'off64_t'"
        hint = _check_builtin_patterns(details)
        assert hint is not None

    def test_go_missing_gosum(self) -> None:
        details = (
            "main.go:7:2: missing go.sum entry for module providing "
            "package github.com/gin-gonic/gin"
        )
        hint = _check_builtin_patterns(details)
        assert hint is not None
        assert "go mod tidy" in hint

    def test_go_no_required_module(self) -> None:
        details = "no required module provides package github.com/lib/pq"
        hint = _check_builtin_patterns(details)
        assert hint is not None
        assert "go mod tidy" in hint

    def test_node_npm_eresolve(self) -> None:
        details = "npm ERR! ERESOLVE unable to resolve dependency tree"
        hint = _check_builtin_patterns(details)
        assert hint is not None
        assert "legacy-peer-deps" in hint

    def test_python_module_not_found(self) -> None:
        details = "ModuleNotFoundError: No module named 'flask'"
        hint = _check_builtin_patterns(details)
        assert hint is not None
        assert "requirements.txt" in hint

    def test_no_match_returns_none(self) -> None:
        details = "Some unknown error that doesn't match any pattern"
        assert _check_builtin_patterns(details) is None

    def test_all_patterns_have_required_fields(self) -> None:
        """Every built-in pattern must have a name, regex, and hint."""
        for p in _BUILTIN_PATTERNS:
            assert p.name, "Pattern missing name"
            assert p.regex, "Pattern missing regex"
            assert p.hint, "Pattern missing hint"
            assert len(p.hint) > 20, f"Pattern {p.name} hint too short"


class TestSearxngSearch:
    """SearXNG self-hosted meta-search integration."""

    @pytest.mark.asyncio
    async def test_returns_results_on_success(self) -> None:
        searxng_response = {
            "results": [
                {
                    "title": "Fix pread64 on Alpine",
                    "url": "https://example.com",
                    "content": "Use golang:1.22 (Debian) instead of alpine.",
                    "engine": "google",
                },
                {
                    "title": "go-sqlite3 musl issue",
                    "url": "https://example2.com",
                    "content": "Alpine uses musl libc which lacks pread64.",
                    "engine": "bing",
                },
            ]
        }
        mock_resp = httpx.Response(
            200,
            json=searxng_response,
            request=httpx.Request("GET", "http://localhost:8888/search"),
        )

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            results = await _search_searxng("go-sqlite3 pread64 alpine fix")

        assert results is not None
        assert len(results) == 2
        assert "alpine" in results[0]["snippet"].lower()

    @pytest.mark.asyncio
    async def test_returns_none_on_http_error(self) -> None:
        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.HTTPStatusError(
                "500",
                request=httpx.Request("GET", "http://localhost:8888/search"),
                response=httpx.Response(500),
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            results = await _search_searxng("test query")

        assert results is None

    @pytest.mark.asyncio
    async def test_returns_none_on_empty_results(self) -> None:
        searxng_response: dict = {"results": []}
        mock_resp = httpx.Response(
            200,
            json=searxng_response,
            request=httpx.Request("GET", "http://localhost:8888/search"),
        )

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            results = await _search_searxng("test query")

        assert results is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self) -> None:
        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            results = await _search_searxng("test query")

        assert results is None

    @pytest.mark.asyncio
    async def test_sends_json_format_param(self) -> None:
        searxng_response = {"results": [{"title": "T", "content": "D"}]}
        mock_resp = httpx.Response(
            200,
            json=searxng_response,
            request=httpx.Request("GET", "http://localhost:8888/search"),
        )

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            await _search_searxng("test")

        call_kwargs = mock_client.get.call_args
        params = call_kwargs.kwargs.get("params", {})
        assert params["format"] == "json"

    @pytest.mark.asyncio
    async def test_respects_custom_base_url(self) -> None:
        searxng_response = {"results": [{"title": "T", "content": "D"}]}
        mock_resp = httpx.Response(
            200,
            json=searxng_response,
            request=httpx.Request("GET", "http://custom:9999/search"),
        )

        with (
            patch.dict("os.environ", {"SEARXNG_URL": "http://custom:9999"}),
            patch("forge.generator.web_search._SEARXNG_BASE_URL", "http://custom:9999"),
            patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls,
        ):
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            await _search_searxng("test")

        call_args = mock_client.get.call_args
        url = call_args.args[0] if call_args.args else ""
        assert "custom:9999" in url


class TestDdgFallback:
    """DDG HTML scraping fallback."""

    @pytest.mark.asyncio
    async def test_returns_results_on_success(self) -> None:
        html = _make_ddg_html([("Title", "Some snippet about the fix.")])
        mock_resp = httpx.Response(200, text=html, request=httpx.Request("GET", "https://ddg"))

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            results = await _search_ddg("test query")

        assert results is not None
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_returns_none_on_202(self) -> None:
        mock_resp = httpx.Response(
            202, text="<html>challenge</html>", request=httpx.Request("GET", "https://ddg")
        )

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            results = await _search_ddg("test query")

        assert results is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self) -> None:
        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            results = await _search_ddg("test query")

        assert results is None


class TestParseDdgHtml:
    def test_parses_snippets(self) -> None:
        html = """
        <a class="result__a" href="http://example.com">Fix pread64 on Alpine</a>
        <a class="result__snippet" href="#">
            Use golang:1.22 instead of alpine for musl compatibility.
        </a>
        <a class="result__a" href="http://example2.com">SQLite CGO issue</a>
        <a class="result__snippet" href="#">
            The go-sqlite3 library requires glibc. Alpine uses musl.
        </a>
        """
        results = _parse_ddg_html(html)
        assert len(results) == 2
        assert "alpine" in results[0]["snippet"].lower() or "musl" in results[0]["snippet"].lower()
        assert results[0]["title"] == "Fix pread64 on Alpine"

    def test_handles_empty_html(self) -> None:
        assert _parse_ddg_html("") == []

    def test_handles_no_snippets(self) -> None:
        html = "<html><body>No results</body></html>"
        assert _parse_ddg_html(html) == []

    def test_strips_html_tags_from_snippets(self) -> None:
        html = """
        <a class="result__snippet" href="#">
            Use <b>golang:1.22</b> instead of <em>alpine</em>.
        </a>
        """
        results = _parse_ddg_html(html)
        assert len(results) == 1
        assert "<b>" not in results[0]["snippet"]
        assert "golang:1.22" in results[0]["snippet"]

    def test_respects_max_results(self) -> None:
        snippets = "".join(f'<a class="result__snippet" href="#">Result {i}</a>' for i in range(10))
        results = _parse_ddg_html(snippets)
        assert len(results) <= 3


class TestSearchBuildError:
    """Integration tests for the full search_build_error pipeline."""

    @pytest.mark.asyncio
    async def test_builtin_pattern_fires_before_web_search(self) -> None:
        """Built-in patterns should return a hint without calling LLM or web."""
        llm = _make_mock_llm("should not be called")
        hint = await search_build_error(
            "sqlite3-binding.c:37644: error: 'pread64' undeclared",
            "Go",
            llm,
            "model",
        )
        assert hint is not None
        assert "BUILT-IN FIX" in hint
        assert "golang:1.22" in hint
        # LLM should NOT have been called
        llm.chat.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_builtin_go_sum_pattern(self) -> None:
        llm = _make_mock_llm("should not be called")
        hint = await search_build_error(
            "missing go.sum entry for module providing package github.com/gin-gonic/gin",
            "Go",
            llm,
            "model",
        )
        assert hint is not None
        assert "BUILT-IN FIX" in hint
        assert "go mod tidy" in hint
        llm.chat.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_searxng_used_when_available(self) -> None:
        """When SearXNG returns results, DDG is not called."""
        llm = _make_mock_llm("some error query")
        searxng_response = {
            "results": [
                {"title": "Fix title", "content": "Fix description here."},
            ]
        }
        mock_resp = httpx.Response(
            200,
            json=searxng_response,
            request=httpx.Request("GET", "http://localhost:8888/search"),
        )

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            hint = await search_build_error(
                "Some unknown error not matching builtins",
                "Rust",
                llm,
                "model",
            )

        assert hint is not None
        assert "WEB SEARCH RESULTS" in hint
        assert "SearXNG" in hint
        # Only one HTTP call (SearXNG), no DDG
        assert mock_client.get.call_count == 1

    @pytest.mark.asyncio
    async def test_falls_back_to_ddg_when_searxng_unavailable(self) -> None:
        """When SearXNG fails, falls back to DDG."""
        llm = _make_mock_llm("rust error query")
        ddg_html = _make_ddg_html([("DDG Title", "DDG fix snippet.")])

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()

            # First call (SearXNG) fails, second call (DDG) succeeds
            mock_client.get.side_effect = [
                httpx.TimeoutException("searxng down"),
                httpx.Response(200, text=ddg_html, request=httpx.Request("GET", "https://ddg")),
            ]
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            hint = await search_build_error(
                "Unknown error no builtin match",
                "Rust",
                llm,
                "model",
            )

        assert hint is not None
        assert "DuckDuckGo" in hint

    @pytest.mark.asyncio
    async def test_returns_none_when_llm_returns_empty(self) -> None:
        llm = _make_mock_llm("")
        hint = await search_build_error("some error no builtin match", "Rust", llm, "model")
        assert hint is None

    @pytest.mark.asyncio
    async def test_returns_none_when_llm_raises(self) -> None:
        llm = AsyncMock()
        llm.chat.side_effect = RuntimeError("API down")
        hint = await search_build_error("some error no builtin match", "Rust", llm, "model")
        assert hint is None

    @pytest.mark.asyncio
    async def test_strips_quotes_from_llm_response(self) -> None:
        """LLM sometimes wraps the query in quotes — we strip them."""
        llm = _make_mock_llm('"rust error fix query"')
        ddg_html = _make_ddg_html([("Title", "Use this fix.")])

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()

            # SearXNG fails, DDG succeeds
            mock_client.get.side_effect = [
                httpx.TimeoutException("searxng down"),
                httpx.Response(200, text=ddg_html, request=httpx.Request("GET", "https://ddg")),
            ]
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            hint = await search_build_error("error details", "Rust", llm, "model")

        assert hint is not None
        # DDG was the second call
        ddg_call = mock_client.get.call_args_list[1]
        actual_query = ddg_call.kwargs.get("params", {}).get("q", "")
        assert not actual_query.startswith('"')

    @pytest.mark.asyncio
    async def test_returns_none_when_all_search_engines_fail(self) -> None:
        """When both SearXNG and DDG fail, returns None."""
        llm = _make_mock_llm("some query")

        with patch("forge.generator.web_search.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            hint = await search_build_error("error no builtin match", "Rust", llm, "model")

        assert hint is None
