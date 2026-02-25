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
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from forge.config import ResolverConfig
from forge.cve.llm_resolver import (
    ResolvedPackage,
    _build_registry_url,
    _extract_search_query,
    _parse_llm_response,
    _validate_package_exists,
    resolve_package,
)
from forge.models import CVETask, TokenUsage


class TestParseLLMResponse:
    def test_clean_json(self) -> None:
        text = json.dumps(
            {
                "package_name": "next",
                "ecosystem": "npm",
                "language": "JavaScript",
                "vulnerable_version": "14.2.24",
                "confidence": "high",
                "reasoning": "test",
            }
        )
        result = _parse_llm_response(text)
        assert result is not None
        assert result["package_name"] == "next"
        assert result["ecosystem"] == "npm"

    def test_json_with_markdown_fences(self) -> None:
        text = '```json\n{"package_name": "mesop", "ecosystem": "pypi"}\n```'
        result = _parse_llm_response(text)
        assert result is not None
        assert result["package_name"] == "mesop"
        assert result["ecosystem"] == "pypi"

    def test_json_with_whitespace(self) -> None:
        text = '\n  {"package_name": "next", "ecosystem": "npm"}  \n'
        result = _parse_llm_response(text)
        assert result is not None
        assert result["package_name"] == "next"

    def test_missing_required_fields(self) -> None:
        text = '{"package_name": "next"}'
        result = _parse_llm_response(text)
        assert result is None

    def test_invalid_json(self) -> None:
        text = "I think the package is next on npm"
        result = _parse_llm_response(text)
        assert result is None

    def test_empty_string(self) -> None:
        result = _parse_llm_response("")
        assert result is None


class TestExtractSearchQuery:
    def test_function_call_syntax(self) -> None:
        text = 'I need to verify. web_search("next.js npm package name")'
        assert _extract_search_query(text) == "next.js npm package name"

    def test_json_query_field(self) -> None:
        text = '{"name": "web_search", "query": "kafka-ui maven central"}'
        assert _extract_search_query(text) == "kafka-ui maven central"

    def test_natural_language(self) -> None:
        text = "Let me search for: 'coolify packagist'"
        assert _extract_search_query(text) == ""

    def test_no_match(self) -> None:
        text = "The package is next on npm"
        assert _extract_search_query(text) == ""


class TestResolvedPackage:
    def test_repr(self) -> None:
        pkg = ResolvedPackage(
            package_name="next",
            ecosystem="npm",
            vulnerable_version="14.2.24",
        )
        assert "next@14.2.24" in repr(pkg)
        assert "npm" in repr(pkg)

    def test_repr_no_version(self) -> None:
        pkg = ResolvedPackage(package_name="next", ecosystem="npm")
        assert "next" in repr(pkg)
        assert "@" not in repr(pkg)


class TestBuildRegistryUrl:
    @pytest.mark.parametrize(
        "url_template,package_name,ecosystem,expected",
        [
            pytest.param(
                "https://registry.npmjs.org/{package}",
                "express",
                "npm",
                "https://registry.npmjs.org/express",
                id="npm-simple",
            ),
            pytest.param(
                "https://registry.npmjs.org/{package}",
                "@scope/pkg",
                "npm",
                "https://registry.npmjs.org/@scope/pkg",
                id="npm-scoped",
            ),
            pytest.param(
                "https://pypi.org/pypi/{package}/json",
                "Django",
                "pypi",
                "https://pypi.org/pypi/Django/json",
                id="pypi",
            ),
            pytest.param(
                "https://repo1.maven.org/maven2/{group_path}/{artifact}/maven-metadata.xml",
                "org.springframework:spring-web",
                "maven",
                "https://repo1.maven.org/maven2/org/springframework/spring-web/maven-metadata.xml",
                id="maven-group-artifact",
            ),
            pytest.param(
                "https://api.nuget.org/v3-flatcontainer/{package_lower}/index.json",
                "Newtonsoft.Json",
                "nuget",
                "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json",
                id="nuget-lowercase",
            ),
            pytest.param(
                "https://proxy.golang.org/{package}/@latest",
                "github.com/gin-gonic/gin",
                "go",
                "https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
                id="go",
            ),
            pytest.param(
                "https://rubygems.org/api/v1/gems/{package}.json",
                "rails",
                "rubygems",
                "https://rubygems.org/api/v1/gems/rails.json",
                id="rubygems",
            ),
            pytest.param(
                "https://crates.io/api/v1/crates/{package}",
                "serde",
                "crates.io",
                "https://crates.io/api/v1/crates/serde",
                id="crates-io",
            ),
        ],
    )
    def test_builds_url(
        self, url_template: str, package_name: str, ecosystem: str, expected: str
    ) -> None:
        assert _build_registry_url(url_template, package_name, ecosystem) == expected


class TestValidatePackageExists:
    @pytest.mark.asyncio
    async def test_package_found(self) -> None:
        mock_resp = MagicMock(status_code=200)
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.head.return_value = mock_resp

        with (
            patch(
                "forge.cve.llm_resolver._load_registry_config",
                return_value={
                    "timeout": 5.0,
                    "registries": {
                        "npm": {
                            "url": "https://registry.npmjs.org/{package}",
                            "method": "HEAD",
                        }
                    },
                },
            ),
            patch("forge.cve.llm_resolver.httpx.AsyncClient", return_value=mock_client),
        ):
            exists, detail = await _validate_package_exists("express", "npm")

        assert exists is True
        assert detail == ""

    @pytest.mark.asyncio
    async def test_package_not_found_404(self) -> None:
        mock_resp = MagicMock(status_code=404)
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.head.return_value = mock_resp

        with (
            patch(
                "forge.cve.llm_resolver._load_registry_config",
                return_value={
                    "timeout": 5.0,
                    "registries": {
                        "npm": {
                            "url": "https://registry.npmjs.org/{package}",
                            "method": "HEAD",
                        }
                    },
                },
            ),
            patch("forge.cve.llm_resolver.httpx.AsyncClient", return_value=mock_client),
        ):
            exists, detail = await _validate_package_exists("@lunary-ai/lunary", "npm")

        assert exists is False
        assert "NOT FOUND" in detail
        assert "@lunary-ai/lunary" in detail

    @pytest.mark.asyncio
    async def test_network_error_assumes_valid(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.head.side_effect = httpx.TimeoutException("connection timed out")

        with (
            patch(
                "forge.cve.llm_resolver._load_registry_config",
                return_value={
                    "timeout": 5.0,
                    "registries": {
                        "npm": {
                            "url": "https://registry.npmjs.org/{package}",
                            "method": "HEAD",
                        }
                    },
                },
            ),
            patch("forge.cve.llm_resolver.httpx.AsyncClient", return_value=mock_client),
        ):
            exists, detail = await _validate_package_exists("express", "npm")

        assert exists is True
        assert detail == ""

    @pytest.mark.asyncio
    async def test_unknown_ecosystem_skips_validation(self) -> None:
        with patch(
            "forge.cve.llm_resolver._load_registry_config",
            return_value={"timeout": 5.0, "registries": {}},
        ):
            exists, detail = await _validate_package_exists("somelib", "unknown")

        assert exists is True
        assert detail == ""

    @pytest.mark.asyncio
    async def test_get_method_ecosystem(self) -> None:
        mock_resp = MagicMock(status_code=200)
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with (
            patch(
                "forge.cve.llm_resolver._load_registry_config",
                return_value={
                    "timeout": 5.0,
                    "registries": {
                        "go": {
                            "url": "https://proxy.golang.org/{package}/@latest",
                            "method": "GET",
                        }
                    },
                },
            ),
            patch("forge.cve.llm_resolver.httpx.AsyncClient", return_value=mock_client),
        ):
            exists, detail = await _validate_package_exists("github.com/gin-gonic/gin", "go")

        assert exists is True
        mock_client.get.assert_called_once()


class TestResolvePackage:
    @pytest.fixture(autouse=True)
    def _mock_registry_validation(self) -> Iterator[None]:
        """Bypass registry validation for all resolve_package flow tests."""
        with patch(
            "forge.cve.llm_resolver._validate_package_exists",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ):
            yield

    @pytest.mark.asyncio
    async def test_successful_resolution(self) -> None:
        llm = AsyncMock()
        llm.chat = AsyncMock(
            return_value=(
                json.dumps(
                    {
                        "package_name": "next",
                        "ecosystem": "npm",
                        "language": "JavaScript",
                        "vulnerable_version": "14.2.24",
                        "confidence": "high",
                        "reasoning": "Next.js publishes as 'next' on npm",
                    }
                ),
                TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1),
            )
        )

        task = CVETask(
            cve_id="CVE-2025-29927",
            description="Next.js is a React framework. Prior to version 15.2.3...",
            cwe_ids=["CWE-285"],
        )
        config = ResolverConfig(model="test-model", max_turns=2)

        result, tokens = await resolve_package(task, llm=llm, config=config)

        assert result is not None
        assert result.package_name == "next"
        assert result.ecosystem == "npm"
        assert result.language == "JavaScript"
        assert tokens.total_tokens == 150

    @pytest.mark.asyncio
    async def test_llm_returns_unparseable_then_json(self) -> None:
        """LLM returns text first, then JSON after nudge."""
        llm = AsyncMock()
        llm.chat = AsyncMock(
            side_effect=[
                (
                    "I think the package is mesop on pypi.",
                    TokenUsage(
                        prompt_tokens=100, completion_tokens=30, total_tokens=130, llm_calls=1
                    ),
                ),
                (
                    json.dumps(
                        {
                            "package_name": "mesop",
                            "ecosystem": "pypi",
                            "language": "Python",
                            "vulnerable_version": "0.9.0",
                            "confidence": "high",
                            "reasoning": "test",
                        }
                    ),
                    TokenUsage(
                        prompt_tokens=150, completion_tokens=50, total_tokens=200, llm_calls=1
                    ),
                ),
            ]
        )

        task = CVETask(
            cve_id="CVE-2024-45601", description="Mesop is a Python-based UI framework..."
        )
        config = ResolverConfig(model="test-model", max_turns=2)

        result, tokens = await resolve_package(task, llm=llm, config=config)

        assert result is not None
        assert result.package_name == "mesop"
        assert tokens.total_tokens == 330  # 130 + 200
        assert llm.chat.call_count == 2

    @pytest.mark.asyncio
    async def test_llm_failure_returns_none(self) -> None:
        llm = AsyncMock()
        llm.chat = AsyncMock(side_effect=RuntimeError("API error"))

        task = CVETask(cve_id="CVE-2024-0001", description="Test")
        config = ResolverConfig(model="test-model", max_turns=1)

        result, _ = await resolve_package(task, llm=llm, config=config)
        assert result is None

    @pytest.mark.asyncio
    async def test_web_search_trigger(self) -> None:
        """LLM requests web search, gets results, then answers."""
        llm = AsyncMock()
        llm.chat = AsyncMock(
            side_effect=[
                (
                    'Let me verify. web_search("kafka-ui maven central artifact")',
                    TokenUsage(
                        prompt_tokens=100, completion_tokens=30, total_tokens=130, llm_calls=1
                    ),
                ),
                (
                    json.dumps(
                        {
                            "package_name": "com.provectus:kafka-ui-api",
                            "ecosystem": "maven",
                            "language": "Java",
                            "vulnerable_version": "0.7.1",
                            "confidence": "high",
                            "reasoning": "verified on Maven Central",
                        }
                    ),
                    TokenUsage(
                        prompt_tokens=200, completion_tokens=50, total_tokens=250, llm_calls=1
                    ),
                ),
            ]
        )

        task = CVETask(cve_id="CVE-2024-32030", description="Kafka UI is an Open-Source Web UI...")
        config = ResolverConfig(model="test-model", max_turns=2)

        with patch("forge.cve.llm_resolver._web_search", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = "- Maven Central: com.provectus:kafka-ui-api 0.7.1"
            result, _ = await resolve_package(task, llm=llm, config=config)

        assert result is not None
        assert result.package_name == "com.provectus:kafka-ui-api"
        mock_search.assert_called_once()


class TestRegistryValidationLoop:
    @pytest.mark.asyncio
    async def test_llm_corrects_after_registry_failure(self) -> None:
        """LLM returns wrong name -> registry 404 -> LLM corrects -> OK."""
        llm = AsyncMock()
        llm.chat = AsyncMock(
            side_effect=[
                (
                    json.dumps(
                        {
                            "package_name": "@lunary-ai/lunary",
                            "ecosystem": "npm",
                            "language": "JavaScript",
                            "vulnerable_version": "1.2.0",
                            "confidence": "high",
                            "reasoning": "from GitHub org",
                        }
                    ),
                    TokenUsage(
                        prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1
                    ),
                ),
                (
                    json.dumps(
                        {
                            "package_name": "lunary",
                            "ecosystem": "npm",
                            "language": "JavaScript",
                            "vulnerable_version": "1.2.0",
                            "confidence": "high",
                            "reasoning": "corrected: npm package is just lunary",
                        }
                    ),
                    TokenUsage(
                        prompt_tokens=200, completion_tokens=50, total_tokens=250, llm_calls=1
                    ),
                ),
            ]
        )

        task = CVETask(cve_id="CVE-2024-10275", description="Lunary is an AI platform...")
        config = ResolverConfig(model="test-model", max_turns=3)

        with patch(
            "forge.cve.llm_resolver._validate_package_exists",
            new_callable=AsyncMock,
            side_effect=[
                (False, "Package '@lunary-ai/lunary' NOT FOUND on npm registry (HTTP 404)"),
                (True, ""),
            ],
        ):
            result, tokens = await resolve_package(task, llm=llm, config=config)

        assert result is not None
        assert result.package_name == "lunary"
        assert result.ecosystem == "npm"
        assert tokens.total_tokens == 400
        assert llm.chat.call_count == 2

    @pytest.mark.asyncio
    async def test_registry_failure_on_final_turn_returns_low_confidence(self) -> None:
        """Package not found on final turn -> returns with low confidence."""
        llm = AsyncMock()
        llm.chat = AsyncMock(
            return_value=(
                json.dumps(
                    {
                        "package_name": "nonexistent-pkg",
                        "ecosystem": "npm",
                        "language": "JavaScript",
                        "vulnerable_version": "1.0.0",
                        "confidence": "high",
                        "reasoning": "test",
                    }
                ),
                TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, llm_calls=1),
            ),
        )

        task = CVETask(cve_id="CVE-2024-0001", description="Test")
        config = ResolverConfig(model="test-model", max_turns=1)

        with patch(
            "forge.cve.llm_resolver._validate_package_exists",
            new_callable=AsyncMock,
            return_value=(False, "Package 'nonexistent-pkg' NOT FOUND on npm registry"),
        ):
            result, tokens = await resolve_package(task, llm=llm, config=config)

        assert result is not None
        assert result.confidence == "low"
        assert "UNVERIFIED" in result.reasoning
