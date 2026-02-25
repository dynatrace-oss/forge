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
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import yaml

from forge.cookbook import CookbookStore, _parse_tips


class TestCookbookStore:
    """Core CookbookStore tests — load, query, format."""

    def test_load_from_directory(self, tmp_path: Path) -> None:
        """Loads all YAML pages from the cookbook directory."""
        lang_dir = tmp_path / "languages"
        lang_dir.mkdir()
        page_data = {
            "language": "python",
            "cwe_category": "",
            "tips": [{"id": "py-001", "tip": "Use Flask", "phase": "generation"}],
        }
        (lang_dir / "python.yaml").write_text(yaml.dump(page_data))

        store = CookbookStore(cookbook_dir=tmp_path)
        assert store.page_count() == 1
        assert store.tip_count() == 1

    def test_query_filters_by_language(self, tmp_path: Path) -> None:
        """query returns only tips for the requested language."""
        lang_dir = tmp_path / "languages"
        lang_dir.mkdir()
        for lang in ("python", "java"):
            page = {
                "language": lang,
                "tips": [{"id": f"{lang}-001", "tip": f"Tip for {lang}"}],
            }
            (lang_dir / f"{lang}.yaml").write_text(yaml.dump(page))

        store = CookbookStore(cookbook_dir=tmp_path)
        tips = store.query(language="python")
        assert len(tips) == 1
        assert tips[0].id == "python-001"

    def test_format_for_prompt_empty_when_no_match(self, tmp_path: Path) -> None:
        """format_for_prompt returns empty string when no tips match."""
        tmp_path.mkdir(exist_ok=True)
        store = CookbookStore(cookbook_dir=tmp_path)
        assert store.format_for_prompt(language="haskell") == ""

    def test_distill_enabled_requires_llm_and_model(self, tmp_path: Path) -> None:
        """distill_enabled is False without llm or model."""
        store = CookbookStore(cookbook_dir=tmp_path)
        assert not store.distill_enabled

        store2 = CookbookStore(
            cookbook_dir=tmp_path,
            llm=AsyncMock(),
            distill_model="gpt-5-mini",
        )
        assert store2.distill_enabled


class TestDistillTips:
    """Tests for auto-distillation of build errors into tips."""

    @pytest.mark.asyncio
    async def test_distill_adds_new_tips(self, tmp_path: Path) -> None:
        """distill_tips adds LLM-generated tips to the language page."""
        lang_dir = tmp_path / "languages"
        lang_dir.mkdir()

        mock_llm = AsyncMock()
        new_tips = [{"id": "auto-001", "tip": "Always pin versions", "phase": "generation"}]
        mock_llm.chat.return_value = (json.dumps(new_tips), AsyncMock())

        store = CookbookStore(
            cookbook_dir=tmp_path,
            llm=mock_llm,
            distill_model="gpt-5-mini",
        )

        added = await store.distill_tips(
            language="python",
            cwe_id="CWE-79",
            build_errors=["ModuleNotFoundError: flask"],
            success=True,
        )

        assert added == 1
        assert store.tip_count() == 1
        # Verify persisted to disk
        yaml_path = tmp_path / "languages" / "python.yaml"
        assert yaml_path.exists()

    @pytest.mark.asyncio
    async def test_distill_skips_when_no_errors(self, tmp_path: Path) -> None:
        """distill_tips returns 0 when build_errors is empty."""
        mock_llm = AsyncMock()
        store = CookbookStore(
            cookbook_dir=tmp_path,
            llm=mock_llm,
            distill_model="gpt-5-mini",
        )

        added = await store.distill_tips(
            language="python",
            cwe_id="CWE-79",
            build_errors=[],
            success=True,
        )
        assert added == 0
        mock_llm.chat.assert_not_called()

    @pytest.mark.asyncio
    async def test_distill_skips_when_not_enabled(self, tmp_path: Path) -> None:
        """distill_tips returns 0 when LLM is not configured."""
        store = CookbookStore(cookbook_dir=tmp_path)

        added = await store.distill_tips(
            language="python",
            cwe_id="CWE-79",
            build_errors=["some error"],
            success=False,
        )
        assert added == 0

    @pytest.mark.asyncio
    async def test_distill_handles_llm_failure(self, tmp_path: Path) -> None:
        """distill_tips returns 0 and logs warning on LLM failure."""
        mock_llm = AsyncMock()
        mock_llm.chat.side_effect = RuntimeError("API down")

        store = CookbookStore(
            cookbook_dir=tmp_path,
            llm=mock_llm,
            distill_model="gpt-5-mini",
        )

        added = await store.distill_tips(
            language="go",
            cwe_id="CWE-22",
            build_errors=["build failed"],
            success=False,
        )
        assert added == 0

    @pytest.mark.asyncio
    async def test_distill_deduplicates_existing_tips(self, tmp_path: Path) -> None:
        """distill_tips updates existing tips with same ID instead of adding."""
        lang_dir = tmp_path / "languages"
        lang_dir.mkdir()
        page = {
            "language": "python",
            "tips": [{"id": "auto-001", "tip": "Old tip", "phase": "generation"}],
        }
        (lang_dir / "python.yaml").write_text(yaml.dump(page))

        mock_llm = AsyncMock()
        updated_tips = [{"id": "auto-001", "tip": "Improved tip", "phase": "generation"}]
        mock_llm.chat.return_value = (json.dumps(updated_tips), AsyncMock())

        store = CookbookStore(
            cookbook_dir=tmp_path,
            llm=mock_llm,
            distill_model="gpt-5-mini",
        )

        added = await store.distill_tips(
            language="python",
            cwe_id="CWE-79",
            build_errors=["some error"],
            success=True,
        )
        # Updated existing tip — not a new addition
        assert added == 0
        assert store.tip_count() == 1
        tips = store.query(language="python")
        assert tips[0].tip == "Improved tip"


class TestParseTips:
    """Tests for _parse_tips JSON extraction."""

    def test_parse_valid_json_array(self) -> None:
        raw = '[{"id": "auto-001", "tip": "Pin versions", "phase": "generation"}]'
        tips = _parse_tips(raw)
        assert len(tips) == 1
        assert tips[0].id == "auto-001"

    def test_parse_empty_array(self) -> None:
        assert _parse_tips("[]") == []

    def test_parse_json_in_markdown(self) -> None:
        raw = '```json\n[{"id": "auto-001", "tip": "Test", "phase": "generation"}]\n```'
        tips = _parse_tips(raw)
        assert len(tips) == 1

    def test_parse_garbage_returns_empty(self) -> None:
        assert _parse_tips("not json at all") == []
