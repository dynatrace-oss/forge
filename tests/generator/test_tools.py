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

import pytest

from forge.tools.generator_tools import (
    AddVulnerability,
    WriteAppFiles,
)


class TestWriteAppFiles:
    @pytest.mark.asyncio
    async def test_empty_array_returns_error(self) -> None:
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        result = await tool.execute({"files": []})
        assert result.error is True
        assert "empty" in result.content.lower()
        assert not app_state

    @pytest.mark.asyncio
    async def test_empty_dict_returns_error_legacy(self) -> None:
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        result = await tool.execute({"files": {}})
        assert result.error is True
        assert "empty" in result.content.lower()
        assert not app_state

    @pytest.mark.asyncio
    async def test_multi_file_write(self) -> None:
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        files = [
            {"path": "app.py", "content": "from flask import Flask\napp = Flask(__name__)\n"},
            {"path": "Dockerfile", "content": "FROM python:3.12\n"},
            {"path": "requirements.txt", "content": "flask\n"},
        ]
        result = await tool.execute({"files": files})
        assert result.error is False
        assert "Wrote 3 files" in result.content
        assert app_state["app.py"] == "from flask import Flask\napp = Flask(__name__)\n"
        assert app_state["Dockerfile"] == "FROM python:3.12\n"
        assert app_state["requirements.txt"] == "flask\n"

    @pytest.mark.asyncio
    async def test_overwrites_existing_files(self) -> None:
        app_state = {"app.py": "old content"}
        tool = WriteAppFiles(app_state)
        result = await tool.execute(
            {
                "files": [
                    {"path": "app.py", "content": "new content"},
                    {"path": "config.py", "content": "x=1"},
                ]
            }
        )
        assert result.error is False
        assert app_state["app.py"] == "new content"
        assert app_state["config.py"] == "x=1"


class TestWriteAppFilesLockfileStripping:
    """Bug 8 regression: WriteAppFiles must strip lockfiles from LLM output."""

    @pytest.mark.asyncio
    async def test_strips_lockfiles(self) -> None:
        """Lockfiles (go.sum, package-lock.json, etc.) are silently removed."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        files = [
            {"path": "main.go", "content": "package main"},
            {"path": "go.sum", "content": "h1:abc123"},
            {"path": "go.mod", "content": "module example.com"},
            {"path": "package-lock.json", "content": '{"lockfileVersion": 3}'},
        ]
        result = await tool.execute({"files": files})
        assert result.error is False
        assert "main.go" in app_state
        assert "go.mod" in app_state
        assert "go.sum" not in app_state
        assert "package-lock.json" not in app_state
        assert "stripped" in result.content.lower()

    @pytest.mark.asyncio
    async def test_non_lockfiles_pass_through(self) -> None:
        """Normal source files are written without modification."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        files = [
            {"path": "app.py", "content": "print('hi')"},
            {"path": "Dockerfile", "content": "FROM python:3.12"},
        ]
        result = await tool.execute({"files": files})
        assert result.error is False
        assert app_state == {"app.py": "print('hi')", "Dockerfile": "FROM python:3.12"}
        assert "stripped" not in result.content.lower()

    @pytest.mark.asyncio
    async def test_all_lockfiles_returns_error(self) -> None:
        """If every file is a lockfile, return an error."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        result = await tool.execute(
            {
                "files": [
                    {"path": "go.sum", "content": "x"},
                    {"path": "yarn.lock", "content": "y"},
                ]
            }
        )
        assert result.error is True
        assert not app_state


class TestWriteAppFilesDictCoercion:
    """Bug: LLM sends package.json as a JSON object instead of a string."""

    @pytest.mark.asyncio
    async def test_dict_value_coerced_to_json_string(self) -> None:
        """Non-string file values (dicts) are serialised to JSON strings."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        pkg = {"name": "my-app", "dependencies": {"express": "^4.18.0"}}
        files = [
            {"path": "app.js", "content": "const express = require('express');"},
            {"path": "package.json", "content": pkg},  # type: ignore[list-item]
        ]
        result = await tool.execute({"files": files})
        assert result.error is False
        assert "package.json" in app_state
        # Must be a string now, parseable as JSON
        parsed = json.loads(app_state["package.json"])
        assert parsed["name"] == "my-app"
        assert parsed["dependencies"]["express"] == "^4.18.0"

    @pytest.mark.asyncio
    async def test_string_values_unchanged(self) -> None:
        """Normal string values pass through without modification."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        content = '{"name": "my-app"}'
        result = await tool.execute({"files": [{"path": "package.json", "content": content}]})
        assert result.error is False
        assert app_state["package.json"] == content


class TestWriteAppFilesGoMessage:
    """Bug: Go-specific lockfile stripping guidance must explain layer ordering."""

    @pytest.mark.asyncio
    async def test_go_sum_stripped_includes_go_guidance(self) -> None:
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        files = [
            {"path": "main.go", "content": "package main"},
            {"path": "go.mod", "content": "module example.com"},
            {"path": "go.sum", "content": "h1:abc"},
        ]
        result = await tool.execute({"files": files})
        assert result.error is False
        assert "go.sum" not in app_state
        assert "COPY . ." in result.content
        assert "go mod tidy" in result.content
        assert "source files" in result.content.lower()

    @pytest.mark.asyncio
    async def test_non_go_lockfile_no_go_guidance(self) -> None:
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        files = [
            {"path": "app.js", "content": "console.log('hi')"},
            {"path": "package-lock.json", "content": "{}"},
        ]
        result = await tool.execute({"files": files})
        assert result.error is False
        assert "Go CRITICAL" not in result.content


class TestAddVulnerability:
    @pytest.mark.asyncio
    async def test_appends_to_existing_file(self) -> None:
        app_state = {"app.py": "# base app\n"}
        tool = AddVulnerability(app_state)
        result = await tool.execute(
            {
                "file_path": "app.py",
                "cwe_id": "CWE-89",
                "endpoint": "/search",
                "code_snippet": "@app.route('/search')\ndef search(): pass\n",
            }
        )
        assert result.error is False
        assert "/search" in app_state["app.py"]


class TestWriteAppFilesLegacyDict:
    """Backward compatibility: legacy dict format still works."""

    @pytest.mark.asyncio
    async def test_legacy_dict_format_accepted(self) -> None:
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        result = await tool.execute(
            {"files": {"app.py": "print('hi')", "Dockerfile": "FROM python:3.12"}}
        )
        assert result.error is False
        assert "Wrote 2 files" in result.content
        assert app_state["app.py"] == "print('hi')"
        assert app_state["Dockerfile"] == "FROM python:3.12"

    @pytest.mark.asyncio
    async def test_legacy_empty_dict_returns_error(self) -> None:
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        result = await tool.execute({"files": {}})
        assert result.error is True


class TestWriteAppFilesStringSerialization:
    """LLMs sometimes double-serialize the files array as a JSON string."""

    @pytest.mark.asyncio
    async def test_single_serialized_string(self) -> None:
        """files sent as a JSON string (single wrap) should be unwrapped."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        files_list = [{"path": "app.py", "content": "print('hi')"}]
        result = await tool.execute({"files": json.dumps(files_list)})
        assert result.error is False
        assert app_state["app.py"] == "print('hi')"

    @pytest.mark.asyncio
    async def test_double_serialized_string(self) -> None:
        """files sent as a double JSON string (string of a string) should be unwrapped."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        files_list = [{"path": "main.py", "content": "x = 1"}]
        # Double-serialize: json.dumps twice
        result = await tool.execute({"files": json.dumps(json.dumps(files_list))})
        assert result.error is False
        assert app_state["main.py"] == "x = 1"

    @pytest.mark.asyncio
    async def test_unparseable_string_returns_error(self) -> None:
        """Garbage string should produce a clear error."""
        app_state: dict[str, str] = {}
        tool = WriteAppFiles(app_state)
        result = await tool.execute({"files": "not json at all"})
        assert result.error is True
        assert "unparseable" in result.content.lower() or "error" in result.content.lower()
