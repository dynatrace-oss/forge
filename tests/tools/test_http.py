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

from unittest.mock import AsyncMock

import pytest

from forge.sandbox.models import HttpResponse
from forge.tools.http_tools import (
    HttpRequest,
)


def _session() -> AsyncMock:
    s = AsyncMock()
    s.http_request = AsyncMock()
    return s


class TestHttpTools:
    @pytest.mark.asyncio
    async def test_http_request_success_and_error(self) -> None:
        s = _session()
        s.http_request.return_value = HttpResponse(status_code=200, headers={}, body="ok")
        r = await HttpRequest(s).execute({"method": "GET", "path": "/"})
        assert "HTTP 200" in r.content

        s.http_request.return_value = HttpResponse(status_code=0, error="refused")
        r = await HttpRequest(s).execute({"method": "GET", "path": "/"})
        assert r.error


class TestHttpRequestMissingPath:
    """Bug 6 regression: missing 'path' must return ToolResult error, not KeyError."""

    @pytest.mark.asyncio
    async def test_missing_path_returns_error_result(self) -> None:
        """http_request with no 'path' key should return an error ToolResult."""
        s = _session()
        tool = HttpRequest(s)
        result = await tool.execute({"method": "GET"})
        assert result.error is True
        assert "path" in result.content.lower()
        s.http_request.assert_not_awaited()


class TestHttpToolFileUpload:
    """Fix 1: http_request supports multipart file upload via 'files' parameter."""

    @pytest.mark.asyncio
    async def test_file_upload_builds_tuples_and_calls_session(self) -> None:
        """Files parameter is converted to httpx-compatible tuples."""
        s = _session()
        s.http_request.return_value = HttpResponse(
            status_code=200, headers={}, body='{"uploaded": true}'
        )

        tool = HttpRequest(s)
        result = await tool.execute(
            {
                "method": "POST",
                "path": "/upload",
                "files": [
                    {
                        "field": "file",
                        "filename": "evil.svg",
                        "content": "<svg onload=alert(1)>",
                        "content_type": "image/svg+xml",
                    },
                ],
            }
        )

        assert not result.error
        assert "HTTP 200" in result.content

        # Verify session.http_request was called with files kwarg
        call_kwargs = s.http_request.call_args
        assert call_kwargs.kwargs["files"] is not None
        files_arg = call_kwargs.kwargs["files"]
        assert len(files_arg) == 1
        field, (filename, content_bytes, ct) = files_arg[0]
        assert field == "file"
        assert filename == "evil.svg"
        assert content_bytes == b"<svg onload=alert(1)>"
        assert ct == "image/svg+xml"
