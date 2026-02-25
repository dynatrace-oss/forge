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
