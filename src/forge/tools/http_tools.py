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

import logging
from typing import Any

from forge.sandbox.protocols import SandboxSession
from forge.tools.base import Tool, ToolResult

logger = logging.getLogger(__name__)

_MAX_BODY = 8_000


class HttpRequest(Tool):
    """Send an HTTP request to the target application."""

    def __init__(self, session: SandboxSession) -> None:
        self._session = session

    @property
    def name(self) -> str:
        return "http_request"

    @property
    def description(self) -> str:
        return (
            "Send an HTTP request to the target application. "
            "Supports GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD. "
            "Supports multipart file upload via the 'files' parameter. "
            "Use this for probing endpoints, sending payloads, "
            "uploading files, and interacting with the vulnerable application."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
                    "description": "HTTP method",
                },
                "path": {
                    "type": "string",
                    "description": "URL path (e.g. /api/login). Relative to target base URL.",
                },
                "headers": {
                    "type": "object",
                    "description": "HTTP headers as key-value pairs",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST/PUT/PATCH). Ignored when files is set.",
                },
                "files": {
                    "type": "array",
                    "description": (
                        "Files to upload as multipart/form-data. "
                        "When set, body is ignored and Content-Type becomes multipart/form-data."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": {
                                "type": "string",
                                "description": "Form field name (e.g. 'file')",
                            },
                            "filename": {
                                "type": "string",
                                "description": "Filename to send (e.g. 'evil.svg')",
                            },
                            "content": {
                                "type": "string",
                                "description": "File content as text",
                            },
                            "content_type": {
                                "type": "string",
                                "description": "MIME type (e.g. 'image/svg+xml')",
                            },
                        },
                        "required": ["field", "filename", "content"],
                    },
                },
            },
            "required": ["method", "path"],
        }

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        method: str = arguments.get("method", "GET")
        path: str | None = arguments.get("path")
        if not path:
            return ToolResult(
                content="Error: 'path' parameter is required (e.g., '/api/endpoint')",
                error=True,
            )

        # Coerce headers from JSON string to dict if needed (LLM quirk).
        raw_headers = arguments.get("headers")
        headers: dict[str, str] | None = None
        if raw_headers is not None:
            try:
                from forge.tools.base import coerce_dict

                headers = coerce_dict(raw_headers, "headers")
            except TypeError:
                logger.warning("Ignoring malformed headers: %.200s", raw_headers)

        body: str | None = arguments.get("body")

        # Build multipart file tuples when the agent provides files
        raw_files: list[dict[str, str]] | None = arguments.get("files")
        file_tuples: list[tuple[str, tuple[str, bytes, str]]] | None = None
        if raw_files:
            file_tuples = []
            for f in raw_files:
                field = f.get("field", "file")
                filename = f.get("filename", "upload")
                content_bytes = f.get("content", "").encode()
                ct = f.get("content_type", "application/octet-stream")
                file_tuples.append((field, (filename, content_bytes, ct)))

        try:
            response = await self._session.http_request(
                method=method,
                path=path,
                headers=headers,
                body=body,
                files=file_tuples,
            )
        except Exception as exc:
            return ToolResult(content=f"HTTP request failed: {exc}", error=True)

        if response.error:
            return ToolResult(content=f"HTTP error: {response.error}", error=True)

        parts = [f"HTTP {response.status_code}"]

        if response.headers:
            header_lines = [f"  {k}: {v}" for k, v in response.headers.items()]
            parts.append("Headers:\n" + "\n".join(header_lines))

        body_text = response.body
        if len(body_text) > _MAX_BODY:
            body_text = body_text[:_MAX_BODY] + f"\n... truncated ({len(response.body)} chars)"

        if body_text:
            parts.append(f"Body:\n{body_text}")

        return ToolResult(content="\n\n".join(parts))


def register_http_tools(session: SandboxSession) -> list[Tool]:
    """Create and return all HTTP tools for the given session."""
    return [
        HttpRequest(session),
    ]
