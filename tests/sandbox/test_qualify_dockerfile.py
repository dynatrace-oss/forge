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

import pytest

from forge.sandbox._base import qualify_dockerfile_images


class TestQualifyDockerfileImages:
    """Verify FROM lines are rewritten for Podman compatibility."""

    def test_bare_image_gets_qualified(self) -> None:
        df = "FROM golang:1.20-alpine\nRUN echo hello"
        result = qualify_dockerfile_images(df)
        assert result == "FROM docker.io/library/golang:1.20-alpine\nRUN echo hello"

    def test_multistage_build(self) -> None:
        df = (
            "FROM golang:1.22-alpine AS builder\n"
            "WORKDIR /app\n"
            "FROM alpine:latest\n"
            "COPY --from=builder /app/server ."
        )
        result = qualify_dockerfile_images(df)
        assert "FROM docker.io/library/golang:1.22-alpine AS builder" in result
        assert "FROM docker.io/library/alpine:latest" in result

    def test_already_qualified_unchanged(self) -> None:
        df = "FROM docker.io/library/python:3.11-slim\nRUN pip install flask"
        result = qualify_dockerfile_images(df)
        assert result == df

    def test_third_party_registry_unchanged(self) -> None:
        df = "FROM ghcr.io/foo/bar:latest\nRUN echo hi"
        result = qualify_dockerfile_images(df)
        assert result == df

    def test_build_arg_reference_skipped(self) -> None:
        df = "ARG BASE_IMAGE=python:3.12\nFROM ${BASE_IMAGE}\nRUN echo hi"
        result = qualify_dockerfile_images(df)
        # The ARG line stays, the FROM ${BASE_IMAGE} is skipped (starts with $)
        assert "FROM ${BASE_IMAGE}" in result

    def test_image_without_tag(self) -> None:
        df = "FROM python\nRUN pip install flask"
        result = qualify_dockerfile_images(df)
        assert result == "FROM docker.io/library/python\nRUN pip install flask"

    def test_image_with_digest(self) -> None:
        df = "FROM node@sha256:abc123\nRUN echo hi"
        result = qualify_dockerfile_images(df)
        assert "FROM docker.io/library/node@sha256:abc123" in result

    @pytest.mark.parametrize(
        ("image", "expected"),
        [
            ("python:3.11-slim", "docker.io/library/python:3.11-slim"),
            ("node:18-alpine", "docker.io/library/node:18-alpine"),
            ("golang:1.22-alpine", "docker.io/library/golang:1.22-alpine"),
            ("maven:3.8.6-eclipse-temurin-11", "docker.io/library/maven:3.8.6-eclipse-temurin-11"),
            ("openjdk:17-slim", "docker.io/library/openjdk:17-slim"),
            ("php:8.1-cli", "docker.io/library/php:8.1-cli"),
            ("ruby:3.2-alpine", "docker.io/library/ruby:3.2-alpine"),
            ("rust:1.75-slim", "docker.io/library/rust:1.75-slim"),
        ],
    )
    def test_common_base_images(self, image: str, expected: str) -> None:
        df = f"FROM {image}\nWORKDIR /app"
        result = qualify_dockerfile_images(df)
        assert f"FROM {expected}" in result

    def test_case_insensitive_from(self) -> None:
        df = "from golang:1.20-alpine\nRUN echo hi"
        result = qualify_dockerfile_images(df)
        assert "docker.io/library/golang:1.20-alpine" in result

    def test_empty_dockerfile(self) -> None:
        assert qualify_dockerfile_images("") == ""

    def test_no_from_lines(self) -> None:
        df = "RUN echo hello\nCOPY . ."
        result = qualify_dockerfile_images(df)
        assert result == df

    def test_preserves_trailing_newline(self) -> None:
        """Splitlines + join drops the trailing newline; verify content integrity."""
        df = "FROM node:18-alpine\nRUN echo hi"
        result = qualify_dockerfile_images(df)
        lines = result.split("\n")
        assert len(lines) == 2

    def test_real_world_go_dockerfile(self) -> None:
        """Exact Dockerfile that caused CVE-2024-37896 failure in v19."""
        df = (
            "FROM golang:1.20-alpine AS builder\n"
            "\n"
            "WORKDIR /app\n"
            "\n"
            "COPY go.mod ./\n"
            "COPY . .\n"
            "\n"
            "RUN go mod tidy && \\\n"
            "    CGO_ENABLED=0 go build -o vulnerable-app .\n"
            "\n"
            "FROM alpine:latest\n"
            "\n"
            "RUN apk --no-cache add ca-certificates\n"
            "\n"
            "WORKDIR /root/\n"
            "\n"
            "COPY --from=builder /app/vulnerable-app .\n"
            "\n"
            "EXPOSE 8080\n"
            "\n"
            'CMD ["./vulnerable-app"]'
        )
        result = qualify_dockerfile_images(df)
        assert "FROM docker.io/library/golang:1.20-alpine AS builder" in result
        assert "FROM docker.io/library/alpine:latest" in result
        assert "COPY --from=builder" in result
