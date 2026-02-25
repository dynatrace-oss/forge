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
