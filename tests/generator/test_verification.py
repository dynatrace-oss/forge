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

from forge.generator.verification import check_vulnerable_package_present


class TestCheckVulnerablePackagePresent:
    """Test the vulnerable package presence check in dependency manifests."""

    def test_no_expected_package(self) -> None:
        """No check when expected_package is empty."""
        assert check_vulnerable_package_present({}, "python", "") == ""

    # -- Python --

    def test_python_found_in_requirements(self) -> None:
        files = {"requirements.txt": "flask==2.3.0\nlunary==1.5.6\n"}
        assert check_vulnerable_package_present(files, "python", "lunary") == ""

    def test_python_missing_from_requirements(self) -> None:
        files = {"requirements.txt": "flask==2.3.0\nbetter-sqlite3==9.0.0\n"}
        result = check_vulnerable_package_present(files, "python", "lunary")
        assert "MISSING VULNERABLE PACKAGE" in result
        assert "lunary" in result

    def test_python_hyphen_underscore_normalization(self) -> None:
        """PyPI packages: hyphens and underscores are interchangeable."""
        files = {"requirements.txt": "my_package==1.0\n"}
        assert check_vulnerable_package_present(files, "python", "my-package") == ""

    def test_python_no_dependency_file(self) -> None:
        """No error when there's no requirements.txt (can't verify)."""
        files = {"app.py": "import flask\n"}
        assert check_vulnerable_package_present(files, "python", "flask") == ""

    def test_python_found_in_pyproject(self) -> None:
        files = {"pyproject.toml": '[project]\nname = "app"\ndependencies = ["flask>=2.0"]'}
        assert check_vulnerable_package_present(files, "python", "flask") == ""

    # -- JavaScript / TypeScript --

    def test_node_found_in_package_json(self) -> None:
        pkg = {"name": "app", "dependencies": {"lunary": "^1.5.6"}}
        files = {"package.json": json.dumps(pkg)}
        assert check_vulnerable_package_present(files, "javascript", "lunary") == ""

    def test_node_missing_from_package_json(self) -> None:
        pkg = {"name": "app", "dependencies": {"express": "^4.0.0"}}
        files = {"package.json": json.dumps(pkg)}
        result = check_vulnerable_package_present(files, "typescript", "lunary")
        assert "MISSING VULNERABLE PACKAGE" in result

    def test_node_scoped_package_match(self) -> None:
        """Match base name of scoped package (e.g. @org/pkg matches 'pkg')."""
        pkg = {"name": "app", "dependencies": {"@lunary/sdk": "^1.0"}}
        files = {"package.json": json.dumps(pkg)}
        assert check_vulnerable_package_present(files, "javascript", "sdk") == ""

    def test_node_case_insensitive(self) -> None:
        pkg = {"name": "app", "dependencies": {"Lunary": "^1.5.6"}}
        files = {"package.json": json.dumps(pkg)}
        assert check_vulnerable_package_present(files, "javascript", "lunary") == ""

    def test_node_no_package_json(self) -> None:
        files = {"app.js": "const express = require('express');"}
        assert check_vulnerable_package_present(files, "javascript", "express") == ""

    def test_node_in_dev_dependencies(self) -> None:
        pkg = {"name": "app", "devDependencies": {"jest": "^29.0"}}
        files = {"package.json": json.dumps(pkg)}
        assert check_vulnerable_package_present(files, "javascript", "jest") == ""

    # -- Go --

    def test_go_found_in_go_mod(self) -> None:
        content = "module myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n"
        files = {"go.mod": content}
        assert check_vulnerable_package_present(files, "go", "gin") == ""

    def test_go_missing_from_go_mod(self) -> None:
        content = "module myapp\n\ngo 1.21\n"
        files = {"go.mod": content}
        result = check_vulnerable_package_present(files, "go", "gin")
        assert "MISSING VULNERABLE PACKAGE" in result

    # -- Java --

    def test_java_found_in_pom(self) -> None:
        content = (
            "<dependencies><dependency>"
            "<groupId>org.apache</groupId>"
            "<artifactId>struts2</artifactId>"
            "</dependency></dependencies>"
        )
        files = {"pom.xml": content}
        assert check_vulnerable_package_present(files, "java", "struts2") == ""

    def test_java_missing_from_pom(self) -> None:
        content = "<dependencies></dependencies>"
        files = {"pom.xml": content}
        result = check_vulnerable_package_present(files, "java", "struts2")
        assert "MISSING VULNERABLE PACKAGE" in result

    # -- Ruby --

    def test_ruby_found_in_gemfile(self) -> None:
        files = {"Gemfile": "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n"}
        assert check_vulnerable_package_present(files, "ruby", "rails") == ""

    def test_ruby_missing_from_gemfile(self) -> None:
        files = {"Gemfile": "source 'https://rubygems.org'\ngem 'sinatra'\n"}
        result = check_vulnerable_package_present(files, "ruby", "rails")
        assert "MISSING VULNERABLE PACKAGE" in result

    # -- PHP --

    def test_php_found_in_composer(self) -> None:
        content = json.dumps({"require": {"laravel/framework": "^10.0"}})
        files = {"composer.json": content}
        assert check_vulnerable_package_present(files, "php", "laravel") == ""

    # -- Rust --

    def test_rust_found_in_cargo(self) -> None:
        content = '[package]\nname = "myapp"\n\n[dependencies]\ntokio = "1.0"\n'
        files = {"Cargo.toml": content}
        assert check_vulnerable_package_present(files, "rust", "tokio") == ""

    def test_rust_missing_from_cargo(self) -> None:
        content = '[package]\nname = "myapp"\n\n[dependencies]\n'
        files = {"Cargo.toml": content}
        result = check_vulnerable_package_present(files, "rust", "tokio")
        assert "MISSING VULNERABLE PACKAGE" in result

    # -- Unsupported language --

    def test_unsupported_language_passes(self) -> None:
        """Unsupported language returns empty (no check possible)."""
        files = {"main.swift": "import Foundation\n"}
        assert check_vulnerable_package_present(files, "swift", "Foundation") == ""
