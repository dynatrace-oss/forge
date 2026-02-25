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

"""Tests for extract_error_summary() — smart build/deploy error extraction."""


from forge.sandbox._base import extract_error_summary


class TestExtractErrorSummary:
    """Verify error extraction picks up actionable lines, not noise."""

    def test_empty_input(self) -> None:
        assert extract_error_summary("") == ""

    def test_composer_security_advisory_captured(self) -> None:
        """Real-world Composer build failure — the security advisory error
        must be captured even when it's in the middle of the output."""
        output = (
            "STEP 1/11: FROM php:8.1-cli\n"
            "--> Using cache abc123\n"
            "STEP 5/11: COPY composer.json ./\n"
            "--> Using cache def456\n"
            "STEP 7/11: RUN composer install --no-dev\n"
            "Loading composer repositories with package information\n"
            "Updating dependencies\n"
            "Your requirements could not be resolved to an installable set of packages.\n"
            "\n"
            "  Problem 1\n"
            "    - Root composer.json requires unisharp/laravel-filemanager 2.8.0 "
            "but these were not loaded, because they are affected by security "
            'advisories ("PKSA-gwgj-6f7y-bmcx"). To turn the feature off entirely, '
            'you can set "block-insecure" to false in your "audit" config.\n'
            "\n"
            'Error: building at STEP "RUN composer install": exit status 1\n'
            "STEP 8/11: COPY . .\n"
            "some cleanup line\n"
            "another cleanup line\n"
        )
        result = extract_error_summary(output)
        assert "security advisories" in result
        assert "block-insecure" in result
        assert "exit status 1" in result

    def test_npm_install_failure_captured(self) -> None:
        """npm install error with dependency resolution failure."""
        output = (
            "STEP 1: FROM node:18-slim\n"
            "STEP 3: RUN npm install\n"
            "npm warn deprecated package@1.0.0: this package is no longer maintained\n"
            "npm error code ERESOLVE\n"
            "npm error ERESOLVE unable to resolve dependency tree\n"
            "npm error\n"
            "npm error While resolving: app@1.0.0\n"
            "npm error Found: express@4.17.1\n"
            "npm error Could not resolve dependency:\n"
            'npm error peer express@"^5.0.0" from some-package@2.0.0\n'
            "npm error Fix the upstream dependency conflict\n"
            "\n"
        )
        result = extract_error_summary(output)
        assert "unable to resolve dependency tree" in result
        assert "Could not resolve dependency" in result

    def test_python_import_error_captured(self) -> None:
        """Runtime container logs with a Python ImportError."""
        output = (
            "[2024-01-15 12:00:00] Starting application\n"
            "[2024-01-15 12:00:00] Loading configuration\n"
            "[2024-01-15 12:00:01] Initializing database\n"
            "Traceback (most recent call last):\n"
            '  File "/app/main.py", line 5, in <module>\n'
            "    from flask_sqlalchemy import SQLAlchemy\n"
            "ModuleNotFoundError: No module named 'flask_sqlalchemy'\n"
        )
        result = extract_error_summary(output)
        assert "Traceback" in result
        assert "ModuleNotFoundError" in result
        assert "flask_sqlalchemy" in result

    def test_truncation_respects_max_chars(self) -> None:
        """Output is truncated to max_chars."""
        # Generate a huge output with errors scattered throughout
        lines = []
        for i in range(200):
            if i % 50 == 0:
                lines.append(f"Error on line {i}: something failed")
            else:
                lines.append(f"STEP {i}: normal build output " * 5)
        output = "\n".join(lines)
        result = extract_error_summary(output, max_chars=500)
        assert len(result) <= 500
