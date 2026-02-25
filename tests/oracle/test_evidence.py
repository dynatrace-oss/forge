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

from forge.models import CWEModule, OracleCriterion
from forge.oracle.evidence import (
    _CWE_ALIASES,
    _CWE_EVIDENCE,
    _CWE_LEVEL_CAPS,
    _analyze_response,
    _classify_connection,
    _classify_error,
    _suggest_fix,
    apply_cwe_level_cap,
    format_oracle_criteria,
    get_cwe_level_cap,
)


def _make_cwe_module(cwe_id: str, cwe_name: str = "Test CWE") -> CWEModule:
    return CWEModule(
        cwe_id=cwe_id,
        cwe_name=cwe_name,
    )


class TestApplyCweLevelCap:
    """CWE-based structural level caps."""

    def test_xss_capped_at_l2(self) -> None:
        cwe = _make_cwe_module("CWE-79", "Cross-site Scripting")
        assert apply_cwe_level_cap(3, cwe) == 2

    def test_path_traversal_capped_at_l2(self) -> None:
        cwe = _make_cwe_module("CWE-22", "Path Traversal")
        assert apply_cwe_level_cap(3, cwe) == 2

    def test_xss_l2_unchanged(self) -> None:
        cwe = _make_cwe_module("CWE-79")
        assert apply_cwe_level_cap(2, cwe) == 2

    def test_xss_l1_unchanged(self) -> None:
        cwe = _make_cwe_module("CWE-79")
        assert apply_cwe_level_cap(1, cwe) == 1

    def test_rce_cwe_not_capped(self) -> None:
        cwe = _make_cwe_module("CWE-78", "OS Command Injection")
        assert apply_cwe_level_cap(3, cwe) == 3

    def test_sql_injection_not_capped(self) -> None:
        cwe = _make_cwe_module("CWE-89", "SQL Injection")
        assert apply_cwe_level_cap(3, cwe) == 3

    def test_none_cwe_module_is_noop(self) -> None:
        assert apply_cwe_level_cap(3, None) == 3

    def test_cwe80_alias_resolves_to_cwe79(self) -> None:
        cwe = _make_cwe_module("CWE-80", "Basic XSS")
        assert apply_cwe_level_cap(3, cwe) == 2

    def test_open_redirect_capped_at_l2(self) -> None:
        cwe = _make_cwe_module("CWE-601", "Open Redirect")
        assert apply_cwe_level_cap(3, cwe) == 2

    def test_dos_capped_at_l2(self) -> None:
        cwe = _make_cwe_module("CWE-400", "DoS")
        assert apply_cwe_level_cap(3, cwe) == 2

    def test_redos_capped_at_l2(self) -> None:
        cwe = _make_cwe_module("CWE-1333", "ReDoS")
        assert apply_cwe_level_cap(3, cwe) == 2

    def test_csrf_capped_at_l2(self) -> None:
        cwe = _make_cwe_module("CWE-352", "CSRF")
        assert apply_cwe_level_cap(3, cwe) == 2

    @pytest.mark.parametrize(
        "cwe_id",
        [
            pytest.param("CWE-29", id="cwe-29-path-traversal-variant"),
            pytest.param("CWE-23", id="cwe-23-relative-path"),
            pytest.param("CWE-36", id="cwe-36-absolute-path"),
        ],
    )
    def test_path_traversal_aliases_capped(self, cwe_id: str) -> None:
        cwe = _make_cwe_module(cwe_id)
        result = apply_cwe_level_cap(3, cwe)
        # Capped only if alias is registered in oracle_patterns.yaml.
        if cwe_id in _CWE_ALIASES:
            assert result == 2

    def test_l0_unchanged_for_any_cwe(self) -> None:
        """L0 should never be capped (already at minimum)."""
        cwe = _make_cwe_module("CWE-79")
        assert apply_cwe_level_cap(0, cwe) == 0


class TestGetCweLevelCap:
    def test_xss_returns_2(self) -> None:
        cwe = _make_cwe_module("CWE-79")
        assert get_cwe_level_cap(cwe) == 2

    def test_rce_returns_none(self) -> None:
        cwe = _make_cwe_module("CWE-78")
        assert get_cwe_level_cap(cwe) is None

    def test_none_module_returns_none(self) -> None:
        assert get_cwe_level_cap(None) is None

    def test_alias_resolves(self) -> None:
        cwe = _make_cwe_module("CWE-80")  # Alias for CWE-79
        assert get_cwe_level_cap(cwe) == 2


class TestFormatOracleCriteria:
    def test_cwe_with_evidence_descriptions(self) -> None:
        cwe = _make_cwe_module("CWE-89", "SQL Injection")
        result = format_oracle_criteria(cwe)
        assert "CWE-SPECIFIC EVIDENCE" in result
        assert "CWE-89" in result

    def test_cwe_with_oracle_criteria_fields_ignored(self) -> None:
        """oracle_criteria on CWEModule no longer renders enrichment section."""
        cwe = CWEModule(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            oracle_criteria=[
                OracleCriterion(
                    level=3,
                    name="Data Exfiltration",
                    description="SQL injection returning database rows",
                    indicators=["UNION SELECT rows", "table dump"],
                ),
            ],
        )
        result = format_oracle_criteria(cwe)
        # Should NOT contain enrichment section (removed)
        assert "ENRICHMENT-BASED CRITERIA" not in result
        # Should still contain hand-curated evidence from oracle_patterns.yaml
        assert "CWE-SPECIFIC EVIDENCE" in result

    def test_unknown_cwe_with_no_criteria(self) -> None:
        cwe = _make_cwe_module("CWE-99999", "Unknown Vuln")
        result = format_oracle_criteria(cwe)
        # No oracle_patterns.yaml entry and no oracle_criteria
        assert result == ""

    def test_empty_when_no_criteria(self) -> None:
        """CWE with no patterns entry and no oracle_criteria → empty string."""
        cwe = _make_cwe_module("CWE-99998")
        assert format_oracle_criteria(cwe) == ""


# ---------------------------------------------------------------------------
# _classify_connection
# ---------------------------------------------------------------------------


class TestClassifyConnection:
    def test_connection_refused(self) -> None:
        assert _classify_connection("ConnectionRefusedError: [Errno 111]") == "refused"

    def test_connection_refused_econnrefused(self) -> None:
        assert _classify_connection("connect ECONNREFUSED 127.0.0.1:8080") == "refused"

    def test_failed_to_establish(self) -> None:
        assert _classify_connection("Failed to establish a new connection") == "refused"

    def test_timeout(self) -> None:
        assert _classify_connection("ReadTimeout: request timed out") == "timeout"

    def test_connect_timeout(self) -> None:
        assert _classify_connection("ConnectTimeout: could not connect") == "timeout"

    def test_crash_connection_reset(self) -> None:
        assert _classify_connection("Connection reset by peer") == "crashed"

    def test_crash_remote_disconnected(self) -> None:
        assert _classify_connection("RemoteDisconnected: Remote end closed") == "crashed"

    def test_crash_broken_pipe(self) -> None:
        assert _classify_connection("BrokenPipeError: [Errno 32]") == "crashed"

    def test_healthy_with_http_status(self) -> None:
        assert _classify_connection("HTTP/1.1 200 OK") == "healthy"

    def test_healthy_with_clean_output(self) -> None:
        assert _classify_connection("some output data") == "healthy"

    def test_unknown_with_error_keyword(self) -> None:
        assert _classify_connection("error occurred") == "unknown"

    def test_empty_output(self) -> None:
        assert _classify_connection("") == "unknown"


class TestClassifyError:
    """Tests for _classify_error — uses connection status and LLM-assessed max_level."""

    def test_none_when_successful_high_level(self) -> None:
        result = _classify_error("", "healthy", 5)
        assert result == "none"

    def test_4xx_with_exploitation_is_partial_trigger(self) -> None:
        result = _classify_error("HTTP 400 Bad Request", "healthy", 1)
        assert result == "partial_trigger"

    def test_4xx_with_no_exploitation_is_wrong_payload(self) -> None:
        result = _classify_error("HTTP 400 Bad Request", "healthy", 0)
        assert result == "wrong_payload_format"

    def test_422_with_no_exploitation_is_wrong_payload(self) -> None:
        result = _classify_error("HTTP 422 Unprocessable Entity", "healthy", 0)
        assert result == "wrong_payload_format"

    def test_404_is_wrong_endpoint(self) -> None:
        result = _classify_error("HTTP 404 Not Found", "healthy", 0)
        assert result == "wrong_endpoint"

    def test_connection_refused(self) -> None:
        result = _classify_error("some output", "refused", 0)
        assert result == "connection_refused"

    def test_infrastructure_error_python_not_found(self) -> None:
        result = _classify_error("python: not found", "healthy", 0)
        assert result == "infrastructure"

    def test_infrastructure_error_oci_runtime(self) -> None:
        result = _classify_error("oci runtime error", "healthy", 0)
        assert result == "infrastructure"

    def test_partial_trigger_mid_level(self) -> None:
        result = _classify_error("some output", "healthy", 2)
        assert result == "partial_trigger"

    def test_fundamental_error_healthy_200(self) -> None:
        result = _classify_error("HTTP/1.1 200 OK", "healthy", 0)
        assert result == "fundamental"

    def test_timeout_treated_as_connection_refused(self) -> None:
        result = _classify_error("some output", "timeout", 0)
        assert result == "connection_refused"

    def test_crashed_treated_as_connection_refused(self) -> None:
        result = _classify_error("some output", "crashed", 0)
        assert result == "connection_refused"

    def test_l3_exploitation_is_none(self) -> None:
        """Full exploitation (L3) with no errors → none."""
        result = _classify_error("uid=0(root)", "healthy", 3)
        assert result == "none"


class TestAnalyzeResponse:
    def test_exploitation_detected(self) -> None:
        result = _analyze_response("some output", 3, "RCE confirmed")
        assert "L3" in result
        assert "RCE confirmed" in result

    def test_no_exploitation(self) -> None:
        result = _analyze_response("HTTP 200 OK", 0)
        assert "No exploitation" in result

    def test_http_status_codes_extracted(self) -> None:
        result = _analyze_response("HTTP/1.1 200 OK\nHTTP/1.1 500 Error", 0)
        assert "200" in result
        assert "500" in result

    def test_result_truncated(self) -> None:
        long_reason = "A" * 1000
        result = _analyze_response("output", 3, long_reason)
        assert len(result) <= 500


class TestSuggestFix:
    def test_connection_refused(self) -> None:
        result = _suggest_fix("connection_refused", "", None)
        assert result is not None
        assert "host" in result.lower() or "port" in result.lower()

    def test_wrong_endpoint(self) -> None:
        result = _suggest_fix("wrong_endpoint", "", None)
        assert result is not None
        assert "404" in result

    def test_wrong_payload_format(self) -> None:
        result = _suggest_fix("wrong_payload_format", "", None)
        assert result is not None
        assert "Content-Type" in result

    def test_infrastructure(self) -> None:
        result = _suggest_fix("infrastructure", "", None)
        assert result is not None

    def test_none_error_returns_none(self) -> None:
        result = _suggest_fix("none", "", None)
        assert result is None


class TestOracleConfig:
    """Verify oracle config loads correctly from oracle_patterns.yaml."""

    def test_aliases_loaded(self) -> None:
        assert _CWE_ALIASES.get("CWE-77") == "CWE-78"
        assert _CWE_ALIASES.get("CWE-80") == "CWE-79"
        assert _CWE_ALIASES.get("CWE-29") == "CWE-22"

    def test_cwe_evidence_loaded(self) -> None:
        assert "CWE-89" in _CWE_EVIDENCE
        assert "CWE-78" in _CWE_EVIDENCE
        assert len(_CWE_EVIDENCE) >= 10

    def test_cwe_evidence_has_indicators(self) -> None:
        entry = _CWE_EVIDENCE.get("CWE-89", {})
        assert "indicators" in entry
        assert isinstance(entry["indicators"], dict)

    def test_cwe_evidence_has_name(self) -> None:
        entry = _CWE_EVIDENCE.get("CWE-89", {})
        assert "name" in entry

    def test_level_caps_present(self) -> None:
        assert _CWE_LEVEL_CAPS["CWE-79"] == 2
        assert _CWE_LEVEL_CAPS["CWE-22"] == 2
        assert "CWE-78" not in _CWE_LEVEL_CAPS  # RCE not capped
