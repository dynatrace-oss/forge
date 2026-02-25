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

from forge.models import CWEModule, TokenUsage
from forge.oracle.inline_oracle import DefaultInlineOracle, summarize_turn
from forge.oracle.llm_critic import LLMOracleCritic
from forge.oracle.models import InlineOracleFeedback
from forge.sandbox.models import SandboxSnapshot


@pytest.fixture()
def empty_snapshot() -> SandboxSnapshot:
    return SandboxSnapshot()


@pytest.fixture()
def marker_snapshot() -> SandboxSnapshot:
    return SandboxSnapshot(files_created=["/tmp/pwned"])


def _cwe_module(cwe_id: str) -> CWEModule:
    """Build a minimal CWEModule for testing."""
    return CWEModule(
        cwe_id=cwe_id,
        cwe_name=f"Test {cwe_id}",
    )


def _mock_critic(
    level: int = 0, confidence: float = 0.5, reasoning: str = "test"
) -> LLMOracleCritic:
    """Build a LLMOracleCritic with a mocked LLM returning a fixed verdict."""
    mock_llm = AsyncMock()
    mock_llm.chat = AsyncMock(
        return_value=(
            f'{{"level": {level}, "confidence": {confidence}, "reasoning": "{reasoning}"}}',
            TokenUsage(
                prompt_tokens=100,
                completion_tokens=30,
                total_tokens=130,
                llm_calls=1,
            ),
        )
    )
    return LLMOracleCritic(llm=mock_llm, model="test")


class TestNoCritic:
    """DefaultInlineOracle with no LLM critic — returns L0, coaching works."""

    @pytest.mark.asyncio
    async def test_evaluates_clean_turn(self, empty_snapshot: SandboxSnapshot) -> None:
        oracle = DefaultInlineOracle()
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            'HTTP 200 OK\n{"status": "ok"}',
            None,
            turn=1,
            prior_level=0,
        )
        assert isinstance(feedback, InlineOracleFeedback)
        assert feedback.turn == 1
        assert feedback.exploitation_level == 0
        assert feedback.progress_delta == 0

    @pytest.mark.asyncio
    async def test_connection_refused(self, empty_snapshot: SandboxSnapshot) -> None:
        oracle = DefaultInlineOracle()
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "ConnectionRefusedError: [Errno 111] Connection refused",
            None,
            turn=1,
            prior_level=0,
        )
        assert feedback.connection_status == "refused"
        assert feedback.error_classification == "connection_refused"

    @pytest.mark.asyncio
    async def test_no_critic_always_l0(self, empty_snapshot: SandboxSnapshot) -> None:
        """Without a critic, LLM evaluation is skipped → always L0."""
        oracle = DefaultInlineOracle()
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root) gid=0(root) groups=0(root)",
            None,
            turn=3,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/rce"},
        )
        assert feedback.exploitation_level == 0

    @pytest.mark.asyncio
    async def test_no_tool_arguments_skips_critic(self, empty_snapshot: SandboxSnapshot) -> None:
        """If tool_arguments is None, the critic is NOT invoked."""
        critic = _mock_critic(level=3, confidence=0.9)
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root)",
            None,
            turn=3,
            prior_level=0,
            tool_name="http_request",
            # tool_arguments defaults to None
        )
        assert feedback.exploitation_level == 0


class TestWithCritic:
    """DefaultInlineOracle with mock LLM critic — verdict propagation."""

    @pytest.mark.asyncio
    async def test_llm_verdict_l3_propagated(self, empty_snapshot: SandboxSnapshot) -> None:
        critic = _mock_critic(level=3, confidence=0.9, reasoning="RCE confirmed")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root)",
            None,
            turn=3,
            prior_level=1,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/rce"},
        )
        assert feedback.exploitation_level == 3
        assert feedback.progress_delta == 2

    @pytest.mark.asyncio
    async def test_llm_verdict_produces_evidence(self, empty_snapshot: SandboxSnapshot) -> None:
        critic = _mock_critic(level=2, confidence=0.8, reasoning="data leak")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "sensitive data",
            None,
            turn=2,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/api"},
        )
        assert len(feedback.evidence) == 1
        assert feedback.evidence[0].level_match == 2
        assert "LLM oracle" in feedback.evidence[0].description

    @pytest.mark.asyncio
    async def test_llm_l0_no_evidence(self, empty_snapshot: SandboxSnapshot) -> None:
        critic = _mock_critic(level=0, confidence=0.9, reasoning="no exploit")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "HTTP 200 OK",
            None,
            turn=1,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/health"},
        )
        assert feedback.exploitation_level == 0
        assert len(feedback.evidence) == 0

    @pytest.mark.asyncio
    async def test_llm_called_with_app_source(self, empty_snapshot: SandboxSnapshot) -> None:
        """app_source parameter is forwarded to the critic."""
        mock_llm = AsyncMock()
        mock_llm.chat = AsyncMock(
            return_value=(
                '{"level": 0, "confidence": 0.5, "reasoning": "no exploit"}',
                TokenUsage(prompt_tokens=100, completion_tokens=30, total_tokens=130, llm_calls=1),
            )
        )
        critic = LLMOracleCritic(llm=mock_llm, model="test")
        oracle = DefaultInlineOracle(critic=critic)

        await oracle.evaluate_turn(
            empty_snapshot,
            "HTTP 200 OK",
            _cwe_module("CWE-89"),
            turn=1,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/api"},
            app_source="from flask import Flask\napp = Flask(__name__)",
        )

        # Verify the critic was called (LLM.chat was invoked)
        mock_llm.chat.assert_awaited_once()
        # System message should contain the app source
        call_args = mock_llm.chat.call_args
        messages = call_args[0][0]
        system_msg = messages[0].content
        assert "flask" in system_msg.lower() or "Flask" in system_msg


class TestCWELevelCaps:
    """CWE structural caps applied after LLM verdict."""

    @pytest.mark.asyncio
    async def test_xss_capped_at_l2(self, empty_snapshot: SandboxSnapshot) -> None:
        critic = _mock_critic(level=3, confidence=0.9, reasoning="XSS reflected")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "<script>alert(1)</script>",
            _cwe_module("CWE-79"),
            turn=2,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/xss"},
        )
        assert feedback.exploitation_level == 2
        # Evidence description should be annotated with cap
        assert any("capped" in e.description.lower() for e in feedback.evidence)

    @pytest.mark.asyncio
    async def test_path_traversal_capped_at_l2(self, empty_snapshot: SandboxSnapshot) -> None:
        critic = _mock_critic(level=3, confidence=0.9, reasoning="file read")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "/etc/passwd content",
            _cwe_module("CWE-22"),
            turn=2,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/../etc/passwd"},
        )
        assert feedback.exploitation_level == 2

    @pytest.mark.asyncio
    async def test_rce_not_capped(self, empty_snapshot: SandboxSnapshot) -> None:
        critic = _mock_critic(level=3, confidence=0.9, reasoning="RCE confirmed")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root)",
            _cwe_module("CWE-78"),
            turn=2,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/rce"},
        )
        assert feedback.exploitation_level == 3

    @pytest.mark.asyncio
    async def test_cwe80_alias_capped(self, empty_snapshot: SandboxSnapshot) -> None:
        """CWE-80 aliases to CWE-79 → capped at L2."""
        critic = _mock_critic(level=3, confidence=0.9)
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "XSS payload reflected",
            _cwe_module("CWE-80"),
            turn=2,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/xss"},
        )
        assert feedback.exploitation_level == 2

    @pytest.mark.asyncio
    async def test_dos_capped_at_l2(self, empty_snapshot: SandboxSnapshot) -> None:
        critic = _mock_critic(level=3, confidence=0.9, reasoning="service crashed")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "server crashed",
            _cwe_module("CWE-400"),
            turn=2,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/dos"},
        )
        assert feedback.exploitation_level == 2


class TestToolLevelCaps:
    """Tool-level caps for sandbox false-positive mitigation."""

    @pytest.mark.asyncio
    async def test_read_file_capped_at_l1(self, empty_snapshot: SandboxSnapshot) -> None:
        """read_file returning /etc/passwd → capped at L1 (container runs as root)."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="passwd content")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            None,
            turn=2,
            prior_level=0,
            tool_name="read_file",
            tool_arguments={"path": "/etc/passwd"},
        )
        assert feedback.exploitation_level <= 1

    @pytest.mark.asyncio
    async def test_read_file_marker_not_capped(self, marker_snapshot: SandboxSnapshot) -> None:
        """read_file of exploit-created marker → NOT capped (Bug B fix)."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="RCE output")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            marker_snapshot,
            "uid=0(root) gid=0(root) groups=0(root)",
            None,
            turn=5,
            prior_level=1,
            tool_name="read_file",
            tool_arguments={"path": "/tmp/pwned"},
        )
        assert feedback.exploitation_level >= 3

    @pytest.mark.asyncio
    async def test_exec_command_sandbox_capped_at_l1(self, empty_snapshot: SandboxSnapshot) -> None:
        """exec_command running 'id' → capped at L1 (not target-facing)."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="root shell")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root) gid=0(root) groups=0(root)",
            None,
            turn=4,
            prior_level=3,
            tool_name="exec_command",
            tool_arguments={"command": "id"},
        )
        assert feedback.exploitation_level <= 1

    @pytest.mark.asyncio
    async def test_exec_command_curl_preserves_level(self, empty_snapshot: SandboxSnapshot) -> None:
        """exec_command with curl → NOT capped (target-facing)."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="RCE via curl")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root) gid=0(root) groups=0(root)",
            None,
            turn=4,
            prior_level=3,
            tool_name="exec_command",
            tool_arguments={"command": "curl http://target:8080/rce?cmd=id"},
        )
        assert feedback.exploitation_level >= 3

    @pytest.mark.asyncio
    async def test_exec_command_wget_not_capped(self, empty_snapshot: SandboxSnapshot) -> None:
        """exec_command with wget → NOT capped (target-facing)."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="RCE via wget")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "exploit output",
            None,
            turn=4,
            prior_level=1,
            tool_name="exec_command",
            tool_arguments={"command": "wget http://target:8080/rce"},
        )
        assert feedback.exploitation_level >= 3

    @pytest.mark.asyncio
    async def test_run_exploit_script_with_requests_not_capped(
        self, empty_snapshot: SandboxSnapshot
    ) -> None:
        """run_exploit_script using requests library → NOT capped (Bug A fix)."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="RCE via script")
        oracle = DefaultInlineOracle(critic=critic)
        script = "import requests\nr = requests.get('http://target:8080/rce')\nprint(r.text)\n"
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root) gid=0(root) groups=0(root)\nRCE confirmed",
            None,
            turn=4,
            prior_level=1,
            tool_name="run_exploit_script",
            tool_arguments={"script": script},
        )
        assert feedback.exploitation_level >= 3

    @pytest.mark.asyncio
    async def test_run_exploit_script_no_network_capped(
        self, empty_snapshot: SandboxSnapshot
    ) -> None:
        """run_exploit_script with no HTTP libraries → capped at L1."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="local command")
        oracle = DefaultInlineOracle(critic=critic)
        script = "import os\nprint(os.popen('id').read())\n"
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root) gid=0(root) groups=0(root)",
            None,
            turn=4,
            prior_level=1,
            tool_name="run_exploit_script",
            tool_arguments={"script": script},
        )
        assert feedback.exploitation_level <= 1

    @pytest.mark.asyncio
    async def test_run_exploit_script_httpx_not_capped(
        self, empty_snapshot: SandboxSnapshot
    ) -> None:
        """run_exploit_script using httpx → NOT capped."""
        critic = _mock_critic(level=3, confidence=0.9)
        oracle = DefaultInlineOracle(critic=critic)
        script = "import httpx\nr = httpx.get('http://target:8080/api')\n"
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "exploit output",
            None,
            turn=4,
            prior_level=1,
            tool_name="run_exploit_script",
            tool_arguments={"script": script},
        )
        assert feedback.exploitation_level >= 3

    @pytest.mark.asyncio
    async def test_http_request_tool_not_capped(self, empty_snapshot: SandboxSnapshot) -> None:
        """http_request tool has no tool-level cap — verdict flows through."""
        critic = _mock_critic(level=3, confidence=0.9, reasoning="RCE confirmed")
        oracle = DefaultInlineOracle(critic=critic)
        feedback = await oracle.evaluate_turn(
            empty_snapshot,
            "uid=0(root)",
            None,
            turn=3,
            prior_level=0,
            tool_name="http_request",
            tool_arguments={"url": "http://target:8080/rce", "method": "POST"},
        )
        assert feedback.exploitation_level == 3


class TestSummarizeTurn:
    def test_http_request_summary(self) -> None:
        feedback = InlineOracleFeedback(turn=1, exploitation_level=0)
        result = summarize_turn(
            "http_request",
            {"method": "GET", "url": "http://target:8080/api/health"},
            "HTTP/1.1 200 OK",
            feedback,
        )
        assert "[http_request]" in result
        assert "GET" in result
        assert "L0" in result

    def test_exec_command_summary(self) -> None:
        feedback = InlineOracleFeedback(turn=2, exploitation_level=1)
        result = summarize_turn(
            "exec_command",
            {"command": "whoami"},
            "root",
            feedback,
        )
        assert "[exec_command]" in result
        assert "whoami" in result
        assert "L1" in result

    def test_read_file_summary(self) -> None:
        feedback = InlineOracleFeedback(turn=3, exploitation_level=0)
        result = summarize_turn(
            "read_file",
            {"path": "/etc/passwd"},
            "root:x:0:0:...",
            feedback,
        )
        assert "[read_file]" in result
        assert "/etc/passwd" in result

    def test_run_exploit_script_summary(self) -> None:
        feedback = InlineOracleFeedback(turn=4, exploitation_level=3)
        result = summarize_turn(
            "run_exploit_script",
            {"script": "import requests\n..."},
            "uid=0(root)",
            feedback,
        )
        assert "[run_exploit_script]" in result
        assert "L3" in result

    def test_get_app_logs_summary(self) -> None:
        feedback = InlineOracleFeedback(turn=5, exploitation_level=0)
        result = summarize_turn(
            "get_app_logs",
            {},
            "Error: segfault at 0x0000",
            feedback,
        )
        assert "[get_app_logs]" in result

    def test_summary_truncated_to_300(self) -> None:
        feedback = InlineOracleFeedback(turn=1, exploitation_level=0)
        result = summarize_turn(
            "http_request",
            {"method": "GET", "url": "http://target:8080/" + "a" * 500},
            "HTTP/1.1 200 OK",
            feedback,
        )
        assert len(result) <= 300

    def test_error_classification_in_summary(self) -> None:
        feedback = InlineOracleFeedback(
            turn=1, exploitation_level=0, error_classification="connection_refused"
        )
        result = summarize_turn(
            "http_request",
            {"method": "GET", "url": "http://target:8080/api"},
            "ConnectionRefusedError",
            feedback,
        )
        assert "err:connection_refused" in result

    def test_suggested_fix_in_summary(self) -> None:
        feedback = InlineOracleFeedback(
            turn=1,
            exploitation_level=0,
            error_classification="wrong_endpoint",
            suggested_fix="Check the endpoint path",
        )
        result = summarize_turn(
            "http_request",
            {"method": "GET", "url": "http://target:8080/bad"},
            "HTTP 404 Not Found",
            feedback,
        )
        assert "fix:" in result
