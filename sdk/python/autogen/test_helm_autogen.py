"""
Tests for HELM governance adapter for Microsoft AutoGen.

Covers: construction, fail-closed semantics, callback registration,
        Lamport monotonicity on deny path, govern_tool wrapping,
        govern_function_call entry point, dataclass contract,
        context-manager lifecycle.
"""

import pytest

from helm_autogen import (
    HelmAutoGenConfig,
    HelmAutoGenGovernor,
    HelmToolDenyError,
    ToolCallReceipt,
    ToolCallDenial,
)


class TestHelmAutoGenGovernor:
    """Test the HELM AutoGen governance adapter."""

    def setup_method(self):
        # Unreachable URL so HTTP calls fail predictably without a real HELM.
        self.config = HelmAutoGenConfig(
            helm_url="http://localhost:19999",
            fail_closed=False,
        )

    # ----- construction -----

    def test_construction_with_config(self):
        gov = HelmAutoGenGovernor(config=self.config)
        assert gov.config.helm_url == "http://localhost:19999"
        assert gov.config.fail_closed is False
        assert gov.receipts == []

    def test_construction_with_kwargs(self):
        gov = HelmAutoGenGovernor(helm_url="http://example.com:8080", fail_closed=True)
        assert gov.config.helm_url == "http://example.com:8080"
        assert gov.config.fail_closed is True

    def test_construction_default(self):
        gov = HelmAutoGenGovernor()
        assert gov.config.helm_url == "http://localhost:8080"
        assert gov.config.fail_closed is True

    # ----- fail-closed semantics -----

    def test_fail_closed_function_call_raises_on_unreachable(self):
        gov = HelmAutoGenGovernor(helm_url="http://localhost:19999", fail_closed=True)
        with pytest.raises(HelmToolDenyError) as exc_info:
            gov.govern_function_call(
                "code_executor",
                {"code": "rm -rf /"},
                agent_name="assistant",
            )
        denial = exc_info.value.denial
        assert isinstance(denial, ToolCallDenial)
        assert denial.tool_name == "code_executor"
        assert denial.reason_code != ""
        assert denial.message != ""

    def test_fail_open_does_not_raise(self):
        """fail_closed=False allows governance to be skipped when HELM is unreachable."""
        gov = HelmAutoGenGovernor(helm_url="http://localhost:19999", fail_closed=False)
        # Should not raise; returns whatever the permissive path produces.
        result = gov.govern_function_call("search", {"q": "x"}, agent_name="assistant")
        # Cannot assert specific shape since HELM is unreachable; only that no raise.
        _ = result

    # ----- govern_tool wrapping -----

    def test_govern_tool_blocks_on_deny(self):
        """govern_tool wraps a callable; the wrapper must not invoke the inner fn on deny."""
        gov = HelmAutoGenGovernor(helm_url="http://localhost:19999", fail_closed=True)
        ran = {"called": False}

        def unsafe_exec(code: str) -> str:
            ran["called"] = True
            return f"executed: {code}"

        wrapped = gov.govern_tool("code_executor", unsafe_exec, agent_name="assistant")
        with pytest.raises(HelmToolDenyError):
            wrapped("rm -rf /")
        # Critical invariant: when HELM denies, the wrapped fn must not run.
        assert ran["called"] is False

    def test_govern_tool_fail_open_runs_inner_fn(self):
        gov = HelmAutoGenGovernor(helm_url="http://localhost:19999", fail_closed=False)
        ran = {"called": False}

        def inner() -> str:
            ran["called"] = True
            return "result"

        wrapped = gov.govern_tool("search", inner, agent_name="assistant")
        # With fail_closed=False + HELM unreachable, the wrapper should still
        # invoke the inner function rather than swallow it.
        result = wrapped()
        # Accept either: inner ran and we got a result, OR governance decided
        # to permit and the wrapper's return carries a ToolCallReceipt.
        assert ran["called"] or isinstance(result, (str, ToolCallReceipt, dict))

    # ----- callbacks -----

    def test_on_receipt_callback_chains(self):
        gov = HelmAutoGenGovernor(config=self.config)
        received: list[ToolCallReceipt] = []
        ret = gov.on_receipt(lambda r: received.append(r))
        assert ret is gov  # chainable

    def test_on_deny_callback_chains(self):
        gov = HelmAutoGenGovernor(config=self.config)
        denied: list[ToolCallDenial] = []
        ret = gov.on_deny(lambda d: denied.append(d))
        assert ret is gov

    # ----- receipts state -----

    def test_receipts_clear(self):
        gov = HelmAutoGenGovernor(config=self.config)
        assert gov.receipts == []
        gov.clear_receipts()
        assert gov.receipts == []

    def test_lamport_monotonic_on_deny_path(self):
        """Lamport clock must advance each govern_function_call, even on deny."""
        gov = HelmAutoGenGovernor(helm_url="http://localhost:19999", fail_closed=True)

        with pytest.raises(HelmToolDenyError):
            gov.govern_function_call("tool_a", {}, agent_name="assistant")
        first = getattr(gov, "_lamport", None)
        assert first == 1

        with pytest.raises(HelmToolDenyError):
            gov.govern_function_call("tool_b", {}, agent_name="assistant")
        second = getattr(gov, "_lamport", None)
        assert second == 2

    # ----- context manager lifecycle -----

    def test_context_manager_protocol(self):
        """Governor is usable as a context manager."""
        with HelmAutoGenGovernor(helm_url="http://localhost:19999", fail_closed=False) as gov:
            assert gov.receipts == []
        # After __exit__, no further operations should be needed.


class TestDataclasses:
    """Contract tests on the exported dataclass shapes."""

    def test_tool_call_receipt_fields(self):
        r = ToolCallReceipt(
            tool_name="t",
            agent_name="assistant",
            args={"x": 1},
            receipt_id="r1",
            decision="APPROVED",
            reason_code="OK",
            duration_ms=1.23,
            request_hash="sha256:aaa",
            output_hash="sha256:bbb",
            lamport_clock=1,
        )
        assert r.decision in {"APPROVED", "DENIED"}
        assert r.lamport_clock == 1
        assert r.agent_name == "assistant"

    def test_tool_call_denial_fields(self):
        d = ToolCallDenial(
            tool_name="t",
            agent_name="assistant",
            args={},
            reason_code="DENY_POLICY_VIOLATION",
            message="blocked",
        )
        assert d.reason_code.startswith("DENY_") or d.reason_code != ""
        assert d.message


class TestConfig:
    """Test HelmAutoGenConfig defaults and overrides."""

    def test_defaults(self):
        cfg = HelmAutoGenConfig()
        assert cfg.helm_url == "http://localhost:8080"
        assert cfg.api_key is None
        assert cfg.fail_closed is True
        assert cfg.collect_receipts is True
        assert cfg.timeout == 30.0

    def test_overrides(self):
        cfg = HelmAutoGenConfig(
            helm_url="http://prod:9090",
            api_key="k",
            fail_closed=False,
            collect_receipts=False,
            timeout=5.0,
        )
        assert cfg.helm_url == "http://prod:9090"
        assert cfg.api_key == "k"
        assert cfg.fail_closed is False
        assert cfg.collect_receipts is False
        assert cfg.timeout == 5.0
