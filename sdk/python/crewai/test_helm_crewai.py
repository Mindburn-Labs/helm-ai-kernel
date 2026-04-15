"""
Tests for HELM CrewAI adapter.

Covers: allow/deny policy decisions, receipt collection, receipt hashing,
per-agent governance, fail-closed behavior, deny callback, evidence pack
generation, multi-tool crew governance.
"""

from __future__ import annotations

import json
import threading
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from helm_crewai import (
    GovernedCrewTool,
    HelmCrewConfig,
    HelmCrewGovernor,
    HelmToolDenyError,
    ToolCallDenial,
    ToolCallReceipt,
)


# ── Mock Helpers ────────────────────────────────────────


class MockCrewTool:
    """A mock CrewAI-compatible tool."""

    def __init__(self, name: str = "web_search", result: Any = "search result"):
        self.name = name
        self.description = f"Mock {name} tool for testing"
        self._result = result
        self._call_log: list[dict] = []

    def _run(self, **kwargs: Any) -> Any:
        self._call_log.append(kwargs)
        return self._result


class MockHelmServer:
    """Mocks HELM API responses for governance testing."""

    @staticmethod
    def approved_response(tool_name: str = "web_search") -> dict[str, Any]:
        return {
            "id": "helm-crewai-test-001",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "helm-governance",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": tool_name,
                                    "arguments": "{}",
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }

    @staticmethod
    def denied_response(reason: str = "DENY_POLICY_VIOLATION") -> dict[str, Any]:
        return {
            "id": "helm-crewai-denied-001",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "helm-governance",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Denied: {reason}",
                    },
                    "finish_reason": "stop",
                }
            ],
        }


# ── Policy Allow/Deny ──────────────────────────────────


class TestGovernedCrewToolAllow:
    """Verify tool calls are allowed through when HELM approves."""

    def test_approved_tool_executes_and_returns_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool(name="web_search", result="Paris is the capital of France")
        governed = governor.govern_tool(tool, agent_role="researcher")

        result = governed(query="capital of France")
        assert result == "Paris is the capital of France"

    def test_approved_tool_via_run_method(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool(name="calculator", result="42")
        governed = governor.govern_tool(tool, agent_role="math_agent")

        result = governed._run(expression="6*7")
        assert result == "42"

    def test_approved_call_forwards_kwargs_to_underlying_tool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool(name="api_call")
        governed = governor.govern_tool(tool, agent_role="ops_agent")
        governed(url="https://api.example.com", method="GET")

        assert len(tool._call_log) == 1
        assert tool._call_log[0]["url"] == "https://api.example.com"
        assert tool._call_log[0]["method"] == "GET"


class TestGovernedCrewToolDeny:
    """Verify tool calls are blocked when HELM denies."""

    def test_denied_tool_raises_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.denied_response(),
        )

        tool = MockCrewTool(name="file_delete")
        governed = governor.govern_tool(tool, agent_role="admin")

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed(path="/etc/passwd")

        assert "DENY_POLICY_VIOLATION" in str(exc_info.value)
        assert exc_info.value.denial.tool_name == "file_delete"
        assert exc_info.value.denial.agent_role == "admin"

    def test_denied_tool_does_not_execute_underlying(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.denied_response(),
        )

        tool = MockCrewTool(name="dangerous_op")
        governed = governor.govern_tool(tool, agent_role="untrusted")

        with pytest.raises(HelmToolDenyError):
            governed(action="rm -rf /")

        assert len(tool._call_log) == 0, "Underlying tool must not be called on deny"

    def test_deny_callback_invoked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.denied_response(),
        )

        deny_cb = MagicMock()
        governor.on_deny(deny_cb)

        tool = MockCrewTool(name="blocked_tool")
        governed = governor.govern_tool(tool, agent_role="agent_x")

        with pytest.raises(HelmToolDenyError):
            governed(input="test")

        deny_cb.assert_called_once()
        denial_arg = deny_cb.call_args[0][0]
        assert isinstance(denial_arg, ToolCallDenial)
        assert denial_arg.tool_name == "blocked_tool"
        assert denial_arg.agent_role == "agent_x"

    def test_http_error_returns_deny_in_fail_closed_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080", fail_closed=True)
        governor = HelmCrewGovernor(config=config)

        def raise_http_error(name, role, args):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(governor, "_evaluate_intent", raise_http_error)

        tool = MockCrewTool(name="any_tool")
        governed = governor.govern_tool(tool, agent_role="agent")

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed(input="test")

        assert exc_info.value.denial.reason_code == "ERROR_INTERNAL"

    def test_http_error_falls_through_when_not_fail_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080", fail_closed=False)
        governor = HelmCrewGovernor(config=config)

        def raise_http_error(name, role, args):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(governor, "_evaluate_intent", raise_http_error)

        tool = MockCrewTool(name="safe_tool", result="fallthrough")
        governed = governor.govern_tool(tool, agent_role="agent")

        result = governed(input="test")
        assert result == "fallthrough"


# ── Receipt Collection ──────────────────────────────────


class TestReceiptCollection:
    """Verify receipts are collected, hashed, and can be cleared."""

    def test_receipts_collected_for_approved_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool()
        governed = governor.govern_tool(tool, agent_role="agent")
        governed(x=1)
        governed(x=2)
        governed(x=3)

        assert len(governor.receipts) == 3
        for r in governor.receipts:
            assert r.decision == "APPROVED"
            assert r.reason_code == "ALLOW"
            assert r.agent_role == "agent"

    def test_receipt_callback_invoked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        receipt_cb = MagicMock()
        governor.on_receipt(receipt_cb)

        tool = MockCrewTool()
        governed = governor.govern_tool(tool, agent_role="agent")
        governed(x=1)
        governed(x=2)

        assert receipt_cb.call_count == 2
        receipt_arg = receipt_cb.call_args[0][0]
        assert isinstance(receipt_arg, ToolCallReceipt)

    def test_clear_receipts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool()
        governed = governor.govern_tool(tool, agent_role="agent")
        governed(x=1)
        governed(x=2)

        assert len(governor.receipts) == 2
        governor.clear_receipts()
        assert len(governor.receipts) == 0

    def test_receipts_not_collected_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080", collect_receipts=False)
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool()
        governed = governor.govern_tool(tool, agent_role="agent")
        governed(x=1)

        assert len(governor.receipts) == 0


# ── Receipt Hashing ─────────────────────────────────────


class TestReceiptHashes:
    """Verify SHA-256 hashes in receipts are deterministic."""

    def test_same_args_produce_same_request_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool(result="42")
        governed = governor.govern_tool(tool, agent_role="agent")
        governed(expression="6*7")
        governed(expression="6*7")

        r1, r2 = governor.receipts
        assert r1.request_hash == r2.request_hash
        assert r1.request_hash.startswith("sha256:")

    def test_same_result_produce_same_output_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool(result="constant")
        governed = governor.govern_tool(tool, agent_role="agent")
        governed(a=1)
        governed(b=2)

        r1, r2 = governor.receipts
        assert r1.output_hash == r2.output_hash
        assert r1.output_hash.startswith("sha256:")

    def test_different_args_produce_different_request_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        tool = MockCrewTool()
        governed = governor.govern_tool(tool, agent_role="agent")
        governed(x=1)
        governed(x=2)

        r1, r2 = governor.receipts
        assert r1.request_hash != r2.request_hash


# ── Per-Agent Governance ────────────────────────────────


class TestPerAgentGovernance:
    """Verify agent_role is tracked per governed tool."""

    def test_agent_role_preserved_in_receipt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, role, args: MockHelmServer.approved_response(name),
        )

        researcher_tool = MockCrewTool(name="search")
        writer_tool = MockCrewTool(name="write")

        gov_researcher = governor.govern_tool(researcher_tool, agent_role="researcher")
        gov_writer = governor.govern_tool(writer_tool, agent_role="writer")

        gov_researcher(query="test")
        gov_writer(content="article")

        receipts = governor.receipts
        assert receipts[0].agent_role == "researcher"
        assert receipts[0].tool_name == "search"
        assert receipts[1].agent_role == "writer"
        assert receipts[1].tool_name == "write"


# ── Multi-Tool Crew Governance ──────────────────────────


class TestCrewGovernance:
    """Verify govern_tools wraps multiple tools correctly."""

    def test_govern_tools_wraps_all_tools(self) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)

        tools = [
            MockCrewTool("search"),
            MockCrewTool("calculator"),
            MockCrewTool("file_reader"),
        ]
        governed = governor.govern_tools(tools, agent_role="analyst")

        assert len(governed) == 3
        assert governed[0].name == "search"
        assert governed[1].name == "calculator"
        assert governed[2].name == "file_reader"
        for g in governed:
            assert isinstance(g, GovernedCrewTool)

    def test_governed_tool_preserves_metadata(self) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)

        tool = MockCrewTool(name="my_tool")
        governed = governor.govern_tool(tool, agent_role="agent")

        assert governed.name == "my_tool"
        assert governed.description == "Mock my_tool tool for testing"
        assert governed._original is tool


# ── Context Manager ─────────────────────────────────────


class TestContextManager:
    """Verify governor can be used as a context manager."""

    def test_context_manager_closes_client(self) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        with HelmCrewGovernor(config=config) as governor:
            assert governor is not None
        # Client is closed after exit; no assertion needed beyond no error.


# ── HTTP 4xx Deny Path ──────────────────────────────────


class TestHttpErrorDeny:
    """Verify HELM 4xx responses produce proper denials."""

    def test_evaluate_intent_raises_on_4xx(self) -> None:
        config = HelmCrewConfig(helm_url="http://localhost:8080")
        governor = HelmCrewGovernor(config=config)

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            "error": {
                "reason_code": "DENY_EGRESS_BLOCKED",
                "message": "Egress to external API is blocked by policy",
            }
        }

        governor._client = MagicMock()
        governor._client.post.return_value = mock_response

        with pytest.raises(HelmToolDenyError) as exc_info:
            governor._evaluate_intent("external_api", "agent", {"url": "http://evil.com"})

        assert exc_info.value.denial.reason_code == "DENY_EGRESS_BLOCKED"
        assert "Egress to external API is blocked" in exc_info.value.denial.message


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
