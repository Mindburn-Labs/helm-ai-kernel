"""
Tests for HELM LangChain adapter.

Covers: allow/deny policy decisions, receipt collection, receipt hashing,
fail-closed behavior, deny/receipt callbacks, HTTP error paths,
tool metadata preservation, multi-tool wrapping, evidence pack hashing.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from helm_langchain import (
    GovernedTool,
    HelmToolDenyError,
    HelmToolWrapper,
    HelmToolWrapperConfig,
    ToolCallDenial,
    ToolCallReceipt,
)


# ── Mock Helpers ────────────────────────────────────────


class MockTool:
    """A mock LangChain-compatible tool."""

    def __init__(self, name: str = "calculator", result: Any = "42"):
        self.name = name
        self.description = f"Mock {name} tool"
        self._result = result
        self._call_log: list[Any] = []

    def _run(self, **kwargs: Any) -> Any:
        self._call_log.append(kwargs)
        return self._result

    def invoke(self, input: Any, config: Any = None) -> Any:
        self._call_log.append(input)
        return self._result


class MockHelmServer:
    """Mocks HELM API responses for testing."""

    @staticmethod
    def approved_response(tool_name: str = "calculator") -> dict[str, Any]:
        return {
            "id": "helm-test-123",
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
            "id": "helm-denied-123",
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

    @staticmethod
    def empty_choices_response() -> dict[str, Any]:
        return {
            "id": "helm-empty-123",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "helm-governance",
            "choices": [],
        }


# ── Policy Allow ────────────────────────────────────────


class TestGovernedToolAllow:
    """Verify tool calls are allowed through when HELM approves."""

    def test_approved_tool_via_invoke(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool(name="calculator", result="42")
        governed = wrapper.wrap_tool(tool)

        result = governed.invoke({"expression": "6*7"})
        assert result == "42"
        assert len(wrapper.receipts) == 1
        assert wrapper.receipts[0].decision == "APPROVED"
        assert wrapper.receipts[0].tool_name == "calculator"

    def test_approved_tool_via_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool(name="search", result="found it")
        governed = wrapper.wrap_tool(tool)

        result = governed(query="test")
        assert result == "found it"

    def test_approved_tool_via_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool(name="calc", result="100")
        governed = wrapper.wrap_tool(tool)

        result = governed._run(x=10, y=10)
        assert result == "100"

    def test_invoke_with_string_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool(name="search", result="result")
        governed = wrapper.wrap_tool(tool)

        result = governed.invoke("query string")
        assert result == "result"


# ── Policy Deny ─────────────────────────────────────────


class TestGovernedToolDeny:
    """Verify tool calls are blocked when HELM denies."""

    def test_denied_tool_raises_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.denied_response(),
        )

        deny_callback = MagicMock()
        wrapper.on_deny(deny_callback)

        tool = MockTool(name="dangerous_tool")
        governed = wrapper.wrap_tool(tool)

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed.invoke({"action": "rm -rf /"})

        assert "DENY_POLICY_VIOLATION" in str(exc_info.value)
        deny_callback.assert_called_once()

    def test_denied_tool_does_not_execute_underlying(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.denied_response(),
        )

        tool = MockTool(name="blocked")
        governed = wrapper.wrap_tool(tool)

        with pytest.raises(HelmToolDenyError):
            governed.invoke({"action": "test"})

        assert len(tool._call_log) == 0

    def test_empty_choices_treated_as_deny(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.empty_choices_response(),
        )

        tool = MockTool(name="some_tool")
        governed = wrapper.wrap_tool(tool)

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed.invoke({"input": "test"})

        assert "DENY_POLICY_VIOLATION" in str(exc_info.value)

    def test_deny_callback_receives_denial_details(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.denied_response("DENY_EGRESS_BLOCKED"),
        )

        denials: list[ToolCallDenial] = []
        wrapper.on_deny(lambda d: denials.append(d))

        tool = MockTool(name="external_call")
        governed = wrapper.wrap_tool(tool)

        with pytest.raises(HelmToolDenyError):
            governed.invoke({"url": "http://evil.com"})

        assert len(denials) == 1
        assert denials[0].tool_name == "external_call"
        assert denials[0].reason_code == "DENY_POLICY_VIOLATION"


# ── Fail-Closed Behavior ───────────────────────────────


class TestFailClosed:
    """Verify fail-closed vs. fail-open behavior on HTTP errors."""

    def test_http_error_raises_in_fail_closed_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(
            config=HelmToolWrapperConfig(
                helm_url="http://localhost:8080", fail_closed=True
            )
        )

        def raise_error(name, args):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(wrapper, "_evaluate_intent", raise_error)

        tool = MockTool(name="any_tool")
        governed = wrapper.wrap_tool(tool)

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed.invoke({"input": "test"})

        assert exc_info.value.denial.reason_code == "ERROR_INTERNAL"

    def test_http_error_falls_through_when_not_fail_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(
            config=HelmToolWrapperConfig(
                helm_url="http://localhost:8080", fail_closed=False
            )
        )

        def raise_error(name, args):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(wrapper, "_evaluate_intent", raise_error)

        tool = MockTool(name="safe_tool", result="fallthrough result")
        governed = wrapper.wrap_tool(tool)

        result = governed.invoke({"input": "test"})
        assert result == "fallthrough result"


# ── Receipt Collection ──────────────────────────────────


class TestReceiptCollection:
    """Verify receipts are collected for approved calls."""

    def test_multiple_receipts_collected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        receipt_callback = MagicMock()
        wrapper.on_receipt(receipt_callback)

        tool = MockTool()
        governed = wrapper.wrap_tool(tool)
        governed.invoke({"x": 1})
        governed.invoke({"x": 2})

        assert len(wrapper.receipts) == 2
        assert receipt_callback.call_count == 2

        wrapper.clear_receipts()
        assert len(wrapper.receipts) == 0

    def test_receipt_fields_populated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool(name="search", result="found")
        governed = wrapper.wrap_tool(tool)
        governed.invoke({"query": "test"})

        receipt = wrapper.receipts[0]
        assert receipt.tool_name == "search"
        assert receipt.decision == "APPROVED"
        assert receipt.reason_code == "ALLOW"
        assert receipt.receipt_id == "helm-test-123"
        assert receipt.duration_ms >= 0
        assert receipt.request_hash.startswith("sha256:")
        assert receipt.output_hash.startswith("sha256:")

    def test_receipts_not_collected_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(
            config=HelmToolWrapperConfig(
                helm_url="http://localhost:8080", collect_receipts=False
            )
        )
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool()
        governed = wrapper.wrap_tool(tool)
        governed.invoke({"x": 1})

        assert len(wrapper.receipts) == 0


# ── Receipt Hashes ──────────────────────────────────────


class TestReceiptHashes:
    """Verify receipt request/output hashes are deterministic."""

    def test_same_args_same_hash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool(result="42")
        governed = wrapper.wrap_tool(tool)
        governed.invoke({"expression": "6*7"})
        governed.invoke({"expression": "6*7"})

        r1, r2 = wrapper.receipts
        assert r1.request_hash == r2.request_hash
        assert r1.output_hash == r2.output_hash
        assert r1.request_hash.startswith("sha256:")

    def test_different_args_different_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockTool()
        governed = wrapper.wrap_tool(tool)
        governed.invoke({"x": 1})
        governed.invoke({"x": 2})

        r1, r2 = wrapper.receipts
        assert r1.request_hash != r2.request_hash

    def test_different_results_different_output_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            wrapper,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool1 = MockTool(name="t", result="alpha")
        tool2 = MockTool(name="t", result="beta")
        gov1 = wrapper.wrap_tool(tool1)
        gov2 = wrapper.wrap_tool(tool2)
        gov1.invoke({"x": 1})
        gov2.invoke({"x": 1})

        r1, r2 = wrapper.receipts
        assert r1.output_hash != r2.output_hash


# ── Multi-Tool Wrapping ─────────────────────────────────


class TestWrapTools:
    """Verify wrap_tools wraps multiple tools correctly."""

    def test_wrap_tools_creates_governed_tools(self) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        tools = [MockTool("calc"), MockTool("search"), MockTool("write")]
        governed = wrapper.wrap_tools(tools)

        assert len(governed) == 3
        assert governed[0].name == "calc"
        assert governed[1].name == "search"
        assert governed[2].name == "write"
        for g in governed:
            assert isinstance(g, GovernedTool)


# ── Metadata Preservation ──────────────────────────────


class TestMetadataPreservation:
    """Verify GovernedTool preserves original tool metadata."""

    def test_preserves_name_and_description(self) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        tool = MockTool(name="my_tool")
        governed = wrapper.wrap_tool(tool)

        assert governed.name == "my_tool"
        assert governed.description == "Mock my_tool tool"
        assert governed._original is tool

    def test_preserves_args_schema(self) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")
        tool = MockTool(name="typed_tool")
        tool.args_schema = {"type": "object", "properties": {"x": {"type": "integer"}}}
        governed = wrapper.wrap_tool(tool)

        assert governed.args_schema == tool.args_schema


# ── HTTP 4xx Deny Path ──────────────────────────────────


class TestHttpErrorDeny:
    """Verify HELM 4xx responses produce proper denials."""

    def test_evaluate_intent_raises_on_4xx(self) -> None:
        wrapper = HelmToolWrapper(helm_url="http://localhost:8080")

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            "error": {
                "reason_code": "DENY_IDENTITY_MISMATCH",
                "message": "Principal not authorized for this tool",
            }
        }

        wrapper._client = MagicMock()
        wrapper._client.post.return_value = mock_response

        with pytest.raises(HelmToolDenyError) as exc_info:
            wrapper._evaluate_intent("admin_tool", {"action": "delete"})

        assert exc_info.value.denial.reason_code == "DENY_IDENTITY_MISMATCH"
        assert "Principal not authorized" in exc_info.value.denial.message


# ── Context Manager ─────────────────────────────────────


class TestContextManager:
    """Verify wrapper can be used as a context manager."""

    def test_context_manager_closes_client(self) -> None:
        with HelmToolWrapper(helm_url="http://localhost:8080") as wrapper:
            assert wrapper is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
