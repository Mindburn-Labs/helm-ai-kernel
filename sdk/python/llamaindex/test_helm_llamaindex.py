"""
Tests for HELM LlamaIndex adapter.

Covers: allow/deny policy decisions, receipt collection, receipt hashing,
fail-closed behavior, deny/receipt callbacks, tool metadata preservation,
LlamaIndex-specific call() interface, query engine tool governance,
evidence pack generation.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from helm_llamaindex import (
    GovernedLlamaIndexTool,
    HelmLlamaIndexConfig,
    HelmToolDenyError,
    HelmToolGovernor,
    ToolCallDenial,
    ToolCallReceipt,
)


# ── Mock Helpers ────────────────────────────────────────


class MockToolMetadata:
    """Mimics LlamaIndex ToolMetadata."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description


class MockLlamaIndexTool:
    """A mock LlamaIndex-compatible tool (like FunctionTool)."""

    def __init__(
        self,
        name: str = "search_tool",
        description: str = "Searches documents",
        result: Any = "found document",
    ):
        self.metadata = MockToolMetadata(name, description)
        self._result = result
        self._call_log: list[dict] = []

    def call(self, **kwargs: Any) -> Any:
        self._call_log.append(kwargs)
        return self._result


class MockQueryEngineTool:
    """A mock LlamaIndex QueryEngineTool (uses call() interface)."""

    def __init__(
        self,
        name: str = "query_engine",
        description: str = "Queries the index",
        result: Any = "query result",
    ):
        self.metadata = MockToolMetadata(name, description)
        self._result = result
        self._call_log: list[dict] = []

    def call(self, **kwargs: Any) -> Any:
        self._call_log.append(kwargs)
        return self._result


class MockCallableTool:
    """A mock tool that uses __call__ instead of call()."""

    def __init__(self, name: str = "callable_tool", result: Any = "callable result"):
        self.name = name
        self.description = f"Mock {name}"
        self.metadata = None
        self._result = result
        self._call_log: list[Any] = []

    def __call__(self, **kwargs: Any) -> Any:
        self._call_log.append(kwargs)
        return self._result


class MockHelmServer:
    """Mocks HELM API responses for governance testing."""

    @staticmethod
    def approved_response(tool_name: str = "search_tool") -> dict[str, Any]:
        return {
            "id": "helm-llama-test-001",
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
            "id": "helm-llama-denied-001",
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
            "id": "helm-llama-empty-001",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "helm-governance",
            "choices": [],
        }


# ── Policy Allow ────────────────────────────────────────


class TestGovernedToolAllow:
    """Verify tool calls are allowed through when HELM approves."""

    def test_approved_function_tool_via_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool(name="search", result="Paris is the capital")
        governed = governor.govern_tool(tool)

        result = governed.call(query="capital of France")
        assert result == "Paris is the capital"

    def test_approved_tool_via_direct_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool(name="lookup", result="found")
        governed = governor.govern_tool(tool)

        result = governed(query="test")
        assert result == "found"

    def test_approved_query_engine_tool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockQueryEngineTool(
            name="doc_query", result="The answer is 42"
        )
        governed = governor.govern_tool(tool)

        result = governed.call(input="What is the answer?")
        assert result == "The answer is 42"

    def test_approved_call_forwards_kwargs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool(name="api_tool")
        governed = governor.govern_tool(tool)
        governed.call(url="https://api.example.com", method="GET")

        assert len(tool._call_log) == 1
        assert tool._call_log[0]["url"] == "https://api.example.com"

    def test_callable_tool_without_call_method(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockCallableTool(name="fn_tool", result="callable ok")
        governed = governor.govern_tool(tool)

        result = governed.call(x=1)
        assert result == "callable ok"


# ── Policy Deny ─────────────────────────────────────────


class TestGovernedToolDeny:
    """Verify tool calls are blocked when HELM denies."""

    def test_denied_tool_raises_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.denied_response(),
        )

        tool = MockLlamaIndexTool(name="file_write")
        governed = governor.govern_tool(tool)

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed.call(path="/etc/passwd", content="hacked")

        assert "DENY_POLICY_VIOLATION" in str(exc_info.value)
        assert exc_info.value.denial.tool_name == "file_write"

    def test_denied_tool_does_not_execute_underlying(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.denied_response(),
        )

        tool = MockLlamaIndexTool(name="dangerous")
        governed = governor.govern_tool(tool)

        with pytest.raises(HelmToolDenyError):
            governed.call(action="rm -rf /")

        assert len(tool._call_log) == 0, "Underlying tool must not execute on deny"

    def test_empty_choices_treated_as_deny(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.empty_choices_response(),
        )

        tool = MockLlamaIndexTool(name="any_tool")
        governed = governor.govern_tool(tool)

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed.call(input="test")

        assert exc_info.value.denial.reason_code == "DENY_POLICY_VIOLATION"

    def test_deny_callback_invoked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.denied_response(),
        )

        deny_cb = MagicMock()
        governor.on_deny(deny_cb)

        tool = MockLlamaIndexTool(name="blocked_tool")
        governed = governor.govern_tool(tool)

        with pytest.raises(HelmToolDenyError):
            governed.call(input="test")

        deny_cb.assert_called_once()
        denial_arg = deny_cb.call_args[0][0]
        assert isinstance(denial_arg, ToolCallDenial)
        assert denial_arg.tool_name == "blocked_tool"


# ── Fail-Closed Behavior ───────────────────────────────


class TestFailClosed:
    """Verify fail-closed vs. fail-open on HTTP errors."""

    def test_http_error_raises_in_fail_closed_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(
            config=HelmLlamaIndexConfig(
                helm_url="http://localhost:8080", fail_closed=True
            )
        )

        def raise_error(name, args):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(governor, "_evaluate_intent", raise_error)

        tool = MockLlamaIndexTool(name="any_tool")
        governed = governor.govern_tool(tool)

        with pytest.raises(HelmToolDenyError) as exc_info:
            governed.call(input="test")

        assert exc_info.value.denial.reason_code == "ERROR_INTERNAL"

    def test_http_error_falls_through_when_not_fail_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(
            config=HelmLlamaIndexConfig(
                helm_url="http://localhost:8080", fail_closed=False
            )
        )

        def raise_error(name, args):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(governor, "_evaluate_intent", raise_error)

        tool = MockLlamaIndexTool(name="safe_tool", result="fallthrough")
        governed = governor.govern_tool(tool)

        result = governed.call(input="test")
        assert result == "fallthrough"

    def test_callable_tool_falls_through_when_not_fail_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(
            config=HelmLlamaIndexConfig(
                helm_url="http://localhost:8080", fail_closed=False
            )
        )

        def raise_error(name, args):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(governor, "_evaluate_intent", raise_error)

        tool = MockCallableTool(name="fn_tool", result="ok")
        governed = governor.govern_tool(tool)

        result = governed.call(x=1)
        assert result == "ok"


# ── Receipt Collection ──────────────────────────────────


class TestReceiptCollection:
    """Verify receipts are collected for approved calls."""

    def test_receipts_collected_for_approved_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool()
        governed = governor.govern_tool(tool)
        governed.call(x=1)
        governed.call(x=2)
        governed.call(x=3)

        assert len(governor.receipts) == 3
        for r in governor.receipts:
            assert r.decision == "APPROVED"
            assert r.reason_code == "ALLOW"

    def test_receipt_callback_invoked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        receipt_cb = MagicMock()
        governor.on_receipt(receipt_cb)

        tool = MockLlamaIndexTool()
        governed = governor.govern_tool(tool)
        governed.call(x=1)
        governed.call(x=2)

        assert receipt_cb.call_count == 2
        receipt_arg = receipt_cb.call_args[0][0]
        assert isinstance(receipt_arg, ToolCallReceipt)

    def test_clear_receipts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool()
        governed = governor.govern_tool(tool)
        governed.call(x=1)
        governed.call(x=2)

        assert len(governor.receipts) == 2
        governor.clear_receipts()
        assert len(governor.receipts) == 0

    def test_receipts_not_collected_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(
            config=HelmLlamaIndexConfig(
                helm_url="http://localhost:8080", collect_receipts=False
            )
        )
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool()
        governed = governor.govern_tool(tool)
        governed.call(x=1)

        assert len(governor.receipts) == 0

    def test_receipt_fields_populated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool(name="doc_search", result="found")
        governed = governor.govern_tool(tool)
        governed.call(query="test")

        receipt = governor.receipts[0]
        assert receipt.tool_name == "doc_search"
        assert receipt.decision == "APPROVED"
        assert receipt.reason_code == "ALLOW"
        assert receipt.receipt_id == "helm-llama-test-001"
        assert receipt.duration_ms >= 0
        assert receipt.request_hash.startswith("sha256:")
        assert receipt.output_hash.startswith("sha256:")


# ── Receipt Hashes ──────────────────────────────────────


class TestReceiptHashes:
    """Verify SHA-256 hashes in receipts are deterministic."""

    def test_same_args_produce_same_request_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool(result="42")
        governed = governor.govern_tool(tool)
        governed.call(expression="6*7")
        governed.call(expression="6*7")

        r1, r2 = governor.receipts
        assert r1.request_hash == r2.request_hash
        assert r1.request_hash.startswith("sha256:")

    def test_same_result_produces_same_output_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool(result="constant")
        governed = governor.govern_tool(tool)
        governed.call(a=1)
        governed.call(b=2)

        r1, r2 = governor.receipts
        assert r1.output_hash == r2.output_hash
        assert r1.output_hash.startswith("sha256:")

    def test_different_args_produce_different_request_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool = MockLlamaIndexTool()
        governed = governor.govern_tool(tool)
        governed.call(x=1)
        governed.call(x=2)

        r1, r2 = governor.receipts
        assert r1.request_hash != r2.request_hash

    def test_different_results_produce_different_output_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tool_a = MockLlamaIndexTool(name="t", result="alpha")
        tool_b = MockLlamaIndexTool(name="t", result="beta")
        gov_a = governor.govern_tool(tool_a)
        gov_b = governor.govern_tool(tool_b)
        gov_a.call(x=1)
        gov_b.call(x=1)

        r1, r2 = governor.receipts
        assert r1.output_hash != r2.output_hash


# ── Tool Metadata Preservation ──────────────────────────


class TestToolMetadata:
    """Verify governed tools preserve LlamaIndex tool metadata."""

    def test_preserves_metadata_from_tool(self) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        tool = MockLlamaIndexTool(name="my_search", description="Searches things")
        governed = governor.govern_tool(tool)

        assert governed.name == "my_search"
        assert governed.description == "Searches things"
        assert governed.metadata is tool.metadata

    def test_preserves_name_without_metadata(self) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        tool = MockCallableTool(name="plain_tool")
        governed = governor.govern_tool(tool)

        assert governed.name == "plain_tool"
        assert governed.metadata is None

    def test_original_tool_reference(self) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        tool = MockLlamaIndexTool(name="ref_test")
        governed = governor.govern_tool(tool)

        assert governed._original is tool


# ── Multi-Tool Governance ───────────────────────────────


class TestMultiToolGovernance:
    """Verify govern_tools wraps multiple tools correctly."""

    def test_govern_tools_wraps_all(self) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        tools = [
            MockLlamaIndexTool("search"),
            MockQueryEngineTool("qa_engine"),
            MockCallableTool("utility"),
        ]
        governed = governor.govern_tools(tools)

        assert len(governed) == 3
        assert governed[0].name == "search"
        assert governed[1].name == "qa_engine"
        assert governed[2].name == "utility"
        for g in governed:
            assert isinstance(g, GovernedLlamaIndexTool)

    def test_governed_tools_share_receipt_store(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")
        monkeypatch.setattr(
            governor,
            "_evaluate_intent",
            lambda name, args: MockHelmServer.approved_response(name),
        )

        tools = [
            MockLlamaIndexTool("tool_a", result="a"),
            MockLlamaIndexTool("tool_b", result="b"),
        ]
        governed = governor.govern_tools(tools)

        governed[0].call(x=1)
        governed[1].call(y=2)

        assert len(governor.receipts) == 2
        assert governor.receipts[0].tool_name == "tool_a"
        assert governor.receipts[1].tool_name == "tool_b"


# ── HTTP 4xx Deny Path ──────────────────────────────────


class TestHttpErrorDeny:
    """Verify HELM 4xx responses produce proper denials."""

    def test_evaluate_intent_raises_on_4xx(self) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            "error": {
                "reason_code": "DENY_EGRESS_BLOCKED",
                "message": "Egress blocked by firewall policy",
            }
        }

        governor._client = MagicMock()
        governor._client.post.return_value = mock_response

        with pytest.raises(HelmToolDenyError) as exc_info:
            governor._evaluate_intent("external_api", {"url": "http://evil.com"})

        assert exc_info.value.denial.reason_code == "DENY_EGRESS_BLOCKED"
        assert "Egress blocked" in exc_info.value.denial.message

    def test_evaluate_intent_raises_on_5xx(self) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = {
            "error": {
                "reason_code": "ERROR_INTERNAL",
                "message": "Internal server error",
            }
        }

        governor._client = MagicMock()
        governor._client.post.return_value = mock_response

        with pytest.raises(HelmToolDenyError) as exc_info:
            governor._evaluate_intent("any_tool", {})

        assert exc_info.value.denial.reason_code == "ERROR_INTERNAL"


# ── Context Manager ─────────────────────────────────────


class TestContextManager:
    """Verify governor can be used as a context manager."""

    def test_context_manager_lifecycle(self) -> None:
        with HelmToolGovernor(helm_url="http://localhost:8080") as governor:
            assert governor is not None


# ── Query Engine Governance Scenario ────────────────────


class TestQueryEngineGovernance:
    """End-to-end scenario: governing a LlamaIndex query engine tool."""

    def test_governed_query_engine_allow_deny_sequence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = HelmToolGovernor(helm_url="http://localhost:8080")

        call_count = 0

        def policy_evaluator(name, args):
            nonlocal call_count
            call_count += 1
            # First call: allow; second call: deny
            if call_count == 1:
                return MockHelmServer.approved_response(name)
            return MockHelmServer.denied_response()

        monkeypatch.setattr(governor, "_evaluate_intent", policy_evaluator)

        engine = MockQueryEngineTool(
            name="knowledge_base",
            result="The HELM firewall is fail-closed by default.",
        )
        governed = governor.govern_tool(engine)

        # First call: allowed
        result = governed.call(input="What is HELM?")
        assert result == "The HELM firewall is fail-closed by default."
        assert len(governor.receipts) == 1

        # Second call: denied
        with pytest.raises(HelmToolDenyError):
            governed.call(input="What is the admin password?")

        # Only one receipt (the allowed call)
        assert len(governor.receipts) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
