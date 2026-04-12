"""
HELM governance adapter for LangGraph.

Wraps LangGraph node functions with HELM governance checks. Each node
execution is evaluated against HELM policy before the node function runs.
Supports fail-closed mode, receipt collection, and state-aware governance.

Usage:
    from helm_langgraph import HelmLangGraphGovernor

    governor = HelmLangGraphGovernor(helm_url="http://localhost:8080")
    governed_node = governor.govern_node("search_node", search_fn)
    # Or govern tool calls within nodes
    governor.govern_tool("web_search", {"query": "test"})
"""

from __future__ import annotations

import hashlib
import json
import time
import threading
import functools
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

import httpx


@dataclass
class HelmLangGraphConfig:
    """Configuration for HELM LangGraph governance."""

    helm_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    fail_closed: bool = True
    collect_receipts: bool = True
    timeout: float = 30.0


@dataclass
class ToolCallReceipt:
    """A receipt for a governed node or tool call."""

    tool_name: str
    args: dict[str, Any]
    receipt_id: str
    decision: str  # "APPROVED" | "DENIED"
    reason_code: str
    duration_ms: float
    request_hash: str
    output_hash: str
    lamport_clock: int = 0


@dataclass
class ToolCallDenial:
    """Details of a denied node or tool call."""

    tool_name: str
    args: dict[str, Any]
    reason_code: str
    message: str


class HelmToolDenyError(Exception):
    """Raised when HELM denies a node or tool call."""

    def __init__(self, denial: ToolCallDenial):
        super().__init__(
            f'HELM denied "{denial.tool_name}": '
            f"{denial.reason_code} — {denial.message}"
        )
        self.denial = denial


class HelmLangGraphGovernor:
    """
    Governs LangGraph node execution through HELM.

    Wraps LangGraph node functions so that every invocation is evaluated
    against HELM policy before the node function executes. Also supports
    governing individual tool calls within nodes.
    """

    def __init__(self, config: Optional[HelmLangGraphConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmLangGraphConfig(**kwargs)
        self.config = config
        self._receipts: list[ToolCallReceipt] = []
        self._on_receipt: Optional[Callable[[ToolCallReceipt], None]] = None
        self._on_deny: Optional[Callable[[ToolCallDenial], None]] = None
        self._lamport = 0
        self._lock = threading.Lock()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        self._client = httpx.Client(
            base_url=config.helm_url,
            headers=headers,
            timeout=config.timeout,
        )

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmLangGraphGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmLangGraphGovernor":
        """Register a callback for denied tool calls."""
        self._on_deny = callback
        return self

    @property
    def receipts(self) -> list[ToolCallReceipt]:
        """Get all collected receipts."""
        return list(self._receipts)

    def clear_receipts(self) -> None:
        """Clear collected receipts."""
        self._receipts.clear()

    def govern_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate a tool call through HELM governance.

        Args:
            tool_name: The tool or node name
            arguments: The tool arguments or state dict

        Returns:
            The HELM governance response

        Raises:
            HelmToolDenyError: If the call is denied
        """
        start_ms = time.monotonic() * 1000

        with self._lock:
            self._lamport += 1
            lamport = self._lamport

        try:
            response = self._evaluate_intent(tool_name, arguments)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=tool_name,
                    args=arguments,
                    reason_code="DENY_POLICY_VIOLATION",
                    message="Denied by HELM governance",
                )
                if self._on_deny:
                    self._on_deny(denial)
                raise HelmToolDenyError(denial)

            duration_ms = time.monotonic() * 1000 - start_ms
            request_hash = "sha256:" + hashlib.sha256(
                json.dumps(arguments, sort_keys=True, default=str).encode()
            ).hexdigest()

            receipt = ToolCallReceipt(
                tool_name=tool_name,
                args=arguments,
                receipt_id=response.get("id", ""),
                decision="APPROVED",
                reason_code="ALLOW",
                duration_ms=duration_ms,
                request_hash=request_hash,
                output_hash="",
                lamport_clock=lamport,
            )

            if self.config.collect_receipts:
                self._receipts.append(receipt)
            if self._on_receipt:
                self._on_receipt(receipt)

            return response

        except HelmToolDenyError:
            raise
        except httpx.HTTPError as e:
            if self.config.fail_closed:
                raise HelmToolDenyError(
                    ToolCallDenial(
                        tool_name=tool_name,
                        args=arguments,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return {"choices": [{"message": {"tool_calls": []}}]}

    def govern_node(self, node_name: str, node_fn: Callable) -> Callable:
        """
        Wrap a LangGraph node function with HELM governance.

        The returned function preserves the node signature (state -> state)
        and evaluates the state through HELM before executing the node.

        Args:
            node_name: Name of the graph node
            node_fn: The node function (state -> state dict)

        Returns:
            A governed wrapper function
        """

        @functools.wraps(node_fn)
        def governed_node(state: Any) -> Any:
            return self._governed_execute(node_name, node_fn, state)

        governed_node.__helm_governed__ = True
        governed_node.__helm_node_name__ = node_name
        return governed_node

    def govern_nodes(self, nodes: dict[str, Callable]) -> dict[str, Callable]:
        """
        Wrap multiple LangGraph node functions with HELM governance.

        Args:
            nodes: Dict mapping node names to node functions

        Returns:
            Dict mapping node names to governed node functions
        """
        return {name: self.govern_node(name, fn) for name, fn in nodes.items()}

    def _governed_execute(self, node_name: str, node_fn: Callable, state: Any) -> Any:
        """Execute a node function through HELM governance."""
        start_ms = time.monotonic() * 1000

        with self._lock:
            self._lamport += 1
            lamport = self._lamport

        # Extract serializable state summary for governance
        if isinstance(state, dict):
            state_summary = {
                k: v for k, v in state.items()
                if isinstance(v, (str, int, float, bool, list, dict, type(None)))
            }
        else:
            state_summary = {"state_type": type(state).__name__}

        try:
            response = self._evaluate_intent(node_name, state_summary)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=node_name,
                    args=state_summary,
                    reason_code="DENY_POLICY_VIOLATION",
                    message="Denied by HELM governance",
                )
                if self._on_deny:
                    self._on_deny(denial)
                raise HelmToolDenyError(denial)

            # Execute the node function.
            result = node_fn(state)

            duration_ms = time.monotonic() * 1000 - start_ms
            receipt = ToolCallReceipt(
                tool_name=node_name,
                args=state_summary,
                receipt_id=response.get("id", ""),
                decision="APPROVED",
                reason_code="ALLOW",
                duration_ms=duration_ms,
                request_hash="sha256:" + hashlib.sha256(
                    json.dumps(state_summary, sort_keys=True, default=str).encode()
                ).hexdigest(),
                output_hash="sha256:" + hashlib.sha256(
                    json.dumps(result, sort_keys=True, default=str).encode()
                    if isinstance(result, dict) else str(result).encode()
                ).hexdigest(),
                lamport_clock=lamport,
            )

            if self.config.collect_receipts:
                self._receipts.append(receipt)
            if self._on_receipt:
                self._on_receipt(receipt)

            return result

        except HelmToolDenyError:
            raise
        except httpx.HTTPError as e:
            if self.config.fail_closed:
                raise HelmToolDenyError(
                    ToolCallDenial(
                        tool_name=node_name,
                        args=state_summary,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return node_fn(state)

    def _evaluate_intent(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Send a node/tool call intent to HELM for policy evaluation."""
        intent = {
            "model": "helm-governance",
            "messages": [
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "type": "tool_call_intent",
                            "tool": tool_name,
                            "arguments": args,
                            "principal": "langgraph-agent",
                        }
                    ),
                }
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": tool_name},
                }
            ],
        }
        resp = self._client.post("/v1/chat/completions", json=intent)
        if resp.status_code >= 400:
            body = resp.json()
            err = body.get("error", {})
            raise HelmToolDenyError(
                ToolCallDenial(
                    tool_name=tool_name,
                    args=args,
                    reason_code=err.get("reason_code", "ERROR_INTERNAL"),
                    message=err.get("message", resp.text),
                )
            )
        return resp.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "HelmLangGraphGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
