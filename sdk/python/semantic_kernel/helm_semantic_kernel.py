"""
HELM governance adapter for Microsoft Semantic Kernel.

Wraps Semantic Kernel function execution with HELM governance checks.
Intercepts kernel function invocations and plugin calls, routing them
through HELM's policy plane. Supports fail-closed mode and receipt
collection.

Usage:
    from helm_semantic_kernel import HelmSemanticKernelGovernor

    governor = HelmSemanticKernelGovernor(helm_url="http://localhost:8080")
    governed_fn = governor.govern_function("plugin", "function", my_fn)
    # Or govern tool calls directly
    governor.govern_tool("search-plugin.web_search", {"query": "test"})
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
class HelmSemanticKernelConfig:
    """Configuration for HELM Semantic Kernel governance."""

    helm_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    fail_closed: bool = True
    collect_receipts: bool = True
    timeout: float = 30.0


@dataclass
class ToolCallReceipt:
    """A receipt for a governed function call."""

    tool_name: str
    plugin_name: str
    function_name: str
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
    """Details of a denied function call."""

    tool_name: str
    plugin_name: str
    function_name: str
    args: dict[str, Any]
    reason_code: str
    message: str


class HelmToolDenyError(Exception):
    """Raised when HELM denies a function call."""

    def __init__(self, denial: ToolCallDenial):
        super().__init__(
            f'HELM denied "{denial.plugin_name}.{denial.function_name}": '
            f"{denial.reason_code} — {denial.message}"
        )
        self.denial = denial


class HelmSemanticKernelGovernor:
    """
    Governs Microsoft Semantic Kernel function calls through HELM.

    Wraps Semantic Kernel function invocations so that every call is
    evaluated against HELM policy before the function executes.
    """

    def __init__(self, config: Optional[HelmSemanticKernelConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmSemanticKernelConfig(**kwargs)
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

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmSemanticKernelGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmSemanticKernelGovernor":
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

    def govern_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Evaluate a Semantic Kernel function call through HELM governance.

        Args:
            tool_name: Fully qualified name (plugin_name.function_name)
            arguments: The function arguments

        Returns:
            The HELM governance response

        Raises:
            HelmToolDenyError: If the call is denied
        """
        parts = tool_name.split(".", 1)
        plugin_name = parts[0] if len(parts) > 1 else ""
        function_name = parts[1] if len(parts) > 1 else parts[0]
        return self._govern_internal(plugin_name, function_name, arguments)

    def govern_function(
        self,
        plugin_name: str,
        function_name: str,
        fn: Callable,
    ) -> Callable:
        """
        Wrap a Semantic Kernel function with HELM governance.

        The returned function preserves the original signature and evaluates
        through HELM before executing.

        Args:
            plugin_name: Name of the plugin
            function_name: Name of the function within the plugin
            fn: The function to wrap

        Returns:
            A governed wrapper function
        """

        @functools.wraps(fn)
        def governed_fn(*args: Any, **kwargs: Any) -> Any:
            tool_args = kwargs if kwargs else {"args": args}
            return self._governed_execute(
                plugin_name, function_name, fn, tool_args, args, kwargs
            )

        governed_fn.__helm_governed__ = True
        governed_fn.__helm_plugin__ = plugin_name
        governed_fn.__helm_function__ = function_name
        return governed_fn

    def govern_function_call_content(
        self,
        function_call: Any,
    ) -> dict[str, Any]:
        """
        Govern a Semantic Kernel FunctionCallContent object.

        Extracts plugin_name, function_name, and arguments from the
        FunctionCallContent and evaluates through HELM.

        Args:
            function_call: A FunctionCallContent object or equivalent dict

        Returns:
            The HELM governance response

        Raises:
            HelmToolDenyError: If the call is denied
        """
        if isinstance(function_call, dict):
            plugin_name = function_call.get("plugin_name", "")
            function_name = function_call.get("function_name", "")
            arguments = function_call.get("arguments", {})
        else:
            plugin_name = getattr(function_call, "plugin_name", "")
            function_name = getattr(function_call, "function_name", "")
            arguments = getattr(function_call, "arguments", {})
            if arguments and not isinstance(arguments, dict):
                try:
                    arguments = json.loads(str(arguments))
                except (json.JSONDecodeError, ValueError):
                    arguments = {"raw": str(arguments)}

        return self._govern_internal(plugin_name, function_name, arguments)

    def _govern_internal(
        self,
        plugin_name: str,
        function_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Internal governance evaluation."""
        start_ms = time.monotonic() * 1000
        tool_name = f"{plugin_name}.{function_name}" if plugin_name else function_name

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
                    plugin_name=plugin_name,
                    function_name=function_name,
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
                plugin_name=plugin_name,
                function_name=function_name,
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
                        plugin_name=plugin_name,
                        function_name=function_name,
                        args=arguments,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return {"choices": [{"message": {"tool_calls": []}}]}

    def _governed_execute(
        self,
        plugin_name: str,
        function_name: str,
        fn: Callable,
        tool_args: dict[str, Any],
        original_args: tuple,
        original_kwargs: dict,
    ) -> Any:
        """Execute a function through HELM governance."""
        start_ms = time.monotonic() * 1000
        tool_name = f"{plugin_name}.{function_name}" if plugin_name else function_name

        with self._lock:
            self._lamport += 1
            lamport = self._lamport

        try:
            response = self._evaluate_intent(tool_name, tool_args)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=tool_name,
                    plugin_name=plugin_name,
                    function_name=function_name,
                    args=tool_args,
                    reason_code="DENY_POLICY_VIOLATION",
                    message="Denied by HELM governance",
                )
                if self._on_deny:
                    self._on_deny(denial)
                raise HelmToolDenyError(denial)

            # Execute the function.
            result = fn(*original_args, **original_kwargs)

            duration_ms = time.monotonic() * 1000 - start_ms
            receipt = ToolCallReceipt(
                tool_name=tool_name,
                plugin_name=plugin_name,
                function_name=function_name,
                args=tool_args,
                receipt_id=response.get("id", ""),
                decision="APPROVED",
                reason_code="ALLOW",
                duration_ms=duration_ms,
                request_hash="sha256:" + hashlib.sha256(
                    json.dumps(tool_args, sort_keys=True, default=str).encode()
                ).hexdigest(),
                output_hash="sha256:" + hashlib.sha256(
                    str(result).encode()
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
                        tool_name=tool_name,
                        plugin_name=plugin_name,
                        function_name=function_name,
                        args=tool_args,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return fn(*original_args, **original_kwargs)

    def _evaluate_intent(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Send a function call intent to HELM for policy evaluation."""
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
                            "principal": "semantic-kernel-agent",
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
                    plugin_name="",
                    function_name=tool_name,
                    args=args,
                    reason_code=err.get("reason_code", "ERROR_INTERNAL"),
                    message=err.get("message", resp.text),
                )
            )
        return resp.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "HelmSemanticKernelGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
