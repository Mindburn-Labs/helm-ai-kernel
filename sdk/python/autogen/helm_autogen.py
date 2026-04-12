"""
HELM governance adapter for Microsoft AutoGen.

Wraps AutoGen agent message handling and tool execution with HELM
governance checks. Intercepts function_call messages and tool invocations
in multi-agent conversations. Supports fail-closed mode and receipt
collection.

Usage:
    from helm_autogen import HelmAutoGenGovernor

    governor = HelmAutoGenGovernor(helm_url="http://localhost:8080")
    governed_tool = governor.govern_tool("code_executor", code_exec_fn)
    # Or govern function calls in agent messages
    governor.govern_function_call("search", {"query": "test"}, agent_name="assistant")
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
class HelmAutoGenConfig:
    """Configuration for HELM AutoGen governance."""

    helm_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    fail_closed: bool = True
    collect_receipts: bool = True
    timeout: float = 30.0


@dataclass
class ToolCallReceipt:
    """A receipt for a governed tool or function call."""

    tool_name: str
    agent_name: str
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
    """Details of a denied tool or function call."""

    tool_name: str
    agent_name: str
    args: dict[str, Any]
    reason_code: str
    message: str


class HelmToolDenyError(Exception):
    """Raised when HELM denies a tool or function call."""

    def __init__(self, denial: ToolCallDenial):
        super().__init__(
            f'HELM denied "{denial.tool_name}" for agent '
            f'"{denial.agent_name}": '
            f"{denial.reason_code} — {denial.message}"
        )
        self.denial = denial


class HelmAutoGenGovernor:
    """
    Governs Microsoft AutoGen multi-agent tool and function calls through HELM.

    Wraps AutoGen function_call messages and tool invocations so that every
    execution is evaluated against HELM policy before the function runs.
    """

    def __init__(self, config: Optional[HelmAutoGenConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmAutoGenConfig(**kwargs)
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

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmAutoGenGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmAutoGenGovernor":
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

    def govern_function_call(
        self,
        function_name: str,
        arguments: dict[str, Any],
        agent_name: str = "unknown",
    ) -> dict[str, Any]:
        """
        Evaluate an AutoGen function call through HELM governance.

        Args:
            function_name: The function name from the function_call message
            arguments: The parsed arguments dict
            agent_name: Name of the calling agent

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
            response = self._evaluate_intent(function_name, arguments, agent_name)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=function_name,
                    agent_name=agent_name,
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
                tool_name=function_name,
                agent_name=agent_name,
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
                        tool_name=function_name,
                        agent_name=agent_name,
                        args=arguments,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return {"choices": [{"message": {"tool_calls": []}}]}

    def govern_tool(
        self,
        tool_name: str,
        tool_fn: Callable,
        agent_name: str = "unknown",
    ) -> Callable:
        """
        Wrap a tool function with HELM governance for use in AutoGen agents.

        The returned function preserves the original signature and evaluates
        through HELM before executing.

        Args:
            tool_name: Name of the tool
            tool_fn: The tool function to wrap
            agent_name: Name of the owning agent

        Returns:
            A governed wrapper function
        """

        @functools.wraps(tool_fn)
        def governed_fn(*args: Any, **kwargs: Any) -> Any:
            tool_args = kwargs if kwargs else {"args": args}
            return self._governed_execute(
                tool_name, tool_fn, tool_args, args, kwargs, agent_name
            )

        governed_fn.__helm_governed__ = True
        governed_fn.__helm_tool_name__ = tool_name
        return governed_fn

    def govern_message(
        self,
        message: dict[str, Any],
        agent_name: str = "unknown",
    ) -> dict[str, Any]:
        """
        Govern function_call or tool_calls in an AutoGen chat message.

        Inspects the message for function_call or tool_calls fields and
        evaluates each through HELM.

        Args:
            message: An AutoGen message dict
            agent_name: Name of the agent producing the message

        Returns:
            The original message (unmodified) if all calls are approved

        Raises:
            HelmToolDenyError: If any function call is denied
        """
        # AutoGen v0.2 format: function_call in message
        if "function_call" in message:
            fc = message["function_call"]
            name = fc.get("name", "")
            args_raw = fc.get("arguments", "{}")
            arguments = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            self.govern_function_call(name, arguments, agent_name)

        # AutoGen v0.2+ format: tool_calls list
        if "tool_calls" in message:
            for tc in message["tool_calls"]:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args_raw = fn.get("arguments", "{}")
                arguments = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                self.govern_function_call(name, arguments, agent_name)

        return message

    def _governed_execute(
        self,
        tool_name: str,
        tool_fn: Callable,
        tool_args: dict[str, Any],
        original_args: tuple,
        original_kwargs: dict,
        agent_name: str,
    ) -> Any:
        """Execute a tool function through HELM governance."""
        start_ms = time.monotonic() * 1000

        with self._lock:
            self._lamport += 1
            lamport = self._lamport

        try:
            response = self._evaluate_intent(tool_name, tool_args, agent_name)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=tool_name,
                    agent_name=agent_name,
                    args=tool_args,
                    reason_code="DENY_POLICY_VIOLATION",
                    message="Denied by HELM governance",
                )
                if self._on_deny:
                    self._on_deny(denial)
                raise HelmToolDenyError(denial)

            # Execute the tool function.
            result = tool_fn(*original_args, **original_kwargs)

            duration_ms = time.monotonic() * 1000 - start_ms
            receipt = ToolCallReceipt(
                tool_name=tool_name,
                agent_name=agent_name,
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
                        agent_name=agent_name,
                        args=tool_args,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return tool_fn(*original_args, **original_kwargs)

    def _evaluate_intent(
        self, tool_name: str, args: dict[str, Any], agent_name: str
    ) -> dict[str, Any]:
        """Send a tool/function call intent to HELM for policy evaluation."""
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
                            "principal": f"autogen-agent:{agent_name}",
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
                    agent_name=agent_name,
                    args=args,
                    reason_code=err.get("reason_code", "ERROR_INTERNAL"),
                    message=err.get("message", resp.text),
                )
            )
        return resp.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "HelmAutoGenGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
