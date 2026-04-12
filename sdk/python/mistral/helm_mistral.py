"""
HELM governance adapter for Mistral AI SDK.

Intercepts Mistral AI tool/function calls in chat completions and routes
them through HELM's governance plane. Supports fail-closed mode, receipt
collection, and async execution.

Usage:
    from helm_mistral import HelmMistralGovernor

    governor = HelmMistralGovernor(helm_url="http://localhost:8080")
    result = governor.govern_tool("web_search", {"query": "latest news"})
    # Or wrap a Mistral client
    governed_client = governor.wrap_client(mistral_client)
"""

from __future__ import annotations

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

import httpx


@dataclass
class HelmMistralConfig:
    """Configuration for HELM Mistral governance."""

    helm_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    fail_closed: bool = True
    collect_receipts: bool = True
    timeout: float = 30.0


@dataclass
class ToolCallReceipt:
    """A receipt for a governed tool call."""

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
    """Details of a denied tool call."""

    tool_name: str
    args: dict[str, Any]
    reason_code: str
    message: str


class HelmToolDenyError(Exception):
    """Raised when HELM denies a tool call."""

    def __init__(self, denial: ToolCallDenial):
        super().__init__(
            f'HELM denied tool call "{denial.tool_name}": '
            f"{denial.reason_code} — {denial.message}"
        )
        self.denial = denial


class HelmMistralGovernor:
    """
    Governs Mistral AI SDK tool calls through HELM.

    Every tool_call in a Mistral chat completion response is evaluated
    against HELM policy before execution. If denied, a HelmToolDenyError
    is raised (fail-closed by default).
    """

    def __init__(self, config: Optional[HelmMistralConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmMistralConfig(**kwargs)
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

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmMistralGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmMistralGovernor":
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
        Evaluate a Mistral tool_call through HELM governance.

        Args:
            tool_name: The function name from tool_call.function.name
            arguments: The parsed arguments from tool_call.function.arguments

        Returns:
            The HELM governance response

        Raises:
            HelmToolDenyError: If the tool call is denied
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
                json.dumps(arguments, sort_keys=True).encode()
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

    def govern_chat_response(self, response: Any) -> list[dict[str, Any]]:
        """
        Govern all tool_calls in a Mistral chat completion response.

        Iterates through response.choices[].message.tool_calls and evaluates
        each through HELM. Returns list of approved tool calls.

        Args:
            response: A Mistral ChatCompletionResponse object

        Returns:
            List of approved tool call dicts (name, arguments)

        Raises:
            HelmToolDenyError: If any tool call is denied (fail-closed)
        """
        approved = []
        choices = getattr(response, "choices", []) if not isinstance(response, dict) else response.get("choices", [])

        for choice in choices:
            message = getattr(choice, "message", None) if not isinstance(choice, dict) else choice.get("message")
            if message is None:
                continue

            tool_calls = (
                getattr(message, "tool_calls", None)
                if not isinstance(message, dict)
                else message.get("tool_calls")
            ) or []

            for tc in tool_calls:
                if isinstance(tc, dict):
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    args_raw = fn.get("arguments", "{}")
                else:
                    fn = getattr(tc, "function", None)
                    name = getattr(fn, "name", "") if fn else ""
                    args_raw = getattr(fn, "arguments", "{}") if fn else "{}"

                arguments = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                self.govern_tool(name, arguments)
                approved.append({"name": name, "arguments": arguments})

        return approved

    def _evaluate_intent(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Send a tool call intent to HELM for policy evaluation."""
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
                            "principal": "mistral-agent",
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

    def __enter__(self) -> "HelmMistralGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
