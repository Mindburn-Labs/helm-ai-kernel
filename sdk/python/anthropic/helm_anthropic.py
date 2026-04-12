"""
HELM governance adapter for Anthropic Claude SDK.

Intercepts tool_use content blocks in Anthropic Messages API responses and
routes them through HELM's governance plane. Supports fail-closed mode,
receipt collection, and async execution.

Usage:
    from helm_anthropic import HelmAnthropicGovernor

    governor = HelmAnthropicGovernor(helm_url="http://localhost:8080")
    approved = governor.govern_tool("file_write", {"path": "/tmp/out.txt", "content": "hello"})
    # Or govern an entire Messages API response
    approved = governor.govern_message_response(response)
"""

from __future__ import annotations

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx


@dataclass
class HelmAnthropicConfig:
    """Configuration for HELM Anthropic governance."""

    helm_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    fail_closed: bool = True
    collect_receipts: bool = True
    timeout: float = 30.0


@dataclass
class ToolCallReceipt:
    """A receipt for a governed tool_use call."""

    tool_name: str
    tool_use_id: str
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
    tool_use_id: str
    args: dict[str, Any]
    reason_code: str
    message: str


class HelmToolDenyError(Exception):
    """Raised when HELM denies a tool_use call."""

    def __init__(self, denial: ToolCallDenial):
        super().__init__(
            f'HELM denied tool_use "{denial.tool_name}" '
            f"(id={denial.tool_use_id}): "
            f"{denial.reason_code} — {denial.message}"
        )
        self.denial = denial


class HelmAnthropicGovernor:
    """
    Governs Anthropic Claude SDK tool_use calls through HELM.

    Intercepts tool_use content blocks in Messages API responses and
    evaluates each against HELM policy. If denied, raises HelmToolDenyError
    (fail-closed by default).
    """

    def __init__(self, config: Optional[HelmAnthropicConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmAnthropicConfig(**kwargs)
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

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmAnthropicGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmAnthropicGovernor":
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
        tool_use_id: str = "",
    ) -> dict[str, Any]:
        """
        Evaluate a single tool_use block through HELM governance.

        Args:
            tool_name: The tool name from the tool_use block
            arguments: The input dict from the tool_use block
            tool_use_id: The id from the tool_use block

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
            response = self._evaluate_intent(tool_name, arguments, tool_use_id)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=tool_name,
                    tool_use_id=tool_use_id,
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
                tool_use_id=tool_use_id,
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
                        tool_use_id=tool_use_id,
                        args=arguments,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return {"choices": [{"message": {"tool_calls": []}}]}

    def govern_message_response(self, response: Any) -> list[dict[str, Any]]:
        """
        Govern all tool_use blocks in an Anthropic Messages API response.

        Iterates through response.content blocks of type "tool_use" and
        evaluates each through HELM. Returns list of approved tool_use dicts.

        Args:
            response: An anthropic.types.Message object or equivalent dict

        Returns:
            List of approved tool_use dicts (id, name, input)

        Raises:
            HelmToolDenyError: If any tool_use is denied (fail-closed)
        """
        approved = []

        # Handle both object and dict responses
        if isinstance(response, dict):
            content_blocks = response.get("content", [])
        else:
            content_blocks = getattr(response, "content", [])

        for block in content_blocks:
            if isinstance(block, dict):
                block_type = block.get("type", "")
                if block_type != "tool_use":
                    continue
                tool_name = block.get("name", "")
                tool_input = block.get("input", {})
                tool_use_id = block.get("id", "")
            else:
                block_type = getattr(block, "type", "")
                if block_type != "tool_use":
                    continue
                tool_name = getattr(block, "name", "")
                tool_input = getattr(block, "input", {})
                tool_use_id = getattr(block, "id", "")

            self.govern_tool(tool_name, tool_input, tool_use_id)
            approved.append({
                "id": tool_use_id,
                "name": tool_name,
                "input": tool_input,
            })

        return approved

    def _evaluate_intent(
        self, tool_name: str, args: dict[str, Any], tool_use_id: str
    ) -> dict[str, Any]:
        """Send a tool_use intent to HELM for policy evaluation."""
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
                            "principal": "anthropic-agent",
                            "tool_use_id": tool_use_id,
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
                    tool_use_id=tool_use_id,
                    args=args,
                    reason_code=err.get("reason_code", "ERROR_INTERNAL"),
                    message=err.get("message", resp.text),
                )
            )
        return resp.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "HelmAnthropicGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
