"""
HELM governance adapter for Deepset Haystack.

Wraps Haystack pipeline components and tool invocations with HELM
governance checks. Intercepts component.run() and pipeline.run() calls,
routing them through HELM's policy plane. Supports fail-closed mode
and receipt collection.

Usage:
    from helm_haystack import HelmHaystackGovernor

    governor = HelmHaystackGovernor(helm_url="http://localhost:8080")
    governed_component = governor.govern_component(my_component)
    # Or wrap tool invocations
    governor.govern_tool("web_search", {"query": "test"})
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
class HelmHaystackConfig:
    """Configuration for HELM Haystack governance."""

    helm_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    fail_closed: bool = True
    collect_receipts: bool = True
    timeout: float = 30.0


@dataclass
class ToolCallReceipt:
    """A receipt for a governed component or tool call."""

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
    """Details of a denied tool/component call."""

    tool_name: str
    args: dict[str, Any]
    reason_code: str
    message: str


class HelmToolDenyError(Exception):
    """Raised when HELM denies a tool or component call."""

    def __init__(self, denial: ToolCallDenial):
        super().__init__(
            f'HELM denied "{denial.tool_name}": '
            f"{denial.reason_code} — {denial.message}"
        )
        self.denial = denial


class HelmHaystackGovernor:
    """
    Governs Deepset Haystack pipeline components through HELM.

    Wraps Haystack component.run() calls so that every invocation is
    evaluated against HELM policy before the underlying component executes.
    """

    def __init__(self, config: Optional[HelmHaystackConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmHaystackConfig(**kwargs)
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

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmHaystackGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmHaystackGovernor":
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
        Evaluate a tool invocation through HELM governance.

        Args:
            tool_name: The tool or component name
            arguments: The tool arguments

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

    def govern_component(self, component: Any) -> Any:
        """
        Wrap a Haystack component with HELM governance.

        The returned wrapper preserves the component interface and routes
        all run() calls through HELM.

        Args:
            component: A Haystack component with a run() method

        Returns:
            A GovernedHaystackComponent wrapper
        """
        return GovernedHaystackComponent(component, self)

    def govern_components(self, components: Sequence[Any]) -> list[Any]:
        """Wrap a list of Haystack components with HELM governance."""
        return [self.govern_component(c) for c in components]

    def _evaluate_intent(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Send a tool/component call intent to HELM for policy evaluation."""
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
                            "principal": "haystack-pipeline",
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

    def __enter__(self) -> "HelmHaystackGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class GovernedHaystackComponent:
    """
    A Haystack-compatible component wrapper that routes execution through HELM.

    Preserves the Haystack component interface: run() method and all
    component metadata.
    """

    def __init__(self, original: Any, governor: HelmHaystackGovernor):
        self._original = original
        self._governor = governor
        # Preserve Haystack component metadata.
        component_class = type(original).__name__
        self.name: str = getattr(original, "name", component_class)
        self.__class__.__name__ = f"Governed{component_class}"

    def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the component through HELM governance."""
        return self._governed_execute(kwargs)

    def _governed_execute(self, args: dict[str, Any]) -> dict[str, Any]:
        """Execute the component through HELM governance."""
        start_ms = time.monotonic() * 1000
        component_name = self.name

        with self._governor._lock:
            self._governor._lamport += 1
            lamport = self._governor._lamport

        try:
            response = self._governor._evaluate_intent(component_name, args)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=component_name,
                    args=args,
                    reason_code="DENY_POLICY_VIOLATION",
                    message="Denied by HELM governance",
                )
                if self._governor._on_deny:
                    self._governor._on_deny(denial)
                raise HelmToolDenyError(denial)

            # Execute the underlying component.
            result = self._original.run(**args)

            duration_ms = time.monotonic() * 1000 - start_ms
            receipt = ToolCallReceipt(
                tool_name=component_name,
                args=args,
                receipt_id=response.get("id", ""),
                decision="APPROVED",
                reason_code="ALLOW",
                duration_ms=duration_ms,
                request_hash="sha256:" + hashlib.sha256(
                    json.dumps(args, sort_keys=True, default=str).encode()
                ).hexdigest(),
                output_hash="sha256:" + hashlib.sha256(
                    json.dumps(result, sort_keys=True, default=str).encode()
                ).hexdigest(),
                lamport_clock=lamport,
            )

            if self._governor.config.collect_receipts:
                self._governor._receipts.append(receipt)
            if self._governor._on_receipt:
                self._governor._on_receipt(receipt)

            return result

        except HelmToolDenyError:
            raise
        except httpx.HTTPError as e:
            if self._governor.config.fail_closed:
                raise HelmToolDenyError(
                    ToolCallDenial(
                        tool_name=component_name,
                        args=args,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return self._original.run(**args)

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the original component."""
        return getattr(self._original, name)
