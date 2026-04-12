"""
HELM governance adapter for HuggingFace Smolagents.

Wraps Smolagents tool execution with HELM governance checks. Intercepts
agent.run() and individual tool calls, routing them through HELM's policy
plane. Supports fail-closed mode and receipt collection.

Usage:
    from helm_smolagents import HelmSmolagentsGovernor

    governor = HelmSmolagentsGovernor(helm_url="http://localhost:8080")
    governed_tool = governor.govern_tool(my_tool)
    # Or wrap all tools on an agent
    governor.govern_agent(agent)
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
class HelmSmolagentsConfig:
    """Configuration for HELM Smolagents governance."""

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


class HelmSmolagentsGovernor:
    """
    Governs HuggingFace Smolagents tool calls through HELM.

    Wraps Smolagents Tool objects so that every invocation is evaluated
    against HELM policy before the underlying tool executes.
    """

    def __init__(self, config: Optional[HelmSmolagentsConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmSmolagentsConfig(**kwargs)
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

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmSmolagentsGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmSmolagentsGovernor":
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

    def govern_tool(self, tool: Any) -> Any:
        """
        Wrap a single Smolagents Tool with HELM governance.

        Args:
            tool: A smolagents.Tool instance

        Returns:
            A GovernedSmolagentsTool wrapper
        """
        return GovernedSmolagentsTool(tool, self)

    def govern_tools(self, tools: Sequence[Any]) -> list[Any]:
        """Wrap a list of Smolagents tools with HELM governance."""
        return [self.govern_tool(t) for t in tools]

    def govern_agent(self, agent: Any) -> None:
        """
        Replace all tools on a Smolagents agent with governed versions.

        Modifies the agent in-place, wrapping each tool in its toolbox.

        Args:
            agent: A smolagents agent (CodeAgent, ToolCallingAgent, etc.)
        """
        if hasattr(agent, "tools") and isinstance(agent.tools, dict):
            governed = {}
            for name, tool in agent.tools.items():
                governed[name] = self.govern_tool(tool)
            agent.tools = governed
        elif hasattr(agent, "toolbox"):
            toolbox = agent.toolbox
            if hasattr(toolbox, "tools") and isinstance(toolbox.tools, dict):
                for name in list(toolbox.tools.keys()):
                    toolbox.tools[name] = self.govern_tool(toolbox.tools[name])

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
                            "principal": "smolagents-agent",
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

    def __enter__(self) -> "HelmSmolagentsGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class GovernedSmolagentsTool:
    """
    A Smolagents-compatible tool wrapper that routes execution through HELM.

    Preserves the Smolagents Tool interface: name, description, inputs,
    output_type, and __call__.
    """

    def __init__(self, original: Any, governor: HelmSmolagentsGovernor):
        self._original = original
        self._governor = governor
        # Preserve Smolagents tool metadata.
        self.name: str = getattr(original, "name", str(original))
        self.description: str = getattr(original, "description", "")
        self.inputs: dict = getattr(original, "inputs", {})
        self.output_type: str = getattr(original, "output_type", "string")

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        """Execute with HELM governance (Smolagents forward interface)."""
        tool_input = kwargs if kwargs else {"input": args}
        return self._governed_execute(tool_input, args, kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Execute with HELM governance."""
        tool_input = kwargs if kwargs else {"input": args}
        return self._governed_execute(tool_input, args, kwargs)

    def _governed_execute(
        self,
        tool_input: dict[str, Any],
        original_args: tuple,
        original_kwargs: dict,
    ) -> Any:
        """Execute the tool through HELM governance."""
        start_ms = time.monotonic() * 1000
        tool_name = self.name

        with self._governor._lock:
            self._governor._lamport += 1
            lamport = self._governor._lamport

        try:
            response = self._governor._evaluate_intent(tool_name, tool_input)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=tool_name,
                    args=tool_input,
                    reason_code="DENY_POLICY_VIOLATION",
                    message="Denied by HELM governance",
                )
                if self._governor._on_deny:
                    self._governor._on_deny(denial)
                raise HelmToolDenyError(denial)

            # Execute the underlying tool.
            if hasattr(self._original, "forward"):
                result = self._original.forward(*original_args, **original_kwargs)
            else:
                result = self._original(*original_args, **original_kwargs)

            duration_ms = time.monotonic() * 1000 - start_ms
            receipt = ToolCallReceipt(
                tool_name=tool_name,
                args=tool_input,
                receipt_id=response.get("id", ""),
                decision="APPROVED",
                reason_code="ALLOW",
                duration_ms=duration_ms,
                request_hash="sha256:" + hashlib.sha256(
                    json.dumps(tool_input, sort_keys=True, default=str).encode()
                ).hexdigest(),
                output_hash="sha256:" + hashlib.sha256(
                    str(result).encode()
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
                        tool_name=tool_name,
                        args=tool_input,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            if hasattr(self._original, "forward"):
                return self._original.forward(*original_args, **original_kwargs)
            return self._original(*original_args, **original_kwargs)
