"""
HELM MCP Trust Verification Layer (Python)

Adds HELM governance to MCP tool calls at the protocol level.
Verifies tool calls against HELM policy and filters available tools
based on the current principal's permissions.

Usage:
    from helm_mcp_trust import MCPTrustProxy

    proxy = MCPTrustProxy(helm_url="http://localhost:8080")
    result = proxy.verify_tool_call("file_write", {"path": "/tmp/out.txt"})
    tools = proxy.get_governed_tools(available_tools)
"""

from __future__ import annotations

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence
import urllib.request
import urllib.error


@dataclass
class ToolCallVerification:
    """Result of verifying an MCP tool call through HELM governance."""
    tool_name: str
    args: dict[str, Any]
    allowed: bool
    verdict: str  # "ALLOW" | "DENY" | "ESCALATE"
    reason_code: str
    receipt_id: str
    request_hash: str
    error: Optional[str] = None


@dataclass
class GovernedTool:
    """An MCP tool with its governance status."""
    name: str
    description: str
    allowed: bool
    reason_code: str
    input_schema: Optional[dict] = None


@dataclass
class HelmReceipt:
    """Governance receipt for an MCP trust operation."""
    receipt_id: str
    timestamp: str
    tool_name: str
    args_hash: str
    verdict: str
    reason_code: str
    lamport_clock: int
    prev_hash: str
    hash: str
    metadata: dict = field(default_factory=dict)


class MCPTrustDenyError(Exception):
    """Raised when HELM denies an MCP tool call."""

    def __init__(self, verification: ToolCallVerification):
        super().__init__(
            f'HELM denied MCP tool call "{verification.tool_name}": '
            f"{verification.reason_code}"
        )
        self.verification = verification


class MCPTrustProxy:
    """
    MCP trust verification layer backed by HELM governance.

    Intercepts MCP tool calls at the protocol level and evaluates them
    against HELM policy. Also provides tool-list filtering to only expose
    tools the current principal is allowed to use.

    Operates fail-closed by default: if HELM is unreachable, tool calls
    are denied and tool lists are empty.

    Args:
        helm_url: Base URL of HELM server
        principal: Default principal identity for tool calls
        fail_closed: Deny on HELM unreachable (default: True)
        collect_receipts: Keep receipt chain (default: True)
        metadata: Global metadata for all receipts
    """

    def __init__(
        self,
        helm_url: str = "http://localhost:8080",
        principal: str = "mcp-client",
        fail_closed: bool = True,
        collect_receipts: bool = True,
        metadata: Optional[dict] = None,
    ):
        self.helm_url = helm_url.rstrip("/")
        self.principal = principal
        self.fail_closed = fail_closed
        self.collect_receipts = collect_receipts
        self.metadata = metadata or {}
        self._receipts: list[HelmReceipt] = []
        self._prev_hash = "GENESIS"
        self._lamport = 0
        self._lock = threading.Lock()

    def verify_tool_call(
        self,
        tool_name: str,
        args: Optional[dict[str, Any]] = None,
        principal: Optional[str] = None,
    ) -> ToolCallVerification:
        """
        Verify an MCP tool call against HELM governance.

        Args:
            tool_name: Name of the MCP tool being called
            args: Tool call arguments
            principal: Override the default principal for this call

        Returns:
            ToolCallVerification with the governance verdict

        Raises:
            MCPTrustDenyError: If the tool call is denied (only in strict mode)
        """
        if args is None:
            args = {}
        caller = principal or self.principal

        args_canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
        args_hash = "sha256:" + hashlib.sha256(args_canonical.encode()).hexdigest()

        verdict = "ALLOW"
        reason_code = "POLICY_PASS"

        try:
            response = self._call_helm("/v1/tools/evaluate", {
                "tool_name": tool_name,
                "arguments": args,
                "principal": caller,
                "args_hash": args_hash,
                "protocol": "mcp",
            })
            verdict = response.get("verdict", "ALLOW")
            reason_code = response.get("reason_code", "POLICY_PASS")
        except (urllib.error.URLError, ConnectionError):
            if self.fail_closed:
                verdict = "DENY"
                reason_code = "HELM_UNREACHABLE"

        receipt = self._record_receipt(tool_name, args_hash, verdict, reason_code)

        return ToolCallVerification(
            tool_name=tool_name,
            args=args,
            allowed=verdict == "ALLOW",
            verdict=verdict,
            reason_code=reason_code,
            receipt_id=receipt.receipt_id,
            request_hash=args_hash,
            error=reason_code if verdict != "ALLOW" else None,
        )

    def get_governed_tools(
        self,
        available_tools: Sequence[dict[str, Any]],
        principal: Optional[str] = None,
    ) -> list[GovernedTool]:
        """
        Filter an MCP tool list based on HELM policy.

        Takes the raw MCP tools/list response and returns only the tools
        the current principal is permitted to invoke.

        Args:
            available_tools: List of MCP tool descriptors (each with "name", "description", "inputSchema")
            principal: Override the default principal

        Returns:
            List of GovernedTool with allowed/denied status
        """
        caller = principal or self.principal
        governed: list[GovernedTool] = []

        for tool in available_tools:
            tool_name = tool.get("name", "")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema", None)

            allowed = True
            reason_code = "POLICY_PASS"

            try:
                response = self._call_helm("/v1/tools/check", {
                    "tool_name": tool_name,
                    "principal": caller,
                    "protocol": "mcp",
                    "check_only": True,
                })
                allowed = response.get("allowed", True)
                reason_code = response.get("reason_code", "POLICY_PASS")
            except (urllib.error.URLError, ConnectionError):
                if self.fail_closed:
                    allowed = False
                    reason_code = "HELM_UNREACHABLE"

            governed.append(GovernedTool(
                name=tool_name,
                description=description,
                allowed=allowed,
                reason_code=reason_code,
                input_schema=input_schema,
            ))

        return governed

    def get_allowed_tools(
        self,
        available_tools: Sequence[dict[str, Any]],
        principal: Optional[str] = None,
    ) -> list[GovernedTool]:
        """Return only the tools that are allowed by HELM policy."""
        return [t for t in self.get_governed_tools(available_tools, principal) if t.allowed]

    @property
    def receipts(self) -> list[HelmReceipt]:
        """Get all collected receipts."""
        return list(self._receipts)

    def clear_receipts(self) -> None:
        """Clear collected receipts."""
        self._receipts.clear()

    def export_evidence_pack(self, path: str) -> str:
        """Export receipts as deterministic .tar EvidencePack."""
        import tarfile
        import io as _io

        with tarfile.open(path, "w") as tar:
            for i, receipt in enumerate(sorted(self._receipts, key=lambda r: r.lamport_clock)):
                data = json.dumps({
                    "receipt_id": receipt.receipt_id,
                    "timestamp": receipt.timestamp,
                    "tool_name": receipt.tool_name,
                    "args_hash": receipt.args_hash,
                    "verdict": receipt.verdict,
                    "reason_code": receipt.reason_code,
                    "lamport_clock": receipt.lamport_clock,
                    "prev_hash": receipt.prev_hash,
                    "hash": receipt.hash,
                    "metadata": receipt.metadata,
                }, indent=2).encode()

                info = tarfile.TarInfo(name=f"{i:03d}_{receipt.receipt_id}.json")
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                tar.addfile(info, _io.BytesIO(data))

            manifest = json.dumps({
                "session_id": f"mcp-trust-{int(time.time())}",
                "receipt_count": len(self._receipts),
                "final_hash": self._prev_hash,
                "lamport": self._lamport,
                "proxy": "mcp-trust",
            }, indent=2).encode()
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            tar.addfile(info, _io.BytesIO(manifest))

        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _record_receipt(
        self,
        tool_name: str,
        args_hash: str,
        verdict: str,
        reason_code: str,
    ) -> HelmReceipt:
        """Record a governance receipt with hash chaining."""
        with self._lock:
            self._lamport += 1
            lamport = self._lamport
            prev_hash = self._prev_hash

            preimage = f"{tool_name}|{args_hash}|{verdict}|{reason_code}|{lamport}|{prev_hash}"
            receipt_hash = hashlib.sha256(preimage.encode()).hexdigest()
            self._prev_hash = receipt_hash

        receipt = HelmReceipt(
            receipt_id=f"rcpt-mcp-{receipt_hash[:8]}-{lamport}",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            tool_name=tool_name,
            args_hash=args_hash,
            verdict=verdict,
            reason_code=reason_code,
            lamport_clock=lamport,
            prev_hash=prev_hash,
            hash=receipt_hash,
            metadata={**self.metadata, "principal": self.principal, "protocol": "mcp"},
        )

        if self.collect_receipts:
            with self._lock:
                self._receipts.append(receipt)

        return receipt

    def _call_helm(self, endpoint: str, payload: dict) -> dict:
        """Call the HELM API."""
        url = f"{self.helm_url}{endpoint}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
