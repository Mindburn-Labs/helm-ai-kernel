"""HELM SDK — Python Client

Typed client for HELM kernel API. Minimal deps (httpx).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Optional, Union

import httpx

from .types_gen import (
    ApprovalRequest,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ConformanceRequest,
    ConformanceResult,
    Receipt,
    Session,
    VerificationResult,
    VersionInfo,
)


@dataclass
class EvidenceEnvelopeExportRequest:
    manifest_id: str
    envelope: str
    native_evidence_hash: str
    subject: Optional[str] = None
    experimental: bool = False


@dataclass
class EvidenceEnvelopeManifest:
    manifest_id: str
    envelope: str
    native_evidence_hash: str
    native_authority: bool
    created_at: str
    subject: Optional[str] = None
    statement_hash: Optional[str] = None
    experimental: bool = False
    manifest_hash: Optional[str] = None


@dataclass
class NegativeBoundaryVector:
    id: str
    category: str
    trigger: str
    expected_verdict: str
    expected_reason_code: str
    must_emit_receipt: bool
    must_not_dispatch: bool
    must_bind_evidence: Optional[list[str]] = None


@dataclass
class MCPRegistryDiscoverRequest:
    server_id: str
    name: Optional[str] = None
    transport: Optional[str] = None
    endpoint: Optional[str] = None
    tool_names: Optional[list[str]] = None
    risk: str = "unknown"
    reason: Optional[str] = None


@dataclass
class MCPRegistryApprovalRequest:
    server_id: str
    approver_id: str
    approval_receipt_id: str
    reason: Optional[str] = None


@dataclass
class MCPQuarantineRecord:
    server_id: str
    risk: str
    state: str
    discovered_at: str
    name: Optional[str] = None
    transport: Optional[str] = None
    endpoint: Optional[str] = None
    tool_names: Optional[list[str]] = None
    approved_at: Optional[str] = None
    approved_by: Optional[str] = None
    approval_receipt_id: Optional[str] = None
    revoked_at: Optional[str] = None
    expires_at: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class SandboxBackendProfile:
    name: str
    kind: str
    runtime: str
    hosted: bool
    deny_network_by_default: bool
    native_isolation: bool
    experimental: bool = False


@dataclass
class SandboxGrant:
    grant_id: str
    runtime: str
    profile: str
    env: dict[str, Any]
    network: dict[str, Any]
    declared_at: str
    runtime_version: Optional[str] = None
    image_digest: Optional[str] = None
    template_digest: Optional[str] = None
    filesystem_preopens: Optional[list[dict[str, Any]]] = None
    limits: Optional[dict[str, Any]] = None
    policy_epoch: Optional[str] = None
    grant_hash: Optional[str] = None


def _json_body(model: Any) -> Any:
    """Serialize a generated SDK model into an HTTP JSON payload."""
    if hasattr(model, "__dataclass_fields__"):
        return {k: v for k, v in asdict(model).items() if v is not None}
    if hasattr(model, "to_dict"):
        return model.to_dict()
    if hasattr(model, "model_dump"):
        return model.model_dump(by_alias=True, exclude_none=True)
    return model


class HelmApiError(Exception):
    """Raised when the HELM API returns a non-2xx response."""

    def __init__(self, status: int, message: str, reason_code: str, details: Any = None):
        super().__init__(message)
        self.status = status
        self.reason_code = reason_code
        self.details = details


class HelmClient:
    """Typed client for HELM kernel API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HelmClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _check(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            try:
                body = resp.json()
                err = body.get("error", {})
                raise HelmApiError(
                    status=resp.status_code,
                    message=err.get("message", resp.text),
                    reason_code=err.get("reason_code", "ERROR_INTERNAL"),
                    details=err.get("details"),
                )
            except (ValueError, KeyError):
                raise HelmApiError(
                    status=resp.status_code,
                    message=resp.text,
                    reason_code="ERROR_INTERNAL",
                )

    # ── OpenAI Proxy ────────────────────────────────
    def chat_completions(self, req: ChatCompletionRequest) -> ChatCompletionResponse:
        resp = self._client.post("/v1/chat/completions", json=_json_body(req))
        self._check(resp)
        result = ChatCompletionResponse.from_dict(resp.json())
        assert result is not None
        return result

    # ── Approval Ceremony ───────────────────────────
    def approve_intent(self, req: ApprovalRequest) -> Receipt:
        resp = self._client.post("/api/v1/kernel/approve", json=_json_body(req))
        self._check(resp)
        result = Receipt.from_dict(resp.json())
        assert result is not None
        return result

    # ── ProofGraph ──────────────────────────────────
    def list_sessions(self, limit: int = 50, offset: int = 0) -> list[Session]:
        resp = self._client.get(f"/api/v1/proofgraph/sessions?limit={limit}&offset={offset}")
        self._check(resp)
        sessions: list[Session] = []
        for item in resp.json():
            session = Session.from_dict(item)
            if session is not None:
                sessions.append(session)
        return sessions

    def get_receipts(self, session_id: str) -> list[Receipt]:
        resp = self._client.get(f"/api/v1/proofgraph/sessions/{session_id}/receipts")
        self._check(resp)
        receipts: list[Receipt] = []
        for item in resp.json():
            receipt = Receipt.from_dict(item)
            if receipt is not None:
                receipts.append(receipt)
        return receipts

    def get_receipt(self, receipt_hash: str) -> Receipt:
        resp = self._client.get(f"/api/v1/proofgraph/receipts/{receipt_hash}")
        self._check(resp)
        result = Receipt.from_dict(resp.json())
        assert result is not None
        return result

    # ── Evidence ────────────────────────────────────
    def export_evidence(self, session_id: Optional[str] = None) -> bytes:
        resp = self._client.post(
            "/api/v1/evidence/export",
            json={"session_id": session_id, "format": "tar.gz"},
        )
        self._check(resp)
        return resp.content

    def verify_evidence(self, bundle: bytes) -> VerificationResult:
        resp = self._client.post(
            "/api/v1/evidence/verify",
            files={"bundle": ("pack.tar.gz", bundle, "application/octet-stream")},
        )
        self._check(resp)
        result = VerificationResult.from_dict(resp.json())
        assert result is not None
        return result

    def replay_verify(self, bundle: bytes) -> VerificationResult:
        resp = self._client.post(
            "/api/v1/replay/verify",
            files={"bundle": ("pack.tar.gz", bundle, "application/octet-stream")},
        )
        self._check(resp)
        result = VerificationResult.from_dict(resp.json())
        assert result is not None
        return result

    def create_evidence_envelope_manifest(
        self,
        req: EvidenceEnvelopeExportRequest,
    ) -> EvidenceEnvelopeManifest:
        resp = self._client.post("/api/v1/evidence/envelopes", json=_json_body(req))
        self._check(resp)
        return EvidenceEnvelopeManifest(**resp.json())

    # ── Conformance ─────────────────────────────────
    def conformance_run(self, req: ConformanceRequest) -> ConformanceResult:
        resp = self._client.post("/api/v1/conformance/run", json=_json_body(req))
        self._check(resp)
        result = ConformanceResult.from_dict(resp.json())
        assert result is not None
        return result

    def get_conformance_report(self, report_id: str) -> ConformanceResult:
        resp = self._client.get(f"/api/v1/conformance/reports/{report_id}")
        self._check(resp)
        result = ConformanceResult.from_dict(resp.json())
        assert result is not None
        return result

    def list_negative_conformance_vectors(self) -> list[NegativeBoundaryVector]:
        resp = self._client.get("/api/v1/conformance/negative")
        self._check(resp)
        return [NegativeBoundaryVector(**item) for item in resp.json()]

    # ── MCP Registry ────────────────────────────────
    def list_mcp_registry(self) -> list[MCPQuarantineRecord]:
        resp = self._client.get("/api/v1/mcp/registry")
        self._check(resp)
        return [MCPQuarantineRecord(**item) for item in resp.json()]

    def discover_mcp_server(
        self,
        req: MCPRegistryDiscoverRequest,
    ) -> MCPQuarantineRecord:
        resp = self._client.post("/api/v1/mcp/registry", json=_json_body(req))
        self._check(resp)
        return MCPQuarantineRecord(**resp.json())

    def approve_mcp_server(
        self,
        req: MCPRegistryApprovalRequest,
    ) -> MCPQuarantineRecord:
        resp = self._client.post("/api/v1/mcp/registry/approve", json=_json_body(req))
        self._check(resp)
        return MCPQuarantineRecord(**resp.json())

    # ── Sandbox ─────────────────────────────────────
    def inspect_sandbox_grants(
        self,
        runtime: Optional[str] = None,
        profile: Optional[str] = None,
        policy_epoch: Optional[str] = None,
    ) -> Union[list[SandboxBackendProfile], SandboxGrant]:
        params = {
            k: v
            for k, v in {
                "runtime": runtime,
                "profile": profile,
                "policy_epoch": policy_epoch,
            }.items()
            if v is not None
        }
        resp = self._client.get("/api/v1/sandbox/grants/inspect", params=params)
        self._check(resp)
        body = resp.json()
        if isinstance(body, list):
            return [SandboxBackendProfile(**item) for item in body]
        return SandboxGrant(**body)

    # ── System ──────────────────────────────────────
    def health(self) -> dict[str, Any]:
        resp = self._client.get("/healthz")
        self._check(resp)
        return resp.json()

    def version(self) -> VersionInfo:
        resp = self._client.get("/version")
        self._check(resp)
        result = VersionInfo.from_dict(resp.json())
        assert result is not None
        return result
