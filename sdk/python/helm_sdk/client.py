"""HELM SDK — Python Client

Typed client for HELM kernel API. Minimal deps (httpx).
"""

from __future__ import annotations

from typing import Any, Optional

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


def _json_body(model: Any) -> Any:
    """Serialize a generated SDK model into an HTTP JSON payload."""
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
