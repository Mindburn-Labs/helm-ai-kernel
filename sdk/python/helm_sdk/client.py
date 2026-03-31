"""HELM SDK — Python Client

Typed client for HELM kernel API. Minimal deps (httpx).
"""

from __future__ import annotations

from dataclasses import asdict
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
        resp = self._client.post("/v1/chat/completions", json=asdict(req))
        self._check(resp)
        data = resp.json()
        # Only pass fields that are present in the response to preserve dataclass defaults
        return ChatCompletionResponse(**{k: data[k] for k in ChatCompletionResponse.__dataclass_fields__ if k in data})

    # ── Approval Ceremony ───────────────────────────
    def approve_intent(self, req: ApprovalRequest) -> Receipt:
        resp = self._client.post("/api/v1/kernel/approve", json=asdict(req))
        self._check(resp)
        return Receipt(**resp.json())

    # ── ProofGraph ──────────────────────────────────
    def list_sessions(self, limit: int = 50, offset: int = 0) -> list[Session]:
        resp = self._client.get(f"/api/v1/proofgraph/sessions?limit={limit}&offset={offset}")
        self._check(resp)
        return [Session(**s) for s in resp.json()]

    def get_receipts(self, session_id: str) -> list[Receipt]:
        resp = self._client.get(f"/api/v1/proofgraph/sessions/{session_id}/receipts")
        self._check(resp)
        return [Receipt(**r) for r in resp.json()]

    def get_receipt(self, receipt_hash: str) -> Receipt:
        resp = self._client.get(f"/api/v1/proofgraph/receipts/{receipt_hash}")
        self._check(resp)
        return Receipt(**resp.json())

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
        return VerificationResult(**resp.json())

    def replay_verify(self, bundle: bytes) -> VerificationResult:
        resp = self._client.post(
            "/api/v1/replay/verify",
            files={"bundle": ("pack.tar.gz", bundle, "application/octet-stream")},
        )
        self._check(resp)
        return VerificationResult(**resp.json())

    # ── Conformance ─────────────────────────────────
    def conformance_run(self, req: ConformanceRequest) -> ConformanceResult:
        resp = self._client.post("/api/v1/conformance/run", json=asdict(req))
        self._check(resp)
        return ConformanceResult(**resp.json())

    def get_conformance_report(self, report_id: str) -> ConformanceResult:
        resp = self._client.get(f"/api/v1/conformance/reports/{report_id}")
        self._check(resp)
        return ConformanceResult(**resp.json())

    # ── System ──────────────────────────────────────
    def health(self) -> dict[str, Any]:
        resp = self._client.get("/healthz")
        self._check(resp)
        return resp.json()

    def version(self) -> VersionInfo:
        resp = self._client.get("/version")
        self._check(resp)
        return VersionInfo(**resp.json())
