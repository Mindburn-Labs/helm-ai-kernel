"""HELM Python SDK — Unit Tests

Tests for HelmClient, HelmApiError, and generated types.
Uses unittest.mock to mock httpx.Client.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from helm_sdk import (
    ApprovalRequest,
    ChatCompletionRequest,
    ChatMessage,
    ConformanceRequest,
    EvidenceEnvelopeExportRequest,
    HelmApiError,
    HelmClient,
    MCPRegistryApprovalRequest,
    MCPRegistryDiscoverRequest,
    Receipt,
    VerificationChecks,
    VerificationResult,
)


# ── Helpers ──────────────────────────────────────────────

def mock_response(status_code: int = 200, json_data: object = None, content: bytes = b"") -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.text = json.dumps(json_data) if json_data else ""
    resp.content = content
    return resp


RECEIPT_DATA = {
    "receipt_id": "r1",
    "decision_id": "d1",
    "effect_id": "e1",
    "status": "APPROVED",
    "reason_code": "ALLOW",
    "output_hash": "h",
    "blob_hash": "b",
    "prev_hash": "p",
    "lamport_clock": 1,
    "signature": "s",
    "timestamp": "2026-01-01T00:00:00Z",
    "principal": "pr",
}


# ── HelmApiError ─────────────────────────────────────────

class TestHelmApiError:
    def test_stores_status_and_reason(self) -> None:
        err = HelmApiError(403, "denied", "DENY_POLICY_VIOLATION", {"policy": "no-writes"})
        assert err.status == 403
        assert err.reason_code == "DENY_POLICY_VIOLATION"
        assert err.details == {"policy": "no-writes"}
        assert str(err) == "denied"

    def test_str_representation(self) -> None:
        err = HelmApiError(500, "internal error", "ERROR_INTERNAL")
        assert "internal error" in str(err)


# ── HelmClient Constructor ───────────────────────────────

class TestHelmClientConstructor:
    def test_strips_trailing_slash(self) -> None:
        client = HelmClient(base_url="http://localhost:8080/")
        assert client.base_url == "http://localhost:8080"

    def test_default_base_url(self) -> None:
        client = HelmClient()
        assert client.base_url == "http://localhost:8080"

    def test_context_manager(self) -> None:
        with HelmClient() as client:
            assert client is not None


# ── Chat Completions ─────────────────────────────────────

class TestChatCompletions:
    @patch("helm_sdk.client.httpx.Client")
    def test_posts_to_correct_endpoint(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.post.return_value = mock_response(200, {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-4",
            "choices": [],
        })

        client = HelmClient(base_url="http://h")
        req = ChatCompletionRequest(model="gpt-4", messages=[ChatMessage(role="user", content="hi")])
        result = client.chat_completions(req)

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "/v1/chat/completions"
        assert result.id == "chatcmpl-1"


# ── Approve Intent ───────────────────────────────────────

class TestApproveIntent:
    @patch("helm_sdk.client.httpx.Client")
    def test_posts_approval_request(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.post.return_value = mock_response(200, RECEIPT_DATA)

        client = HelmClient(base_url="http://h")
        req = ApprovalRequest(intent_hash="abc", signature_b64="s", public_key_b64="pk")
        result = client.approve_intent(req)

        mock_client.post.assert_called_once()
        assert result.receipt_id == "r1"
        assert result.status == "APPROVED"


# ── ProofGraph ───────────────────────────────────────────

class TestProofGraph:
    @patch("helm_sdk.client.httpx.Client")
    def test_list_sessions(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(200, [
            {"session_id": "s1", "created_at": "2026-01-01T00:00:00Z", "receipt_count": 1, "last_lamport_clock": 1},
        ])

        client = HelmClient(base_url="http://h")
        result = client.list_sessions(10, 5)

        mock_client.get.assert_called_once()
        assert len(result) == 1
        assert result[0].session_id == "s1"

    @patch("helm_sdk.client.httpx.Client")
    def test_get_receipts(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(200, [RECEIPT_DATA])

        client = HelmClient(base_url="http://h")
        result = client.get_receipts("sess-1")

        assert len(result) == 1
        assert result[0].receipt_id == "r1"

    @patch("helm_sdk.client.httpx.Client")
    def test_get_receipt(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(200, RECEIPT_DATA)

        client = HelmClient(base_url="http://h")
        result = client.get_receipt("hash-abc")
        assert result.receipt_id == "r1"


# ── Error Handling ───────────────────────────────────────

class TestErrorHandling:
    @patch("helm_sdk.client.httpx.Client")
    def test_raises_helm_api_error_on_4xx(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(422, {
            "error": {
                "message": "bad schema",
                "type": "invalid_request",
                "code": "ERR",
                "reason_code": "DENY_SCHEMA_MISMATCH",
            }
        })

        client = HelmClient(base_url="http://h")
        with pytest.raises(HelmApiError) as exc_info:
            client.health()

        assert exc_info.value.status == 422
        assert exc_info.value.reason_code == "DENY_SCHEMA_MISMATCH"

    @patch("helm_sdk.client.httpx.Client")
    def test_raises_on_malformed_error_body(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        resp = MagicMock()
        resp.status_code = 500
        resp.json.side_effect = ValueError("no JSON")
        resp.text = "Internal Server Error"
        mock_client.get.return_value = resp

        client = HelmClient(base_url="http://h")
        with pytest.raises(HelmApiError) as exc_info:
            client.health()

        assert exc_info.value.status == 500
        assert exc_info.value.reason_code == "ERROR_INTERNAL"


# ── System Endpoints ─────────────────────────────────────

class TestSystemEndpoints:
    @patch("helm_sdk.client.httpx.Client")
    def test_health(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(200, {"status": "ok", "version": "0.1.0"})

        client = HelmClient(base_url="http://h")
        result = client.health()
        assert result["status"] == "ok"

    @patch("helm_sdk.client.httpx.Client")
    def test_version(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(200, {
            "version": "0.1.0",
            "commit": "abc123",
            "build_time": "2026-01-01T00:00:00Z",
            "go_version": "1.24",
        })

        client = HelmClient(base_url="http://h")
        result = client.version()
        assert result.version == "0.1.0"
        assert result.commit == "abc123"


# ── Generated Types ──────────────────────────────────────

class TestGeneratedTypes:
    def test_chat_message_alias(self) -> None:
        msg = ChatMessage(role="user", content="hello")
        assert msg.role == "user"
        assert msg.content == "hello"

    def test_receipt_model_dump(self) -> None:
        r = Receipt(**RECEIPT_DATA)
        payload = r.to_dict()
        assert r.receipt_id == "r1"
        assert payload["status"] == "APPROVED"

    def test_conformance_request_defaults(self) -> None:
        req = ConformanceRequest(level="L1")
        assert req.level == "L1"
        assert req.profile == "full"

    def test_verification_result(self) -> None:
        vr = VerificationResult(
            verdict="PASS",
            checks=VerificationChecks(signatures="PASS", causal_chain="PASS"),
            errors=[],
        )
        assert vr.verdict == "PASS"
        assert len(vr.errors) == 0


# ── Execution Boundary Surfaces ─────────────────────────

class TestExecutionBoundarySurfaces:
    @patch("helm_sdk.client.httpx.Client")
    def test_create_evidence_envelope_manifest(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.post.return_value = mock_response(200, {
            "manifest_id": "env1",
            "envelope": "dsse",
            "native_evidence_hash": "sha256:native",
            "native_authority": True,
            "created_at": "2026-05-05T00:00:00Z",
        })

        client = HelmClient(base_url="http://h")
        result = client.create_evidence_envelope_manifest(
            EvidenceEnvelopeExportRequest(
                manifest_id="env1",
                envelope="dsse",
                native_evidence_hash="sha256:native",
            )
        )

        mock_client.post.assert_called_once()
        assert mock_client.post.call_args[0][0] == "/api/v1/evidence/envelopes"
        assert result.native_authority is True

    @patch("helm_sdk.client.httpx.Client")
    def test_list_negative_conformance_vectors(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(200, [{
            "id": "pdp-outage",
            "category": "policy",
            "trigger": "PDP unavailable",
            "expected_verdict": "DENY",
            "expected_reason_code": "PDP_ERROR",
            "must_emit_receipt": True,
            "must_not_dispatch": True,
        }])

        client = HelmClient(base_url="http://h")
        result = client.list_negative_conformance_vectors()

        mock_client.get.assert_called_once_with("/api/v1/conformance/negative")
        assert result[0].id == "pdp-outage"

    @patch("helm_sdk.client.httpx.Client")
    def test_mcp_registry_methods(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        record = {
            "server_id": "mcp1",
            "risk": "high",
            "state": "quarantined",
            "discovered_at": "2026-05-05T00:00:00Z",
        }
        mock_client.post.return_value = mock_response(200, record)

        client = HelmClient(base_url="http://h")
        discovered = client.discover_mcp_server(MCPRegistryDiscoverRequest(server_id="mcp1", risk="high"))
        assert discovered.state == "quarantined"

        mock_client.post.return_value = mock_response(200, {**record, "state": "approved"})
        approved = client.approve_mcp_server(
            MCPRegistryApprovalRequest(
                server_id="mcp1",
                approver_id="user1",
                approval_receipt_id="rcpt1",
            )
        )
        assert approved.state == "approved"

    @patch("helm_sdk.client.httpx.Client")
    def test_inspect_sandbox_grants(self, mock_client_cls: MagicMock) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.get.return_value = mock_response(200, {
            "grant_id": "grant1",
            "runtime": "wazero",
            "profile": "deny-default",
            "env": {"mode": "deny-all"},
            "network": {"mode": "deny-all"},
            "declared_at": "2026-05-05T00:00:00Z",
        })

        client = HelmClient(base_url="http://h")
        result = client.inspect_sandbox_grants("wazero", "deny-default", "epoch1")

        mock_client.get.assert_called_once_with(
            "/api/v1/sandbox/grants/inspect",
            params={"runtime": "wazero", "profile": "deny-default", "policy_epoch": "epoch1"},
        )
        assert not isinstance(result, list)
        assert result.grant_id == "grant1"
