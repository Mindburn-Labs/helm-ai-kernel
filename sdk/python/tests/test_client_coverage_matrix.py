from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from helm_sdk.client import (
    EvidenceEnvelopeExportRequest,
    HelmApiError,
    HelmClient,
    MCPRegistryApprovalRequest,
    MCPRegistryDiscoverRequest,
    _json_body,
)
from helm_sdk.types_gen import DecisionRequest
from tests.test_generated_models_coverage import CLASSES, _build_model


class FakeResponse:
    def __init__(self, body: Any = None, status_code: int = 200, content: bytes = b"payload") -> None:
        self._body = {} if body is None else body
        self.status_code = status_code
        self.content = content
        if isinstance(self._body, str):
            self.text = self._body
        else:
            try:
                self.text = json.dumps(self._body)
            except TypeError:
                self.text = repr(self._body)

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeHTTPClient:
    def __init__(self) -> None:
        self.responses: list[FakeResponse] = []
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.closed = False

    def queue(self, body: Any = None, *, content: bytes = b"payload", status_code: int = 200) -> None:
        self.responses.append(FakeResponse(body, status_code=status_code, content=content))

    def _next(self, method: str, path: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, path, kwargs))
        return self.responses.pop(0) if self.responses else FakeResponse({})

    def get(self, path: str, **kwargs: Any) -> FakeResponse:
        return self._next("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> FakeResponse:
        return self._next("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> FakeResponse:
        return self._next("PUT", path, **kwargs)

    def close(self) -> None:
        self.closed = True


def model_payload(name: str) -> dict[str, Any]:
    return _build_model(CLASSES[name], (name,)).to_dict()


def model_request(name: str) -> Any:
    return _build_model(CLASSES[name], (name,))


NEGATIVE_VECTOR = {
    "id": "n1",
    "category": "boundary",
    "trigger": "tool",
    "expected_verdict": "DENY",
    "expected_reason_code": "DENY_POLICY_VIOLATION",
    "must_emit_receipt": True,
    "must_not_dispatch": True,
    "must_bind_evidence": ["receipt"],
}

MCP_RECORD = {
    "server_id": "srv",
    "risk": "low",
    "state": "approved",
    "discovered_at": "2026-01-01T00:00:00Z",
}

SANDBOX_PROFILE = {
    "name": "default",
    "kind": "wasi-wazero",
    "runtime": "wasi",
    "hosted": False,
    "deny_network_by_default": True,
    "native_isolation": True,
}

SANDBOX_GRANT = {
    "grant_id": "grant",
    "runtime": "wasi",
    "profile": "default",
    "env": {"A": "B"},
    "network": {"egress": False},
    "declared_at": "2026-01-01T00:00:00Z",
}

ENVELOPE_MANIFEST = {
    "manifest_id": "m1",
    "envelope": "dsse",
    "native_evidence_hash": "hash",
    "native_authority": True,
    "created_at": "2026-01-01T00:00:00Z",
}


class DumpOnly:
    value = "x"

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return {"value": self.value, "kwargs": kwargs}


def test_constructor_sets_headers_timeout_and_close() -> None:
    fake = FakeHTTPClient()
    client_cls = MagicMock(return_value=fake)
    with patch("helm_sdk.client.httpx.Client", client_cls):
        client = HelmClient(
            base_url="http://h/",
            api_key="key",
            tenant_id="tenant",
            timeout=2.5,
            principal_id="principal",
            workspace_id="workspace",
        )
        assert client.base_url == "http://h"
        client.close()

    assert fake.closed is True
    kwargs = client_cls.call_args.kwargs
    assert kwargs["base_url"] == "http://h"
    assert kwargs["timeout"] == 2.5
    assert kwargs["headers"] == {
        "Authorization": "Bearer key",
        "X-Helm-Tenant-ID": "tenant",
        "X-Helm-Principal-ID": "principal",
        "X-Helm-Workspace-ID": "workspace",
    }


def test_evaluate_uses_only_the_canonical_generated_request_fields() -> None:
    fake = FakeHTTPClient()
    fake.queue(model_payload("DecisionRecord"))
    request = DecisionRequest(action="EXECUTE_TOOL", resource="local.echo", context={"request_id": "req-1"})
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h", api_key="key", tenant_id="tenant", principal_id="principal")
        client.evaluate_decision(request)

    assert fake.calls == [
        (
            "POST",
            "/api/v1/evaluate",
            {"json": {"action": request.action, "resource": request.resource, "context": request.context}},
        )
    ]


def test_decision_request_rejects_unknown_fields() -> None:
    payload = {"action": "EXECUTE_TOOL", "resource": "local.echo", "principal": "attacker"}

    with pytest.raises(ValidationError):
        DecisionRequest(**payload)
    with pytest.raises(ValidationError):
        DecisionRequest.from_dict(payload)


def test_evaluate_preserves_explicit_null_context() -> None:
    fake = FakeHTTPClient()
    fake.queue(model_payload("DecisionRecord"))
    request = DecisionRequest(action="EXECUTE_TOOL", resource="local.echo", context=None)
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h", api_key="key", tenant_id="tenant", principal_id="principal")
        client.evaluate_decision(request)

    assert fake.calls == [
        (
            "POST",
            "/api/v1/evaluate",
            {"json": {"action": "EXECUTE_TOOL", "resource": "local.echo", "context": None}},
        )
    ]
    assert "context" not in DecisionRequest.from_dict({"action": "EXECUTE_TOOL", "resource": "local.echo"}).model_fields_set
    assert DecisionRequest.from_dict({"action": "EXECUTE_TOOL", "resource": "local.echo", "context": None}).to_dict()["context"] is None


def test_json_body_handles_dataclass_generated_model_model_dump_and_plain_dict() -> None:
    req = EvidenceEnvelopeExportRequest("m1", "dsse", "hash")
    assert _json_body(req) == {"manifest_id": "m1", "envelope": "dsse", "native_evidence_hash": "hash", "experimental": False}
    assert _json_body(model_request("ApprovalRequest"))["intent_hash"] == "sample"
    assert _json_body(DumpOnly())["kwargs"] == {"by_alias": True, "exclude_none": True}
    assert _json_body({"raw": True}) == {"raw": True}


def test_check_handles_non_object_error_body() -> None:
    fake = FakeHTTPClient()
    fake.queue({"error": "not-an-object"}, status_code=418)
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h")
        with pytest.raises(HelmApiError) as exc_info:
            client.health()
    assert exc_info.value.status == 418
    assert exc_info.value.reason_code == "ERROR_INTERNAL"
    assert exc_info.value.details == {"error": "not-an-object"}


@pytest.mark.parametrize(
    ("method_name", "invoke", "response", "expected_method", "expected_path"),
    [
        ("evaluate_decision", lambda c: c.evaluate_decision(model_request("DecisionRequest")), model_payload("DecisionRecord"), "POST", "/api/v1/evaluate"),
        ("run_public_demo_empty_args", lambda c: c.run_public_demo("read_ticket"), {"ok": True}, "POST", "/api/demo/run"),
        ("run_public_demo_with_args", lambda c: c.run_public_demo("read_ticket", {"id": 1}), {"ok": True}, "POST", "/api/demo/run"),
        ("verify_public_demo_receipt", lambda c: c.verify_public_demo_receipt({"r": 1}, "hash"), {"ok": True}, "POST", "/api/demo/verify"),
        ("export_evidence", lambda c: c.export_evidence("session"), {}, "POST", "/api/v1/evidence/export"),
        ("verify_evidence", lambda c: c.verify_evidence(b"bundle"), model_payload("VerificationResult"), "POST", "/api/v1/evidence/verify"),
        ("replay_verify", lambda c: c.replay_verify(b"bundle"), model_payload("VerificationResult"), "POST", "/api/v1/replay/verify"),
        (
            "create_evidence_envelope_manifest",
            lambda c: c.create_evidence_envelope_manifest(EvidenceEnvelopeExportRequest("m1", "dsse", "hash")),
            ENVELOPE_MANIFEST,
            "POST",
            "/api/v1/evidence/envelopes",
        ),
        ("list_evidence_envelope_manifests", lambda c: c.list_evidence_envelope_manifests(), [{"id": "m1"}], "GET", "/api/v1/evidence/envelopes"),
        ("get_evidence_envelope_manifest", lambda c: c.get_evidence_envelope_manifest("m1"), {"id": "m1"}, "GET", "/api/v1/evidence/envelopes/m1"),
        ("verify_evidence_envelope_manifest", lambda c: c.verify_evidence_envelope_manifest("m1"), {"ok": True}, "POST", "/api/v1/evidence/envelopes/m1/verify"),
        ("get_evidence_envelope_payload", lambda c: c.get_evidence_envelope_payload("m1"), {"payload": True}, "GET", "/api/v1/evidence/envelopes/m1/payload"),
        ("get_boundary_status", lambda c: c.get_boundary_status(), {"status": "ok"}, "GET", "/api/v1/boundary/status"),
        ("list_boundary_capabilities", lambda c: c.list_boundary_capabilities(), [{"cap": "x"}], "GET", "/api/v1/boundary/capabilities"),
        ("list_boundary_records", lambda c: c.list_boundary_records(actor="a", empty=None), [{"id": "r"}], "GET", "/api/v1/boundary/records"),
        ("get_boundary_record", lambda c: c.get_boundary_record("r1"), {"id": "r1"}, "GET", "/api/v1/boundary/records/r1"),
        ("verify_boundary_record", lambda c: c.verify_boundary_record("r1"), {"ok": True}, "POST", "/api/v1/boundary/records/r1/verify"),
        ("list_boundary_checkpoints", lambda c: c.list_boundary_checkpoints(), [{"id": "c"}], "GET", "/api/v1/boundary/checkpoints"),
        ("create_boundary_checkpoint", lambda c: c.create_boundary_checkpoint(), {"id": "c"}, "POST", "/api/v1/boundary/checkpoints"),
        ("verify_boundary_checkpoint", lambda c: c.verify_boundary_checkpoint("c1"), {"ok": True}, "POST", "/api/v1/boundary/checkpoints/c1/verify"),
        ("conformance_run", lambda c: c.conformance_run(model_request("ConformanceRequest")), model_payload("ConformanceResult"), "POST", "/api/v1/conformance/run"),
        ("get_conformance_report", lambda c: c.get_conformance_report("rep"), model_payload("ConformanceResult"), "GET", "/api/v1/conformance/reports/rep"),
        ("list_conformance_reports", lambda c: c.list_conformance_reports(), [{"id": "rep"}], "GET", "/api/v1/conformance/reports"),
        ("list_conformance_vectors", lambda c: c.list_conformance_vectors(), [{"id": "v"}], "GET", "/api/v1/conformance/vectors"),
        ("list_negative_conformance_vectors", lambda c: c.list_negative_conformance_vectors(), [NEGATIVE_VECTOR], "GET", "/api/v1/conformance/negative"),
        ("list_mcp_registry", lambda c: c.list_mcp_registry(), [MCP_RECORD], "GET", "/api/v1/mcp/registry"),
        (
            "discover_mcp_server",
            lambda c: c.discover_mcp_server(MCPRegistryDiscoverRequest("srv")),
            MCP_RECORD,
            "POST",
            "/api/v1/mcp/registry",
        ),
        (
            "approve_mcp_server",
            lambda c: c.approve_mcp_server(MCPRegistryApprovalRequest("srv", "operator", "receipt")),
            MCP_RECORD,
            "POST",
            "/api/v1/mcp/registry/approve",
        ),
        ("get_mcp_registry_record", lambda c: c.get_mcp_registry_record("srv"), MCP_RECORD, "GET", "/api/v1/mcp/registry/srv"),
        ("approve_mcp_registry_record", lambda c: c.approve_mcp_registry_record("srv", {"ok": True}), MCP_RECORD, "POST", "/api/v1/mcp/registry/srv/approve"),
        ("revoke_mcp_registry_record_none", lambda c: c.revoke_mcp_registry_record("srv"), MCP_RECORD, "POST", "/api/v1/mcp/registry/srv/revoke"),
        ("revoke_mcp_registry_record_reason", lambda c: c.revoke_mcp_registry_record("srv", "expired"), MCP_RECORD, "POST", "/api/v1/mcp/registry/srv/revoke"),
        ("scan_mcp_server", lambda c: c.scan_mcp_server({"server_id": "srv"}), {"ok": True}, "POST", "/api/v1/mcp/scan"),
        ("list_mcp_auth_profiles", lambda c: c.list_mcp_auth_profiles(), [{"id": "p"}], "GET", "/api/v1/mcp/auth-profiles"),
        ("put_mcp_auth_profile", lambda c: c.put_mcp_auth_profile("p1", {"kind": "token"}), {"id": "p1"}, "PUT", "/api/v1/mcp/auth-profiles/p1"),
        ("authorize_mcp_call", lambda c: c.authorize_mcp_call({"tool": "x"}), {"allowed": True}, "POST", "/api/v1/mcp/authorize-call"),
        ("inspect_sandbox_grants_list", lambda c: c.inspect_sandbox_grants(), [SANDBOX_PROFILE], "GET", "/api/v1/sandbox/grants/inspect"),
        ("inspect_sandbox_grants_object", lambda c: c.inspect_sandbox_grants("wasi", "default", "1"), SANDBOX_GRANT, "GET", "/api/v1/sandbox/grants/inspect"),
        ("list_sandbox_profiles", lambda c: c.list_sandbox_profiles(), [SANDBOX_PROFILE], "GET", "/api/v1/sandbox/profiles"),
        ("list_sandbox_grants", lambda c: c.list_sandbox_grants(), [SANDBOX_GRANT], "GET", "/api/v1/sandbox/grants"),
        ("create_sandbox_grant", lambda c: c.create_sandbox_grant({"runtime": "wasi"}), SANDBOX_GRANT, "POST", "/api/v1/sandbox/grants"),
        ("get_sandbox_grant", lambda c: c.get_sandbox_grant("grant"), SANDBOX_GRANT, "GET", "/api/v1/sandbox/grants/grant"),
        ("verify_sandbox_grant", lambda c: c.verify_sandbox_grant("grant"), {"ok": True}, "POST", "/api/v1/sandbox/grants/grant/verify"),
        ("preflight_sandbox_grant", lambda c: c.preflight_sandbox_grant({"runtime": "wasi"}), {"ok": True}, "POST", "/api/v1/sandbox/preflight"),
        ("list_agent_identities", lambda c: c.list_agent_identities(), [{"id": "agent"}], "GET", "/api/v1/identity/agents"),
        ("get_authz_health", lambda c: c.get_authz_health(), {"ok": True}, "GET", "/api/v1/authz/health"),
        ("check_authz", lambda c: c.check_authz({"actor": "a"}), {"allowed": True}, "POST", "/api/v1/authz/check"),
        ("list_authz_snapshots", lambda c: c.list_authz_snapshots(), [{"id": "s"}], "GET", "/api/v1/authz/snapshots"),
        ("get_authz_snapshot", lambda c: c.get_authz_snapshot("s1"), {"id": "s1"}, "GET", "/api/v1/authz/snapshots/s1"),
        ("list_approval_ceremonies", lambda c: c.list_approval_ceremonies(), [{"id": "a"}], "GET", "/api/v1/approvals"),
        ("create_approval_ceremony", lambda c: c.create_approval_ceremony({"subject": "x"}), {"id": "a"}, "POST", "/api/v1/approvals"),
        ("transition_approval_ceremony_empty", lambda c: c.transition_approval_ceremony("a1", "approve"), {"id": "a1"}, "POST", "/api/v1/approvals/a1/approve"),
        ("transition_approval_ceremony_body", lambda c: c.transition_approval_ceremony("a1", "deny", {"reason": "x"}), {"id": "a1"}, "POST", "/api/v1/approvals/a1/deny"),
        ("create_approval_webauthn_challenge_empty", lambda c: c.create_approval_webauthn_challenge("a1"), {"challenge": "c"}, "POST", "/api/v1/approvals/a1/webauthn/challenge"),
        ("create_approval_webauthn_challenge_body", lambda c: c.create_approval_webauthn_challenge("a1", {"rp": "x"}), {"challenge": "c"}, "POST", "/api/v1/approvals/a1/webauthn/challenge"),
        ("assert_approval_webauthn_challenge", lambda c: c.assert_approval_webauthn_challenge("a1", {"proof": "p"}), {"ok": True}, "POST", "/api/v1/approvals/a1/webauthn/assert"),
        ("list_budget_ceilings", lambda c: c.list_budget_ceilings(), [{"id": "b"}], "GET", "/api/v1/budgets"),
        ("put_budget_ceiling", lambda c: c.put_budget_ceiling("b1", {"limit": 1}), {"id": "b1"}, "PUT", "/api/v1/budgets/b1"),
        ("get_coexistence_capabilities", lambda c: c.get_coexistence_capabilities(), {"ok": True}, "GET", "/api/v1/coexistence/capabilities"),
        ("get_telemetry_otel_config", lambda c: c.get_telemetry_otel_config(), {"endpoint": "otel"}, "GET", "/api/v1/telemetry/otel/config"),
        ("export_telemetry", lambda c: c.export_telemetry({"format": "json"}), {"ok": True}, "POST", "/api/v1/telemetry/export"),
    ],
)
def test_client_endpoint_matrix(method_name: str, invoke: Any, response: Any, expected_method: str, expected_path: str) -> None:
    fake = FakeHTTPClient()
    content = b"bundle" if method_name == "export_evidence" else b"payload"
    fake.queue(response, content=content)
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h", api_key="key", tenant_id="tenant", principal_id="principal")
        result = invoke(client)

    assert fake.calls[0][0] == expected_method
    assert fake.calls[0][1] == expected_path
    if method_name == "export_evidence":
        assert result == b"bundle"


def test_list_sessions_uses_params_for_query_values() -> None:
    fake = FakeHTTPClient()
    fake.queue([])
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h")
        client.list_sessions(limit=10, offset=5)

    assert fake.calls == [("GET", "/api/v1/proofgraph/sessions", {"params": {"limit": 10, "offset": 5}})]


def test_path_segments_are_encoded_as_single_segments() -> None:
    fake = FakeHTTPClient()
    fake.queue(model_payload("Receipt"))
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h")
        client.get_receipt("sha256:abc+def@key")

    assert fake.calls[0][1] == "/api/v1/proofgraph/receipts/sha256%3Aabc%2Bdef%40key"


@pytest.mark.parametrize("bad_id", ["../other", "a%2fb", "id?debug=true", "id&limit=999", "", "..", "space id"])
def test_path_segment_inputs_reject_scope_and_query_injection(bad_id: str) -> None:
    fake = FakeHTTPClient()
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h")
        with pytest.raises(ValueError):
            client.get_evidence_envelope_manifest(bad_id)

    assert fake.calls == []


def test_session_and_receipt_lists_skip_none_items() -> None:
    fake = FakeHTTPClient()
    fake.queue([model_payload("Session"), None])
    fake.queue([model_payload("Receipt"), None])
    with patch("helm_sdk.client.httpx.Client", return_value=fake):
        client = HelmClient(base_url="http://h")
        assert len(client.list_sessions()) == 1
        assert len(client.get_receipts("session")) == 1
