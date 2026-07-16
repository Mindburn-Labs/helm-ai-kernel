package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExecutionBoundaryClientMethods(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/evidence/envelopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		writeJSON(t, w, EvidenceEnvelopeManifest{
			ManifestID:         "env1",
			Envelope:           "dsse",
			NativeEvidenceHash: "sha256:native",
			NativeAuthority:    true,
			PayloadHash:        "sha256:payload",
		})
	})
	mux.HandleFunc("/api/v1/evidence/envelopes/env1/payload", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, EvidenceEnvelopePayload{"manifest_id": "env1", "payload_hash": "sha256:payload"})
	})
	mux.HandleFunc("/api/v1/boundary/checkpoints/cp1/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, SurfaceRecord{"verdict": "PASS", "checkpoint_id": "cp1"})
	})
	mux.HandleFunc("/api/v1/approvals/ap1/webauthn/challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, ApprovalWebAuthnChallenge{"challenge_id": "ch1", "approval_id": "ap1"})
	})
	mux.HandleFunc("/api/v1/approvals/ap1/webauthn/assert", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, ApprovalCeremony{"approval_id": "ap1", "state": "approved"})
	})
	mux.HandleFunc("/api/v1/conformance/negative", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, []NegativeBoundaryVector{{ID: "pdp-outage", Category: "policy"}})
	})
	mux.HandleFunc("/api/v1/mcp/registry", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, MCPQuarantineRecord{ServerID: "mcp1", Risk: "high", State: "quarantined"})
	})
	mux.HandleFunc("/api/v1/mcp/registry/approve", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, MCPQuarantineRecord{ServerID: "mcp1", Risk: "high", State: "approved"})
	})
	mux.HandleFunc("/api/v1/sandbox/grants/inspect", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("runtime") == "" {
			writeJSON(t, w, []SandboxBackendProfile{{Name: "wazero-deny-default", Runtime: "wazero"}})
			return
		}
		writeJSON(t, w, SandboxGrant{GrantID: "grant1", Runtime: "wazero", Profile: "deny-default"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client := New(server.URL)

	manifest, err := client.CreateEvidenceEnvelopeManifest(EvidenceEnvelopeExportRequest{
		ManifestID:         "env1",
		Envelope:           "dsse",
		NativeEvidenceHash: "sha256:native",
	})
	if err != nil || !manifest.NativeAuthority {
		t.Fatalf("manifest = %#v, err = %v", manifest, err)
	}
	if manifest.PayloadHash != "sha256:payload" {
		t.Fatalf("payload hash = %q", manifest.PayloadHash)
	}
	payload, err := client.GetEvidenceEnvelopePayload("env1")
	if err != nil || (*payload)["payload_hash"] != "sha256:payload" {
		t.Fatalf("payload = %#v, err = %v", payload, err)
	}
	checkpoint, err := client.VerifyBoundaryCheckpoint("cp1")
	if err != nil || (*checkpoint)["verdict"] != "PASS" {
		t.Fatalf("checkpoint = %#v, err = %v", checkpoint, err)
	}
	challenge, err := client.CreateApprovalWebAuthnChallenge("ap1", SurfaceRecord{"actor": "user1"})
	if err != nil || (*challenge)["challenge_id"] != "ch1" {
		t.Fatalf("challenge = %#v, err = %v", challenge, err)
	}
	asserted, err := client.AssertApprovalWebAuthnChallenge("ap1", ApprovalWebAuthnAssertion{"challenge_id": "ch1", "assertion": "sig"})
	if err != nil || (*asserted)["state"] != "approved" {
		t.Fatalf("asserted = %#v, err = %v", asserted, err)
	}
	vectors, err := client.ListNegativeConformanceVectors()
	if err != nil || vectors[0].ID != "pdp-outage" {
		t.Fatalf("vectors = %#v, err = %v", vectors, err)
	}
	record, err := client.DiscoverMCPServer(MCPRegistryDiscoverRequest{ServerID: "mcp1", Risk: "high"})
	if err != nil || record.State != "quarantined" {
		t.Fatalf("discover = %#v, err = %v", record, err)
	}
	approved, err := client.ApproveMCPServer(MCPRegistryApprovalRequest{
		ServerID:          "mcp1",
		ApproverID:        "user1",
		ApprovalReceiptID: "rcpt1",
	})
	if err != nil || approved.State != "approved" {
		t.Fatalf("approve = %#v, err = %v", approved, err)
	}
	profiles, err := client.ListSandboxBackendProfiles()
	if err != nil || profiles[0].Runtime != "wazero" {
		t.Fatalf("profiles = %#v, err = %v", profiles, err)
	}
	grant, err := client.InspectSandboxGrant("wazero", "deny-default", "epoch1")
	if err != nil || grant.GrantID != "grant1" {
		t.Fatalf("grant = %#v, err = %v", grant, err)
	}
}

func TestGoClientEndpointCoverageMatrix(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing authorization header for %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("X-Helm-Tenant-ID") != "tenant-a" {
			t.Fatalf("missing tenant header for %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("X-Helm-Principal-ID") != "operator-a" {
			t.Fatalf("missing principal header for %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("X-Helm-Workspace-ID") != "workspace-a" {
			t.Fatalf("missing workspace header for %s %s", r.Method, r.URL.RequestURI())
		}
		if r.URL.Path == "/api/v1/evaluate" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode evaluate body: %v", err)
			}
			if len(body) != 2 || body["action"] != "EXECUTE_TOOL" || body["resource"] != "local.echo" {
				t.Fatalf("evaluate body must contain only the canonical request fields: %#v", body)
			}
			writeJSON(t, w, DecisionRecord{})
			return
		}
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("X-Helm-Receipt-ID", "receipt-1")
			w.Header().Set("X-Helm-Status", "ALLOW")
			w.Header().Set("X-Helm-Output-Hash", "sha256:out")
			w.Header().Set("X-Helm-Lamport-Clock", "7")
			w.Header().Set("X-Helm-Reason-Code", "ALLOW")
			w.Header().Set("X-Helm-Decision-ID", "decision-1")
			w.Header().Set("X-Helm-ProofGraph-Node", "proof-1")
			w.Header().Set("X-Helm-Signature", "sig")
			w.Header().Set("X-Helm-Tool-Calls", "2")
		}
		if r.URL.Path == "/api/v1/evidence/export" {
			_, _ = w.Write([]byte("tgz"))
			return
		}
		writeJSON(t, w, responseForClientMatrix(r.Method, r.URL))
	}))
	defer server.Close()
	client := New(server.URL, WithAPIKey("token"), WithTenantID("tenant-a"), WithPrincipalID("operator-a"), WithWorkspaceID("workspace-a"))

	cases := []struct {
		name string
		want string
		call func() error
	}{
		{"chat completions", "POST /v1/chat/completions", func() error {
			_, err := client.ChatCompletions(ChatCompletionRequest{})
			return err
		}},
		{"chat completions with receipt", "POST /v1/chat/completions", func() error {
			got, err := client.ChatCompletionsWithReceipt(ChatCompletionRequest{})
			if err == nil && (got.Governance.ReceiptID != "receipt-1" || got.Governance.LamportClock != 7 || got.Governance.ToolCalls != 2) {
				t.Fatalf("governance headers not parsed: %+v", got.Governance)
			}
			return err
		}},
		{"evaluate decision", "POST /api/v1/evaluate", func() error {
			_, err := client.EvaluateDecision(DecisionRequest{
				Action:   "EXECUTE_TOOL",
				Resource: "local.echo",
			})
			return err
		}},
		{"run public demo", "POST /api/demo/run", func() error { _, err := client.RunPublicDemo("read_ticket", SurfaceRecord{"id": 1}); return err }},
		{"verify public demo receipt", "POST /api/demo/verify", func() error {
			_, err := client.VerifyPublicDemoReceipt(SurfaceRecord{"receipt_id": "r1"}, "hash")
			return err
		}},
		{"approve intent", "POST /api/v1/kernel/approve", func() error { _, err := client.ApproveIntent(ApprovalRequest{}); return err }},
		{"list sessions", "GET /api/v1/proofgraph/sessions?limit=7&offset=3", func() error { _, err := client.ListSessions(7, 3); return err }},
		{"get receipts", "GET /api/v1/proofgraph/sessions/session%2Fone/receipts", func() error { _, err := client.GetReceipts("session/one"); return err }},
		{"get receipt", "GET /api/v1/proofgraph/receipts/receipt%23one", func() error { _, err := client.GetReceipt("receipt#one"); return err }},
		{"export evidence", "POST /api/v1/evidence/export", func() error { _, err := client.ExportEvidence("session"); return err }},
		{"verify evidence", "POST /api/v1/evidence/verify", func() error { _, err := client.VerifyEvidence([]byte("bundle")); return err }},
		{"replay verify", "POST /api/v1/replay/verify", func() error { _, err := client.ReplayVerify([]byte("bundle")); return err }},
		{"create evidence envelope", "POST /api/v1/evidence/envelopes", func() error {
			_, err := client.CreateEvidenceEnvelopeManifest(EvidenceEnvelopeExportRequest{ManifestID: "m1", Envelope: "dsse", NativeEvidenceHash: "hash"})
			return err
		}},
		{"list evidence envelopes", "GET /api/v1/evidence/envelopes", func() error { _, err := client.ListEvidenceEnvelopeManifests(); return err }},
		{"get evidence envelope", "GET /api/v1/evidence/envelopes/manifest%2Fa%20b", func() error { _, err := client.GetEvidenceEnvelopeManifest("manifest/a b"); return err }},
		{"verify evidence envelope", "POST /api/v1/evidence/envelopes/manifest%2Fa%20b/verify", func() error {
			_, err := client.VerifyEvidenceEnvelopeManifest("manifest/a b")
			return err
		}},
		{"get evidence payload", "GET /api/v1/evidence/envelopes/manifest%2Fa%20b/payload", func() error {
			_, err := client.GetEvidenceEnvelopePayload("manifest/a b")
			return err
		}},
		{"boundary status", "GET /api/v1/boundary/status", func() error { _, err := client.GetBoundaryStatus(); return err }},
		{"boundary capabilities", "GET /api/v1/boundary/capabilities", func() error { _, err := client.ListBoundaryCapabilities(); return err }},
		{"boundary records", "GET /api/v1/boundary/records?limit=10&offset=0", func() error {
			_, err := client.ListBoundaryRecords(url.Values{"limit": {"10"}, "offset": {"0"}})
			return err
		}},
		{"get boundary record", "GET /api/v1/boundary/records/record%2Fa%20b", func() error { _, err := client.GetBoundaryRecord("record/a b"); return err }},
		{"verify boundary record", "POST /api/v1/boundary/records/record%2Fa%20b/verify", func() error {
			_, err := client.VerifyBoundaryRecord("record/a b")
			return err
		}},
		{"boundary checkpoints", "GET /api/v1/boundary/checkpoints", func() error { _, err := client.ListBoundaryCheckpoints(); return err }},
		{"create boundary checkpoint", "POST /api/v1/boundary/checkpoints", func() error { _, err := client.CreateBoundaryCheckpoint(); return err }},
		{"verify boundary checkpoint", "POST /api/v1/boundary/checkpoints/checkpoint%2Fa%20b/verify", func() error {
			_, err := client.VerifyBoundaryCheckpoint("checkpoint/a b")
			return err
		}},
		{"conformance run", "POST /api/v1/conformance/run", func() error { _, err := client.ConformanceRun(ConformanceRequest{}); return err }},
		{"get conformance report", "GET /api/v1/conformance/reports/report-1", func() error { _, err := client.GetConformanceReport("report-1"); return err }},
		{"list conformance reports", "GET /api/v1/conformance/reports", func() error { _, err := client.ListConformanceReports(); return err }},
		{"list conformance vectors", "GET /api/v1/conformance/vectors", func() error { _, err := client.ListConformanceVectors(); return err }},
		{"list negative vectors", "GET /api/v1/conformance/negative", func() error { _, err := client.ListNegativeConformanceVectors(); return err }},
		{"list mcp registry", "GET /api/v1/mcp/registry", func() error { _, err := client.ListMCPRegistry(); return err }},
		{"discover mcp", "POST /api/v1/mcp/registry", func() error {
			_, err := client.DiscoverMCPServer(MCPRegistryDiscoverRequest{ServerID: "srv"})
			return err
		}},
		{"approve mcp", "POST /api/v1/mcp/registry/approve", func() error {
			_, err := client.ApproveMCPServer(MCPRegistryApprovalRequest{ServerID: "srv", ApproverID: "me", ApprovalReceiptID: "receipt"})
			return err
		}},
		{"get mcp record", "GET /api/v1/mcp/registry/srv%2Fa%20b", func() error { _, err := client.GetMCPRegistryRecord("srv/a b"); return err }},
		{"approve mcp record", "POST /api/v1/mcp/registry/srv%2Fa%20b/approve", func() error {
			_, err := client.ApproveMCPRegistryRecord("srv/a b", MCPRegistryApprovalRequest{ServerID: "srv", ApproverID: "me", ApprovalReceiptID: "receipt"})
			return err
		}},
		{"revoke mcp record", "POST /api/v1/mcp/registry/srv%2Fa%20b/revoke", func() error { _, err := client.RevokeMCPRegistryRecord("srv/a b", "stale"); return err }},
		{"scan mcp", "POST /api/v1/mcp/scan", func() error { _, err := client.ScanMCPServer(MCPScanRequest{"server_id": "srv"}); return err }},
		{"list mcp auth profiles", "GET /api/v1/mcp/auth-profiles", func() error { _, err := client.ListMCPAuthProfiles(); return err }},
		{"put mcp auth profile", "PUT /api/v1/mcp/auth-profiles/profile%2Fa%20b", func() error {
			_, err := client.PutMCPAuthProfile("profile/a b", MCPAuthorizationProfile{"scopes": []string{"tools"}})
			return err
		}},
		{"authorize mcp call", "POST /api/v1/mcp/authorize-call", func() error { _, err := client.AuthorizeMCPCall(MCPAuthorizeCallRequest{"tool": "read"}); return err }},
		{"list sandbox backends", "GET /api/v1/sandbox/grants/inspect", func() error { _, err := client.ListSandboxBackendProfiles(); return err }},
		{"inspect sandbox grant", "GET /api/v1/sandbox/grants/inspect?policy_epoch=epoch&profile=profile&runtime=runtime", func() error {
			_, err := client.InspectSandboxGrant("runtime", "profile", "epoch")
			return err
		}},
		{"list sandbox profiles", "GET /api/v1/sandbox/profiles", func() error { _, err := client.ListSandboxProfiles(); return err }},
		{"list sandbox grants", "GET /api/v1/sandbox/grants", func() error { _, err := client.ListSandboxGrants(); return err }},
		{"create sandbox grant", "POST /api/v1/sandbox/grants", func() error { _, err := client.CreateSandboxGrant(SurfaceRecord{"runtime": "wasi"}); return err }},
		{"get sandbox grant", "GET /api/v1/sandbox/grants/grant%2Fa%20b", func() error { _, err := client.GetSandboxGrant("grant/a b"); return err }},
		{"verify sandbox grant", "POST /api/v1/sandbox/grants/grant%2Fa%20b/verify", func() error {
			_, err := client.VerifySandboxGrant("grant/a b")
			return err
		}},
		{"preflight sandbox", "POST /api/v1/sandbox/preflight", func() error {
			_, err := client.PreflightSandboxGrant(SandboxPreflightRequest{"runtime": "wasi"})
			return err
		}},
		{"list identities", "GET /api/v1/identity/agents", func() error { _, err := client.ListAgentIdentities(); return err }},
		{"authz health", "GET /api/v1/authz/health", func() error { _, err := client.GetAuthzHealth(); return err }},
		{"check authz", "POST /api/v1/authz/check", func() error { _, err := client.CheckAuthz(SurfaceRecord{"subject": "agent"}); return err }},
		{"list authz snapshots", "GET /api/v1/authz/snapshots", func() error { _, err := client.ListAuthzSnapshots(); return err }},
		{"get authz snapshot", "GET /api/v1/authz/snapshots/snapshot%2Fa%20b", func() error { _, err := client.GetAuthzSnapshot("snapshot/a b"); return err }},
		{"list approvals", "GET /api/v1/approvals", func() error { _, err := client.ListApprovalCeremonies(); return err }},
		{"create approval", "POST /api/v1/approvals", func() error {
			_, err := client.CreateApprovalCeremony(ApprovalCeremony{"approval_id": "a1"})
			return err
		}},
		{"transition approval", "POST /api/v1/approvals/approval%2Fa%20b/approve", func() error {
			_, err := client.TransitionApprovalCeremony("approval/a b", "approve", SurfaceRecord{"reason": "ok"})
			return err
		}},
		{"approval webauthn challenge", "POST /api/v1/approvals/approval%2Fa%20b/webauthn/challenge", func() error {
			_, err := client.CreateApprovalWebAuthnChallenge("approval/a b", SurfaceRecord{"user": "me"})
			return err
		}},
		{"approval webauthn assert", "POST /api/v1/approvals/approval%2Fa%20b/webauthn/assert", func() error {
			_, err := client.AssertApprovalWebAuthnChallenge("approval/a b", ApprovalWebAuthnAssertion{"credential": "c"})
			return err
		}},
		{"list budgets", "GET /api/v1/budgets", func() error { _, err := client.ListBudgetCeilings(); return err }},
		{"put budget", "PUT /api/v1/budgets/budget%2Fa%20b", func() error { _, err := client.PutBudgetCeiling("budget/a b", BudgetCeiling{"limit": 1}); return err }},
		{"coexistence", "GET /api/v1/coexistence/capabilities", func() error { _, err := client.GetCoexistenceCapabilities(); return err }},
		{"otel config", "GET /api/v1/telemetry/otel/config", func() error { _, err := client.GetTelemetryOTelConfig(); return err }},
		{"export telemetry", "POST /api/v1/telemetry/export", func() error { _, err := client.ExportTelemetry(TelemetryExportRequest{"span": "all"}); return err }},
		{"health", "GET /healthz", func() error { _, err := client.Health(); return err }},
		{"version", "GET /version", func() error { _, err := client.Version(); return err }},
	}

	for i, tc := range cases {
		if err := tc.call(); err != nil {
			t.Fatalf("%s returned error: %v", tc.name, err)
		}
		if got := seen[i]; got != tc.want {
			t.Fatalf("%s request = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestEvaluateDecisionPreservesExplicitNullContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/evaluate" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode evaluate body: %v", err)
		}
		if len(body) != 3 || body["action"] != "EXECUTE_TOOL" || body["resource"] != "local.echo" {
			t.Fatalf("evaluate body = %#v", body)
		}
		context, exists := body["context"]
		if !exists || context != nil {
			t.Fatalf("explicit null context was not preserved: %#v", body)
		}
		writeJSON(t, w, DecisionRecord{})
	}))
	defer server.Close()

	request := NewDecisionRequest("EXECUTE_TOOL", "local.echo")
	request.SetContext(nil)
	client := New(server.URL, WithAPIKey("token"), WithTenantID("tenant-a"), WithPrincipalID("operator-a"))
	if _, err := client.EvaluateDecision(*request); err != nil {
		t.Fatalf("EvaluateDecision returned error: %v", err)
	}
}

func TestDecisionRequestRejectsUnknownFieldsAndPreservesContextPresence(t *testing.T) {
	absent := NewDecisionRequest("EXECUTE_TOOL", "local.echo")
	absentJSON, err := json.Marshal(absent)
	if err != nil {
		t.Fatalf("marshal absent context: %v", err)
	}
	var absentBody map[string]any
	if err := json.Unmarshal(absentJSON, &absentBody); err != nil {
		t.Fatalf("decode absent context: %v", err)
	}
	if _, exists := absentBody["context"]; exists {
		t.Fatalf("absent context was serialized: %#v", absentBody)
	}

	explicitNull := NewDecisionRequest("EXECUTE_TOOL", "local.echo")
	explicitNull.SetContext(nil)
	explicitNullJSON, err := json.Marshal(explicitNull)
	if err != nil {
		t.Fatalf("marshal explicit null context: %v", err)
	}
	var explicitNullBody map[string]any
	if err := json.Unmarshal(explicitNullJSON, &explicitNullBody); err != nil {
		t.Fatalf("decode explicit null context: %v", err)
	}
	if context, exists := explicitNullBody["context"]; !exists || context != nil {
		t.Fatalf("explicit null context was not preserved: %#v", explicitNullBody)
	}

	var request DecisionRequest
	if err := json.Unmarshal([]byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","principal":"attacker"}`), &request); err == nil {
		t.Fatal("DecisionRequest accepted an undeclared property")
	}
}

func TestEvaluateDecisionRequiresIdentityBindings(t *testing.T) {
	client := New("http://helm.test")
	if _, err := client.EvaluateDecision(DecisionRequest{Action: "EXECUTE_TOOL", Resource: "local.echo"}); err == nil {
		t.Fatal("EvaluateDecision accepted missing API key, tenant, and principal bindings")
	}
}

func responseForClientMatrix(method string, u *url.URL) any {
	switch u.Path {
	case "/healthz":
		return map[string]string{"status": "ok", "version": "test"}
	case "/api/v1/proofgraph/sessions",
		"/api/v1/boundary/capabilities",
		"/api/v1/boundary/records",
		"/api/v1/conformance/reports",
		"/api/v1/conformance/vectors",
		"/api/v1/conformance/negative",
		"/api/v1/mcp/auth-profiles",
		"/api/v1/sandbox/profiles",
		"/api/v1/identity/agents",
		"/api/v1/authz/snapshots",
		"/api/v1/budgets":
		return []map[string]any{}
	case "/api/v1/boundary/checkpoints",
		"/api/v1/mcp/registry",
		"/api/v1/sandbox/grants",
		"/api/v1/approvals":
		if method == http.MethodGet {
			return []map[string]any{}
		}
		return map[string]any{}
	case "/api/v1/evidence/envelopes":
		if method == http.MethodGet {
			return []map[string]any{}
		}
		return map[string]any{}
	case "/api/v1/sandbox/grants/inspect":
		if u.Query().Get("runtime") != "" {
			return map[string]any{}
		}
		return []map[string]any{}
	}
	if len(u.Path) > len("/api/v1/proofgraph/sessions/") && u.Path[len(u.Path)-len("/receipts"):] == "/receipts" {
		return []map[string]any{}
	}
	return map[string]any{}
}

func writeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatal(err)
	}
}
