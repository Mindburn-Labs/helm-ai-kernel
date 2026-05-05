package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func writeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatal(err)
	}
}
