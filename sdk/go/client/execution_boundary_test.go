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
		})
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
