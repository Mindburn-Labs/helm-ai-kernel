// quantum_posture: this test verifies classical Ed25519 permit signatures via
// core/pkg/crypto; it exercises no post-quantum or hybrid path and asserts none.

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	rtmcp "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters/mcp"
)

// testSigningSeed is a valid 32-byte Ed25519 seed for the wiring tests. It is
// not a real key and signs nothing that ships.
func testSigningSeed() []byte { return []byte("0123456789abcdef0123456789abcdef") }

// decodeEffectsDoc pulls the machine document out of a governed tool response.
func decodeEffectsDoc(t *testing.T, resp mcppkg.ToolExecutionResponse) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(resp.Content), &doc); err != nil {
		t.Fatalf("decode effects doc: %v (content=%q)", err, resp.Content)
	}
	return doc
}

func TestGitHubEffectsToolRefsDiscloseUnavailableRuntime(t *testing.T) {
	rt, err := newGitHubEffectsRuntime("ghp-test", "https://api.github.test", testSigningSeed())
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}
	want := "Configured but unavailable until shared Guardian wiring exists; calls fail closed in the current runtime."
	wantNames := map[string]bool{
		"github.list_prs":     true,
		"github.read_pr":      true,
		"github.create_issue": true,
		"github.add_comment":  true,
	}
	refs := rt.toolRefs()
	if len(refs) != len(wantNames) {
		t.Fatalf("registered GitHub tool count = %d, want %d", len(refs), len(wantNames))
	}
	for _, ref := range refs {
		if !wantNames[ref.Name] {
			t.Fatalf("unexpected GitHub tool %q", ref.Name)
		}
		if ref.Description != want {
			t.Errorf("%s description = %q, want unavailable-state disclosure", ref.Name, ref.Description)
		}
	}
}

// TestGitHubEffectsRuntimeFailsClosedWithoutGuardianGates is the shipped-path
// boundary proof: the real provider connector is configured, but this caller
// does not inject a shared full-gate Guardian, so the bridge refuses before the
// connector can reach an external HTTP endpoint.
func TestGitHubEffectsRuntimeFailsClosedWithoutGuardianGates(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"number":7,"title":"Fix","body":"Body","state":"open","created_at":"2026-08-01T00:00:00Z","user":{"login":"ada"},"head":{"ref":"feature"},"base":{"ref":"main"}}]`))
	}))
	defer server.Close()

	rt, err := newGitHubEffectsRuntime("ghp-test", server.URL, testSigningSeed())
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}

	resp, err := rt.execute(context.Background(), mcppkg.ToolExecutionRequest{
		ToolName:  "github.list_prs",
		Arguments: map[string]any{"repo": "owner/repo", "state": "open"},
		SessionID: "sess-read",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("configured connector call was not refused: %s", resp.Content)
	}
	doc := decodeEffectsDoc(t, resp)
	if doc["verdict"] != "DENY" {
		t.Fatalf("verdict = %v, want DENY (reason=%v)", doc["verdict"], doc["reason"])
	}
	if doc["reason_code"] != "GUARDIAN_GATES_UNAVAILABLE" {
		t.Fatalf("reason_code = %v, want GUARDIAN_GATES_UNAVAILABLE", doc["reason_code"])
	}
	if doc["dispatch_state"] != rtmcp.DispatchStateNotDispatched {
		t.Fatalf("dispatch_state = %v, want %q", doc["dispatch_state"], rtmcp.DispatchStateNotDispatched)
	}
	if requests != 0 {
		t.Fatalf("Guardian gate refusal reached GitHub %d times", requests)
	}
}

// TestGitHubEffectsRuntimeRefusesWithoutSigningSeed is the vacuous-pass guard.
// The dispatch gate is a no-op when the bridge has no permit signer, so the
// wiring must refuse to construct without a valid seed rather than arm dispatch
// behind a gate that can never fire. The second half shows exactly what it is
// preventing: a bridge built the same way but seedless has no signing key and
// waves an unsigned permit straight through.
func TestGitHubEffectsRuntimeRefusesWithoutSigningSeed(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed []byte
	}{
		{"nil seed", nil},
		{"short seed", []byte("too-short")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newGitHubEffectsRuntime("ghp-test", "https://api.github.test", tc.seed); err == nil {
				t.Fatal("runtime armed dispatch without a usable permit signer")
			}
		})
	}

	// Demonstrate the failure mode the guard prevents: a seedless bridge built
	// the same way has no signing key, so the dispatch gate it exposes is a
	// no-op. (The gate's enforcement with a signer present is proven inside the
	// mcp package by TestBridgeDispatchGateRefusesUnsignedAndTamperedPermits;
	// here we only show why the seed is mandatory for this wiring.)
	seedless := rtmcp.NewGovernedBridge(rtmcp.BridgeConfig{
		ServerID: githubEffectsServerID,
		Profile:  githubEffectsProfile(),
	})
	if seedless.PermitSigningPublicKey() != "" {
		t.Fatal("a seedless bridge reported a signing key")
	}
	seeded := rtmcp.NewGovernedBridge(rtmcp.BridgeConfig{
		ServerID:    githubEffectsServerID,
		Profile:     githubEffectsProfile(),
		SigningSeed: testSigningSeed(),
	})
	if seeded.PermitSigningPublicKey() == "" {
		t.Fatal("a seeded bridge reported no signing key; permits would be unsigned")
	}
}

// TestGitHubEffectsWriteRequiresGuardianBeforeApproval proves the generic
// bridge gate precedes approval handling: this caller lacks the shared Guardian
// required for any configured connector, so no write reaches approval or HTTP.
func TestGitHubEffectsWriteRequiresGuardianBeforeApproval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("write reached GitHub without approval")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	rt, err := newGitHubEffectsRuntime("ghp-test", server.URL, testSigningSeed())
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}
	resp, err := rt.execute(context.Background(), mcppkg.ToolExecutionRequest{
		ToolName:  "github.create_issue",
		Arguments: map[string]any{"repo": "owner/repo", "title": "should not send"},
		SessionID: "sess-write",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("bounded write was not refused: %s", resp.Content)
	}
	doc := decodeEffectsDoc(t, resp)
	if doc["verdict"] != "DENY" {
		t.Fatalf("verdict = %v, want DENY", doc["verdict"])
	}
	if doc["reason_code"] != "GUARDIAN_GATES_UNAVAILABLE" {
		t.Fatalf("reason_code = %v, want GUARDIAN_GATES_UNAVAILABLE", doc["reason_code"])
	}
	if doc["dispatch_state"] != rtmcp.DispatchStateNotDispatched {
		t.Fatalf("dispatch_state = %v, want %q", doc["dispatch_state"], rtmcp.DispatchStateNotDispatched)
	}
}
