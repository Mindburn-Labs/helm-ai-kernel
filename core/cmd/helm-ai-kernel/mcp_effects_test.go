// quantum_posture: this test verifies classical Ed25519 permit signatures via
// core/pkg/crypto; it exercises no post-quantum or hybrid path and asserts none.

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
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

// TestGitHubEffectsRuntimeDispatchesReadUnderVerifiedPermit is the W1 keystone
// acceptance proof on the shipped path: a governed github.list_prs call
// dispatches against a real HTTP endpoint under a permit the bridge signed and
// verified, the receipt's output hash reflects the real response, and the
// emitted permit verifies offline with the reported key. The mutation at the
// end shows the signature actually covers the permit: flip one byte and offline
// verification fails.
func TestGitHubEffectsRuntimeDispatchesReadUnderVerifiedPermit(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
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
	if resp.IsError {
		t.Fatalf("read call reported error: %s", resp.Content)
	}
	doc := decodeEffectsDoc(t, resp)

	// Acceptance 1 + 4: the call actually dispatched and the receipt binds the
	// real response.
	if doc["verdict"] != "ALLOW" {
		t.Fatalf("verdict = %v, want ALLOW (reason=%v)", doc["verdict"], doc["reason"])
	}
	if doc["dispatch_state"] != rtmcp.DispatchStateDispatched {
		t.Fatalf("dispatch_state = %v, want %q", doc["dispatch_state"], rtmcp.DispatchStateDispatched)
	}
	if doc["dispatch_state"] == rtmcp.DispatchStateNoDispatch {
		t.Fatal("shipped path emitted a no-dispatch proof; the connector was not wired")
	}
	if oh, _ := doc["output_hash"].(string); oh == "" {
		t.Fatal("output_hash is empty; the receipt does not bind the real response")
	}
	if !strings.Contains(gotPath, "/repos/owner/repo/pulls") {
		t.Fatalf("connector did not reach the GitHub pulls endpoint; hit %q", gotPath)
	}
	if doc["result"] == nil {
		t.Fatal("no result returned from a dispatched read")
	}

	// Acceptance 2 + 5: the emitted permit is signed and verifies offline with
	// the key the response reports — no HELM service in the trust path.
	pubKey, _ := doc["permit_public_key"].(string)
	if pubKey == "" {
		t.Fatal("response did not report the permit public key")
	}
	permit := decodePermit(t, doc["permit"])
	if permit.Signature == "" {
		t.Fatal("dispatched permit is unsigned")
	}
	ok, err := helmcrypto.VerifyPermit(pubKey, permit)
	if err != nil || !ok {
		t.Fatalf("emitted permit failed offline verification: ok=%v err=%v", ok, err)
	}

	// Mutation: the signature must actually cover the permit. Widen the scope
	// after issuance and offline verification must reject it.
	tampered := *permit
	tampered.Scope.AllowedAction = "github.create_issue"
	if ok, _ := helmcrypto.VerifyPermit(pubKey, &tampered); ok {
		t.Fatal("a permit whose scope was changed after signing still verified; the signature does not cover scope")
	}

	// The shipped response is already a receipt_verify bundle. Round-trip its
	// exact JSON wire shape and verify it using the same offline library as the
	// binary, with the signing key supplied as an explicit trust root.
	bundleRaw, err := json.Marshal(doc["receipt_bundle"])
	if err != nil {
		t.Fatalf("marshal receipt bundle: %v", err)
	}
	var bundle receiptverify.Bundle
	if err := json.Unmarshal(bundleRaw, &bundle); err != nil {
		t.Fatalf("decode receipt_verify bundle: %v", err)
	}
	if len(bundle.Receipts) != 1 || len(bundle.Permits) != 1 {
		t.Fatalf("bundle counts = receipts:%d permits:%d, want 1/1", len(bundle.Receipts), len(bundle.Permits))
	}
	receipt := bundle.Receipts[0]
	if receipt.DecisionID != doc["decision_id"] {
		t.Fatalf("receipt decision = %q, response decision = %v", receipt.DecisionID, doc["decision_id"])
	}
	if receipt.OutputHash != doc["output_hash"] {
		t.Fatalf("receipt output hash = %q, response output hash = %v", receipt.OutputHash, doc["output_hash"])
	}
	receiptHash, err := contracts.ReceiptChainHash(receipt)
	if err != nil {
		t.Fatalf("hash execution receipt: %v", err)
	}
	if receiptHash != doc["execution_receipt_hash"] {
		t.Fatalf("execution receipt hash = %q, response = %v", receiptHash, doc["execution_receipt_hash"])
	}
	verification := receiptverify.VerifyBundle(bundle, receiptverify.TrustRoot{
		Keys: map[string]string{receipt.KeyID: pubKey},
	})
	if !verification.Valid || verification.Receipts != 1 || verification.Permits != 1 {
		t.Fatalf("offline bundle verification failed: %+v", verification)
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

// TestGitHubEffectsWriteEscalatesWithoutApproval proves bounded writes stay
// fail-closed on this path: with no approval store configured, create_issue
// escalates and never dispatches, so no external write can occur.
func TestGitHubEffectsWriteEscalatesWithoutApproval(t *testing.T) {
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
	if doc["verdict"] != "ESCALATE" {
		t.Fatalf("verdict = %v, want ESCALATE", doc["verdict"])
	}
	if doc["dispatch_state"] == rtmcp.DispatchStateDispatched {
		t.Fatal("bounded write dispatched without approval")
	}
}

// decodePermit round-trips the response's permit field back into an
// effects.EffectPermit for offline verification.
func decodePermit(t *testing.T, v any) *effects.EffectPermit {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal permit: %v", err)
	}
	var permit effects.EffectPermit
	if err := json.Unmarshal(raw, &permit); err != nil {
		t.Fatalf("unmarshal permit: %v", err)
	}
	return &permit
}
