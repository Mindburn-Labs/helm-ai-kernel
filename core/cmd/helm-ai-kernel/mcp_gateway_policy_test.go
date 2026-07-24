package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// writeMountedServePolicyFixture writes a serve policy plus reference pack in
// the exact form `quickstart` emits and returns both paths.
func writeMountedServePolicyFixture(t *testing.T, dir, packJSON string) (string, string) {
	t.Helper()
	refDir := filepath.Join(dir, "reference_packs")
	if err := os.MkdirAll(refDir, 0o750); err != nil {
		t.Fatal(err)
	}
	refPath := filepath.Join(refDir, "runtime.json")
	if err := os.WriteFile(refPath, []byte(packJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.toml")
	policyBytes := []byte(`
name = "runtime"
profile = "test"
reference_pack = "./reference_packs/runtime.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`)
	if err := os.WriteFile(policyPath, policyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return policyPath, refPath
}

func newMountedPolicyReconciler(t *testing.T, source policyreconcile.PolicySource, store policyreconcile.PolicySnapshotStore) *policyreconcile.Reconciler {
	t.Helper()
	reconciler, err := policyreconcile.NewReconciler(policyreconcile.ReconcilerConfig{
		Source:            source,
		Store:             store,
		Compiler:          compileServePolicySnapshot,
		KeepLastKnownGood: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

// TestMountedPackRuntimeActionsReconcileIntoAllowRules covers HELM-362: a
// mounted reference pack's runtime_actions must compile into ALLOW rules
// through the reconcile path, and editing only the pack (policy file mtime
// unchanged) must trigger a re-reconcile instead of a no_change.
func TestMountedPackRuntimeActionsReconcileIntoAllowRules(t *testing.T) {
	dir := t.TempDir()
	policyPath, refPath := writeMountedServePolicyFixture(t, dir, `{
  "pack_id": "runtime-pack",
  "version": 1,
  "runtime_actions": [
    {"action": "file_read", "expression": "true"}
  ]
}`)

	source := policyreconcile.NewMountedFileSource(policyPath, policyreconcile.DefaultScope)
	store := policyreconcile.NewAtomicSnapshotStore()
	reconciler := newMountedPolicyReconciler(t, source, store)

	status, err := reconciler.Reconcile(context.Background(), policyreconcile.DefaultScope)
	if err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if !status.Updated {
		t.Fatalf("initial reconcile did not install a snapshot: %+v", status)
	}
	snapshot, ok := store.Get(policyreconcile.DefaultScope)
	if !ok || snapshot.Graph == nil {
		t.Fatalf("no compiled snapshot installed: %+v", status)
	}
	if _, ok := snapshot.Graph.Rules["file_read"]; !ok {
		t.Fatalf("pack runtime_actions did not compile into graph rules: %+v", snapshot.Graph.Rules)
	}

	// Edit only the mounted pack; the policy file (and its mtime/epoch) is
	// untouched, so change detection must come from the pack digest.
	if err := os.WriteFile(refPath, []byte(`{
  "pack_id": "runtime-pack",
  "version": 2,
  "runtime_actions": [
    {"action": "file_read", "expression": "true"},
    {"action": "file_write", "expression": "true"}
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err = reconciler.Reconcile(context.Background(), policyreconcile.DefaultScope)
	if err != nil {
		t.Fatalf("pack-edit reconcile: %v", err)
	}
	if !status.Updated || status.ReconcileStatus == policyreconcile.StatusNoChange {
		t.Fatalf("pack edit did not trigger a re-reconcile: %+v", status)
	}
	snapshot, ok = store.Get(policyreconcile.DefaultScope)
	if !ok || snapshot.Graph == nil {
		t.Fatalf("snapshot missing after pack edit: %+v", status)
	}
	if _, ok := snapshot.Graph.Rules["file_write"]; !ok {
		t.Fatalf("edited pack runtime_actions did not compile into graph rules: %+v", snapshot.Graph.Rules)
	}
}

// TestDeployedMCPGatewayEnforcesReconciledSnapshot covers HELM-362 on the
// deployed surface: the gateway wired like RegisterSubsystemRoutes must
// enforce the reconciled snapshot, so a pack-allowed tool reaches ALLOW while
// tools outside the pack stay fail-closed.
func TestDeployedMCPGatewayEnforcesReconciledSnapshot(t *testing.T) {
	dir := t.TempDir()
	policyPath, _ := writeMountedServePolicyFixture(t, dir, `{
  "pack_id": "runtime-pack",
  "version": 1,
  "runtime_actions": [
    {"action": "file_read", "expression": "true"}
  ]
}`)

	source := policyreconcile.NewMountedFileSource(policyPath, policyreconcile.DefaultScope)
	store := policyreconcile.NewAtomicSnapshotStore()
	reconciler := newMountedPolicyReconciler(t, source, store)
	if status, err := reconciler.Reconcile(context.Background(), policyreconcile.DefaultScope); err != nil || !status.Updated {
		t.Fatalf("initial reconcile: status=%+v err=%v", status, err)
	}

	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	guard := guardian.NewGuardian(signer, nil, nil, guardian.WithPolicySnapshots(store, policyreconcile.DefaultScope))
	gateway, err := newLocalMCPGatewayWithEvaluator(mcppkg.GatewayConfig{}, guard)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	callTool := func(t *testing.T, name string, args map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params":  map[string]any{"name": name, "arguments": args},
		})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(payload)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("tools/call %s returned status %d: %s", name, recorder.Code, recorder.Body.String())
		}
		return recorder.Body.String()
	}

	target := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(target, []byte("helm-362-allow"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := callTool(t, "file_read", map[string]any{"path": target})
	if !strings.Contains(body, "helm-362-allow") || strings.Contains(body, "Access Denied") {
		t.Fatalf("pack-allowed file_read did not reach ALLOW: %s", body)
	}

	body = callTool(t, "file_write", map[string]any{"path": filepath.Join(dir, "denied.txt"), "content": "x"})
	if !strings.Contains(body, "Access Denied") {
		t.Fatalf("tool outside the pack was not fail-closed: %s", body)
	}
}

// TestMCPGatewayDecisionsPersistQueryableReceipts covers HELM-363: every
// governed decision through the MCP gateway — ALLOW and DENY — must persist a
// signed receipt into the same store /api/v1/receipts reads.
func TestMCPGatewayDecisionsPersistQueryableReceipts(t *testing.T) {
	dir := t.TempDir()
	policyPath, _ := writeMountedServePolicyFixture(t, dir, `{
  "pack_id": "runtime-pack",
  "version": 1,
  "runtime_actions": [
    {"action": "file_read", "expression": "true"}
  ]
}`)

	source := policyreconcile.NewMountedFileSource(policyPath, policyreconcile.DefaultScope)
	policyStore := policyreconcile.NewAtomicSnapshotStore()
	reconciler := newMountedPolicyReconciler(t, source, policyStore)
	if status, err := reconciler.Reconcile(context.Background(), policyreconcile.DefaultScope); err != nil || !status.Updated {
		t.Fatalf("initial reconcile: status=%+v err=%v", status, err)
	}

	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{ReceiptStore: receiptStore, ReceiptSigner: signer}

	guard := guardian.NewGuardian(signer, nil, nil, guardian.WithPolicySnapshots(policyStore, policyreconcile.DefaultScope))
	gateway, err := newLocalMCPGatewayWithEvaluator(mcppkg.GatewayConfig{}, &receiptPersistingEvaluator{svc: svc, inner: guard})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	callTool := func(t *testing.T, name string, args map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params":  map[string]any{"name": name, "arguments": args},
		})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(payload)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("tools/call %s returned status %d: %s", name, recorder.Code, recorder.Body.String())
		}
		return recorder.Body.String()
	}

	target := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(target, []byte("helm-363-allow"), 0o600); err != nil {
		t.Fatal(err)
	}
	if body := callTool(t, "file_read", map[string]any{"path": target}); !strings.Contains(body, "helm-363-allow") {
		t.Fatalf("expected ALLOW for pack-declared file_read: %s", body)
	}
	if body := callTool(t, "file_write", map[string]any{"path": filepath.Join(dir, "denied.txt"), "content": "x"}); !strings.Contains(body, "Access Denied") {
		t.Fatalf("expected DENY for file_write: %s", body)
	}

	// The same read path /api/v1/receipts uses.
	receipts, err := receiptStore.ListSince(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	verdicts := map[string]string{}
	for _, receipt := range receipts {
		resource, _ := receipt.Metadata["resource"].(string)
		verdicts[resource] = receipt.Status
		if receipt.Signature == "" {
			t.Fatalf("receipt %s is unsigned", receipt.ReceiptID)
		}
	}
	if verdicts["file_read"] != string(contracts.VerdictAllow) {
		t.Fatalf("missing ALLOW receipt for file_read: %+v", verdicts)
	}
	if verdicts["file_write"] != string(contracts.VerdictDeny) {
		t.Fatalf("missing DENY receipt for file_write: %+v", verdicts)
	}
}
