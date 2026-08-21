package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

type fixedMCPDecisionEvaluator struct {
	decision *contracts.DecisionRecord
}

func (e fixedMCPDecisionEvaluator) EvaluateDecision(context.Context, guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	return e.decision, nil
}

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
	target := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(target, []byte("helm-362-allow"), 0o600); err != nil {
		t.Fatal(err)
	}
	pack, err := json.Marshal(map[string]any{
		"pack_id": "runtime-pack",
		"version": 1,
		"runtime_actions": []map[string]any{{
			"action":     "file_read",
			"expression": "input.effect.params.path == " + strconv.Quote(target),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policyPath, _ := writeMountedServePolicyFixture(t, dir, string(pack))

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

	body := callTool(t, "file_read", map[string]any{"path": target})
	if !strings.Contains(body, "helm-362-allow") || strings.Contains(body, "Access Denied") {
		t.Fatalf("pack-allowed file_read did not reach ALLOW: %s", body)
	}

	deniedTarget := filepath.Join(dir, "not-allowed.txt")
	if err := os.WriteFile(deniedTarget, []byte("must-stay-denied"), 0o600); err != nil {
		t.Fatal(err)
	}
	body = callTool(t, "file_read", map[string]any{"path": deniedTarget})
	if !strings.Contains(body, "Access Denied") {
		t.Fatalf("file_read path outside the rule was not fail-closed: %s", body)
	}

	body = callTool(t, "file_write", map[string]any{"path": filepath.Join(dir, "denied.txt"), "content": "x"})
	if !strings.Contains(body, "Access Denied") {
		t.Fatalf("tool outside the pack was not fail-closed: %s", body)
	}
}

// TestMCPGatewayDecisionsPersistSignedReceiptsOutsideTenantScope covers the
// part of HELM-363 that is actually true: every governed decision through the
// MCP gateway — ALLOW and DENY — persists a signed, durable receipt.
//
// It deliberately does NOT claim those receipts are readable through
// /api/v1/receipts. They are written unscoped, because the gateway routes run
// under RouteAuthAdmin and so carry no authenticated tenant to scope by, while
// that route reads through ListByTenantCursor. The final assertion pins that
// boundary so the gap cannot silently reappear as a green test.
func TestMCPGatewayDecisionsPersistSignedReceiptsOutsideTenantScope(t *testing.T) {
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

	// Sequence-ordered read. This is NOT the read path /api/v1/receipts uses —
	// that route goes through listReceiptsForCursor -> ListByTenantCursor, which
	// filters on the tenant-qualified scope prefix. See the scope assertion at
	// the end of this test.
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

	// Pin the scope boundary this test used to misdescribe (HELM-363). The
	// gateway runs under RouteAuthAdmin, which establishes no tenant binding, so
	// persistDecisionReceipt writes these rows unscoped by design, and every
	// /api/v1/receipts read filters on the "tenant:" scope prefix — which is why
	// these receipts cannot be reached there.
	//
	// This asserts on the durable scope actually stored rather than on a guessed
	// tenant id, so it fails for any tenant if a future change starts scoping
	// these rows. When that happens, rewrite it; do not delete it to make a
	// build green.
	scopeRows, err := db.QueryContext(context.Background(), `SELECT COALESCE(causal_session_id, '') FROM receipts`)
	if err != nil {
		t.Fatalf("read durable receipt scopes: %v", err)
	}
	defer scopeRows.Close()
	scopes := 0
	for scopeRows.Next() {
		var scope string
		if err := scopeRows.Scan(&scope); err != nil {
			t.Fatalf("scan receipt scope: %v", err)
		}
		scopes++
		if strings.HasPrefix(scope, "tenant:") {
			t.Fatalf("gateway receipt is tenant-scoped (%q); the route has no authenticated tenant to derive that from, and this test's claim about /api/v1/receipts needs revisiting (HELM-363)", scope)
		}
	}
	if err := scopeRows.Err(); err != nil {
		t.Fatalf("iterate receipt scopes: %v", err)
	}
	if scopes == 0 {
		t.Fatal("expected the gateway to have persisted receipts")
	}
}

func TestReceiptPersistingEvaluatorFailsClosedWhenStoreFails(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	storeErr := errors.New("store unavailable")
	evaluator := &receiptPersistingEvaluator{
		svc: &Services{
			ReceiptStore:  &captureReceiptStore{storeErr: storeErr},
			ReceiptSigner: signer,
		},
		inner: fixedMCPDecisionEvaluator{decision: &contracts.DecisionRecord{
			ID:      "mcp-decision",
			Verdict: string(contracts.VerdictAllow),
		}},
	}
	decision, err := evaluator.EvaluateDecision(context.Background(), guardian.DecisionRequest{
		Principal: "agent.test",
		Action:    "EXECUTE_TOOL",
		Resource:  "file_read",
	})
	if decision != nil || !errors.Is(err, storeErr) {
		t.Fatalf("persistence failure must block decision: decision=%+v err=%v", decision, err)
	}
}

func TestGatewayDecisionReceiptPreimageBindsArguments(t *testing.T) {
	base := guardian.DecisionRequest{
		Principal: "session-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "file_read",
		Context:   map[string]any{"path": "/tmp/a"},
	}
	first, err := canonicalize.JCS(base)
	if err != nil {
		t.Fatal(err)
	}
	again, err := canonicalize.JCS(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Context = map[string]any{"path": "/tmp/b"}
	second, err := canonicalize.JCS(changed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("identical decision requests must have identical receipt preimages")
	}
	if bytes.Equal(first, second) {
		t.Fatal("different tool arguments must have different receipt preimages")
	}
}

func TestDeployedMCPRouteRegistryMatchesHandlerAuthentication(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "test-admin-key")
	mux := http.NewServeMux()
	registerDeployedMCPRoutes(mux, mcppkg.NewGateway(mcppkg.NewToolCatalog(), mcppkg.GatewayConfig{}))

	registered := make(map[string]RouteAuth, len(RuntimeRouteSpecs()))
	for _, spec := range RuntimeRouteSpecs() {
		registered[spec.Method+" "+spec.Path] = spec.Auth
	}

	for _, tc := range []struct {
		name, method, path, body string
		wantAuth                 RouteAuth
		protected                bool
	}{
		{name: "mcp transport get", method: http.MethodGet, path: "/mcp", wantAuth: RouteAuthAdmin, protected: true},
		{name: "mcp transport post", method: http.MethodPost, path: "/mcp", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, wantAuth: RouteAuthAdmin, protected: true},
		{name: "mcp capabilities", method: http.MethodGet, path: "/mcp/v1/capabilities", wantAuth: RouteAuthAdmin, protected: true},
		{name: "mcp execute", method: http.MethodPost, path: "/mcp/v1/execute", body: `{"method":"missing"}`, wantAuth: RouteAuthAdmin, protected: true},
		{name: "mcp protected-resource metadata", method: http.MethodGet, path: "/.well-known/oauth-protected-resource/mcp", wantAuth: RouteAuthPublic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.method + " " + tc.path
			if got, ok := registered[key]; !ok {
				t.Fatalf("route %s is missing from the runtime registry", key)
			} else if got != tc.wantAuth {
				t.Fatalf("route %s registry auth = %q, want %q", key, got, tc.wantAuth)
			}

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if tc.protected && rec.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated protected route %s status = %d body=%s", key, rec.Code, rec.Body.String())
			}
			if !tc.protected && rec.Code == http.StatusUnauthorized {
				t.Fatalf("public route %s was unexpectedly authenticated", key)
			}
		})
	}
}

func TestGovernedDeployedMCPGatewayRequiresReceiptComponents(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	guard := &guardian.Guardian{}

	for name, svc := range map[string]*Services{
		"missing store":  {Guardian: guard, ReceiptSigner: signer},
		"missing signer": {Guardian: guard, ReceiptStore: &captureReceiptStore{}},
	} {
		t.Run(name, func(t *testing.T) {
			gateway, err := newDeployedMCPGateway(svc)
			if err == nil || gateway != nil {
				t.Fatalf("governed gateway must fail closed: gateway=%v err=%v", gateway, err)
			}
		})
	}

	gateway, err := newDeployedMCPGateway(&Services{
		Guardian:      guard,
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	})
	if err != nil || gateway == nil {
		t.Fatalf("fully receipted governed gateway unavailable: gateway=%v err=%v", gateway, err)
	}
}

func TestDeployedMCPGatewayRegistersConfiguredGitHubEffects(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(githubEffectsTokenEnv, "inert-test-token")
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}

	gateway, err := newDeployedMCPGateway(&Services{
		DataDir:       dataDir,
		Guardian:      &guardian.Guardian{},
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", recorder.Code, recorder.Body.String())
	}
	for _, tool := range []string{"github.list_prs", "github.read_pr", "github.create_issue", "github.add_comment"} {
		if !strings.Contains(recorder.Body.String(), `"name":"`+tool+`"`) {
			t.Fatalf("configured deployed gateway did not register %s: %s", tool, recorder.Body.String())
		}
	}
}

func TestDeployedMCPGatewayLeavesGitHubEffectsDisabledWithoutToken(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(githubEffectsTokenEnv, "")
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}

	gateway, err := newDeployedMCPGateway(&Services{
		DataDir:       dataDir,
		Guardian:      &guardian.Guardian{},
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"name":"github.`) {
		t.Fatalf("unconfigured deployed gateway widened tool surface: %s", recorder.Body.String())
	}
}

func TestUnavailableMCPGatewayLogsWarning(t *testing.T) {
	previousLogger := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	svc.Guardian = &guardian.Guardian{}
	RegisterSubsystemRoutes(http.NewServeMux(), svc)

	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil && record["msg"] == "MCP gateway unavailable" {
			if record["level"] != "WARN" {
				t.Fatalf("MCP gateway log level = %v, want WARN", record["level"])
			}
			return
		}
	}
	t.Fatalf("MCP gateway warning missing from logs: %s", output.String())
}
