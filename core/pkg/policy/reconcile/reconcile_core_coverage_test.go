package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMountedFileSourceAndStaticSourceBranches(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "policy.json")
	bundle := []byte(`{"policy":"mounted"}`)
	if err := os.WriteFile(bundlePath, bundle, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(bundlePath+".sig", []byte(" signature-1 \n"), 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	source := NewMountedFileSource(bundlePath, PolicyScope{})
	scopes, err := source.ListScopes(context.Background())
	if err != nil || len(scopes) != 1 || scopes[0].Key() != DefaultScope.Key() {
		t.Fatalf("mounted scopes = %+v err=%v", scopes, err)
	}
	head, err := source.Head(context.Background(), DefaultScope)
	if err != nil {
		t.Fatalf("mounted head: %v", err)
	}
	if head.PolicyHash != HashBytes(bundle) || head.Signature != "signature-1" || len(head.SourceRefs) != 2 {
		t.Fatalf("unexpected mounted head: %+v", head)
	}
	loaded, err := source.Load(context.Background(), DefaultScope, head.PolicyEpoch)
	if err != nil || string(loaded) != string(bundle) {
		t.Fatalf("mounted load = %q err=%v", loaded, err)
	}
	hash, err := MountedFileBundleHash(bundlePath)
	if err != nil || hash != HashBytes(bundle) {
		t.Fatalf("MountedFileBundleHash = %q err=%v", hash, err)
	}

	noSigPath := filepath.Join(dir, "policy-nosig.json")
	if err := os.WriteFile(noSigPath, []byte("nosig"), 0o644); err != nil {
		t.Fatalf("write no-sig bundle: %v", err)
	}
	noSig := NewMountedFileSource(noSigPath, PolicyScope{TenantID: "tenant", WorkspaceID: "workspace"})
	head, err = noSig.Head(context.Background(), noSig.Scope)
	if err != nil {
		t.Fatalf("no-sig head: %v", err)
	}
	if head.Signature != "" || len(head.SourceRefs) != 1 {
		t.Fatalf("unexpected no-sig head: %+v", head)
	}

	empty := NewMountedFileSource("", DefaultScope)
	if _, _, err := empty.read(context.Background()); err == nil {
		t.Fatal("expected mounted source path error")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := source.read(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled read, got %v", err)
	}
	if _, _, err := source.readSignature(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled signature read, got %v", err)
	}

	static := NewStaticSource(PolicyHead{
		Scope:       PolicyScope{TenantID: "tenant-b", WorkspaceID: "workspace-b"},
		PolicyEpoch: 3,
		PolicyHash:  HashBytes([]byte("b")),
	}, []byte("b"))
	static.Heads["tenant-a/workspace-a"] = PolicyHead{
		Scope:       PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"},
		PolicyEpoch: 1,
		PolicyHash:  HashBytes([]byte("a")),
	}
	static.Bundles["tenant-a/workspace-a"] = []byte("a")
	scopes, err = static.ListScopes(context.Background())
	if err != nil || len(scopes) != 2 || scopes[0].TenantID != "tenant-a" {
		t.Fatalf("static scopes = %+v err=%v", scopes, err)
	}
	if _, err := static.Head(context.Background(), PolicyScope{TenantID: "missing", WorkspaceID: "workspace"}); !errors.Is(err, ErrPolicyNotReady) {
		t.Fatalf("expected missing static head, got %v", err)
	}
	loaded, err = static.Load(context.Background(), PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}, 1)
	if err != nil || string(loaded) != "a" {
		t.Fatalf("static load = %q err=%v", loaded, err)
	}
	loaded[0] = 'z'
	loaded, _ = static.Load(context.Background(), PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}, 1)
	if string(loaded) != "a" {
		t.Fatalf("static load did not return a copy: %q", loaded)
	}
	if _, err := static.Load(context.Background(), PolicyScope{TenantID: "missing", WorkspaceID: "workspace"}, 1); !errors.Is(err, ErrPolicyNotReady) {
		t.Fatalf("expected missing static bundle, got %v", err)
	}
}

func TestControlPlaneSourceErrorAndHeaderBranches(t *testing.T) {
	scope := PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	source := NewControlPlaneSource("", scope)
	if _, err := source.ListScopes(context.Background()); err != nil {
		t.Fatalf("controlplane list scopes: %v", err)
	}
	if _, err := source.Head(context.Background(), scope); err == nil {
		t.Fatal("expected empty controlplane URL error")
	}
	if _, err := source.Load(context.Background(), scope, 1); err == nil {
		t.Fatal("expected empty controlplane load URL error")
	}

	bundle := []byte("controlplane-policy")
	head := PolicyHead{Scope: DefaultScope, PolicyEpoch: 9, PolicyHash: HashBytes(bundle)}
	var sawBearer bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer token-1" {
			sawBearer = true
		}
		switch r.URL.Path {
		case "/api/v1/policy/head":
			if r.URL.Query().Get("tenant_id") != scope.TenantID || r.URL.Query().Get("workspace_id") != scope.WorkspaceID {
				http.Error(w, "wrong scope", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(head)
		case "/api/v1/policy/bundle":
			_, _ = w.Write(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source = NewControlPlaneSource(server.URL, scope)
	source.HTTPClient = nil
	source.BearerToken = " token-1 "
	gotHead, err := source.Head(context.Background(), scope)
	if err != nil {
		t.Fatalf("controlplane head: %v", err)
	}
	if gotHead.Scope.Key() != scope.Key() || !sawBearer {
		t.Fatalf("head scope/header not normalized: %+v bearer=%v", gotHead, sawBearer)
	}
	loaded, err := source.Load(context.Background(), scope, 9)
	if err != nil || string(loaded) != string(bundle) {
		t.Fatalf("controlplane load = %q err=%v", loaded, err)
	}

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusInternalServerError)
	}))
	defer errorServer.Close()
	source = NewControlPlaneSource(errorServer.URL, scope)
	if _, err := source.Head(context.Background(), scope); err == nil {
		t.Fatal("expected controlplane head status error")
	}
	if _, err := source.Load(context.Background(), scope, 1); err == nil {
		t.Fatal("expected controlplane load status error")
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSON.Close()
	source = NewControlPlaneSource(invalidJSON.URL, scope)
	if _, err := source.Head(context.Background(), scope); err == nil {
		t.Fatal("expected controlplane decode error")
	}
}

func TestReconcilerStatusAndFailureBranches(t *testing.T) {
	if _, err := NewReconciler(ReconcilerConfig{}); err == nil {
		t.Fatal("expected missing source error")
	}
	if _, err := NewReconciler(ReconcilerConfig{Source: &mutableSource{}}); err == nil {
		t.Fatal("expected missing store error")
	}
	if _, err := NewReconciler(ReconcilerConfig{Source: &mutableSource{}, Store: NewAtomicSnapshotStore()}); err == nil {
		t.Fatal("expected missing compiler error")
	}
	store := NewAtomicSnapshotStore()
	if err := store.Swap(DefaultScope, nil); err == nil {
		t.Fatal("expected nil snapshot swap error")
	}

	bundle := []byte("policy")
	source := &mutableSource{head: PolicyHead{Scope: DefaultScope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)}, bundle: bundle}
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if _, ok := reconciler.LastStatus(DefaultScope); ok {
		t.Fatal("LastStatus should be empty before reconcile")
	}
	if _, err := reconciler.Reconcile(context.Background(), DefaultScope); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	status, ok := reconciler.LastStatus(DefaultScope)
	if !ok || status.ReconcileStatus != "ok" {
		t.Fatalf("LastStatus missing success: %+v ok=%v", status, ok)
	}
	status, err = reconciler.Reconcile(context.Background(), DefaultScope)
	if err != nil || status.ReconcileStatus != StatusNoChange {
		t.Fatalf("expected no-change status, got %+v err=%v", status, err)
	}

	nilCompiler, err := NewReconciler(ReconcilerConfig{
		Source:   source,
		Store:    NewAtomicSnapshotStore(),
		Compiler: func(context.Context, PolicyHead, []byte) (*EffectivePolicySnapshot, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("new nil compiler reconciler: %v", err)
	}
	status, err = nilCompiler.Reconcile(context.Background(), DefaultScope)
	if !errors.Is(err, ErrPolicyNotReady) || status.ReconcileStatus != StatusCompileError {
		t.Fatalf("expected nil compiler policy-not-ready, got status=%+v err=%v", status, err)
	}

	compileErr, err := NewReconciler(ReconcilerConfig{
		Source: source,
		Store:  NewAtomicSnapshotStore(),
		Compiler: func(context.Context, PolicyHead, []byte) (*EffectivePolicySnapshot, error) {
			return nil, errors.New("compile failed")
		},
	})
	if err != nil {
		t.Fatalf("new compile-error reconciler: %v", err)
	}
	status, err = compileErr.Reconcile(context.Background(), DefaultScope)
	if err == nil || status.ReconcileStatus != StatusCompileError {
		t.Fatalf("expected compile error, got status=%+v err=%v", status, err)
	}

	swapErr, err := NewReconciler(ReconcilerConfig{Source: source, Store: failingStore{}, Compiler: testCompiler})
	if err != nil {
		t.Fatalf("new swap-error reconciler: %v", err)
	}
	status, err = swapErr.Reconcile(context.Background(), DefaultScope)
	if err == nil || status.ReconcileStatus != StatusSourceError {
		t.Fatalf("expected swap error, got status=%+v err=%v", status, err)
	}
}

func TestEmergencyVerifierDirectBranches(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	bundle := []byte("policy-with-emergency")
	head := PolicyHead{
		Scope:          DefaultScope,
		PolicyEpoch:    7,
		PolicyHash:     HashBytes(bundle),
		P0CeilingsHash: "sha256:p0",
		P1BundleHash:   "sha256:p1",
	}
	capsule := testEmergencyCapsule(now, HashBytes(bundle))
	verifier := SafeDepEmergencyVerifier{Now: func() time.Time { return now }, MaxTTL: time.Hour}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyEmergencyCapsule(ctx, head, capsule); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled emergency verification, got %v", err)
	}

	capsule.AllowedActions = nil
	if err := verifier.VerifyEmergencyCapsule(context.Background(), head, capsule); err == nil {
		t.Fatal("expected invalid emergency capsule")
	}
}

type failingStore struct{}

func (failingStore) Get(PolicyScope) (*EffectivePolicySnapshot, bool) { return nil, false }
func (failingStore) Swap(PolicyScope, *EffectivePolicySnapshot) error {
	return errors.New("swap failed")
}

func TestScopeAndHelperBranches(t *testing.T) {
	if DefaultScope != (*EffectivePolicySnapshot)(nil).Scope() {
		t.Fatal("nil snapshot should report default scope")
	}
	partial := PolicyScope{TenantID: "tenant"}
	if partial.Normalize().WorkspaceID != DefaultScope.WorkspaceID {
		t.Fatalf("partial scope did not normalize: %+v", partial.Normalize())
	}
	if err := verifyExpectedHash("", []byte("x")); !errors.Is(err, ErrPolicyNotReady) {
		t.Fatalf("expected empty hash not-ready, got %v", err)
	}
	data := mustJSON(map[string]any{"bad": func() {}})
	if len(data) == 0 {
		t.Fatal("mustJSON fallback returned empty data")
	}
	if err := validateSnapshot(&EffectivePolicySnapshot{TenantID: "", WorkspaceID: "w", PolicyHash: "sha256:x"}); !errors.Is(err, ErrPolicyNotReady) {
		t.Fatalf("expected empty scope validation error, got %v", err)
	}
	if err := validateSnapshot(&EffectivePolicySnapshot{TenantID: "t", WorkspaceID: "w"}); !errors.Is(err, ErrPolicyNotReady) {
		t.Fatalf("expected empty hash validation error, got %v", err)
	}
}
