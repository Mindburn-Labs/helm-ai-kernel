// quantum_posture: these tests exercise classical Ed25519 signatures and
// X.509/TLS trust rotation only; they make no post-quantum assurance claim.
package reconcile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	source = NewControlPlaneSource("http://controlplane.example", scope)
	if _, err := source.Head(context.Background(), scope); err == nil {
		t.Fatal("expected non-HTTPS controlplane URL error")
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
	if gotHead.Scope != DefaultScope || !sawBearer {
		t.Fatalf("head scope was rewritten or authorization missing: %+v bearer=%v", gotHead, sawBearer)
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
	source.BearerToken = "token-1"
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
	source.BearerToken = "token-1"
	if _, err := source.Head(context.Background(), scope); err == nil {
		t.Fatal("expected controlplane decode error")
	}
}

func TestControlPlaneHTTPClientUsesExclusiveRotatingCA(t *testing.T) {
	serverOne := newControlPlaneTLSServer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scope":{"tenant_id":"default","workspace_id":"default"},"policy_epoch":1,"policy_hash":"hash"}`))
	}))
	defer serverOne.Close()
	serverTwo := newControlPlaneTLSServer(t, 2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scope":{"tenant_id":"default","workspace_id":"default"},"policy_epoch":2,"policy_hash":"hash"}`))
	}))
	defer serverTwo.Close()

	caFile := filepath.Join(t.TempDir(), "controlplane-ca.pem")
	writeControlPlaneTestCA(t, caFile, serverOne)
	client, err := NewControlPlaneHTTPClient(serverOne.URL, caFile)
	if err != nil {
		t.Fatalf("new controlplane client: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 || transport.TLSClientConfig.InsecureSkipVerify || transport.DialTLSContext == nil {
		t.Fatalf("unexpected private-CA transport: %+v", transport)
	}

	source := NewControlPlaneSource(serverOne.URL, DefaultScope)
	source.HTTPClient = client
	source.BearerToken = "token"
	if _, err := source.Head(context.Background(), DefaultScope); err != nil {
		t.Fatalf("initial private CA rejected: %v", err)
	}

	writeControlPlaneTestCA(t, caFile, serverTwo)
	source.BaseURL = serverTwo.URL
	if _, err := source.Head(context.Background(), DefaultScope); err != nil {
		t.Fatalf("rotated private CA rejected: %v", err)
	}
	source.BaseURL = serverOne.URL
	if _, err := source.Head(context.Background(), DefaultScope); err == nil {
		t.Fatal("retired private CA remained trusted")
	}
}

func TestControlPlaneHTTPClientRejectsRedirects(t *testing.T) {
	leakedAuthorization := make(chan string, 1)
	plaintextTarget := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		leakedAuthorization <- request.Header.Get("Authorization")
	}))
	defer plaintextTarget.Close()

	redirector := newControlPlaneTLSServer(t, 3, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, plaintextTarget.URL, http.StatusFound)
	}))
	defer redirector.Close()

	caFile := filepath.Join(t.TempDir(), "controlplane-ca.pem")
	writeControlPlaneTestCA(t, caFile, redirector)
	client, err := NewControlPlaneHTTPClient(redirector.URL, caFile)
	if err != nil {
		t.Fatalf("new controlplane client: %v", err)
	}
	source := NewControlPlaneSource(redirector.URL, DefaultScope)
	source.HTTPClient = client
	source.BearerToken = "secret-policy-token"
	if _, err := source.Head(context.Background(), DefaultScope); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
	select {
	case authorization := <-leakedAuthorization:
		t.Fatalf("redirect reached plaintext target with authorization %q", authorization)
	default:
	}
}

func newControlPlaneTLSServer(t *testing.T, serial int64, handler http.Handler) *httptest.Server {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate controlplane test key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:        true, BasicConstraintsValid: true,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create controlplane test certificate: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}}}
	server.StartTLS()
	return server
}

func writeControlPlaneTestCA(t *testing.T, path string, server *httptest.Server) {
	t.Helper()
	certificate := server.TLS.Certificates[0].Certificate[0]
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o600); err != nil {
		t.Fatalf("write controlplane CA: %v", err)
	}
}

func TestControlPlaneSourceRejectsOversizedOrAmbiguousResponses(t *testing.T) {
	scope := PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	payload := "{}"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	source := NewControlPlaneSource(server.URL, scope)
	source.BearerToken = "token-1"
	for _, test := range []struct {
		name    string
		payload string
		needle  string
	}{
		{name: "unknown head field", payload: `{"unknown":true}`, needle: "unknown field"},
		{name: "multiple head values", payload: `{} {}`, needle: "exactly one JSON value"},
		{name: "oversized head", payload: strings.Repeat(" ", int(maxControlPlaneHeadBytes)) + `{}`, needle: "exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload = test.payload
			if _, err := source.Head(context.Background(), scope); err == nil || !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("Head error = %v, want %q", err, test.needle)
			}
		})
	}

	payload = strings.Repeat("x", int(maxControlPlaneBundleBytes)+1)
	if _, err := source.Load(context.Background(), scope, 1); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load error = %v, want oversized response rejection", err)
	}
}

func TestControlPlaneSourceReloadsProjectedBearerToken(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("token-1"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	scope := PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	bundle := []byte("policy")
	head := PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)}
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		if r.URL.Path == "/api/v1/policy/head" {
			_ = json.NewEncoder(w).Encode(head)
			return
		}
		_, _ = w.Write(bundle)
	}))
	defer server.Close()

	source := NewControlPlaneSource(server.URL, scope)
	source.BearerTokenFile = tokenPath
	if _, err := source.Head(context.Background(), scope); err != nil {
		t.Fatalf("head with projected token: %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte("token-2"), 0o600); err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	if _, err := source.Load(context.Background(), scope, 1); err != nil {
		t.Fatalf("load with rotated token: %v", err)
	}
	if len(authorizations) != 2 || authorizations[0] != "Bearer token-1" || authorizations[1] != "Bearer token-2" {
		t.Fatalf("projected token rotation was not observed: %v", authorizations)
	}

	source.BearerToken = "static-token"
	if _, err := source.Head(context.Background(), scope); err == nil || !strings.Contains(err.Error(), "either a bearer token or a token file") {
		t.Fatalf("expected conflicting credential error, got %v", err)
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
func (failingStore) Invalidate(PolicyScope, string) (*EffectivePolicySnapshot, bool) {
	return nil, false
}

func TestScopeAndHelperBranches(t *testing.T) {
	if DefaultScope != (*EffectivePolicySnapshot)(nil).Scope() {
		t.Fatal("nil snapshot should report default scope")
	}
	partial := PolicyScope{TenantID: "tenant"}
	if partial.Normalize().WorkspaceID != DefaultScope.WorkspaceID {
		t.Fatalf("partial scope did not normalize: %+v", partial.Normalize())
	}
	if err := verifyExpectedPolicyHash(PolicyHead{}, []byte("x")); !errors.Is(err, ErrPolicyNotReady) {
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

func TestMountedFileSourceBindsReferencePackDigest(t *testing.T) {
	dir := t.TempDir()
	refDir := filepath.Join(dir, "reference_packs")
	if err := os.MkdirAll(refDir, 0o750); err != nil {
		t.Fatal(err)
	}
	refPath := filepath.Join(refDir, "runtime.json")
	if err := os.WriteFile(refPath, []byte(`{"pack_id":"runtime","version":1}`), 0o600); err != nil {
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

	source := NewMountedFileSource(policyPath, DefaultScope)
	head, err := source.Head(context.Background(), DefaultScope)
	if err != nil {
		t.Fatal(err)
	}
	if head.PolicyHash == HashBytes(policyBytes) {
		t.Fatalf("reference pack digest was not bound into policy hash")
	}
	refDigest := HashBytes([]byte(`{"pack_id":"runtime","version":1}`))
	if len(head.SourceRefs) < 2 || !strings.Contains(strings.Join(head.SourceRefs, "\n"), "@"+refDigest) {
		t.Fatalf("source refs missing reference pack digest: %+v", head.SourceRefs)
	}
	if err := verifyExpectedPolicyHash(head, policyBytes); err != nil {
		t.Fatalf("composite policy hash did not verify: %v", err)
	}

	if err := os.WriteFile(refPath, []byte(`{"pack_id":"runtime","version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := source.Head(context.Background(), DefaultScope)
	if err != nil {
		t.Fatal(err)
	}
	if tampered.PolicyHash == head.PolicyHash {
		t.Fatal("reference pack mutation did not change mounted policy hash")
	}
}

func TestMountedFileSourceRejectsReferencePackEscape(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(`
name = "runtime"
profile = "test"
reference_pack = "../outside.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	source := NewMountedFileSource(policyPath, DefaultScope)
	if _, err := source.Head(context.Background(), DefaultScope); err == nil || !strings.Contains(err.Error(), "must not escape") {
		t.Fatalf("expected reference_pack escape denial, got %v", err)
	}
}
