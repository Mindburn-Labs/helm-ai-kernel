package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/cpi"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

type mutableSource struct {
	head   PolicyHead
	bundle []byte
	err    error
}

type serializedReconcileSource struct {
	*mutableSource
	secondHead chan struct{}

	mu        sync.Mutex
	headCalls int
}

func (s *serializedReconcileSource) Head(ctx context.Context, scope PolicyScope) (PolicyHead, error) {
	s.mu.Lock()
	s.headCalls++
	call := s.headCalls
	s.mu.Unlock()
	if call == 2 {
		close(s.secondHead)
	}
	return s.mutableSource.Head(ctx, scope)
}

func (s *mutableSource) ListScopes(context.Context) ([]PolicyScope, error) {
	return []PolicyScope{s.head.Scope.Normalize()}, nil
}

func (s *mutableSource) Head(context.Context, PolicyScope) (PolicyHead, error) {
	if s.err != nil {
		return PolicyHead{}, s.err
	}
	return s.head, nil
}

func (s *mutableSource) Load(context.Context, PolicyScope, uint64) ([]byte, error) {
	return append([]byte(nil), s.bundle...), nil
}

type rejectingVerifier struct{}

func (rejectingVerifier) VerifyPolicyBundle(context.Context, PolicyHead, []byte) error {
	return errors.New("bad signature")
}

type testEmergencyVerifier struct {
	now time.Time
}

func (v testEmergencyVerifier) VerifyEmergencyCapsule(_ context.Context, head PolicyHead, capsule contracts.EmergencyCapsule) error {
	if err := safedep.ValidateEmergencyCapsule(capsule, safedep.CapsuleExpectation{
		HazardCode:     capsule.HazardCode,
		State:          contracts.SafeDepDegradedNarrowing,
		PolicyEpoch:    head.PolicyEpoch,
		PolicyHash:     head.PolicyHash,
		P0CeilingsHash: head.P0CeilingsHash,
		P1BundleHash:   head.P1BundleHash,
		Now:            v.now,
		MaxTTL:         time.Hour,
	}); err != nil {
		return err
	}
	return safedep.ValidateHardwareCeremony(capsule.Ceremony, safedep.CeremonyExpectation{RequiredQuorum: 3, PolicyEpoch: head.PolicyEpoch, Now: v.now})
}

func testCompiler(_ context.Context, head PolicyHead, _ []byte) (*EffectivePolicySnapshot, error) {
	scope := head.Scope.Normalize()
	return &EffectivePolicySnapshot{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		PolicyEpoch: head.PolicyEpoch,
		PolicyHash:  head.PolicyHash,
		Validation:  ValidationStatus{Status: StatusActive},
		Graph:       prg.NewGraph(),
	}, nil
}

func assertInvalidSnapshot(t *testing.T, snapshot *EffectivePolicySnapshot) {
	t.Helper()
	if snapshot == nil || snapshot.Validation.Status != StatusInvalid {
		t.Fatalf("snapshot was not invalidated: %+v", snapshot)
	}
	if snapshot.Graph != nil || snapshot.PDP != nil || len(snapshot.PolicyLayers) != 0 {
		t.Fatalf("invalid snapshot retained executable policy material: %+v", snapshot)
	}
}

func TestReconcilerInstallsInitialSnapshotAndUpdatesOnPoll(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("policy-v1")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler, KeepLastKnownGood: true})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), scope)
	if err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if !status.Updated || status.InstalledPolicyHash != HashBytes(bundle) || status.InstalledPolicyEpoch != 1 {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	next := []byte("policy-v2")
	source.head = PolicyHead{Scope: scope, PolicyEpoch: 2, PolicyHash: HashBytes(next)}
	source.bundle = next
	statuses, err := reconciler.ReconcileAll(context.Background())
	if err != nil {
		t.Fatalf("poll reconcile: %v", err)
	}
	if len(statuses) != 1 || statuses[0].InstalledPolicyEpoch != 2 {
		t.Fatalf("poll did not install epoch 2: %+v", statuses)
	}
}

func TestControlPlaneSourcePublishesPolicyToReconciler(t *testing.T) {
	scope := PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	bundle := []byte("commercial-policy-v7")
	head := PolicyHead{
		Scope:       scope,
		PolicyEpoch: 7,
		PolicyHash:  HashBytes(bundle),
		BundleRef:   "controlplane://policies/tenant-a/workspace-a/7",
		SourceRefs:  []string{"company-policy-version:7", "approval:policy-council"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tenant_id") != scope.TenantID || r.URL.Query().Get("workspace_id") != scope.WorkspaceID {
			http.Error(w, "wrong scope", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/api/v1/policy/head":
			_ = json.NewEncoder(w).Encode(head)
		case "/api/v1/policy/bundle":
			if r.URL.Query().Get("policy_epoch") != "7" {
				http.Error(w, "wrong epoch", http.StatusBadRequest)
				return
			}
			_, _ = w.Write(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source := NewControlPlaneSource(server.URL, scope)
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:            source,
		Store:             store,
		Compiler:          testCompiler,
		KeepLastKnownGood: true,
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err != nil {
		t.Fatalf("reconcile controlplane source: status=%+v err=%v", status, err)
	}
	if !status.Updated || status.PolicyEpoch != 7 || status.PolicyHash != HashBytes(bundle) {
		t.Fatalf("controlplane policy was not installed: %+v", status)
	}
	if status.BundleRef != head.BundleRef || len(status.SourceRefs) != 2 || status.AuditEvent != "policy_reconcile" {
		t.Fatalf("status missing policy audit/source refs: %+v", status)
	}
	current, ok := store.Get(scope)
	if !ok || current.PolicyEpoch != 7 || current.PolicyHash != HashBytes(bundle) {
		t.Fatalf("store missing installed controlplane policy: %+v", current)
	}
	if len(current.SourceRefs) != 2 {
		t.Fatalf("snapshot did not retain source refs: %+v", current)
	}
}

func TestReconcilerStartPollingRecoversLostHint(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("policy-v1")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler, KeepLastKnownGood: true})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), scope); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	next := []byte("policy-v2-no-hint")
	source.head = PolicyHead{Scope: scope, PolicyEpoch: 2, PolicyHash: HashBytes(next)}
	source.bundle = next
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reconciler.Start(ctx, time.Millisecond)

	deadline := time.After(500 * time.Millisecond)
	for {
		current, ok := store.Get(scope)
		if ok && current.PolicyEpoch == 2 && current.PolicyHash == HashBytes(next) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("poller did not recover lost hint; current=%+v", current)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestReconcilerRejectsHashMismatch(t *testing.T) {
	scope := DefaultScope
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: "sha256:not-the-bundle"},
		bundle: []byte("actual-policy"),
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || !errors.Is(err, ErrPolicyHashMismatch) {
		t.Fatalf("expected hash mismatch, got status=%+v err=%v", status, err)
	}
	if _, ok := store.Get(scope); ok {
		t.Fatal("hash mismatch installed a snapshot")
	}
}

func TestReconcilerRejectsInvalidSignature(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("signed-policy")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle), Signature: "sig"},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler, Verifier: rejectingVerifier{}})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Fatalf("expected invalid signature, got status=%+v err=%v", status, err)
	}
	if _, ok := store.Get(scope); ok {
		t.Fatal("invalid signature installed a snapshot")
	}
}

func TestReconcilerRejectsMissingRequiredSignature(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("unsigned-policy")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler, RequireSignature: true})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Fatalf("expected missing signature rejection, got status=%+v err=%v", status, err)
	}
	if _, ok := store.Get(scope); ok {
		t.Fatal("unsigned policy installed when signatures are required")
	}
}

func TestReconcilerInstallsValidEd25519Signature(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("signed-policy-v1")
	signer, err := helmcrypto.NewEd25519Signer("policy-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signature, err := signer.Sign(bundle)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle), Signature: signature},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:           source,
		Store:            store,
		Compiler:         testCompiler,
		Verifier:         NewEd25519PolicyVerifier(signer.PublicKey()),
		RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), scope)
	if err != nil {
		t.Fatalf("reconcile signed bundle: status=%+v err=%v", status, err)
	}
	if !status.Updated || status.InstalledPolicyHash != HashBytes(bundle) || status.InstalledPolicyEpoch != 1 {
		t.Fatalf("signed bundle was not installed: %+v", status)
	}
}

func TestReconcilerRequiresCompositeSignatureForDigestBoundPolicy(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("signed-policy-with-reference")
	sourceRefs := []string{"policy.toml", "reference_pack:/policy/reference.json@sha256:" + strings.Repeat("a", 64)}
	policyHash := PolicyHashWithSourceRefs(bundle, sourceRefs)
	signer, err := helmcrypto.NewEd25519Signer("policy-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	bundleOnlySignature, err := signer.Sign(bundle)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: policyHash, SourceRefs: sourceRefs, Signature: bundleOnlySignature},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:           source,
		Store:            store,
		Compiler:         testCompiler,
		Verifier:         NewEd25519PolicyVerifier(signer.PublicKey()),
		RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if status, err := reconciler.Reconcile(context.Background(), scope); err == nil {
		t.Fatalf("bundle-only signature installed digest-bound policy: %+v", status)
	}

	compositeSignature, err := signer.Sign(PolicyHashMaterial(bundle, sourceRefs))
	if err != nil {
		t.Fatalf("sign composite material: %v", err)
	}
	source.head.Signature = compositeSignature
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err != nil {
		t.Fatalf("composite signature rejected: status=%+v err=%v", status, err)
	}
	if !status.Updated || status.InstalledPolicyHash != policyHash {
		t.Fatalf("digest-bound policy not installed: %+v", status)
	}
}

func TestReconcilerRejectsTamperedEd25519Signature(t *testing.T) {
	scope := DefaultScope
	signedBundle := []byte("signed-policy-v1")
	loadedBundle := []byte("signed-policy-v2")
	signer, err := helmcrypto.NewEd25519Signer("policy-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signature, err := signer.Sign(signedBundle)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(loadedBundle), Signature: signature},
		bundle: loadedBundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:           source,
		Store:            store,
		Compiler:         testCompiler,
		Verifier:         NewEd25519PolicyVerifier(signer.PublicKey()),
		RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Fatalf("expected tampered signature rejection, got status=%+v err=%v", status, err)
	}
	if _, ok := store.Get(scope); ok {
		t.Fatal("tampered signature installed a snapshot")
	}
}

func TestReconcilerInvalidUpdateKeepsLastKnownGood(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("policy-v1")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler, KeepLastKnownGood: true})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), scope); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	source.head = PolicyHead{Scope: scope, PolicyEpoch: 2, PolicyHash: "sha256:bad"}
	source.bundle = []byte("tampered")
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil {
		t.Fatalf("expected invalid update, got status=%+v", status)
	}
	current, ok := store.Get(scope)
	if !ok || current.PolicyEpoch != 1 || current.PolicyHash != HashBytes(bundle) {
		t.Fatalf("last-known-good was not preserved: %+v", current)
	}
	if status.InstalledPolicyEpoch != 1 {
		t.Fatalf("status did not report last-known-good: %+v", status)
	}
}

func TestReconcilerNoChangeRefreshesLastVerifiedAt(t *testing.T) {
	scope := DefaultScope
	verifiedAt := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	initialVerification := verifiedAt
	bundle := []byte("policy-v1")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:            source,
		Store:             store,
		Compiler:          testCompiler,
		KeepLastKnownGood: true,
		Clock:             func() time.Time { return verifiedAt },
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), scope); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	installed, ok := store.Get(scope)
	if !ok || !installed.LastVerifiedAt.Equal(verifiedAt) {
		t.Fatalf("initial verification time was not recorded: %+v", installed)
	}

	verifiedAt = verifiedAt.Add(DefaultLKGMaxAge - time.Minute)
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err != nil || status.ReconcileStatus != StatusNoChange || status.Updated {
		t.Fatalf("expected no-change reconcile, got status=%+v err=%v", status, err)
	}
	refreshed, ok := store.Get(scope)
	if !ok || refreshed == installed || !refreshed.LastVerifiedAt.Equal(verifiedAt) {
		t.Fatalf("no-change reconcile did not copy and refresh verification time: %+v", refreshed)
	}
	if !installed.LastVerifiedAt.Equal(initialVerification) {
		t.Fatalf("no-change reconcile mutated the prior immutable snapshot: %+v", installed)
	}

	source.err = errors.New("control plane unavailable")
	verifiedAt = verifiedAt.Add(time.Minute)
	status, err = reconciler.Reconcile(context.Background(), scope)
	if err == nil || status.ReconcileStatus != StatusSourceError || status.SnapshotStatus != StatusActive {
		t.Fatalf("refreshed last-known-good did not survive the original expiry boundary: status=%+v err=%v", status, err)
	}
}

func TestReconcilerSourceFaultKeepsFreshLastKnownGood(t *testing.T) {
	scope := DefaultScope
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	bundle := []byte("policy-v1")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:            source,
		Store:             store,
		Compiler:          testCompiler,
		KeepLastKnownGood: true,
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if reconciler.lkgMaxAge != DefaultLKGMaxAge {
		t.Fatalf("expected default LKG max age %s, got %s", DefaultLKGMaxAge, reconciler.lkgMaxAge)
	}
	if _, err := reconciler.Reconcile(context.Background(), scope); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	current, ok := store.Get(scope)
	if !ok || !current.LastVerifiedAt.Equal(now) {
		t.Fatalf("initial snapshot verification time was not recorded: %+v", current)
	}

	source.err = errors.New("control plane unavailable")
	now = now.Add(DefaultLKGMaxAge - time.Nanosecond)
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || status.ReconcileStatus != StatusSourceError || status.SnapshotStatus != StatusActive {
		t.Fatalf("expected fresh LKG preservation after source fault, got status=%+v err=%v", status, err)
	}
	current, ok = store.Get(scope)
	if !ok || current.Validation.Status != StatusActive || current.Graph == nil {
		t.Fatalf("fresh LKG was not preserved: %+v", current)
	}
}

func TestReconcilerSourceFaultExpiresLastKnownGoodFailClosed(t *testing.T) {
	scope := DefaultScope
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	bundle := []byte("policy-v1")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:            source,
		Store:             store,
		Compiler:          testCompiler,
		KeepLastKnownGood: true,
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), scope); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	current, ok := store.Get(scope)
	if !ok {
		t.Fatal("initial snapshot missing")
	}
	current.PDP = pdp.NewHelmPDP("test", nil)
	current.PolicyLayers = []cpi.PolicyLayer{{Name: "P0"}}

	source.err = errors.New("control plane unavailable")
	now = now.Add(DefaultLKGMaxAge)
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || status.ReconcileStatus != StatusSourceError || status.SnapshotStatus != StatusInvalid || !strings.Contains(status.Reason, lkgExpiredReasonText) {
		t.Fatalf("expected expired LKG failure, got status=%+v err=%v", status, err)
	}
	current, ok = store.Get(scope)
	if !ok || !strings.Contains(current.Validation.Reason, lkgExpiredReasonText) {
		t.Fatalf("expired LKG was not recorded as invalid: %+v", current)
	}
	assertInvalidSnapshot(t, current)

	source.err = nil
	now = now.Add(time.Second)
	status, err = reconciler.Reconcile(context.Background(), scope)
	if err != nil || status.ReconcileStatus != "ok" || status.SnapshotStatus != StatusActive {
		t.Fatalf("reconciler did not recover an invalidated snapshot: status=%+v err=%v", status, err)
	}
}

func TestReconcilerSourceFaultWithoutLKGInvalidatesSnapshot(t *testing.T) {
	scope := DefaultScope
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	bundle := []byte("policy-v1")
	source := &mutableSource{
		head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:   source,
		Store:    store,
		Compiler: testCompiler,
		Clock:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), scope); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	current, ok := store.Get(scope)
	if !ok {
		t.Fatal("initial snapshot missing")
	}
	current.PDP = pdp.NewHelmPDP("test", nil)
	current.PolicyLayers = []cpi.PolicyLayer{{Name: "P0"}}

	source.err = errors.New("control plane unavailable")
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || status.ReconcileStatus != StatusSourceError || status.SnapshotStatus != StatusInvalid || !strings.Contains(status.Reason, lkgRetentionDisabledReasonText) {
		t.Fatalf("expected disabled LKG invalidation, got status=%+v err=%v", status, err)
	}
	current, ok = store.Get(scope)
	if !ok || !strings.Contains(current.Validation.Reason, lkgRetentionDisabledReasonText) {
		t.Fatalf("disabled LKG was not recorded as invalid: %+v", current)
	}
	assertInvalidSnapshot(t, current)
}

func TestLastKnownGoodRequiresVerificationTime(t *testing.T) {
	reconciler := &Reconciler{
		keepLastKnownGood: true,
		lkgMaxAge:         DefaultLKGMaxAge,
		now:               func() time.Time { return time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) },
	}
	if reconciler.lastKnownGoodFresh(&EffectivePolicySnapshot{Validation: ValidationStatus{Status: StatusActive}}) {
		t.Fatal("last-known-good snapshot without verification time must not be fresh")
	}
	if reason := reconciler.lkgInvalidationReason(&EffectivePolicySnapshot{}); reason != lkgMissingVerificationTimeReasonText {
		t.Fatalf("missing verification time reason = %q", reason)
	}
}

func TestReconcilerSerializesFullReconcile(t *testing.T) {
	scope := DefaultScope
	bundle := []byte("policy-v1")
	source := &serializedReconcileSource{
		mutableSource: &mutableSource{
			head:   PolicyHead{Scope: scope, PolicyEpoch: 1, PolicyHash: HashBytes(bundle)},
			bundle: bundle,
		},
		secondHead: make(chan struct{}),
	}
	firstCompiler := make(chan struct{})
	releaseFirstCompiler := make(chan struct{})
	var compilerMu sync.Mutex
	compilerCalls := 0
	compiler := func(ctx context.Context, head PolicyHead, bundle []byte) (*EffectivePolicySnapshot, error) {
		compilerMu.Lock()
		compilerCalls++
		call := compilerCalls
		compilerMu.Unlock()
		if call == 1 {
			close(firstCompiler)
			<-releaseFirstCompiler
		}
		return testCompiler(ctx, head, bundle)
	}
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: NewAtomicSnapshotStore(), Compiler: compiler})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	releaseCompiler := func() {
		select {
		case <-releaseFirstCompiler:
		default:
			close(releaseFirstCompiler)
		}
	}
	defer releaseCompiler()

	firstDone := make(chan error, 1)
	go func() {
		_, err := reconciler.Reconcile(context.Background(), scope)
		firstDone <- err
	}()
	select {
	case <-firstCompiler:
	case <-time.After(time.Second):
		t.Fatal("first reconcile did not reach the compiler")
	}

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, err := reconciler.Reconcile(context.Background(), scope)
		secondDone <- err
	}()
	<-secondStarted
	select {
	case <-source.secondHead:
		t.Fatal("second reconcile entered the source before the first completed")
	case <-time.After(50 * time.Millisecond):
	}

	releaseCompiler()
	if err := <-firstDone; err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	select {
	case <-source.secondHead:
	case <-time.After(time.Second):
		t.Fatal("second reconcile did not run after the first completed")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

func TestReconcilerInitialSnapshotRequired(t *testing.T) {
	scope := DefaultScope
	source := &mutableSource{head: PolicyHead{Scope: scope}, err: ErrPolicyNotReady}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || !errors.Is(err, ErrPolicyNotReady) {
		t.Fatalf("expected not ready, got status=%+v err=%v", status, err)
	}
	if status.ReconcileStatus != StatusSourceError || status.SnapshotStatus != StatusNoPolicy {
		t.Fatalf("unexpected status for missing snapshot: %+v", status)
	}
}

func TestReconcilerRequiresEmergencyCapsuleVerifier(t *testing.T) {
	scope := DefaultScope
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	bundle := []byte("policy-with-emergency-capsule")
	capsule := testEmergencyCapsule(now, HashBytes(bundle))
	source := &mutableSource{
		head: PolicyHead{
			Scope:            scope,
			PolicyEpoch:      7,
			PolicyHash:       HashBytes(bundle),
			P0CeilingsHash:   "sha256:p0",
			P1BundleHash:     "sha256:p1",
			EmergencyCapsule: &capsule,
		},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{Source: source, Store: store, Compiler: testCompiler})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected missing emergency verifier rejection, got status=%+v err=%v", status, err)
	}
	if _, ok := store.Get(scope); ok {
		t.Fatal("emergency capsule installed without verifier")
	}
}

func TestReconcilerInstallsVerifiedEmergencyCapsuleMetadata(t *testing.T) {
	scope := DefaultScope
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	bundle := []byte("policy-with-emergency-capsule")
	capsule := testEmergencyCapsule(now, HashBytes(bundle))
	source := &mutableSource{
		head: PolicyHead{
			Scope:            scope,
			PolicyEpoch:      7,
			PolicyHash:       HashBytes(bundle),
			P0CeilingsHash:   "sha256:p0",
			P1BundleHash:     "sha256:p1",
			EmergencyCapsule: &capsule,
		},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:            source,
		Store:             store,
		Compiler:          testCompiler,
		EmergencyVerifier: testEmergencyVerifier{now: now},
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err != nil {
		t.Fatalf("reconcile emergency capsule: status=%+v err=%v", status, err)
	}
	current, ok := store.Get(scope)
	if !ok {
		t.Fatal("policy snapshot not installed")
	}
	if current.EmergencyCapsuleHash == "" || current.EmergencyApertureID != "rotate-credential" || !current.EmergencyExpiresAt.Equal(capsule.ExpiresAt) {
		t.Fatalf("snapshot missing emergency metadata: %+v", current)
	}
}

func TestReconcilerRejectsInvalidEmergencyCapsule(t *testing.T) {
	scope := DefaultScope
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	bundle := []byte("policy-with-invalid-emergency-capsule")
	capsule := testEmergencyCapsule(now, HashBytes(bundle))
	capsule.SubsetProofHash = ""
	source := &mutableSource{
		head: PolicyHead{
			Scope:            scope,
			PolicyEpoch:      7,
			PolicyHash:       HashBytes(bundle),
			P0CeilingsHash:   "sha256:p0",
			P1BundleHash:     "sha256:p1",
			EmergencyCapsule: &capsule,
		},
		bundle: bundle,
	}
	store := NewAtomicSnapshotStore()
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:            source,
		Store:             store,
		Compiler:          testCompiler,
		EmergencyVerifier: testEmergencyVerifier{now: now},
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	status, err := reconciler.Reconcile(context.Background(), scope)
	if err == nil || !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected invalid emergency capsule rejection, got status=%+v err=%v", status, err)
	}
	if _, ok := store.Get(scope); ok {
		t.Fatal("invalid emergency capsule installed")
	}
}

func testEmergencyCapsule(now time.Time, policyHash string) contracts.EmergencyCapsule {
	return contracts.EmergencyCapsule{
		CapsuleID:       "capsule-1",
		Version:         1,
		ApertureID:      "rotate-credential",
		HazardCode:      contracts.HazardCredentialExpired,
		State:           contracts.SafeDepDegradedNarrowing,
		PolicyEpoch:     7,
		PolicyHash:      policyHash,
		P0CeilingsHash:  "sha256:p0",
		P1BundleHash:    "sha256:p1",
		SubsetProofHash: "sha256:subset",
		SubsetProofKind: "cpi-narrowing-v1",
		TTLSeconds:      600,
		NotBefore:       now.Add(-time.Minute),
		ExpiresAt:       now.Add(10 * time.Minute),
		Signatures: []contracts.ThresholdSignature{
			{SignerID: "alice", Role: "founder", DeviceID: "yubi-a", KeyID: "k1", Signature: "sig-a"},
			{SignerID: "bob", Role: "security", DeviceID: "yubi-b", KeyID: "k2", Signature: "sig-b"},
			{SignerID: "carol", Role: "ops", DeviceID: "yubi-c", KeyID: "k3", Signature: "sig-c"},
		},
		Ceremony: contracts.HardwareCeremonyTranscript{
			CeremonyID:          "ceremony-1",
			RequiredQuorum:      3,
			EnrolledSignerCount: 5,
			StartedAt:           now.Add(-time.Minute),
			ExpiresAt:           now.Add(5 * time.Minute),
			TranscriptHash:      "sha256:ceremony",
			Approvals: []contracts.HardwareApproval{
				{SignerID: "alice", Role: "founder", DeviceID: "yubi-a", AssertionHash: "sha256:a", SignedAt: now},
				{SignerID: "bob", Role: "security", DeviceID: "yubi-b", AssertionHash: "sha256:b", SignedAt: now},
				{SignerID: "carol", Role: "ops", DeviceID: "yubi-c", AssertionHash: "sha256:c", SignedAt: now},
			},
		},
		Delegation: contracts.EmergencyDelegationChain{
			SessionID:      "session-1",
			HumanSubjectID: "alice",
			MaxHops:        1,
			NotBefore:      now.Add(-time.Minute),
			ExpiresAt:      now.Add(10 * time.Minute),
		},
		Attestation: contracts.AttestationResultEnvelope{
			EnvelopeID: "attestation-1",
			ProfileID:  "nitro-prod",
			TrustTier:  "verified",
			PolicyHash: "sha256:appraisal",
			Nonce:      "nonce-1",
			ExpiresAt:  now.Add(time.Minute),
			Signature:  "sig-attestation",
		},
	}
}
