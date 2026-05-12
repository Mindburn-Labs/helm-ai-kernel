package reconcile

import (
	"context"
	"errors"
	"testing"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

type mutableSource struct {
	head   PolicyHead
	bundle []byte
	err    error
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
	if status.SnapshotStatus != StatusNoPolicy {
		t.Fatalf("unexpected status for missing snapshot: %+v", status)
	}
}
