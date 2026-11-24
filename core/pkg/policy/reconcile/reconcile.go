// Package reconcile owns runtime policy reconciliation.
//
// Policy delivery mechanisms only expose heads and bytes. The reconciler is
// the authority boundary that verifies, compiles, validates, and atomically
// swaps immutable policy snapshots used by the runtime.
//
// quantum_posture: policy signatures use classical Ed25519 verification;
// reconciliation fails closed and makes no post-quantum resistance claim.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/cpi"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

const (
	StatusActive        = "active"
	StatusInvalid       = "invalid"
	StatusNoChange      = "no_change"
	StatusNoPolicy      = "no_policy"
	StatusSourceError   = "source_error"
	StatusCompileError  = "compile_error"
	StatusValidateError = "validate_error"
	DefaultLKGMaxAge    = 10 * time.Minute

	maxControlPlaneHeadBytes   int64 = 64 << 10
	maxControlPlaneBundleBytes int64 = 1 << 20
	controlPlaneRequestTimeout       = 30 * time.Second
)

const (
	lkgExpiredReasonText                 = "last-known-good snapshot expired"
	lkgMissingVerificationTimeReasonText = "last-known-good snapshot has no verification time"
	lkgRetentionDisabledReasonText       = "last-known-good retention disabled"
)

var (
	ErrPolicyNotReady          = errors.New("policy not ready")
	ErrPolicyHashMismatch      = errors.New("policy hash mismatch")
	ErrPolicySignatureInvalid  = errors.New("policy signature invalid")
	ErrPolicyScopeMismatch     = errors.New("policy scope mismatch")
	ErrPolicyEpochRollback     = errors.New("policy epoch rollback")
	ErrPolicyEpochEquivocation = errors.New("policy epoch equivocation")
	ErrEmergencyCapsuleInvalid = errors.New("emergency capsule invalid")
)

// PolicyScope identifies the tenant/workspace policy authority boundary.
type PolicyScope struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
}

// DefaultScope is used by the current OSS single-tenant runtime.
var DefaultScope = PolicyScope{TenantID: "default", WorkspaceID: "default"}

func (s PolicyScope) Normalize() PolicyScope {
	if strings.TrimSpace(s.TenantID) == "" {
		s.TenantID = DefaultScope.TenantID
	}
	if strings.TrimSpace(s.WorkspaceID) == "" {
		s.WorkspaceID = DefaultScope.WorkspaceID
	}
	return s
}

func (s PolicyScope) Key() string {
	s = s.Normalize()
	return s.TenantID + "/" + s.WorkspaceID
}

// PolicyHead is the cheap source-of-truth pointer read before loading bytes.
type PolicyHead struct {
	Scope            PolicyScope                 `json:"scope"`
	PolicyEpoch      uint64                      `json:"policy_epoch"`
	PolicyHash       string                      `json:"policy_hash"`
	BundleRef        string                      `json:"bundle_ref,omitempty"`
	P0CeilingsHash   string                      `json:"p0_ceilings_hash,omitempty"`
	P1BundleHash     string                      `json:"p1_bundle_hash,omitempty"`
	P2OverlayHashes  []string                    `json:"p2_overlay_hashes,omitempty"`
	ProofRef         string                      `json:"proof_ref,omitempty"`
	Signature        string                      `json:"signature,omitempty"`
	SourceRefs       []string                    `json:"source_refs,omitempty"`
	EmergencyCapsule *contracts.EmergencyCapsule `json:"emergency_capsule,omitempty"`
}

// PolicySource reads policy truth from a backend. Watchers, callbacks, and
// sidecars should only wake Reconciler; they must not install policy bytes.
type PolicySource interface {
	ListScopes(ctx context.Context) ([]PolicyScope, error)
	Head(ctx context.Context, scope PolicyScope) (PolicyHead, error)
	Load(ctx context.Context, scope PolicyScope, epoch uint64) ([]byte, error)
}

// ValidationStatus captures snapshot validation outcome.
type ValidationStatus struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Hash   string `json:"hash,omitempty"`
}

// EffectivePolicySnapshot is the immutable authority installed for a scope.
type EffectivePolicySnapshot struct {
	TenantID             string           `json:"tenant_id"`
	WorkspaceID          string           `json:"workspace_id"`
	PolicyEpoch          uint64           `json:"policy_epoch"`
	PolicyHash           string           `json:"policy_hash"`
	PolicyHeadHash       string           `json:"policy_head_hash,omitempty"`
	P0CeilingsHash       string           `json:"p0_ceilings_hash,omitempty"`
	P1BundleHash         string           `json:"p1_bundle_hash,omitempty"`
	P2OverlayHashes      []string         `json:"p2_overlay_hashes,omitempty"`
	EmergencyCapsuleHash string           `json:"emergency_capsule_hash,omitempty"`
	EmergencyApertureID  string           `json:"emergency_aperture_id,omitempty"`
	EmergencyExpiresAt   time.Time        `json:"emergency_expires_at,omitempty"`
	SourceRefs           []string         `json:"source_refs,omitempty"`
	Validation           ValidationStatus `json:"validation"`
	LastVerifiedAt       time.Time        `json:"last_verified_at,omitempty"`

	Graph        *prg.Graph              `json:"-"`
	PDP          pdp.PolicyDecisionPoint `json:"-"`
	PolicyLayers []cpi.PolicyLayer       `json:"-"`
}

func (s *EffectivePolicySnapshot) Scope() PolicyScope {
	if s == nil {
		return DefaultScope
	}
	return PolicyScope{TenantID: s.TenantID, WorkspaceID: s.WorkspaceID}.Normalize()
}

// PolicySnapshotStore provides atomic per-scope snapshot reads and swaps.
type PolicySnapshotStore interface {
	Get(scope PolicyScope) (*EffectivePolicySnapshot, bool)
	Swap(scope PolicyScope, snapshot *EffectivePolicySnapshot) error
	// Invalidate must leave a stored snapshot unable to authorize policy execution.
	Invalidate(scope PolicyScope, reason string) (*EffectivePolicySnapshot, bool)
}

// SnapshotCompiler turns verified policy bytes into an effective snapshot.
type SnapshotCompiler func(ctx context.Context, head PolicyHead, bundle []byte) (*EffectivePolicySnapshot, error)

// SignatureVerifier verifies the complete unsigned policy head.
type SignatureVerifier interface {
	VerifyPolicyHead(ctx context.Context, head PolicyHead) error
}

// EmergencyCapsuleVerifier verifies hardware-quorum emergency capsules before
// the reconciler installs any snapshot that references them.
type EmergencyCapsuleVerifier interface {
	VerifyEmergencyCapsule(ctx context.Context, head PolicyHead, capsule contracts.EmergencyCapsule) error
}

// Ed25519PolicyVerifier verifies complete policy heads against an
// operator-provided Ed25519 public key. PolicyHash binds the exact bundle bytes.
type Ed25519PolicyVerifier struct {
	PublicKeyHex string
}

func NewEd25519PolicyVerifier(publicKeyHex string) *Ed25519PolicyVerifier {
	return &Ed25519PolicyVerifier{PublicKeyHex: strings.TrimSpace(publicKeyHex)}
}

func (v *Ed25519PolicyVerifier) VerifyPolicyHead(ctx context.Context, head PolicyHead) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey := strings.TrimSpace(v.PublicKeyHex)
	if publicKey == "" {
		return fmt.Errorf("%w: policy trust public key is empty", ErrPolicySignatureInvalid)
	}
	signature := strings.TrimSpace(head.Signature)
	if signature == "" {
		return fmt.Errorf("%w: policy head has empty signature", ErrPolicySignatureInvalid)
	}
	material, err := PolicyHeadSignatureMaterial(head)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicySignatureInvalid, err)
	}
	ok, err := helmcrypto.Verify(publicKey, signature, material)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicySignatureInvalid, err)
	}
	if !ok {
		return fmt.Errorf("%w: signature verification failed for policy %s", ErrPolicySignatureInvalid, head.PolicyHash)
	}
	return nil
}

// ReconcileStatus is returned by wake-only reconcile routes.
type ReconcileStatus struct {
	TenantID             string   `json:"tenant_id"`
	WorkspaceID          string   `json:"workspace_id"`
	PolicyHash           string   `json:"policy_hash,omitempty"`
	PolicyEpoch          uint64   `json:"policy_epoch,omitempty"`
	InstalledPolicyHash  string   `json:"installed_policy_hash,omitempty"`
	InstalledPolicyEpoch uint64   `json:"installed_policy_epoch,omitempty"`
	DesiredPolicyHash    string   `json:"desired_policy_hash,omitempty"`
	DesiredPolicyEpoch   uint64   `json:"desired_policy_epoch,omitempty"`
	ReconcileStatus      string   `json:"reconcile_status"`
	SnapshotStatus       string   `json:"snapshot_status,omitempty"`
	BundleRef            string   `json:"bundle_ref,omitempty"`
	SourceRefs           []string `json:"source_refs,omitempty"`
	AuditEvent           string   `json:"audit_event,omitempty"`
	Reason               string   `json:"reason,omitempty"`
	Updated              bool     `json:"updated"`
}

// Reconciler verifies source truth and atomically installs compiled snapshots.
type Reconciler struct {
	source            PolicySource
	store             PolicySnapshotStore
	compiler          SnapshotCompiler
	verifier          SignatureVerifier
	emergencyVerifier EmergencyCapsuleVerifier
	requireSignature  bool
	keepLastKnownGood bool
	lkgMaxAge         time.Duration
	now               func() time.Time

	reconcileMu sync.Mutex
	mu          sync.Mutex
	status      map[string]ReconcileStatus
}

type ReconcilerConfig struct {
	Source              PolicySource
	Store               PolicySnapshotStore
	Compiler            SnapshotCompiler
	Verifier            SignatureVerifier
	EmergencyVerifier   EmergencyCapsuleVerifier
	RequireSignature    bool
	KeepLastKnownGood   bool
	LastKnownGoodMaxAge time.Duration
	Clock               func() time.Time
}

func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	if cfg.Source == nil {
		return nil, fmt.Errorf("policy reconciler source is required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("policy reconciler store is required")
	}
	if cfg.Compiler == nil {
		return nil, fmt.Errorf("policy reconciler compiler is required")
	}
	now := cfg.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	lkgMaxAge := cfg.LastKnownGoodMaxAge
	if cfg.KeepLastKnownGood && lkgMaxAge <= 0 {
		lkgMaxAge = DefaultLKGMaxAge
	}
	return &Reconciler{
		source:            cfg.Source,
		store:             cfg.Store,
		compiler:          cfg.Compiler,
		verifier:          cfg.Verifier,
		emergencyVerifier: cfg.EmergencyVerifier,
		requireSignature:  cfg.RequireSignature,
		keepLastKnownGood: cfg.KeepLastKnownGood,
		lkgMaxAge:         lkgMaxAge,
		now:               now,
		status:            make(map[string]ReconcileStatus),
	}, nil
}

func (r *Reconciler) ReconcileAll(ctx context.Context) ([]ReconcileStatus, error) {
	scopes, err := r.source.ListScopes(ctx)
	if err != nil {
		return nil, err
	}
	statuses := make([]ReconcileStatus, 0, len(scopes))
	var errs []error
	for _, scope := range scopes {
		status, err := r.Reconcile(ctx, scope)
		statuses = append(statuses, status)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return statuses, errors.Join(errs...)
}

func (r *Reconciler) Reconcile(ctx context.Context, scope PolicyScope) (ReconcileStatus, error) {
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()

	scope = scope.Normalize()
	status := ReconcileStatus{
		TenantID:        scope.TenantID,
		WorkspaceID:     scope.WorkspaceID,
		ReconcileStatus: StatusSourceError,
		SnapshotStatus:  StatusNoPolicy,
	}

	head, err := r.source.Head(ctx, scope)
	if err != nil {
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	status.DesiredPolicyHash = head.PolicyHash
	status.DesiredPolicyEpoch = head.PolicyEpoch
	status.BundleRef = head.BundleRef
	status.SourceRefs = append([]string(nil), head.SourceRefs...)
	status.AuditEvent = "policy_reconcile"
	if head.Scope != scope {
		err := fmt.Errorf("%w: requested %s got %s", ErrPolicyScopeMismatch, scope.Key(), head.Scope.Key())
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	headMaterial, err := PolicyHeadSignatureMaterial(head)
	if err != nil {
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	desiredHeadHash := HashBytes(headMaterial)
	if err := r.verifyPolicyHeadSignature(ctx, head); err != nil {
		status.Reason = err.Error()
		return r.invalid(status, err)
	}

	if installed, ok := r.store.Get(scope); ok {
		status.PolicyHash = installed.PolicyHash
		status.PolicyEpoch = installed.PolicyEpoch
		status.InstalledPolicyHash = installed.PolicyHash
		status.InstalledPolicyEpoch = installed.PolicyEpoch
		status.SnapshotStatus = installed.Validation.Status
		if head.PolicyEpoch < installed.PolicyEpoch {
			err := fmt.Errorf("%w: installed epoch %d, desired epoch %d", ErrPolicyEpochRollback, installed.PolicyEpoch, head.PolicyEpoch)
			status.Reason = err.Error()
			return r.invalid(status, err)
		}
		if head.PolicyEpoch == installed.PolicyEpoch && installed.PolicyHash != head.PolicyHash {
			err := fmt.Errorf("%w: epoch %d changed policy hash", ErrPolicyEpochEquivocation, head.PolicyEpoch)
			status.Reason = err.Error()
			return r.invalid(status, err)
		}
		if head.PolicyEpoch == installed.PolicyEpoch && installed.PolicyHeadHash != "" && installed.PolicyHeadHash != desiredHeadHash {
			err := fmt.Errorf("%w: epoch %d changed signed head", ErrPolicyEpochEquivocation, head.PolicyEpoch)
			status.Reason = err.Error()
			return r.invalid(status, err)
		}
		if installed.Validation.Status == StatusActive && installed.PolicyHash == head.PolicyHash &&
			installed.PolicyEpoch == head.PolicyEpoch && installed.PolicyHeadHash == desiredHeadHash {
			refreshed := *installed
			refreshed.LastVerifiedAt = r.now().UTC()
			if err := r.store.Swap(scope, &refreshed); err != nil {
				status.Reason = err.Error()
				return status, err
			}
			status.ReconcileStatus = StatusNoChange
			r.remember(status)
			return status, nil
		}
	}

	bundle, err := r.source.Load(ctx, scope, head.PolicyEpoch)
	if err != nil {
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	if err := verifyExpectedPolicyHash(head, bundle); err != nil {
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	if head.EmergencyCapsule != nil {
		if r.emergencyVerifier == nil {
			err := fmt.Errorf("%w: no emergency capsule verifier configured for capsule %s", ErrEmergencyCapsuleInvalid, head.EmergencyCapsule.CapsuleID)
			status.Reason = err.Error()
			return r.invalid(status, err)
		}
		if err := r.emergencyVerifier.VerifyEmergencyCapsule(ctx, head, *head.EmergencyCapsule); err != nil {
			err = fmt.Errorf("%w: %v", ErrEmergencyCapsuleInvalid, err)
			status.Reason = err.Error()
			return r.invalid(status, err)
		}
	}

	snapshot, err := r.compiler(ctx, head, bundle)
	if err != nil {
		status.ReconcileStatus = StatusCompileError
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	if snapshot == nil {
		err := fmt.Errorf("%w: compiler returned nil snapshot", ErrPolicyNotReady)
		status.ReconcileStatus = StatusCompileError
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	normalizeSnapshot(snapshot, head)
	snapshot.PolicyHeadHash = desiredHeadHash
	if err := validateSnapshot(snapshot); err != nil {
		status.ReconcileStatus = StatusValidateError
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	snapshot.LastVerifiedAt = r.now().UTC()
	if err := r.store.Swap(scope, snapshot); err != nil {
		status.Reason = err.Error()
		return status, err
	}

	status.InstalledPolicyHash = snapshot.PolicyHash
	status.InstalledPolicyEpoch = snapshot.PolicyEpoch
	status.PolicyHash = snapshot.PolicyHash
	status.PolicyEpoch = snapshot.PolicyEpoch
	status.ReconcileStatus = "ok"
	status.SnapshotStatus = StatusActive
	status.Updated = true
	r.remember(status)
	return status, nil
}

func (r *Reconciler) verifyPolicyHeadSignature(ctx context.Context, head PolicyHead) error {
	signature := strings.TrimSpace(head.Signature)
	if signature == "" && r.requireSignature {
		return fmt.Errorf("%w: source head has empty signature", ErrPolicySignatureInvalid)
	}
	if signature == "" {
		return nil
	}
	if r.verifier == nil {
		return fmt.Errorf("%w: no verifier configured for signed policy %s", ErrPolicySignatureInvalid, head.PolicyHash)
	}
	if err := r.verifier.VerifyPolicyHead(ctx, head); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicySignatureInvalid, err)
	}
	return nil
}

func (r *Reconciler) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = r.ReconcileAll(ctx)
			}
		}
	}()
}

func (r *Reconciler) LastStatus(scope PolicyScope) (ReconcileStatus, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	status, ok := r.status[scope.Normalize().Key()]
	return status, ok
}

func (r *Reconciler) invalid(status ReconcileStatus, err error) (ReconcileStatus, error) {
	scope := PolicyScope{TenantID: status.TenantID, WorkspaceID: status.WorkspaceID}.Normalize()
	installed, ok := r.store.Get(scope)
	if !ok || installed == nil {
		r.remember(status)
		return status, err
	}
	status.PolicyHash = installed.PolicyHash
	status.PolicyEpoch = installed.PolicyEpoch
	status.InstalledPolicyHash = installed.PolicyHash
	status.InstalledPolicyEpoch = installed.PolicyEpoch
	if r.lastKnownGoodFresh(installed) {
		status.SnapshotStatus = StatusActive
		r.remember(status)
		return status, err
	}

	reason := r.lkgInvalidationReason(installed)
	if status.Reason == "" {
		status.Reason = reason
	} else {
		status.Reason += "; " + reason
	}
	status.SnapshotStatus = StatusInvalid
	r.store.Invalidate(scope, reason)
	r.remember(status)
	return status, err
}

func (r *Reconciler) lastKnownGoodFresh(snapshot *EffectivePolicySnapshot) bool {
	if snapshot == nil || !r.keepLastKnownGood || snapshot.Validation.Status != StatusActive || snapshot.LastVerifiedAt.IsZero() || r.lkgMaxAge <= 0 {
		return false
	}
	now := r.now().UTC()
	return !now.Before(snapshot.LastVerifiedAt) && now.Before(snapshot.LastVerifiedAt.Add(r.lkgMaxAge))
}

func (r *Reconciler) lkgInvalidationReason(snapshot *EffectivePolicySnapshot) string {
	if !r.keepLastKnownGood {
		return lkgRetentionDisabledReasonText
	}
	if snapshot == nil || snapshot.LastVerifiedAt.IsZero() {
		return lkgMissingVerificationTimeReasonText
	}
	if snapshot.Validation.Status != StatusActive {
		return "last-known-good snapshot is not active"
	}
	return fmt.Sprintf("%s after %s", lkgExpiredReasonText, r.lkgMaxAge)
}

func (r *Reconciler) remember(status ReconcileStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status[PolicyScope{TenantID: status.TenantID, WorkspaceID: status.WorkspaceID}.Normalize().Key()] = status
}

func normalizeSnapshot(snapshot *EffectivePolicySnapshot, head PolicyHead) {
	scope := head.Scope.Normalize()
	if strings.TrimSpace(snapshot.TenantID) == "" {
		snapshot.TenantID = scope.TenantID
	}
	if strings.TrimSpace(snapshot.WorkspaceID) == "" {
		snapshot.WorkspaceID = scope.WorkspaceID
	}
	if snapshot.PolicyEpoch == 0 {
		snapshot.PolicyEpoch = head.PolicyEpoch
	}
	if strings.TrimSpace(snapshot.PolicyHash) == "" {
		snapshot.PolicyHash = head.PolicyHash
	}
	if strings.TrimSpace(snapshot.P0CeilingsHash) == "" {
		snapshot.P0CeilingsHash = head.P0CeilingsHash
	}
	if strings.TrimSpace(snapshot.P1BundleHash) == "" {
		snapshot.P1BundleHash = head.P1BundleHash
	}
	if len(snapshot.P2OverlayHashes) == 0 {
		snapshot.P2OverlayHashes = append([]string(nil), head.P2OverlayHashes...)
	}
	if head.EmergencyCapsule != nil {
		if strings.TrimSpace(snapshot.EmergencyCapsuleHash) == "" {
			snapshot.EmergencyCapsuleHash = HashBytes(mustJSON(head.EmergencyCapsule))
		}
		if strings.TrimSpace(snapshot.EmergencyApertureID) == "" {
			snapshot.EmergencyApertureID = head.EmergencyCapsule.ApertureID
		}
		if snapshot.EmergencyExpiresAt.IsZero() {
			snapshot.EmergencyExpiresAt = head.EmergencyCapsule.ExpiresAt
		}
	}
	if len(snapshot.SourceRefs) == 0 {
		snapshot.SourceRefs = append([]string(nil), head.SourceRefs...)
	}
	if snapshot.Validation.Status == "" {
		snapshot.Validation.Status = StatusActive
	}
}

func validateSnapshot(snapshot *EffectivePolicySnapshot) error {
	if strings.TrimSpace(snapshot.TenantID) == "" || strings.TrimSpace(snapshot.WorkspaceID) == "" {
		return fmt.Errorf("%w: snapshot scope is empty", ErrPolicyNotReady)
	}
	if strings.TrimSpace(snapshot.PolicyHash) == "" {
		return fmt.Errorf("%w: snapshot policy hash is empty", ErrPolicyNotReady)
	}
	if len(snapshot.PolicyLayers) == 0 {
		return nil
	}
	facts, err := json.Marshal(snapshot.PolicyLayers)
	if err != nil {
		return fmt.Errorf("policy layer marshal: %w", err)
	}
	resultBytes, err := cpi.Validate(nil, nil, nil, facts)
	if err != nil {
		return err
	}
	var result cpi.ValidationResult
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return err
	}
	snapshot.Validation = ValidationStatus{Status: strings.ToLower(string(result.Verdict)), Hash: result.Hash}
	if result.Verdict != cpi.VerdictConsistent {
		return fmt.Errorf("policy CPI validation failed: %s", result.Verdict)
	}
	snapshot.Validation.Status = StatusActive
	return nil
}

func verifyExpectedPolicyHash(head PolicyHead, bundle []byte) error {
	expected := strings.TrimSpace(head.PolicyHash)
	if expected == "" {
		return fmt.Errorf("%w: source head has empty policy hash", ErrPolicyNotReady)
	}
	actual := HashBytes(bundle)
	if !strings.EqualFold(expected, actual) {
		composite := PolicyHashWithSourceRefs(bundle, head.SourceRefs)
		if !strings.EqualFold(expected, composite) {
			return fmt.Errorf("%w: expected %s got %s", ErrPolicyHashMismatch, expected, actual)
		}
	}
	return nil
}

func PolicyHashWithSourceRefs(bundle []byte, sourceRefs []string) string {
	return HashBytes(PolicyHashMaterial(bundle, sourceRefs))
}

// PolicyHeadSignatureMaterial binds every policy-head field except Signature.
// PolicyHash separately commits the exact bundle bytes.
func PolicyHeadSignatureMaterial(head PolicyHead) ([]byte, error) {
	unsigned := head
	unsigned.Signature = ""
	if unsigned.PolicyEpoch == 0 || strings.TrimSpace(unsigned.Scope.TenantID) == "" ||
		strings.TrimSpace(unsigned.Scope.WorkspaceID) == "" || strings.TrimSpace(unsigned.PolicyHash) == "" {
		return nil, fmt.Errorf("%w: policy head signature fields are incomplete", ErrPolicyNotReady)
	}
	return json.Marshal(struct {
		Version string     `json:"version"`
		Head    PolicyHead `json:"head"`
	}{Version: "helm-policy-publication-signature.v1", Head: unsigned})
}

// PolicySignatureMaterial is retained for source compatibility. Bundle is
// ignored because PolicyHash already binds its exact bytes.
func PolicySignatureMaterial(head PolicyHead, _ []byte) []byte {
	material, _ := PolicyHeadSignatureMaterial(head)
	return material
}

func PolicyHashMaterial(bundle []byte, sourceRefs []string) []byte {
	refs := digestSourceRefs(sourceRefs)
	data, err := json.Marshal(struct {
		BundleHash string   `json:"bundle_hash"`
		SourceRefs []string `json:"source_refs"`
	}{
		BundleHash: HashBytes(bundle),
		SourceRefs: refs,
	})
	if err != nil {
		return []byte(HashBytes(bundle))
	}
	return data
}

func digestSourceRefs(sourceRefs []string) []string {
	refs := make([]string, 0, len(sourceRefs))
	for _, ref := range sourceRefs {
		ref = strings.TrimSpace(ref)
		if strings.Contains(ref, "@sha256:") {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs
}

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf("%v", v))
	}
	return data
}

// AtomicSnapshotStore is an in-memory per-scope snapshot store.
type AtomicSnapshotStore struct {
	mu        sync.RWMutex
	snapshots map[string]*EffectivePolicySnapshot
}

func NewAtomicSnapshotStore() *AtomicSnapshotStore {
	return &AtomicSnapshotStore{snapshots: make(map[string]*EffectivePolicySnapshot)}
}

func (s *AtomicSnapshotStore) Get(scope PolicyScope) (*EffectivePolicySnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot, ok := s.snapshots[scope.Normalize().Key()]
	return snapshot, ok
}

func (s *AtomicSnapshotStore) Swap(scope PolicyScope, snapshot *EffectivePolicySnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("nil policy snapshot")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[scope.Normalize().Key()] = snapshot
	return nil
}

func (s *AtomicSnapshotStore) Invalidate(scope PolicyScope, reason string) (*EffectivePolicySnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, ok := s.snapshots[scope.Normalize().Key()]
	if !ok || snapshot == nil {
		return nil, false
	}
	invalidated := *snapshot
	invalidated.Validation.Status = StatusInvalid
	invalidated.Validation.Reason = strings.TrimSpace(reason)
	invalidated.Graph = nil
	invalidated.PDP = nil
	invalidated.PolicyLayers = nil
	s.snapshots[scope.Normalize().Key()] = &invalidated
	return &invalidated, true
}
