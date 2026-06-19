// Package reconcile owns runtime policy reconciliation.
//
// Policy delivery mechanisms only expose heads and bytes. The reconciler is
// the authority boundary that verifies, compiles, validates, and atomically
// swaps immutable policy snapshots used by the runtime.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
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
)

const lkgExpiredReasonText = "last-known-good snapshot expired"

var (
	ErrPolicyNotReady          = errors.New("policy not ready")
	ErrPolicyHashMismatch      = errors.New("policy hash mismatch")
	ErrPolicySignatureInvalid  = errors.New("policy signature invalid")
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
	P0CeilingsHash       string           `json:"p0_ceilings_hash,omitempty"`
	P1BundleHash         string           `json:"p1_bundle_hash,omitempty"`
	P2OverlayHashes      []string         `json:"p2_overlay_hashes,omitempty"`
	EmergencyCapsuleHash string           `json:"emergency_capsule_hash,omitempty"`
	EmergencyApertureID  string           `json:"emergency_aperture_id,omitempty"`
	EmergencyExpiresAt   time.Time        `json:"emergency_expires_at,omitempty"`
	SourceRefs           []string         `json:"source_refs,omitempty"`
	Validation           ValidationStatus `json:"validation"`
	InstalledAt          time.Time        `json:"installed_at,omitempty"`

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
	Invalidate(scope PolicyScope, reason string) (*EffectivePolicySnapshot, bool)
}

// SnapshotCompiler turns verified policy bytes into an effective snapshot.
type SnapshotCompiler func(ctx context.Context, head PolicyHead, bundle []byte) (*EffectivePolicySnapshot, error)

// SignatureVerifier verifies optional policy signatures/provenance.
type SignatureVerifier interface {
	VerifyPolicyBundle(ctx context.Context, head PolicyHead, bundle []byte) error
}

// EmergencyCapsuleVerifier verifies hardware-quorum emergency capsules before
// the reconciler installs any snapshot that references them.
type EmergencyCapsuleVerifier interface {
	VerifyEmergencyCapsule(ctx context.Context, head PolicyHead, capsule contracts.EmergencyCapsule) error
}

// Ed25519PolicyVerifier verifies policy bundles against an operator-provided
// Ed25519 public key. Signatures are computed over exact canonical bundle bytes.
type Ed25519PolicyVerifier struct {
	PublicKeyHex string
}

func NewEd25519PolicyVerifier(publicKeyHex string) *Ed25519PolicyVerifier {
	return &Ed25519PolicyVerifier{PublicKeyHex: strings.TrimSpace(publicKeyHex)}
}

func (v *Ed25519PolicyVerifier) VerifyPolicyBundle(ctx context.Context, head PolicyHead, bundle []byte) error {
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
	material := PolicySignatureMaterial(head, bundle)
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

	mu     sync.Mutex
	status map[string]ReconcileStatus
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
	head.Scope = head.Scope.Normalize()
	if head.Scope.Key() != scope.Key() {
		head.Scope = scope
	}
	status.DesiredPolicyHash = head.PolicyHash
	status.DesiredPolicyEpoch = head.PolicyEpoch
	status.BundleRef = head.BundleRef
	status.SourceRefs = append([]string(nil), head.SourceRefs...)
	status.AuditEvent = "policy_reconcile"

	if installed, ok := r.store.Get(scope); ok {
		status.PolicyHash = installed.PolicyHash
		status.PolicyEpoch = installed.PolicyEpoch
		status.InstalledPolicyHash = installed.PolicyHash
		status.InstalledPolicyEpoch = installed.PolicyEpoch
		status.SnapshotStatus = installed.Validation.Status
		if installed.PolicyHash == head.PolicyHash && installed.PolicyEpoch == head.PolicyEpoch {
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
	signature := strings.TrimSpace(head.Signature)
	if signature == "" && r.requireSignature {
		err := fmt.Errorf("%w: source head has empty signature", ErrPolicySignatureInvalid)
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	if signature != "" {
		if r.verifier == nil {
			err := fmt.Errorf("%w: no verifier configured for signed policy %s", ErrPolicySignatureInvalid, head.PolicyHash)
			status.Reason = err.Error()
			return r.invalid(status, err)
		}
		if err := r.verifier.VerifyPolicyBundle(ctx, head, bundle); err != nil {
			err = fmt.Errorf("%w: %v", ErrPolicySignatureInvalid, err)
			status.Reason = err.Error()
			return r.invalid(status, err)
		}
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
	if err := validateSnapshot(snapshot); err != nil {
		status.ReconcileStatus = StatusValidateError
		status.Reason = err.Error()
		return r.invalid(status, err)
	}
	snapshot.InstalledAt = r.now()
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
	scope := PolicyScope{TenantID: status.TenantID, WorkspaceID: status.WorkspaceID}
	if installed, ok := r.store.Get(scope); ok && r.keepLastKnownGood {
		status.PolicyHash = installed.PolicyHash
		status.PolicyEpoch = installed.PolicyEpoch
		status.InstalledPolicyHash = installed.PolicyHash
		status.InstalledPolicyEpoch = installed.PolicyEpoch
		if r.lastKnownGoodFresh(installed) {
			status.SnapshotStatus = installed.Validation.Status
			r.remember(status)
			return status, err
		}
		reason := fmt.Sprintf("%s after %s", lkgExpiredReasonText, r.lkgMaxAge)
		status.SnapshotStatus = StatusInvalid
		if status.Reason == "" {
			status.Reason = reason
		} else {
			status.Reason += "; " + reason
		}
		if expired, expiredOK := r.store.Invalidate(scope, reason); expiredOK && expired != nil {
			status.SnapshotStatus = expired.Validation.Status
		}
		r.remember(status)
		return status, err
	}
	if status.SnapshotStatus == "" {
		status.SnapshotStatus = StatusInvalid
	}
	r.remember(status)
	return status, err
}

func (r *Reconciler) lastKnownGoodFresh(snapshot *EffectivePolicySnapshot) bool {
	if snapshot == nil || !r.keepLastKnownGood {
		return false
	}
	if snapshot.Validation.Status != "" && snapshot.Validation.Status != StatusActive {
		return false
	}
	if r.lkgMaxAge <= 0 || snapshot.InstalledAt.IsZero() {
		return true
	}
	return r.now().Sub(snapshot.InstalledAt) <= r.lkgMaxAge
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

func PolicySignatureMaterial(head PolicyHead, bundle []byte) []byte {
	if strings.EqualFold(strings.TrimSpace(head.PolicyHash), PolicyHashWithSourceRefs(bundle, head.SourceRefs)) &&
		!strings.EqualFold(strings.TrimSpace(head.PolicyHash), HashBytes(bundle)) {
		return PolicyHashMaterial(bundle, head.SourceRefs)
	}
	return bundle
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
	if snapshot.InstalledAt.IsZero() {
		snapshot.InstalledAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[scope.Normalize().Key()] = snapshot
	return nil
}

func (s *AtomicSnapshotStore) Invalidate(scope PolicyScope, reason string) (*EffectivePolicySnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scope.Normalize().Key()
	snapshot, ok := s.snapshots[key]
	if !ok || snapshot == nil {
		return nil, false
	}
	expired := *snapshot
	expired.Validation = ValidationStatus{Status: StatusInvalid, Reason: strings.TrimSpace(reason), Hash: snapshot.PolicyHash}
	expired.Graph = nil
	expired.PDP = nil
	expired.PolicyLayers = nil
	s.snapshots[key] = &expired
	return &expired, true
}

// MountedFileSource is the OSS/local policy backend. The mounted file is
// delivery only; Reconciler still verifies and compiles before installing.
type MountedFileSource struct {
	Path          string
	SignaturePath string
	Scope         PolicyScope
}

func NewMountedFileSource(path string, scope PolicyScope) *MountedFileSource {
	return &MountedFileSource{Path: path, Scope: scope.Normalize()}
}

func (s *MountedFileSource) ListScopes(context.Context) ([]PolicyScope, error) {
	return []PolicyScope{s.Scope.Normalize()}, nil
}

func (s *MountedFileSource) Head(ctx context.Context, scope PolicyScope) (PolicyHead, error) {
	data, epoch, err := s.read(ctx)
	if err != nil {
		return PolicyHead{}, err
	}
	scope = s.Scope.Normalize()
	signature, signatureRef, err := s.readSignature(ctx)
	if err != nil {
		return PolicyHead{}, err
	}
	sourceRefs := []string{s.Path}
	if ref, err := mountedReferencePackSourceRef(s.Path, data); err != nil {
		return PolicyHead{}, err
	} else if ref != "" {
		sourceRefs = append(sourceRefs, ref)
	}
	policyHash := HashBytes(data)
	if len(digestSourceRefs(sourceRefs)) > 0 {
		policyHash = PolicyHashWithSourceRefs(data, sourceRefs)
	}
	if signatureRef != "" {
		sourceRefs = append(sourceRefs, signatureRef)
	}
	return PolicyHead{
		Scope:       scope,
		PolicyEpoch: epoch,
		PolicyHash:  policyHash,
		BundleRef:   s.Path,
		Signature:   signature,
		SourceRefs:  sourceRefs,
	}, nil
}

func (s *MountedFileSource) Load(ctx context.Context, scope PolicyScope, epoch uint64) ([]byte, error) {
	data, _, err := s.read(ctx)
	return data, err
}

func (s *MountedFileSource) read(ctx context.Context) ([]byte, uint64, error) {
	if strings.TrimSpace(s.Path) == "" {
		return nil, 0, fmt.Errorf("mounted policy path is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, 0, err
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		return nil, 0, err
	}
	epoch := uint64(info.ModTime().UnixNano())
	if epoch == 0 {
		epoch = 1
	}
	return data, epoch, nil
}

func (s *MountedFileSource) readSignature(ctx context.Context) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	path := strings.TrimSpace(s.SignaturePath)
	if path == "" {
		path = strings.TrimSpace(s.Path) + ".sig"
	}
	if strings.TrimSpace(path) == "" {
		return "", "", nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(data)), path, nil
}

type mountedPolicyRef struct {
	ReferencePack string `toml:"reference_pack"`
}

func mountedReferencePackSourceRef(policyPath string, policyBytes []byte) (string, error) {
	if strings.ToLower(filepath.Ext(policyPath)) != ".toml" {
		return "", nil
	}
	var ref mountedPolicyRef
	if _, err := toml.Decode(string(policyBytes), &ref); err != nil {
		return "", fmt.Errorf("decode mounted policy reference_pack: %w", err)
	}
	if strings.TrimSpace(ref.ReferencePack) == "" {
		return "", nil
	}
	refPath, err := ResolveReferencePackPath(policyPath, ref.ReferencePack)
	if err != nil {
		return "", err
	}
	refData, err := os.ReadFile(refPath)
	if err != nil {
		return "", fmt.Errorf("read reference_pack %s: %w", ref.ReferencePack, err)
	}
	return fmt.Sprintf("reference_pack:%s@%s", refPath, HashBytes(refData)), nil
}

func ResolveReferencePackPath(policyPath, referencePack string) (string, error) {
	referencePack = strings.TrimSpace(referencePack)
	if referencePack == "" {
		return "", fmt.Errorf("reference_pack is required")
	}
	if filepath.IsAbs(referencePack) {
		return "", fmt.Errorf("reference_pack must be relative to the policy file")
	}
	base, err := filepath.Abs(filepath.Dir(policyPath))
	if err != nil {
		return "", err
	}
	target := filepath.Clean(filepath.Join(base, referencePack))
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, targetAbs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("reference_pack must not escape the policy directory")
	}
	return targetAbs, nil
}

// ControlPlaneSource is the HTTP contract for managed policy publication.
// The payload format is intentionally opaque to the source; the compiler owns
// policy semantics.
type ControlPlaneSource struct {
	BaseURL     string
	HTTPClient  *http.Client
	Scope       PolicyScope
	BearerToken string
}

func NewControlPlaneSource(baseURL string, scope PolicyScope) *ControlPlaneSource {
	return &ControlPlaneSource{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: http.DefaultClient, Scope: scope.Normalize()}
}

func ValidateControlPlaneURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("controlplane URL is invalid: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("controlplane URL must be an absolute URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackControlPlaneHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("controlplane URL must use https unless the host is localhost or loopback")
	default:
		return fmt.Errorf("controlplane URL must use https")
	}
}

func isLoopbackControlPlaneHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *ControlPlaneSource) ListScopes(ctx context.Context) ([]PolicyScope, error) {
	return []PolicyScope{s.Scope.Normalize()}, nil
}

func (s *ControlPlaneSource) Head(ctx context.Context, scope PolicyScope) (PolicyHead, error) {
	endpoint, err := s.url("/api/v1/policy/head", scope.Normalize(), 0)
	if err != nil {
		return PolicyHead{}, err
	}
	var head PolicyHead
	if err := s.getJSON(ctx, endpoint, &head); err != nil {
		return PolicyHead{}, err
	}
	if head.Scope.Key() == DefaultScope.Key() {
		head.Scope = scope.Normalize()
	}
	return head, nil
}

func (s *ControlPlaneSource) Load(ctx context.Context, scope PolicyScope, epoch uint64) ([]byte, error) {
	endpoint, err := s.url("/api/v1/policy/bundle", scope.Normalize(), epoch)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	s.authorize(req)
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("controlplane load failed: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (s *ControlPlaneSource) url(path string, scope PolicyScope, epoch uint64) (string, error) {
	if strings.TrimSpace(s.BaseURL) == "" {
		return "", fmt.Errorf("controlplane URL is required")
	}
	if err := ValidateControlPlaneURL(s.BaseURL); err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimRight(s.BaseURL, "/") + path)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("tenant_id", scope.TenantID)
	q.Set("workspace_id", scope.WorkspaceID)
	if epoch > 0 {
		q.Set("policy_epoch", fmt.Sprintf("%d", epoch))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *ControlPlaneSource) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	s.authorize(req)
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("controlplane head failed: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *ControlPlaneSource) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return http.DefaultClient
}

func (s *ControlPlaneSource) authorize(req *http.Request) {
	if strings.TrimSpace(s.BearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(s.BearerToken))
	}
}

// StaticSource is useful for tests and bootstrap code.
type StaticSource struct {
	Heads   map[string]PolicyHead
	Bundles map[string][]byte
}

func NewStaticSource(head PolicyHead, bundle []byte) *StaticSource {
	head.Scope = head.Scope.Normalize()
	return &StaticSource{
		Heads:   map[string]PolicyHead{head.Scope.Key(): head},
		Bundles: map[string][]byte{head.Scope.Key(): append([]byte(nil), bundle...)},
	}
}

func (s *StaticSource) ListScopes(context.Context) ([]PolicyScope, error) {
	scopes := make([]PolicyScope, 0, len(s.Heads))
	for _, head := range s.Heads {
		scopes = append(scopes, head.Scope.Normalize())
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Key() < scopes[j].Key() })
	return scopes, nil
}

func (s *StaticSource) Head(_ context.Context, scope PolicyScope) (PolicyHead, error) {
	head, ok := s.Heads[scope.Normalize().Key()]
	if !ok {
		return PolicyHead{}, ErrPolicyNotReady
	}
	return head, nil
}

func (s *StaticSource) Load(_ context.Context, scope PolicyScope, epoch uint64) ([]byte, error) {
	bundle, ok := s.Bundles[scope.Normalize().Key()]
	if !ok {
		return nil, ErrPolicyNotReady
	}
	return append([]byte(nil), bundle...), nil
}

// MountedFileBundleHash computes the hash used by MountedFileSource.
func MountedFileBundleHash(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	return HashBytes(data), nil
}
