package skillpacks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	ProjectionLifecycleResultSchemaV1 = "helm.skill-projection-result.v1"
	ProjectionTrustRequestSchemaV1    = "helm.skill-projection-trust-request.v1"
	ProjectionTrustDecisionSchemaV1   = "helm.skill-projection-trust-decision.v1"
	projectionTrustBindingSchemaV1    = "helm.skill-projection-trust-binding.v1"
	projectionLifecycleStateSchemaV1  = "helm.skill-projection-state.v1"
	projectionRecoveryJournalSchemaV1 = "helm.skill-projection-recovery-journal.v1"
	projectionLifecycleStateMACV1     = "helm.skill-projection-state-mac.v1"
	projectionRecoveryJournalMACV1    = "helm.skill-projection-recovery-journal-mac.v1"
	projectionRollbackPermitMACV1     = "helm.skill-projection-rollback-permit-mac.v1"

	projectionStatusActive  = "active"
	projectionStatusRevoked = "revoked"

	maxProjectionArtifactBytes = 1 << 20
	// V1 retains the newest immutable generation metadata as the supported
	// rollback window. Artifact bytes remain immutable on disk by generation.
	maxProjectionGenerationEntries = 256
	// V1 retains exact result/attempt bindings for the most recent operations.
	// Oldest-first compaction prevents readbacks from exhausting state forever.
	maxProjectionReplayEntries = 256
	// Lifecycle state contains bounded generation, replay, and attempt metadata.
	// Each V1 mutation can retain 16 bounded certification refs plus
	// an exact replay result and attempt binding; 16 MiB gives that metadata a
	// distinct operational envelope while keeping reads and writes bounded.
	maxProjectionLifecycleStateBytes = 16 << 20
	// A recovery journal stores exact previous/next bounded state payloads,
	// previous/next bounded prompts, and one bounded generation manifest as
	// base64 plus fixed identity/hash metadata. 48 MiB is the deterministic V1
	// envelope for 2*16 MiB + 3*1 MiB raw bytes.
	maxProjectionRecoveryJournalBytes = 48 << 20
	// Verification runs while the projection root is single-writer locked. A
	// deterministic wall-clock bound prevents a verifier from retaining that
	// lock indefinitely; context-aware verifiers receive the same deadline.
	projectionTrustVerifierTimeout = 30 * time.Second

	projectionMutationAfterJournal    = "after_journal"
	projectionMutationAfterGeneration = "after_generation"
	projectionMutationAfterLive       = "after_live"
	projectionMutationAfterState      = "after_state"
	projectionTrustSignaturePrefix    = "hmac-sha256:"
)

var (
	ErrProjectionDrift            = errors.New("skillpacks: managed projection drift")
	ErrUnmanagedProjection        = errors.New("skillpacks: unmanaged projection exists")
	ErrProjectionReplayNotFound   = errors.New("skillpacks: projection replay not found")
	ErrProjectionReplayConflict   = errors.New("skillpacks: projection replay conflict")
	ErrProjectionPathUnsafe       = errors.New("skillpacks: unsafe managed path")
	ErrProjectionLockContended    = errors.New("skillpacks: projection root lock contended")
	ErrProjectionLockUnsupported  = errors.New("skillpacks: projection root lock unsupported")
	ErrProjectionFileTooLarge     = errors.New("skillpacks: managed projection file exceeds size limit")
	ErrProjectionRollbackRequired = errors.New("skillpacks: retained artifact requires rollback authority")
	ErrProjectionTrustRejected    = errors.New("skillpacks: projection trust verification rejected")
	ErrProjectionRecoveryPending  = errors.New("skillpacks: projection recovery pending")
)

// SkillProjectionArtifact is the exact artifact submitted to the lifecycle.
// V1 accepts exactly skillpack.json and SKILL.md.
type SkillProjectionArtifact struct {
	Files map[string][]byte
}

// ProjectionLifecycleResult is the unsigned canonical result returned to the
// runner. ResultHash is the exact payload a later runner signer can bind.
type ProjectionLifecycleResult struct {
	SchemaVersion string `json:"schema_version"`
	Action        string `json:"action"`
	Status        string `json:"status"`

	TenantID     string `json:"tenant_id"`
	WorkspaceID  string `json:"workspace_id"`
	SkillID      string `json:"skill_id"`
	SkillVersion string `json:"skill_version"`
	AgentTarget  string `json:"agent_target"`

	CanonicalRequestHash   string `json:"canonical_request_hash"`
	IdempotencyKey         string `json:"idempotency_key"`
	AttemptID              string `json:"attempt_id"`
	ConsumedPermitRef      string `json:"consumed_permit_ref"`
	RollbackPermitRef      string `json:"rollback_permit_ref,omitempty"`
	TrustVerificationRef   string `json:"trust_verification_ref"`
	TrustDecisionHash      string `json:"trust_decision_hash"`
	TrustDecisionAction    string `json:"trust_decision_action"`
	TrustDecisionCanonical string `json:"trust_decision_canonical_request_hash"`
	TrustVerifierID        string `json:"trust_verifier_id"`
	TrustKeyID             string `json:"trust_key_id"`
	TrustBindingHash       string `json:"trust_binding_hash"`
	TrustDecisionSignature string `json:"trust_decision_signature"`
	TrustArtifactHash      string `json:"trust_artifact_hash"`
	TrustContentHash       string `json:"trust_content_hash"`
	TrustManifestHash      string `json:"trust_manifest_hash"`
	TrustPolicyHash        string `json:"trust_policy_hash"`
	TrustSchemaHash        string `json:"trust_schema_hash"`
	TrustCertificationHash string `json:"trust_certification_hash"`
	TrustSandboxProfile    string `json:"trust_sandbox_profile"`

	PreviousGeneration     uint64 `json:"previous_generation"`
	NewGeneration          uint64 `json:"new_generation"`
	RestoredFromGeneration uint64 `json:"restored_from_generation,omitempty"`

	PreviousArtifactHash string `json:"previous_artifact_hash,omitempty"`
	NewArtifactHash      string `json:"new_artifact_hash,omitempty"`
	ObservedArtifactHash string `json:"observed_artifact_hash,omitempty"`
	PreviousContentHash  string `json:"previous_content_hash,omitempty"`
	NewContentHash       string `json:"new_content_hash,omitempty"`
	ObservedContentHash  string `json:"observed_content_hash,omitempty"`
	PreviousManifestHash string `json:"previous_manifest_hash,omitempty"`
	NewManifestHash      string `json:"new_manifest_hash,omitempty"`
	ObservedManifestHash string `json:"observed_manifest_hash,omitempty"`

	RelativePath string `json:"relative_path"`
	ResultHash   string `json:"result_hash,omitempty"`
}

// ProjectionLifecycle owns one server-configured filesystem root. Request
// payloads never supply paths.
type ProjectionLifecycle struct {
	managed          *os.Root
	verifier         ProjectionTrustVerifier
	verifierKey      ProjectionTrustVerifierKey
	verificationKeys map[projectionTrustKeyIdentity]ProjectionTrustVerifierKey
	clock            func() time.Time
	verifierTimeout  time.Duration
	verifierInFlight chan struct{}
	verifierContext  context.Context
	cancelVerifier   context.CancelFunc
	mutationHook     func(string) error
	mu               sync.Mutex
	closing          atomic.Bool
}

// NewProjectionLifecycle preserves the original constructor surface but fails
// closed because it cannot authenticate verifier decisions without a pinned
// key. Use NewProjectionLifecycleWithVerifierKey for a working lifecycle.
func NewProjectionLifecycle(_ string, _ ProjectionTrustVerifier) (*ProjectionLifecycle, error) {
	return nil, fmt.Errorf("%w: pinned verifier identity/key is required", ErrProjectionTrustRejected)
}

// NewProjectionLifecycleWithVerifierKey constructs a lifecycle whose trust
// receipts must authenticate under the exact server-configured verifier key.
func NewProjectionLifecycleWithVerifierKey(
	root string,
	verifier ProjectionTrustVerifier,
	verifierKey ProjectionTrustVerifierKey,
) (*ProjectionLifecycle, error) {
	return NewProjectionLifecycleWithVerifierKeyring(root, verifier, ProjectionTrustVerifierKeyring{Current: verifierKey})
}

// NewProjectionLifecycleWithVerifierKeyring constructs a lifecycle that signs
// new trust/state records with Current and verifies older durable records only
// with the explicitly accepted Historical keys.
func NewProjectionLifecycleWithVerifierKeyring(
	root string,
	verifier ProjectionTrustVerifier,
	keyring ProjectionTrustVerifierKeyring,
) (*ProjectionLifecycle, error) {
	if verifier == nil {
		return nil, fmt.Errorf("%w: configured verifier is required", ErrProjectionTrustRejected)
	}
	if err := validateProjectionTrustVerifierKeyring(keyring); err != nil {
		return nil, err
	}
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("skillpacks: projection root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("skillpacks: resolve projection root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("skillpacks: create projection root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("skillpacks: resolve projection root symlinks: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("skillpacks: projection root is not a directory")
	}
	managed, err := openManagedRoot(resolved)
	if err != nil {
		return nil, err
	}
	opened, err := managed.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = managed.Close()
		return nil, fmt.Errorf("%w: projection root changed during construction", ErrProjectionPathUnsafe)
	}
	verifierKey := cloneProjectionTrustVerifierKey(keyring.Current)
	verificationKeys := make(map[projectionTrustKeyIdentity]ProjectionTrustVerifierKey, 1+len(keyring.Historical))
	for _, key := range append([]ProjectionTrustVerifierKey{keyring.Current}, keyring.Historical...) {
		verificationKeys[projectionTrustKeyIdentity{VerifierID: key.VerifierID, KeyID: key.KeyID}] = cloneProjectionTrustVerifierKey(key)
	}
	verifierContext, cancelVerifier := context.WithCancel(context.Background())
	return &ProjectionLifecycle{
		managed: managed, verifier: verifier, verifierKey: verifierKey, verificationKeys: verificationKeys,
		clock:           func() time.Time { return time.Now().UTC() },
		verifierTimeout: projectionTrustVerifierTimeout, verifierInFlight: make(chan struct{}, 1),
		verifierContext: verifierContext, cancelVerifier: cancelVerifier,
	}, nil
}

// Close releases the descriptor that anchors the configured projection root.
// It is safe to call more than once and waits for an in-flight Apply.
func (l *ProjectionLifecycle) Close() error {
	if l == nil {
		return nil
	}
	l.closing.Store(true)
	if l.cancelVerifier != nil {
		l.cancelVerifier()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.managed == nil {
		return nil
	}
	err := l.managed.Close()
	l.managed = nil
	for i := range l.verifierKey.HMACKey {
		l.verifierKey.HMACKey[i] = 0
	}
	for identity, key := range l.verificationKeys {
		for i := range key.HMACKey {
			key.HMACKey[i] = 0
		}
		delete(l.verificationKeys, identity)
	}
	return err
}

// Apply validates authority and filesystem truth, then executes one lifecycle
// operation. consumedPermitRef must be the already-verified consumption record
// reference supplied by the runner.
func (l *ProjectionLifecycle) Apply(
	effect contracts.SkillProjectionEffect,
	artifact *SkillProjectionArtifact,
	consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (result ProjectionLifecycleResult, returnErr error) {
	if l == nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: projection lifecycle is nil")
	}
	if rollbackPermit != nil {
		permitCopy := *rollbackPermit
		rollbackPermit = &permitCopy
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing.Load() || l.managed == nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: projection lifecycle is closed")
	}
	// Rollback authentication reads lifecycle-owned key material. Keep that
	// read inside the same mutex Close uses to zero and discard the keyring.
	if err := l.validateProjectionAuthorityBinding(effect, consumedPermitRef, rollbackPermit); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	releaseRootLock, err := l.acquireRootLock()
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	defer func() {
		if err := releaseRootLock(); err != nil {
			result = ProjectionLifecycleResult{}
			returnErr = errors.Join(returnErr, fmt.Errorf("skillpacks: release projection root lock: %w", err))
		}
	}()
	// Authority can expire while waiting for either lock. Revalidate at the
	// single-writer boundary before reading or mutating any projection state.
	now := l.clock().UTC()
	authorityErr := l.validateProjectionAuthority(effect, consumedPermitRef, rollbackPermit, now)

	projection, err := projectionRelativePath(effect.SkillID, effect.AgentTarget)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	relativePath := filepath.ToSlash(projection.Path)
	if err := l.recoverProjectionJournal(effect, relativePath, rollbackPermit, authorityErr); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if authorityErr != nil {
		return ProjectionLifecycleResult{}, authorityErr
	}

	var installGeneration projectionGeneration
	var manifestBytes, contentBytes []byte
	if effect.Action == contracts.SkillProjectionActionInstall {
		installGeneration, manifestBytes, contentBytes, err = validateProjectionArtifact(effect, artifact)
		if err != nil {
			return ProjectionLifecycleResult{}, err
		}
	} else if artifact != nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: artifact is only valid for install")
	}
	state, err := l.readState(effect, relativePath)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if state != nil {
		if err := validateProjectionStateIdentity(*state, effect, relativePath); err != nil {
			return ProjectionLifecycleResult{}, err
		}
		if replay, ok := findProjectionReplay(state.Replays, effect.IdempotencyKey); ok {
			if replay.RequestHash != effect.CanonicalRequestHash {
				return ProjectionLifecycleResult{}, ErrProjectionReplayConflict
			}
			if err := verifyProjectionLifecycleResult(replay.Result); err != nil {
				return ProjectionLifecycleResult{}, err
			}
			if err := l.verifyManagedState(*state); err != nil {
				return ProjectionLifecycleResult{}, err
			}
			if _, err := l.verifyReplayTrust(effect, *state, rollbackPermit); err != nil {
				return ProjectionLifecycleResult{}, err
			}
			return replay.Result, nil
		}
		if attempt, ok := findProjectionAttempt(state.Attempts, effect.AttemptID); ok &&
			(attempt.IdempotencyKey != effect.IdempotencyKey || attempt.RequestHash != effect.CanonicalRequestHash) {
			return ProjectionLifecycleResult{}, ErrProjectionReplayConflict
		}
	}
	// Historical keys authenticate only durable state, recovery journals, and
	// exact replays. Any rollback that reaches this point is a fresh mutation
	// and therefore requires authority under the lifecycle's current key.
	if effect.Action == contracts.SkillProjectionActionRollback {
		if err := l.verifyProjectionRollbackPermitCurrentAuthority(*rollbackPermit); err != nil {
			return ProjectionLifecycleResult{}, err
		}
	}

	if effect.Action == contracts.SkillProjectionActionReadback {
		if state == nil {
			return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: projection is not managed")
		}
		if effect.Generation != state.Generation {
			return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: readback generation mismatch")
		}
	} else {
		expected := uint64(1)
		if state != nil {
			expected = state.Generation + 1
		}
		if effect.Generation != expected {
			return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: generation mismatch: got %d want %d", effect.Generation, expected)
		}
	}

	if state == nil {
		if effect.Action != contracts.SkillProjectionActionInstall {
			return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: projection is not managed")
		}
		if err := l.verifyProjectionAbsent(effect, relativePath); err != nil {
			return ProjectionLifecycleResult{}, err
		}
	} else if err := l.verifyManagedState(*state); err != nil {
		return ProjectionLifecycleResult{}, err
	}

	switch effect.Action {
	case contracts.SkillProjectionActionInstall:
		return l.applyInstall(effect, state, relativePath, installGeneration, manifestBytes, contentBytes)
	case contracts.SkillProjectionActionReadback:
		return l.applyReadback(effect, state, relativePath)
	case contracts.SkillProjectionActionRevoke:
		return l.applyRevoke(effect, state, relativePath)
	case contracts.SkillProjectionActionRollback:
		return l.applyRollback(effect, state, relativePath, *rollbackPermit)
	default:
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: unsupported projection action")
	}
}

// LookupReplay returns one authenticated durable result without dispatching,
// recovering, or otherwise mutating a projection. An authenticated recovery
// journal remains owned by Apply, which revalidates live authority and trust
// before completing or aborting the pending mutation.
func (l *ProjectionLifecycle) LookupReplay(
	effect contracts.SkillProjectionEffect,
	consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (result ProjectionLifecycleResult, returnErr error) {
	if l == nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: projection lifecycle is nil")
	}
	if rollbackPermit != nil {
		permitCopy := *rollbackPermit
		rollbackPermit = &permitCopy
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing.Load() || l.managed == nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: projection lifecycle is closed")
	}
	if err := l.validateProjectionAuthorityBinding(effect, consumedPermitRef, rollbackPermit); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	releaseRootLock, err := l.acquireRootLock()
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	defer func() {
		if err := releaseRootLock(); err != nil {
			result = ProjectionLifecycleResult{}
			returnErr = errors.Join(returnErr, fmt.Errorf("skillpacks: release projection root lock: %w", err))
		}
	}()

	projection, err := projectionRelativePath(effect.SkillID, effect.AgentTarget)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	relativePath := filepath.ToSlash(projection.Path)
	pending, err := l.hasPendingProjectionRecoveryJournal(effect, relativePath)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if pending {
		return ProjectionLifecycleResult{}, ErrProjectionRecoveryPending
	}

	state, err := l.readState(effect, relativePath)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if state == nil {
		if err := l.verifyProjectionAbsent(effect, relativePath); err != nil {
			return ProjectionLifecycleResult{}, err
		}
		return ProjectionLifecycleResult{}, ErrProjectionReplayNotFound
	}
	replay, ok := findProjectionReplay(state.Replays, effect.IdempotencyKey)
	if !ok {
		if attempt, found := findProjectionAttempt(state.Attempts, effect.AttemptID); found &&
			(attempt.IdempotencyKey != effect.IdempotencyKey || attempt.RequestHash != effect.CanonicalRequestHash) {
			return ProjectionLifecycleResult{}, ErrProjectionReplayConflict
		}
		if err := l.verifyManagedState(*state); err != nil {
			return ProjectionLifecycleResult{}, err
		}
		return ProjectionLifecycleResult{}, ErrProjectionReplayNotFound
	}
	if err := validateProjectionReplayLookupBinding(effect, relativePath, consumedPermitRef, rollbackPermit, replay); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if err := l.verifyManagedState(*state); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	return replay.Result, nil
}

func validateProjectionReplayLookupBinding(
	effect contracts.SkillProjectionEffect,
	relativePath, consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	replay projectionReplay,
) error {
	if replay.RequestHash != effect.CanonicalRequestHash {
		return ErrProjectionReplayConflict
	}
	if err := verifyProjectionLifecycleResult(replay.Result); err != nil {
		return fmt.Errorf("%w: stored replay result: %v", ErrProjectionDrift, err)
	}
	expectedRollbackPermitRef := ""
	if rollbackPermit != nil {
		expectedRollbackPermitRef = rollbackPermit.PermitRef
	}
	if replay.Result.Action != effect.Action || replay.Result.TenantID != effect.TenantID ||
		replay.Result.WorkspaceID != effect.WorkspaceID || replay.Result.SkillID != effect.SkillID ||
		replay.Result.SkillVersion != effect.SkillVersion || replay.Result.AgentTarget != effect.AgentTarget ||
		replay.Result.CanonicalRequestHash != effect.CanonicalRequestHash ||
		replay.Result.IdempotencyKey != effect.IdempotencyKey || replay.Result.AttemptID != effect.AttemptID ||
		replay.Result.ConsumedPermitRef != consumedPermitRef ||
		replay.Result.RollbackPermitRef != expectedRollbackPermitRef ||
		replay.Result.NewGeneration != effect.Generation || replay.Result.RelativePath != relativePath {
		return fmt.Errorf("%w: stored replay does not match lookup authority", ErrProjectionDrift)
	}
	return nil
}

func (l *ProjectionLifecycle) applyInstall(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
	generation projectionGeneration,
	manifestBytes, contentBytes []byte,
) (ProjectionLifecycleResult, error) {
	retained, err := l.immutableProjectionArtifactExists(effect, generation.ArtifactHash)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if retained {
		return ProjectionLifecycleResult{}, ErrProjectionRollbackRequired
	}
	trust, err := l.verifyProjectionTrust(effect, generation, manifestBytes, contentBytes, nil)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	generation.TrustVerificationRef = trust.VerificationRef
	generation.TrustDecisionHash = trust.DecisionHash
	generation.TrustVerifierID = trust.VerifierID
	generation.TrustKeyID = trust.KeyID
	generation.TrustAction = effect.Action
	generation.TrustCanonicalHash = effect.CanonicalRequestHash
	generation.TrustBindingHash = trust.BindingHash
	generation.TrustDecisionSignature = trust.Signature
	if err := l.validateProjectionPublicationAuthority(effect, nil, trust, nil); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	next := newProjectionState(effect, relativePath, current)
	previousGeneration, previous := currentProjectionGeneration(current)
	next.Status = projectionStatusActive
	next.Generation = effect.Generation
	next.ArchiveGeneration = effect.Generation
	appendProjectionGeneration(&next, generation)
	status := "installed"
	if current != nil && current.Status == projectionStatusActive {
		status = "upgraded"
	}
	result := newProjectionResult(effect, relativePath, status, previousGeneration, previous, generation)
	result.ObservedArtifactHash = generation.ArtifactHash
	result.ObservedContentHash = generation.ContentHash
	result.ObservedManifestHash = generation.ManifestHash
	bindProjectionResultTrust(&result, trust, effect)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	appendProjectionReplay(&next, effect, sealed)
	if err := l.commitProjectionMutation(effect, current, next, relativePath, manifestBytes, true, contentBytes, sealed, nil, trust); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	return sealed, nil
}

func (l *ProjectionLifecycle) applyReadback(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
) (ProjectionLifecycleResult, error) {
	record, ok := findProjectionGeneration(current.Generations, current.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: readback binding mismatch")
	}
	manifestBytes, contentBytes, err := l.readGeneration(effect, record)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	trust, err := l.verifyProjectionTrust(effect, record, manifestBytes, contentBytes, nil)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	result := newProjectionResult(effect, relativePath, current.Status, current.Generation, record, record)
	if current.Status == projectionStatusActive {
		result.ObservedArtifactHash = record.ArtifactHash
		result.ObservedContentHash = record.ContentHash
		result.ObservedManifestHash = record.ManifestHash
	} else {
		result.NewArtifactHash = ""
		result.NewContentHash = ""
		result.NewManifestHash = ""
	}
	bindProjectionResultTrust(&result, trust, effect)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	next := cloneProjectionState(*current)
	appendProjectionReplay(&next, effect, sealed)
	nextLiveBytes := contentBytes
	if current.Status == projectionStatusRevoked {
		nextLiveBytes = nil
	}
	if err := l.commitProjectionMutation(effect, current, next, relativePath, nil, current.Status == projectionStatusActive, nextLiveBytes, sealed, nil, trust); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	return sealed, nil
}

func (l *ProjectionLifecycle) applyRevoke(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
) (ProjectionLifecycleResult, error) {
	if current == nil || current.Status != projectionStatusActive {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: only an active projection can be revoked")
	}
	record, ok := findProjectionGeneration(current.Generations, current.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: revoke binding mismatch")
	}
	if _, err := l.validateStoredRevocationArchive(effect, *current); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	next := cloneProjectionState(*current)
	next.Status = projectionStatusRevoked
	next.Generation = effect.Generation
	result := newProjectionResult(effect, relativePath, projectionStatusRevoked, current.Generation, record, projectionGeneration{})
	bindProjectionResultStoredGenerationTrust(&result, record)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	appendProjectionReplay(&next, effect, sealed)
	if err := l.commitProjectionMutation(effect, current, next, relativePath, nil, false, nil, sealed, nil, ProjectionTrustDecision{}); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	return sealed, nil
}

func (l *ProjectionLifecycle) applyRollback(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
	permit contracts.SkillProjectionRollbackPermit,
) (ProjectionLifecycleResult, error) {
	if current == nil || permit.FromGeneration != current.Generation {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: rollback source generation mismatch")
	}
	target, ok := findProjectionGeneration(current.Generations, permit.TargetGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, target) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: rollback target binding mismatch")
	}
	manifestBytes, contentBytes, err := l.readGeneration(effect, target)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	trust, err := l.verifyProjectionTrust(effect, target, manifestBytes, contentBytes, &permit)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	restored := target
	restored.Generation = effect.Generation
	restored.TrustVerificationRef = trust.VerificationRef
	restored.TrustDecisionHash = trust.DecisionHash
	restored.TrustVerifierID = trust.VerifierID
	restored.TrustKeyID = trust.KeyID
	restored.TrustAction = effect.Action
	restored.TrustCanonicalHash = effect.CanonicalRequestHash
	restored.TrustBindingHash = trust.BindingHash
	restored.TrustDecisionSignature = trust.Signature
	if err := l.validateProjectionPublicationAuthority(effect, &permit, trust, nil); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	previousGeneration, previous := currentProjectionGeneration(current)
	next := cloneProjectionState(*current)
	next.Status = projectionStatusActive
	next.Generation = effect.Generation
	next.ArchiveGeneration = effect.Generation
	appendProjectionGeneration(&next, restored)
	result := newProjectionResult(effect, relativePath, "rolled_back", previousGeneration, previous, restored)
	result.RestoredFromGeneration = permit.TargetGeneration
	result.RollbackPermitRef = permit.PermitRef
	result.ObservedArtifactHash = restored.ArtifactHash
	result.ObservedContentHash = restored.ContentHash
	result.ObservedManifestHash = restored.ManifestHash
	bindProjectionResultTrust(&result, trust, effect)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	appendProjectionReplay(&next, effect, sealed)
	if err := l.commitProjectionMutation(effect, current, next, relativePath, manifestBytes, true, contentBytes, sealed, &permit, trust); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	return sealed, nil
}

func (l *ProjectionLifecycle) acquireRootLock() (func() error, error) {
	root := l.managed
	if root == nil {
		return nil, fmt.Errorf("skillpacks: projection lifecycle is closed")
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	lockFile, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	lockInfo, err := lockFile.Stat()
	if err != nil || !rootInfo.IsDir() || !lockInfo.IsDir() || !os.SameFile(rootInfo, lockInfo) {
		_ = lockFile.Close()
		return nil, ErrProjectionPathUnsafe
	}
	releaseLock, err := lockProjectionFile(lockFile)
	if err != nil {
		return nil, err
	}
	observed, err := root.Stat(".")
	if err != nil || !os.SameFile(lockInfo, observed) {
		_ = releaseLock()
		return nil, ErrProjectionPathUnsafe
	}
	return releaseLock, nil
}

func newProjectionResult(
	effect contracts.SkillProjectionEffect,
	relativePath, status string,
	previousGeneration uint64,
	previous, next projectionGeneration,
) ProjectionLifecycleResult {
	return ProjectionLifecycleResult{
		SchemaVersion: ProjectionLifecycleResultSchemaV1,
		Action:        effect.Action, Status: status,
		TenantID: effect.TenantID, WorkspaceID: effect.WorkspaceID,
		SkillID: effect.SkillID, SkillVersion: effect.SkillVersion, AgentTarget: effect.AgentTarget,
		CanonicalRequestHash: effect.CanonicalRequestHash,
		IdempotencyKey:       effect.IdempotencyKey, AttemptID: effect.AttemptID,
		ConsumedPermitRef:  effect.ConsumedPermitRef,
		PreviousGeneration: previousGeneration, NewGeneration: effect.Generation,
		PreviousArtifactHash: previous.ArtifactHash, NewArtifactHash: next.ArtifactHash,
		PreviousContentHash: previous.ContentHash, NewContentHash: next.ContentHash,
		PreviousManifestHash: previous.ManifestHash, NewManifestHash: next.ManifestHash,
		RelativePath: relativePath,
	}
}
