package skillpacks

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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

// ProjectionTrustRequest is the exact, immutable material a configured
// verifier must authenticate. The verifier is responsible for resolving the
// policy and certification references against current trusted evidence and
// validating their signatures before returning an allow decision.
type ProjectionTrustRequest struct {
	SchemaVersion  string                          `json:"schema_version"`
	Effect         contracts.SkillProjectionEffect `json:"effect"`
	Manifest       Manifest                        `json:"manifest"`
	ManifestBytes  []byte                          `json:"manifest_bytes"`
	ContentBytes   []byte                          `json:"content_bytes"`
	EvaluationTime time.Time                       `json:"evaluation_time"`
}

// ProjectionTrustDecision is the schema-pinned, canonical verifier output.
// VerificationRef names the verifier's immutable signed evidence record;
// DecisionHash protects the exact decision returned across the interface.
type ProjectionTrustDecision struct {
	SchemaVersion string `json:"schema_version"`
	Verdict       string `json:"verdict"`

	Action       string `json:"action"`
	TenantID     string `json:"tenant_id"`
	WorkspaceID  string `json:"workspace_id"`
	SkillID      string `json:"skill_id"`
	SkillVersion string `json:"skill_version"`
	AgentTarget  string `json:"agent_target"`

	CanonicalRequestHash string `json:"canonical_request_hash"`
	ArtifactHash         string `json:"artifact_hash"`
	ContentHash          string `json:"content_hash"`
	ManifestHash         string `json:"manifest_hash"`
	PolicyHash           string `json:"policy_hash"`
	SchemaHash           string `json:"schema_hash"`
	SandboxProfile       string `json:"sandbox_profile"`

	Publisher         string   `json:"publisher"`
	ManifestStatus    string   `json:"manifest_status"`
	PolicyRef         string   `json:"policy_ref"`
	CertificationRefs []string `json:"certification_refs"`

	VerifiedAt      time.Time `json:"verified_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	VerificationRef string    `json:"verification_ref"`
	VerifierID      string    `json:"verifier_id"`
	KeyID           string    `json:"key_id"`
	BindingHash     string    `json:"binding_hash"`
	Signature       string    `json:"signature,omitempty"`
	DecisionHash    string    `json:"decision_hash,omitempty"`
}

// ProjectionTrustVerifierKey pins the only verifier identity/key accepted by
// one lifecycle instance. HMACKey comes from server configuration, never from
// a projection request or SkillPack artifact.
type ProjectionTrustVerifierKey struct {
	VerifierID string
	KeyID      string
	HMACKey    []byte
}

// ProjectionTrustVerifierKeyring pins the current signing key plus the exact
// historical keys that may continue verifying durable receipts after a key
// rotation. Omitting a historical key revokes it; historical keys never sign
// new decisions or lifecycle state.
type ProjectionTrustVerifierKeyring struct {
	Current    ProjectionTrustVerifierKey
	Historical []ProjectionTrustVerifierKey
}

// ProjectionTrustVerifier is mandatory for every lifecycle instance. A
// concrete verifier may live in the runner. Install, readback, and rollback
// require a current exact-hash decision; revoke authenticates removal from the
// consumed revoke authority and the stored admission receipt instead.
type ProjectionTrustVerifier interface {
	VerifyProjectionTrust(ProjectionTrustRequest) (ProjectionTrustDecision, error)
}

// ProjectionTrustContextVerifier is an optional cancellation contract for
// verifiers that can stop their work when the lifecycle deadline elapses.
// Implementations must also satisfy ProjectionTrustVerifier for constructor
// compatibility; legacy verifiers are isolated behind the same hard deadline.
type ProjectionTrustContextVerifier interface {
	ProjectionTrustVerifier
	VerifyProjectionTrustContext(context.Context, ProjectionTrustRequest) (ProjectionTrustDecision, error)
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

type projectionLifecycleState struct {
	SchemaVersion     string `json:"schema_version"`
	TenantID          string `json:"tenant_id"`
	WorkspaceID       string `json:"workspace_id"`
	SkillID           string `json:"skill_id"`
	AgentTarget       string `json:"agent_target"`
	RelativePath      string `json:"relative_path"`
	Status            string `json:"status"`
	Generation        uint64 `json:"generation"`
	ArchiveGeneration uint64 `json:"archive_generation"`

	Generations     []projectionGeneration `json:"generations"`
	Replays         []projectionReplay     `json:"replays"`
	Attempts        []projectionAttempt    `json:"attempts"`
	StateVerifierID string                 `json:"state_verifier_id"`
	StateKeyID      string                 `json:"state_key_id"`
	StateSignature  string                 `json:"state_signature,omitempty"`
	StateHash       string                 `json:"state_hash,omitempty"`
}

type projectionTrustKeyIdentity struct {
	VerifierID string
	KeyID      string
}

type projectionTrustVerificationResult struct {
	decision ProjectionTrustDecision
	err      error
}

type projectionGeneration struct {
	Generation             uint64   `json:"generation"`
	SkillVersion           string   `json:"skill_version"`
	ArtifactHash           string   `json:"artifact_hash"`
	ContentHash            string   `json:"content_hash"`
	ManifestHash           string   `json:"manifest_hash"`
	PolicyHash             string   `json:"policy_hash"`
	SchemaHash             string   `json:"schema_hash"`
	CertificationRefs      []string `json:"certification_refs"`
	SandboxProfile         string   `json:"sandbox_profile"`
	TrustVerificationRef   string   `json:"trust_verification_ref"`
	TrustDecisionHash      string   `json:"trust_decision_hash"`
	TrustVerifierID        string   `json:"trust_verifier_id"`
	TrustKeyID             string   `json:"trust_key_id"`
	TrustAction            string   `json:"trust_action"`
	TrustCanonicalHash     string   `json:"trust_canonical_request_hash"`
	TrustBindingHash       string   `json:"trust_binding_hash"`
	TrustDecisionSignature string   `json:"trust_decision_signature"`
}

type projectionReplay struct {
	IdempotencyKey string                    `json:"idempotency_key"`
	RequestHash    string                    `json:"request_hash"`
	Result         ProjectionLifecycleResult `json:"result"`
}

type projectionAttempt struct {
	AttemptID      string `json:"attempt_id"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestHash    string `json:"request_hash"`
}

type projectionRecoveryJournal struct {
	SchemaVersion string `json:"schema_version"`
	Action        string `json:"action"`

	TenantID     string `json:"tenant_id"`
	WorkspaceID  string `json:"workspace_id"`
	SkillID      string `json:"skill_id"`
	SkillVersion string `json:"skill_version"`
	AgentTarget  string `json:"agent_target"`
	RelativePath string `json:"relative_path"`

	CanonicalRequestHash   string `json:"canonical_request_hash"`
	IdempotencyKey         string `json:"idempotency_key"`
	AttemptID              string `json:"attempt_id"`
	ResultHash             string `json:"result_hash"`
	TrustVerificationRef   string `json:"trust_verification_ref"`
	TrustDecisionHash      string `json:"trust_decision_hash"`
	TrustDecisionAction    string `json:"trust_decision_action"`
	TrustDecisionCanonical string `json:"trust_decision_canonical_request_hash"`
	TrustVerifierID        string `json:"trust_verifier_id"`
	TrustKeyID             string `json:"trust_key_id"`
	TrustBindingHash       string `json:"trust_binding_hash"`
	TrustDecisionSignature string `json:"trust_decision_signature"`

	PreviousStatePresent bool   `json:"previous_state_present"`
	PreviousStateBytes   []byte `json:"previous_state_bytes,omitempty"`
	PreviousStateHash    string `json:"previous_state_hash,omitempty"`
	NextStateBytes       []byte `json:"next_state_bytes"`
	NextStateHash        string `json:"next_state_hash"`

	PreviousLivePresent     bool   `json:"previous_live_present"`
	PreviousLiveBytes       []byte `json:"previous_live_bytes,omitempty"`
	PreviousLiveHash        string `json:"previous_live_hash,omitempty"`
	NextLivePresent         bool   `json:"next_live_present"`
	NextLiveBytes           []byte `json:"next_live_bytes,omitempty"`
	NextLiveHash            string `json:"next_live_hash,omitempty"`
	GenerationManifestBytes []byte `json:"generation_manifest_bytes,omitempty"`

	JournalVerifierID string `json:"journal_verifier_id"`
	JournalKeyID      string `json:"journal_key_id"`
	JournalSignature  string `json:"journal_signature,omitempty"`
	JournalHash       string `json:"journal_hash,omitempty"`
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

func (l *ProjectionLifecycle) validateProjectionAuthority(
	effect contracts.SkillProjectionEffect,
	consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	now time.Time,
) error {
	if err := l.validateProjectionAuthorityBinding(effect, consumedPermitRef, rollbackPermit); err != nil {
		return err
	}
	if err := effect.ValidateAt(now); err != nil {
		return err
	}
	if effect.Action == contracts.SkillProjectionActionRollback {
		return effect.ValidateRollbackPermit(*rollbackPermit, now)
	}
	return nil
}

func (l *ProjectionLifecycle) validateProjectionAuthorityBinding(
	effect contracts.SkillProjectionEffect,
	consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) error {
	if err := effect.Validate(); err != nil {
		return err
	}
	if effect.CanonicalRequestHash == "" {
		return fmt.Errorf("%w: canonical_request_hash is required", contracts.ErrSkillProjectionEffectIntegrity)
	}
	sealed, err := effect.Seal()
	if err != nil || !constantStringEqual(sealed.CanonicalRequestHash, effect.CanonicalRequestHash) {
		return fmt.Errorf("%w: canonical_request_hash mismatch", contracts.ErrSkillProjectionEffectIntegrity)
	}
	if !constantStringEqual(effect.ConsumedPermitRef, consumedPermitRef) {
		return fmt.Errorf("skillpacks: consumed permit reference mismatch")
	}
	if effect.Action == contracts.SkillProjectionActionRollback {
		if rollbackPermit == nil {
			return fmt.Errorf("skillpacks: rollback permit is required")
		}
		// IssuedAt is the one time guaranteed active by a structurally valid
		// permit. This checks its seal and exact effect binding without allowing
		// an expired permit to bypass recovery of its own pending journal.
		if err := effect.ValidateRollbackPermit(*rollbackPermit, rollbackPermit.IssuedAt); err != nil {
			return err
		}
		return l.verifyProjectionRollbackPermitAuthentication(*rollbackPermit)
	}
	if rollbackPermit != nil {
		return fmt.Errorf("skillpacks: rollback permit is only valid for rollback")
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

func validateProjectionArtifact(
	effect contracts.SkillProjectionEffect,
	artifact *SkillProjectionArtifact,
) (projectionGeneration, []byte, []byte, error) {
	if artifact == nil || len(artifact.Files) != 2 {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: V1 artifact requires exactly skillpack.json and SKILL.md")
	}
	manifestBytes, manifestOK := artifact.Files["skillpack.json"]
	contentBytes, contentOK := artifact.Files["SKILL.md"]
	if !manifestOK || !contentOK || len(manifestBytes) == 0 || len(contentBytes) == 0 {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: V1 artifact requires non-empty skillpack.json and SKILL.md")
	}
	if len(manifestBytes) > maxProjectionArtifactBytes || len(contentBytes) > maxProjectionArtifactBytes ||
		!utf8.Valid(manifestBytes) || !utf8.Valid(contentBytes) ||
		strings.ContainsRune(string(manifestBytes), 0) || strings.ContainsRune(string(contentBytes), 0) {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: artifact contains unsupported binary or oversized content")
	}
	if HashBytes(manifestBytes) != effect.ManifestHash || HashBytes(contentBytes) != effect.ContentHash {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: artifact byte hash mismatch")
	}
	artifactHash, err := contracts.ComputeSkillProjectionArtifactHash(effect.ManifestHash, effect.ContentHash)
	if err != nil || artifactHash != effect.ArtifactHash {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: artifact aggregate hash mismatch")
	}
	var manifest Manifest
	if err := decodeStrictProjectionJSON(manifestBytes, &manifest); err != nil {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: parse skillpack.json: %w", err)
	}
	if err := ValidateManifest(manifest, contentBytes); err != nil {
		return projectionGeneration{}, nil, nil, err
	}
	if manifest.Status == StatusBlocked {
		return projectionGeneration{}, nil, nil, fmt.Errorf("%w: blocked SkillPack cannot be projected", ErrProjectionTrustRejected)
	}
	if manifest.ID != effect.SkillID || manifest.Version != effect.SkillVersion || manifest.ContentHash != effect.ContentHash {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: manifest identity/hash does not match effect")
	}
	if len(manifest.Scripts) != 0 || len(manifest.Hooks) != 0 ||
		len(manifest.RequestedMCPServers) != 0 || len(manifest.RequestedMCPTools) != 0 {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: V1 projection denies scripts, hooks, MCP, and executable adapters")
	}
	if !containsString(manifest.AgentTargets, effect.AgentTarget) {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: manifest does not certify requested agent target")
	}
	if manifest.SignatureRef == "" || manifest.ProvenanceRef == "" ||
		!containsString(effect.CertificationRefs, manifest.SignatureRef) ||
		!containsString(effect.CertificationRefs, manifest.ProvenanceRef) {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: certification refs do not bind manifest signature/provenance")
	}
	scan, err := Scan(SkillPack{Manifest: manifest, SkillMD: string(contentBytes)})
	if err != nil || scan.Verdict != VerdictAllow {
		if err != nil {
			return projectionGeneration{}, nil, nil, err
		}
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: prompt scan denied projection: %s", scan.ReasonCode)
	}
	return projectionGeneration{
		Generation:        effect.Generation,
		SkillVersion:      effect.SkillVersion,
		ArtifactHash:      effect.ArtifactHash,
		ContentHash:       effect.ContentHash,
		ManifestHash:      effect.ManifestHash,
		PolicyHash:        effect.PolicyHash,
		SchemaHash:        effect.SchemaHash,
		CertificationRefs: append([]string(nil), effect.CertificationRefs...),
		SandboxProfile:    effect.SandboxProfile,
	}, append([]byte(nil), manifestBytes...), append([]byte(nil), contentBytes...), nil
}

func (l *ProjectionLifecycle) verifyProjectionTrust(
	effect contracts.SkillProjectionEffect,
	record projectionGeneration,
	manifestBytes, contentBytes []byte,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (ProjectionTrustDecision, error) {
	if l == nil || l.verifier == nil {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: configured verifier is required", ErrProjectionTrustRejected)
	}
	if !projectionEffectMatchesGeneration(effect, record) ||
		HashBytes(manifestBytes) != effect.ManifestHash || HashBytes(contentBytes) != effect.ContentHash {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier input does not match effect", ErrProjectionTrustRejected)
	}
	artifactHash, err := contracts.ComputeSkillProjectionArtifactHash(HashBytes(manifestBytes), HashBytes(contentBytes))
	if err != nil || !constantStringEqual(artifactHash, effect.ArtifactHash) {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier artifact binding mismatch", ErrProjectionTrustRejected)
	}
	var manifest Manifest
	if err := decodeStrictProjectionJSON(manifestBytes, &manifest); err != nil {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: decode verifier manifest: %v", ErrProjectionTrustRejected, err)
	}
	if err := ValidateManifest(manifest, contentBytes); err != nil {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier manifest validation: %v", ErrProjectionTrustRejected, err)
	}
	if manifest.Status == StatusBlocked {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: blocked SkillPack cannot be projected", ErrProjectionTrustRejected)
	}
	if manifest.ID != effect.SkillID || manifest.Version != effect.SkillVersion ||
		manifest.ContentHash != effect.ContentHash || strings.TrimSpace(manifest.PolicyRef) == "" ||
		!containsString(manifest.AgentTargets, effect.AgentTarget) ||
		manifest.SignatureRef == "" || manifest.ProvenanceRef == "" ||
		!containsString(effect.CertificationRefs, manifest.SignatureRef) ||
		!containsString(effect.CertificationRefs, manifest.ProvenanceRef) {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: manifest trust binding mismatch", ErrProjectionTrustRejected)
	}
	evaluationTime := l.clock().UTC()
	if err := l.validateProjectionAuthority(effect, effect.ConsumedPermitRef, rollbackPermit, evaluationTime); err != nil {
		return ProjectionTrustDecision{}, err
	}

	request := ProjectionTrustRequest{
		SchemaVersion:  ProjectionTrustRequestSchemaV1,
		Effect:         cloneProjectionEffect(effect),
		Manifest:       cloneProjectionManifest(manifest),
		ManifestBytes:  append([]byte(nil), manifestBytes...),
		ContentBytes:   append([]byte(nil), contentBytes...),
		EvaluationTime: evaluationTime,
	}
	decision, err := l.callProjectionTrustVerifier(request, effect, rollbackPermit)
	if err != nil {
		return ProjectionTrustDecision{}, errors.Join(ErrProjectionTrustRejected, err)
	}
	validationTime := l.clock().UTC()
	if err := l.validateProjectionAuthority(effect, effect.ConsumedPermitRef, rollbackPermit, validationTime); err != nil {
		return ProjectionTrustDecision{}, err
	}
	if err := l.validateProjectionTrustDecision(decision, effect, manifest, validationTime); err != nil {
		return ProjectionTrustDecision{}, err
	}
	return decision, nil
}

func (l *ProjectionLifecycle) callProjectionTrustVerifier(
	request ProjectionTrustRequest,
	effect contracts.SkillProjectionEffect,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (ProjectionTrustDecision, error) {
	if l.verifier == nil || l.verifierContext == nil || l.verifierInFlight == nil || l.verifierTimeout <= 0 {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: configured verifier is unavailable", ErrProjectionTrustRejected)
	}
	timeout := l.verifierTimeout
	if remaining := effect.ExpiresAt.Sub(request.EvaluationTime); remaining < timeout {
		timeout = remaining
	}
	if rollbackPermit != nil {
		if remaining := rollbackPermit.ExpiresAt.Sub(request.EvaluationTime); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier authority deadline elapsed", ErrProjectionTrustRejected)
	}
	ctx, cancel := context.WithTimeout(l.verifierContext, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return ProjectionTrustDecision{}, errors.Join(ErrProjectionTrustRejected, err)
	}
	select {
	case l.verifierInFlight <- struct{}{}:
	default:
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier call is already in flight", ErrProjectionTrustRejected)
	}

	verifier := l.verifier
	gate := l.verifierInFlight
	results := make(chan projectionTrustVerificationResult, 1)
	go func() {
		var decision ProjectionTrustDecision
		var err error
		if contextual, ok := verifier.(ProjectionTrustContextVerifier); ok {
			decision, err = contextual.VerifyProjectionTrustContext(ctx, request)
		} else {
			decision, err = verifier.VerifyProjectionTrust(request)
		}
		<-gate
		results <- projectionTrustVerificationResult{decision: decision, err: err}
	}()

	select {
	case result := <-results:
		return result.decision, result.err
	case <-ctx.Done():
		return ProjectionTrustDecision{}, errors.Join(ErrProjectionTrustRejected, ctx.Err())
	}
}

func (l *ProjectionLifecycle) validateProjectionPublicationAuthority(
	effect contracts.SkillProjectionEffect,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	decision ProjectionTrustDecision,
	revocationState *projectionLifecycleState,
) error {
	now := l.clock().UTC()
	if err := l.validateProjectionAuthority(effect, effect.ConsumedPermitRef, rollbackPermit, now); err != nil {
		return err
	}
	if effect.Action == contracts.SkillProjectionActionRevoke {
		if revocationState == nil {
			return fmt.Errorf("%w: authenticated revocation state is required", ErrProjectionTrustRejected)
		}
		_, err := l.validateStoredRevocationArchive(effect, *revocationState)
		return err
	}
	if err := verifyProjectionTrustDecisionIntegrity(decision); err != nil {
		return err
	}
	if err := verifyProjectionTrustDecisionSignature(decision, l.verifierKey); err != nil {
		return err
	}
	expectedBindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromEffect(effect))
	if err != nil || !constantStringEqual(expectedBindingHash, decision.BindingHash) ||
		decision.VerifiedAt.After(now) || !now.Before(decision.ExpiresAt) {
		return fmt.Errorf("%w: trust decision is not current for publication", ErrProjectionTrustRejected)
	}
	return nil
}

func (l *ProjectionLifecycle) validateProjectionTrustDecision(
	decision ProjectionTrustDecision,
	effect contracts.SkillProjectionEffect,
	manifest Manifest,
	now time.Time,
) error {
	if err := verifyProjectionTrustDecisionIntegrity(decision); err != nil {
		return err
	}
	if err := verifyProjectionTrustDecisionSignature(decision, l.verifierKey); err != nil {
		return err
	}
	expectedBindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromEffect(effect))
	if err != nil {
		return fmt.Errorf("%w: compute trust decision binding: %v", ErrProjectionTrustRejected, err)
	}
	if decision.SchemaVersion != ProjectionTrustDecisionSchemaV1 || decision.Verdict != VerdictAllow ||
		decision.Action != effect.Action || decision.TenantID != effect.TenantID ||
		decision.WorkspaceID != effect.WorkspaceID || decision.SkillID != effect.SkillID ||
		decision.SkillVersion != effect.SkillVersion || decision.AgentTarget != effect.AgentTarget ||
		decision.CanonicalRequestHash != effect.CanonicalRequestHash ||
		decision.ArtifactHash != effect.ArtifactHash || decision.ContentHash != effect.ContentHash ||
		decision.ManifestHash != effect.ManifestHash || decision.PolicyHash != effect.PolicyHash ||
		decision.SchemaHash != effect.SchemaHash || decision.SandboxProfile != effect.SandboxProfile ||
		decision.BindingHash != expectedBindingHash || decision.Publisher != manifest.Publisher ||
		decision.ManifestStatus != manifest.Status || decision.PolicyRef != manifest.PolicyRef ||
		!equalStrings(decision.CertificationRefs, effect.CertificationRefs) {
		return fmt.Errorf("%w: trust decision does not exactly bind the request", ErrProjectionTrustRejected)
	}
	if !validProjectionSHA256(decision.VerificationRef) || decision.VerifiedAt.IsZero() ||
		decision.ExpiresAt.IsZero() || decision.VerifiedAt.Location() != time.UTC ||
		decision.ExpiresAt.Location() != time.UTC || decision.VerifiedAt.After(now) ||
		!now.Before(decision.ExpiresAt) || !decision.ExpiresAt.After(decision.VerifiedAt) {
		return fmt.Errorf("%w: trust decision is not current", ErrProjectionTrustRejected)
	}
	return nil
}

func cloneProjectionEffect(effect contracts.SkillProjectionEffect) contracts.SkillProjectionEffect {
	clone := effect
	clone.CertificationRefs = append([]string(nil), effect.CertificationRefs...)
	return clone
}

func cloneProjectionManifest(manifest Manifest) Manifest {
	clone := manifest
	clone.AgentTargets = append([]string(nil), manifest.AgentTargets...)
	clone.RequestedMCPServers = append([]string(nil), manifest.RequestedMCPServers...)
	clone.RequestedMCPTools = append([]string(nil), manifest.RequestedMCPTools...)
	clone.Hooks = append([]string(nil), manifest.Hooks...)
	clone.Scripts = append([]string(nil), manifest.Scripts...)
	return clone
}

type projectionTrustBinding struct {
	SchemaVersion         string `json:"schema_version"`
	Action                string `json:"action"`
	TenantID              string `json:"tenant_id"`
	WorkspaceID           string `json:"workspace_id"`
	SkillID               string `json:"skill_id"`
	SkillVersion          string `json:"skill_version"`
	AgentTarget           string `json:"agent_target"`
	CanonicalRequestHash  string `json:"canonical_request_hash"`
	ArtifactHash          string `json:"artifact_hash"`
	ContentHash           string `json:"content_hash"`
	ManifestHash          string `json:"manifest_hash"`
	PolicyHash            string `json:"policy_hash"`
	SchemaHash            string `json:"schema_hash"`
	CertificationRefsHash string `json:"certification_refs_hash"`
	SandboxProfile        string `json:"sandbox_profile"`
}

func projectionCertificationRefsHash(refs []string) string {
	data, err := json.Marshal(refs)
	if err != nil {
		return ""
	}
	return HashBytes(append([]byte("helm.skill-projection-certification-refs.v1\x00"), data...))
}

func projectionTrustBindingHash(binding projectionTrustBinding) (string, error) {
	data, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("skillpacks: seal projection trust binding: %w", err)
	}
	return HashBytes(data), nil
}

func projectionTrustBindingFromEffect(effect contracts.SkillProjectionEffect) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: effect.Action,
		TenantID: effect.TenantID, WorkspaceID: effect.WorkspaceID,
		SkillID: effect.SkillID, SkillVersion: effect.SkillVersion, AgentTarget: effect.AgentTarget,
		CanonicalRequestHash: effect.CanonicalRequestHash,
		ArtifactHash:         effect.ArtifactHash, ContentHash: effect.ContentHash, ManifestHash: effect.ManifestHash,
		PolicyHash: effect.PolicyHash, SchemaHash: effect.SchemaHash,
		CertificationRefsHash: projectionCertificationRefsHash(effect.CertificationRefs),
		SandboxProfile:        effect.SandboxProfile,
	}
}

func projectionTrustBindingFromDecision(decision ProjectionTrustDecision) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: decision.Action,
		TenantID: decision.TenantID, WorkspaceID: decision.WorkspaceID,
		SkillID: decision.SkillID, SkillVersion: decision.SkillVersion, AgentTarget: decision.AgentTarget,
		CanonicalRequestHash: decision.CanonicalRequestHash,
		ArtifactHash:         decision.ArtifactHash, ContentHash: decision.ContentHash, ManifestHash: decision.ManifestHash,
		PolicyHash: decision.PolicyHash, SchemaHash: decision.SchemaHash,
		CertificationRefsHash: projectionCertificationRefsHash(decision.CertificationRefs),
		SandboxProfile:        decision.SandboxProfile,
	}
}

func projectionTrustBindingFromGeneration(
	state projectionLifecycleState,
	record projectionGeneration,
) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: record.TrustAction,
		TenantID: state.TenantID, WorkspaceID: state.WorkspaceID,
		SkillID: state.SkillID, SkillVersion: record.SkillVersion, AgentTarget: state.AgentTarget,
		CanonicalRequestHash: record.TrustCanonicalHash,
		ArtifactHash:         record.ArtifactHash, ContentHash: record.ContentHash, ManifestHash: record.ManifestHash,
		PolicyHash: record.PolicyHash, SchemaHash: record.SchemaHash,
		CertificationRefsHash: projectionCertificationRefsHash(record.CertificationRefs),
		SandboxProfile:        record.SandboxProfile,
	}
}

func projectionTrustBindingFromResult(result ProjectionLifecycleResult) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: result.TrustDecisionAction,
		TenantID: result.TenantID, WorkspaceID: result.WorkspaceID,
		SkillID: result.SkillID, SkillVersion: result.SkillVersion, AgentTarget: result.AgentTarget,
		CanonicalRequestHash:  result.TrustDecisionCanonical,
		ArtifactHash:          result.TrustArtifactHash,
		ContentHash:           result.TrustContentHash,
		ManifestHash:          result.TrustManifestHash,
		PolicyHash:            result.TrustPolicyHash,
		SchemaHash:            result.TrustSchemaHash,
		CertificationRefsHash: result.TrustCertificationHash,
		SandboxProfile:        result.TrustSandboxProfile,
	}
}

// SignProjectionTrustDecision creates the authenticated receipt returned by a
// configured verifier. Kernel independently recomputes both the decision hash
// and HMAC using its pinned verifier key.
func SignProjectionTrustDecision(
	decision ProjectionTrustDecision,
	key ProjectionTrustVerifierKey,
) (ProjectionTrustDecision, error) {
	if err := validateProjectionTrustVerifierKey(key); err != nil {
		return ProjectionTrustDecision{}, err
	}
	if !validProjectionSHA256(decision.CanonicalRequestHash) {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: trust decision canonical request hash is invalid", ErrProjectionTrustRejected)
	}
	bindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromDecision(decision))
	if err != nil {
		return ProjectionTrustDecision{}, err
	}
	decision.BindingHash = bindingHash
	decision.VerifierID = key.VerifierID
	decision.KeyID = key.KeyID
	sealed, err := SealProjectionTrustDecision(decision)
	if err != nil {
		return ProjectionTrustDecision{}, err
	}
	sealed.Signature = projectionTrustSignature(sealed.DecisionHash, sealed.BindingHash, key)
	return sealed, nil
}

// SignProjectionRollbackPermit authenticates a separately action-bound
// rollback permit with an explicitly configured authority key. Permit.Seal
// remains an integrity operation and cannot mint this authority signature.
func SignProjectionRollbackPermit(
	permit contracts.SkillProjectionRollbackPermit,
	key ProjectionTrustVerifierKey,
) (contracts.SkillProjectionRollbackPermit, error) {
	if err := validateProjectionTrustVerifierKey(key); err != nil {
		return contracts.SkillProjectionRollbackPermit{}, err
	}
	permit.IssuerID = key.VerifierID
	permit.KeyID = key.KeyID
	permit.Signature = ""
	sealed, err := permit.Seal()
	if err != nil {
		return contracts.SkillProjectionRollbackPermit{}, err
	}
	sealed.Signature = projectionRollbackPermitSignature(sealed.PermitHash, key)
	return sealed, nil
}

func validateProjectionTrustVerifierKey(key ProjectionTrustVerifierKey) error {
	if !validProjectionTrustIdentity(key.VerifierID) || !validProjectionTrustIdentity(key.KeyID) ||
		len(key.HMACKey) < 32 || len(key.HMACKey) > 4096 {
		return fmt.Errorf("%w: pinned verifier identity/key is invalid", ErrProjectionTrustRejected)
	}
	return nil
}

func validateProjectionTrustVerifierKeyring(keyring ProjectionTrustVerifierKeyring) error {
	keys := append([]ProjectionTrustVerifierKey{keyring.Current}, keyring.Historical...)
	seen := make(map[projectionTrustKeyIdentity]struct{}, len(keys))
	for _, key := range keys {
		if err := validateProjectionTrustVerifierKey(key); err != nil {
			return err
		}
		identity := projectionTrustKeyIdentity{VerifierID: key.VerifierID, KeyID: key.KeyID}
		if _, ok := seen[identity]; ok {
			return fmt.Errorf("%w: duplicate verifier identity/key", ErrProjectionTrustRejected)
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func cloneProjectionTrustVerifierKey(key ProjectionTrustVerifierKey) ProjectionTrustVerifierKey {
	key.HMACKey = append([]byte(nil), key.HMACKey...)
	return key
}

func validProjectionTrustIdentity(value string) bool {
	return validProjectionTrustToken(value, 128)
}

func validProjectionTrustToken(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool {
		return r == 0 || r == '\u007f' || r == '\u2028' || r == '\u2029' ||
			r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) == -1
}

func validProjectionTrustSignature(value string) bool {
	if len(value) != len(projectionTrustSignaturePrefix)+64 || !strings.HasPrefix(value, projectionTrustSignaturePrefix) {
		return false
	}
	digest := strings.TrimPrefix(value, projectionTrustSignaturePrefix)
	if strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

func projectionTrustSignature(decisionHash, bindingHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(ProjectionTrustDecisionSchemaV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(decisionHash))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(bindingHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func projectionLifecycleStateSignature(stateHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(projectionLifecycleStateMACV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(stateHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func projectionRecoveryJournalSignature(journalHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(projectionRecoveryJournalMACV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(journalHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func projectionRollbackPermitSignature(permitHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(projectionRollbackPermitMACV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(contracts.SkillProjectionRollbackPermitSchemaV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(contracts.SkillProjectionRollbackPermitContractV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(permitHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func (l *ProjectionLifecycle) verifyProjectionRollbackPermitAuthentication(
	permit contracts.SkillProjectionRollbackPermit,
) error {
	if !validProjectionTrustIdentity(permit.IssuerID) || !validProjectionTrustIdentity(permit.KeyID) ||
		!validProjectionTrustSignature(permit.Signature) {
		return fmt.Errorf("%w: authenticated rollback permit is required", contracts.ErrSkillProjectionEffectIntegrity)
	}
	key, ok := l.verificationKeys[projectionTrustKeyIdentity{VerifierID: permit.IssuerID, KeyID: permit.KeyID}]
	if !ok {
		return fmt.Errorf("%w: rollback permit issuer/key is not accepted", contracts.ErrSkillProjectionEffectIntegrity)
	}
	expected := projectionRollbackPermitSignature(permit.PermitHash, key)
	if !constantStringEqual(permit.Signature, expected) {
		return fmt.Errorf("%w: rollback permit signature mismatch", contracts.ErrSkillProjectionEffectIntegrity)
	}
	return nil
}

func (l *ProjectionLifecycle) verifyProjectionRollbackPermitCurrentAuthority(
	permit contracts.SkillProjectionRollbackPermit,
) error {
	if permit.IssuerID != l.verifierKey.VerifierID || permit.KeyID != l.verifierKey.KeyID {
		return fmt.Errorf("%w: fresh rollback permit must use current issuer/key", contracts.ErrSkillProjectionEffectIntegrity)
	}
	expected := projectionRollbackPermitSignature(permit.PermitHash, l.verifierKey)
	if !constantStringEqual(permit.Signature, expected) {
		return fmt.Errorf("%w: fresh rollback permit signature mismatch", contracts.ErrSkillProjectionEffectIntegrity)
	}
	return nil
}

func verifyProjectionTrustDecisionSignature(decision ProjectionTrustDecision, key ProjectionTrustVerifierKey) error {
	if err := validateProjectionTrustVerifierKey(key); err != nil {
		return err
	}
	if decision.VerifierID != key.VerifierID || decision.KeyID != key.KeyID ||
		!validProjectionSHA256(decision.BindingHash) || !validProjectionTrustSignature(decision.Signature) {
		return fmt.Errorf("%w: trust decision verifier identity/key mismatch", ErrProjectionTrustRejected)
	}
	expected := projectionTrustSignature(decision.DecisionHash, decision.BindingHash, key)
	if !constantStringEqual(decision.Signature, expected) {
		return fmt.Errorf("%w: trust decision signature mismatch", ErrProjectionTrustRejected)
	}
	return nil
}

func (l *ProjectionLifecycle) verifyStoredProjectionTrustSignature(
	decisionHash, bindingHash, verifierID, keyID, signature string,
) error {
	key, ok := l.verificationKeys[projectionTrustKeyIdentity{VerifierID: verifierID, KeyID: keyID}]
	if !ok {
		return fmt.Errorf("%w: stored trust verifier identity/key is not accepted", ErrProjectionTrustRejected)
	}
	decision := ProjectionTrustDecision{
		BindingHash:  bindingHash,
		DecisionHash: decisionHash,
		VerifierID:   verifierID,
		KeyID:        keyID,
		Signature:    signature,
	}
	return verifyProjectionTrustDecisionSignature(decision, key)
}

func (l *ProjectionLifecycle) verifyProjectionLifecycleState(state projectionLifecycleState) error {
	key, ok := l.verificationKeys[projectionTrustKeyIdentity{VerifierID: state.StateVerifierID, KeyID: state.StateKeyID}]
	if !ok {
		return fmt.Errorf("%w: projection state verifier identity/key is not accepted", ErrProjectionDrift)
	}
	if err := verifyProjectionLifecycleStateAuthentication(state, key); err != nil {
		return fmt.Errorf("%w: %v", ErrProjectionDrift, err)
	}
	return nil
}

func (l *ProjectionLifecycle) verifyProjectionRecoveryJournal(journal projectionRecoveryJournal) error {
	key, ok := l.verificationKeys[projectionTrustKeyIdentity{
		VerifierID: journal.JournalVerifierID,
		KeyID:      journal.JournalKeyID,
	}]
	if !ok {
		return fmt.Errorf("%w: recovery journal verifier identity/key is not accepted", ErrProjectionDrift)
	}
	return verifyProjectionRecoveryJournalAuthentication(journal, key)
}

func projectionJournalMatchesTrustEffect(
	journal projectionRecoveryJournal,
	effect contracts.SkillProjectionEffect,
) bool {
	return journal.Action == effect.Action && journal.TenantID == effect.TenantID &&
		journal.WorkspaceID == effect.WorkspaceID && journal.SkillID == effect.SkillID &&
		journal.SkillVersion == effect.SkillVersion && journal.AgentTarget == effect.AgentTarget &&
		journal.CanonicalRequestHash == effect.CanonicalRequestHash &&
		journal.IdempotencyKey == effect.IdempotencyKey && journal.AttemptID == effect.AttemptID
}

func projectionGenerationMatchesTrustEffect(
	state projectionLifecycleState,
	record projectionGeneration,
) bool {
	if record.TrustAction != contracts.SkillProjectionActionInstall && record.TrustAction != contracts.SkillProjectionActionRollback {
		return false
	}
	bindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromGeneration(state, record))
	return err == nil && constantStringEqual(bindingHash, record.TrustBindingHash)
}

func projectionResultMatchesTrustEffect(result ProjectionLifecycleResult) bool {
	bindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromResult(result))
	if err != nil || !constantStringEqual(bindingHash, result.TrustBindingHash) {
		return false
	}
	switch result.Action {
	case contracts.SkillProjectionActionInstall, contracts.SkillProjectionActionRollback:
		if result.TrustDecisionAction != result.Action || result.TrustDecisionCanonical != result.CanonicalRequestHash {
			return false
		}
		validStatus := result.Status == "installed" || result.Status == "upgraded"
		if result.Action == contracts.SkillProjectionActionRollback {
			validStatus = result.Status == "rolled_back"
		}
		return validStatus && result.NewArtifactHash == result.TrustArtifactHash && result.NewContentHash == result.TrustContentHash &&
			result.NewManifestHash == result.TrustManifestHash && result.ObservedArtifactHash == result.TrustArtifactHash &&
			result.ObservedContentHash == result.TrustContentHash && result.ObservedManifestHash == result.TrustManifestHash
	case contracts.SkillProjectionActionReadback:
		if result.TrustDecisionAction != result.Action || result.TrustDecisionCanonical != result.CanonicalRequestHash {
			return false
		}
		if result.PreviousArtifactHash != result.TrustArtifactHash || result.PreviousContentHash != result.TrustContentHash ||
			result.PreviousManifestHash != result.TrustManifestHash {
			return false
		}
		if result.Status == projectionStatusRevoked {
			return result.NewArtifactHash == "" && result.NewContentHash == "" && result.NewManifestHash == "" &&
				result.ObservedArtifactHash == "" && result.ObservedContentHash == "" && result.ObservedManifestHash == ""
		}
		return result.Status == projectionStatusActive && result.NewArtifactHash == result.TrustArtifactHash &&
			result.NewContentHash == result.TrustContentHash && result.NewManifestHash == result.TrustManifestHash &&
			result.ObservedArtifactHash == result.TrustArtifactHash && result.ObservedContentHash == result.TrustContentHash &&
			result.ObservedManifestHash == result.TrustManifestHash
	case contracts.SkillProjectionActionRevoke:
		if result.TrustDecisionAction != contracts.SkillProjectionActionInstall &&
			result.TrustDecisionAction != contracts.SkillProjectionActionRollback {
			return false
		}
		return result.Status == projectionStatusRevoked && result.PreviousArtifactHash == result.TrustArtifactHash &&
			result.PreviousContentHash == result.TrustContentHash && result.PreviousManifestHash == result.TrustManifestHash &&
			result.NewArtifactHash == "" && result.NewContentHash == "" && result.NewManifestHash == "" &&
			result.ObservedArtifactHash == "" && result.ObservedContentHash == "" && result.ObservedManifestHash == ""
	default:
		return false
	}
}

func (l *ProjectionLifecycle) verifyReplayTrust(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (ProjectionTrustDecision, error) {
	if effect.Action == contracts.SkillProjectionActionRevoke {
		replay, ok := findProjectionReplay(state.Replays, effect.IdempotencyKey)
		if !ok {
			return ProjectionTrustDecision{}, fmt.Errorf("%w: revoke replay trust receipt mismatch", ErrProjectionDrift)
		}
		if _, err := l.validateStoredRevocationReplay(effect, state, replay.Result); err != nil {
			return ProjectionTrustDecision{}, err
		}
		return ProjectionTrustDecision{}, nil
	}
	for _, record := range state.Generations {
		if !projectionEffectMatchesGeneration(effect, record) {
			continue
		}
		manifestBytes, contentBytes, err := l.readGeneration(effect, record)
		if err != nil {
			return ProjectionTrustDecision{}, err
		}
		return l.verifyProjectionTrust(effect, record, manifestBytes, contentBytes, rollbackPermit)
	}
	return ProjectionTrustDecision{}, fmt.Errorf("%w: replay has no retained trust material", ErrProjectionDrift)
}

func (l *ProjectionLifecycle) validateStoredRevocationState(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
) error {
	if effect.Action != contracts.SkillProjectionActionRevoke ||
		state.TenantID != effect.TenantID || state.WorkspaceID != effect.WorkspaceID ||
		state.SkillID != effect.SkillID || state.AgentTarget != effect.AgentTarget {
		return fmt.Errorf("%w: revocation state identity mismatch", ErrProjectionDrift)
	}
	if err := l.verifyProjectionLifecycleState(state); err != nil {
		return err
	}
	return l.verifyProjectionStateTrustReceipts(state)
}

func (l *ProjectionLifecycle) validateStoredRevocationArchive(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
) (projectionGeneration, error) {
	if err := l.validateStoredRevocationState(effect, state); err != nil {
		return projectionGeneration{}, err
	}
	record, ok := findProjectionGeneration(state.Generations, state.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return projectionGeneration{}, fmt.Errorf("%w: archived revocation trust receipt mismatch", ErrProjectionDrift)
	}
	return record, nil
}

func (l *ProjectionLifecycle) validateStoredRevocationReplay(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
	result ProjectionLifecycleResult,
) (projectionGeneration, error) {
	if err := l.validateStoredRevocationState(effect, state); err != nil {
		return projectionGeneration{}, err
	}
	for _, record := range state.Generations {
		if projectionEffectMatchesGeneration(effect, record) && projectionResultMatchesGenerationTrust(result, record) {
			return record, nil
		}
	}
	return projectionGeneration{}, fmt.Errorf("%w: revoke replay has no retained trust receipt", ErrProjectionDrift)
}

func bindProjectionResultTrust(
	result *ProjectionLifecycleResult,
	decision ProjectionTrustDecision,
	effect contracts.SkillProjectionEffect,
) {
	result.TrustVerificationRef = decision.VerificationRef
	result.TrustDecisionHash = decision.DecisionHash
	result.TrustDecisionAction = decision.Action
	result.TrustDecisionCanonical = decision.CanonicalRequestHash
	result.TrustVerifierID = decision.VerifierID
	result.TrustKeyID = decision.KeyID
	result.TrustBindingHash = decision.BindingHash
	result.TrustDecisionSignature = decision.Signature
	result.TrustArtifactHash = effect.ArtifactHash
	result.TrustContentHash = effect.ContentHash
	result.TrustManifestHash = effect.ManifestHash
	result.TrustPolicyHash = effect.PolicyHash
	result.TrustSchemaHash = effect.SchemaHash
	result.TrustCertificationHash = projectionCertificationRefsHash(effect.CertificationRefs)
	result.TrustSandboxProfile = effect.SandboxProfile
}

func bindProjectionResultStoredGenerationTrust(
	result *ProjectionLifecycleResult,
	record projectionGeneration,
) {
	result.TrustVerificationRef = record.TrustVerificationRef
	result.TrustDecisionHash = record.TrustDecisionHash
	result.TrustDecisionAction = record.TrustAction
	result.TrustDecisionCanonical = record.TrustCanonicalHash
	result.TrustVerifierID = record.TrustVerifierID
	result.TrustKeyID = record.TrustKeyID
	result.TrustBindingHash = record.TrustBindingHash
	result.TrustDecisionSignature = record.TrustDecisionSignature
	result.TrustArtifactHash = record.ArtifactHash
	result.TrustContentHash = record.ContentHash
	result.TrustManifestHash = record.ManifestHash
	result.TrustPolicyHash = record.PolicyHash
	result.TrustSchemaHash = record.SchemaHash
	result.TrustCertificationHash = projectionCertificationRefsHash(record.CertificationRefs)
	result.TrustSandboxProfile = record.SandboxProfile
}

func projectionResultMatchesGenerationTrust(
	result ProjectionLifecycleResult,
	record projectionGeneration,
) bool {
	return result.TrustVerificationRef == record.TrustVerificationRef &&
		result.TrustDecisionHash == record.TrustDecisionHash && result.TrustDecisionAction == record.TrustAction &&
		result.TrustDecisionCanonical == record.TrustCanonicalHash && result.TrustVerifierID == record.TrustVerifierID &&
		result.TrustKeyID == record.TrustKeyID && result.TrustBindingHash == record.TrustBindingHash &&
		result.TrustDecisionSignature == record.TrustDecisionSignature && result.TrustArtifactHash == record.ArtifactHash &&
		result.TrustContentHash == record.ContentHash && result.TrustManifestHash == record.ManifestHash &&
		result.TrustPolicyHash == record.PolicyHash && result.TrustSchemaHash == record.SchemaHash &&
		result.TrustCertificationHash == projectionCertificationRefsHash(record.CertificationRefs) &&
		result.TrustSandboxProfile == record.SandboxProfile
}

func (l *ProjectionLifecycle) commitProjectionMutation(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	next projectionLifecycleState,
	relativePath string,
	generationManifestBytes []byte,
	nextLivePresent bool,
	nextLiveBytes []byte,
	result ProjectionLifecycleResult,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	trust ProjectionTrustDecision,
) error {
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, current); err != nil {
		return err
	}
	journal, err := l.buildProjectionRecoveryJournal(effect, current, next, relativePath, generationManifestBytes, nextLivePresent, nextLiveBytes, result)
	if err != nil {
		return err
	}
	if err := l.writeProjectionRecoveryJournal(effect, relativePath, journal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.runProjectionMutationHook(projectionMutationAfterJournal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, current); err != nil {
		return l.abortProjectionMutation(effect, relativePath, journal, err)
	}
	if err := l.persistRecoveryGeneration(effect, journal, next); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.runProjectionMutationHook(projectionMutationAfterGeneration); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, current); err != nil {
		return l.abortProjectionMutation(effect, relativePath, journal, err)
	}
	if err := l.publishRecoveryLive(effect, journal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.runProjectionMutationHook(projectionMutationAfterLive); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, current); err != nil {
		return l.abortProjectionMutation(effect, relativePath, journal, err)
	}
	if err := l.publishRecoveryState(effect, journal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.runProjectionMutationHook(projectionMutationAfterState); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, current); err != nil {
		return l.abortProjectionMutation(effect, relativePath, journal, err)
	}
	if err := l.verifyRecoveryTarget(effect, relativePath, journal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.clearProjectionRecoveryJournal(effect, relativePath, journal.JournalHash); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	return nil
}

func (l *ProjectionLifecycle) buildProjectionRecoveryJournal(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	next projectionLifecycleState,
	relativePath string,
	generationManifestBytes []byte,
	nextLivePresent bool,
	nextLiveBytes []byte,
	result ProjectionLifecycleResult,
) (projectionRecoveryJournal, error) {
	if err := verifyProjectionLifecycleResult(result); err != nil {
		return projectionRecoveryJournal{}, err
	}
	sealedNext, nextStateBytes, err := l.marshalProjectionLifecycleState(next)
	if err != nil {
		return projectionRecoveryJournal{}, err
	}
	previousStatePresent := current != nil
	var previousStateBytes []byte
	previousStateHash := ""
	if previousStatePresent {
		previousStateBytes, err = readManagedFileAt(l.managed, l.stateRel(effect), maxProjectionLifecycleStateBytes)
		if err != nil {
			return projectionRecoveryJournal{}, fmt.Errorf("%w: read previous state for recovery: %w", ErrProjectionDrift, err)
		}
		previousStateHash = HashBytes(previousStateBytes)
	}
	previousLivePresent, previousLiveHash, err := expectedProjectionLive(current)
	if err != nil {
		return projectionRecoveryJournal{}, err
	}
	var previousLiveBytes []byte
	if previousLivePresent {
		previousLiveBytes, err = readManagedFileAt(
			l.managed,
			filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath)),
			maxProjectionArtifactBytes,
		)
		if err != nil || HashBytes(previousLiveBytes) != previousLiveHash {
			return projectionRecoveryJournal{}, fmt.Errorf("%w: read previous live projection: %v", ErrProjectionDrift, err)
		}
	}
	nextExpectedPresent, nextExpectedHash, err := expectedProjectionLive(&sealedNext)
	if err != nil {
		return projectionRecoveryJournal{}, err
	}
	if nextLivePresent != nextExpectedPresent ||
		(nextLivePresent && (len(nextLiveBytes) == 0 || len(nextLiveBytes) > maxProjectionArtifactBytes ||
			HashBytes(nextLiveBytes) != nextExpectedHash)) ||
		(!nextLivePresent && len(nextLiveBytes) != 0) {
		return projectionRecoveryJournal{}, fmt.Errorf("%w: next live content does not match next state", ErrProjectionDrift)
	}
	journal := projectionRecoveryJournal{
		SchemaVersion: projectionRecoveryJournalSchemaV1,
		Action:        effect.Action,
		TenantID:      effect.TenantID,
		WorkspaceID:   effect.WorkspaceID,
		SkillID:       effect.SkillID,
		SkillVersion:  effect.SkillVersion,
		AgentTarget:   effect.AgentTarget,
		RelativePath:  relativePath,

		CanonicalRequestHash:   effect.CanonicalRequestHash,
		IdempotencyKey:         effect.IdempotencyKey,
		AttemptID:              effect.AttemptID,
		ResultHash:             result.ResultHash,
		TrustVerificationRef:   result.TrustVerificationRef,
		TrustDecisionHash:      result.TrustDecisionHash,
		TrustDecisionAction:    result.TrustDecisionAction,
		TrustDecisionCanonical: result.TrustDecisionCanonical,
		TrustVerifierID:        result.TrustVerifierID,
		TrustKeyID:             result.TrustKeyID,
		TrustBindingHash:       result.TrustBindingHash,
		TrustDecisionSignature: result.TrustDecisionSignature,

		PreviousStatePresent: previousStatePresent,
		PreviousStateBytes:   append([]byte(nil), previousStateBytes...),
		PreviousStateHash:    previousStateHash,
		NextStateBytes:       append([]byte(nil), nextStateBytes...),
		NextStateHash:        HashBytes(nextStateBytes),

		PreviousLivePresent:     previousLivePresent,
		PreviousLiveBytes:       append([]byte(nil), previousLiveBytes...),
		PreviousLiveHash:        previousLiveHash,
		NextLivePresent:         nextLivePresent,
		NextLiveBytes:           append([]byte(nil), nextLiveBytes...),
		NextLiveHash:            nextExpectedHash,
		GenerationManifestBytes: append([]byte(nil), generationManifestBytes...),
	}
	sealed, err := sealProjectionRecoveryJournal(journal, l.verifierKey)
	if err != nil {
		return projectionRecoveryJournal{}, err
	}
	if _, err := l.validateProjectionRecoveryJournal(sealed, effect, relativePath); err != nil {
		return projectionRecoveryJournal{}, err
	}
	return sealed, nil
}

func expectedProjectionLive(state *projectionLifecycleState) (bool, string, error) {
	if state == nil || state.Status == projectionStatusRevoked {
		return false, "", nil
	}
	if state.Status != projectionStatusActive {
		return false, "", fmt.Errorf("%w: projection state status is invalid", ErrProjectionDrift)
	}
	record, ok := findProjectionGeneration(state.Generations, state.ArchiveGeneration)
	if !ok || !validProjectionSHA256(record.ContentHash) {
		return false, "", fmt.Errorf("%w: projection live generation is missing", ErrProjectionDrift)
	}
	return true, record.ContentHash, nil
}

func (l *ProjectionLifecycle) validateProjectionRecoveryJournal(
	journal projectionRecoveryJournal,
	effect contracts.SkillProjectionEffect,
	relativePath string,
) (projectionLifecycleState, error) {
	if err := l.verifyProjectionRecoveryJournal(journal); err != nil {
		return projectionLifecycleState{}, err
	}
	if journal.SchemaVersion != projectionRecoveryJournalSchemaV1 ||
		journal.TenantID != effect.TenantID || journal.WorkspaceID != effect.WorkspaceID ||
		journal.SkillID != effect.SkillID || journal.AgentTarget != effect.AgentTarget ||
		journal.RelativePath != relativePath || journal.SkillVersion == "" ||
		!validProjectionSHA256(journal.CanonicalRequestHash) || journal.IdempotencyKey == "" || journal.AttemptID == "" ||
		!validProjectionSHA256(journal.ResultHash) || !validProjectionSHA256(journal.TrustVerificationRef) ||
		!validProjectionSHA256(journal.TrustDecisionHash) || !validProjectionAction(journal.TrustDecisionAction) ||
		!validProjectionSHA256(journal.TrustDecisionCanonical) || !validProjectionSHA256(journal.TrustBindingHash) ||
		!validProjectionTrustIdentity(journal.TrustVerifierID) ||
		!validProjectionTrustIdentity(journal.TrustKeyID) || !validProjectionTrustSignature(journal.TrustDecisionSignature) {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal identity is invalid", ErrProjectionDrift)
	}
	if err := l.verifyStoredProjectionTrustSignature(
		journal.TrustDecisionHash, journal.TrustBindingHash, journal.TrustVerifierID,
		journal.TrustKeyID, journal.TrustDecisionSignature,
	); err != nil {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal trust receipt: %v", ErrProjectionDrift, err)
	}
	if !projectionJournalMatchesTrustEffect(journal, effect) {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal trust effect mismatch", ErrProjectionDrift)
	}
	if journal.Action != contracts.SkillProjectionActionRevoke {
		expectedBindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromEffect(effect))
		if err != nil || !constantStringEqual(expectedBindingHash, journal.TrustBindingHash) ||
			journal.TrustDecisionAction != effect.Action ||
			journal.TrustDecisionCanonical != effect.CanonicalRequestHash {
			return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal trust effect mismatch", ErrProjectionDrift)
		}
	}
	switch journal.Action {
	case contracts.SkillProjectionActionInstall, contracts.SkillProjectionActionReadback,
		contracts.SkillProjectionActionRevoke, contracts.SkillProjectionActionRollback:
	default:
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal action is invalid", ErrProjectionDrift)
	}
	if journal.PreviousStatePresent != (journal.PreviousStateHash != "") ||
		journal.PreviousStatePresent != (len(journal.PreviousStateBytes) != 0) ||
		(journal.PreviousStatePresent && (!validProjectionSHA256(journal.PreviousStateHash) ||
			len(journal.PreviousStateBytes) > maxProjectionLifecycleStateBytes ||
			HashBytes(journal.PreviousStateBytes) != journal.PreviousStateHash)) ||
		len(journal.NextStateBytes) == 0 || len(journal.NextStateBytes) > maxProjectionLifecycleStateBytes ||
		!validProjectionSHA256(journal.NextStateHash) || HashBytes(journal.NextStateBytes) != journal.NextStateHash ||
		journal.PreviousLivePresent != (journal.PreviousLiveHash != "") ||
		journal.PreviousLivePresent != (len(journal.PreviousLiveBytes) != 0) ||
		(journal.PreviousLivePresent && (!validProjectionSHA256(journal.PreviousLiveHash) ||
			len(journal.PreviousLiveBytes) > maxProjectionArtifactBytes ||
			HashBytes(journal.PreviousLiveBytes) != journal.PreviousLiveHash)) ||
		journal.NextLivePresent != (journal.NextLiveHash != "") ||
		(journal.NextLivePresent && (!validProjectionSHA256(journal.NextLiveHash) || len(journal.NextLiveBytes) == 0 ||
			len(journal.NextLiveBytes) > maxProjectionArtifactBytes || HashBytes(journal.NextLiveBytes) != journal.NextLiveHash)) ||
		(!journal.NextLivePresent && len(journal.NextLiveBytes) != 0) {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal disk bindings are invalid", ErrProjectionDrift)
	}
	var previous *projectionLifecycleState
	if journal.PreviousStatePresent {
		var decodedPrevious projectionLifecycleState
		if err := decodeStrictProjectionJSON(journal.PreviousStateBytes, &decodedPrevious); err != nil {
			return projectionLifecycleState{}, fmt.Errorf("%w: decode previous recovery state: %v", ErrProjectionDrift, err)
		}
		if err := l.verifyProjectionLifecycleState(decodedPrevious); err != nil {
			return projectionLifecycleState{}, fmt.Errorf("%w: previous recovery state integrity: %v", ErrProjectionDrift, err)
		}
		if err := validateProjectionStateIdentity(decodedPrevious, effect, relativePath); err != nil {
			return projectionLifecycleState{}, err
		}
		if err := l.verifyProjectionStateTrustReceipts(decodedPrevious); err != nil {
			return projectionLifecycleState{}, err
		}
		previousLivePresent, previousLiveHash, err := expectedProjectionLive(&decodedPrevious)
		if err != nil || previousLivePresent != journal.PreviousLivePresent || previousLiveHash != journal.PreviousLiveHash {
			return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal previous live state is invalid", ErrProjectionDrift)
		}
		previous = &decodedPrevious
	} else if journal.PreviousLivePresent {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal has live bytes without previous state", ErrProjectionDrift)
	}
	var next projectionLifecycleState
	if err := decodeStrictProjectionJSON(journal.NextStateBytes, &next); err != nil {
		return projectionLifecycleState{}, fmt.Errorf("%w: decode recovery state: %v", ErrProjectionDrift, err)
	}
	if err := l.verifyProjectionLifecycleState(next); err != nil {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery state integrity: %v", ErrProjectionDrift, err)
	}
	if err := validateProjectionStateIdentity(next, effect, relativePath); err != nil {
		return projectionLifecycleState{}, err
	}
	if err := l.verifyProjectionStateTrustReceipts(next); err != nil {
		return projectionLifecycleState{}, err
	}
	replay, ok := findProjectionReplay(next.Replays, journal.IdempotencyKey)
	if !ok || replay.RequestHash != journal.CanonicalRequestHash || replay.Result.ResultHash != journal.ResultHash ||
		replay.Result.Action != journal.Action || replay.Result.SkillVersion != journal.SkillVersion ||
		replay.Result.AttemptID != journal.AttemptID || replay.Result.TrustVerificationRef != journal.TrustVerificationRef ||
		replay.Result.TrustDecisionHash != journal.TrustDecisionHash ||
		replay.Result.TrustDecisionAction != journal.TrustDecisionAction ||
		replay.Result.TrustDecisionCanonical != journal.TrustDecisionCanonical ||
		replay.Result.TrustVerifierID != journal.TrustVerifierID ||
		replay.Result.TrustKeyID != journal.TrustKeyID || replay.Result.TrustBindingHash != journal.TrustBindingHash ||
		replay.Result.TrustDecisionSignature != journal.TrustDecisionSignature {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal replay binding is invalid", ErrProjectionDrift)
	}
	nextLivePresent, nextLiveHash, err := expectedProjectionLive(&next)
	if err != nil || nextLivePresent != journal.NextLivePresent || nextLiveHash != journal.NextLiveHash {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal next live state is invalid", ErrProjectionDrift)
	}
	if err := validateProjectionStateTransition(previous, next, effect, relativePath, replay.Result); err != nil {
		return projectionLifecycleState{}, err
	}
	if effect.Action == contracts.SkillProjectionActionInstall || effect.Action == contracts.SkillProjectionActionRollback {
		record, ok := findProjectionGeneration(next.Generations, effect.Generation)
		if !ok || len(journal.GenerationManifestBytes) == 0 ||
			len(journal.GenerationManifestBytes) > maxProjectionArtifactBytes ||
			HashBytes(journal.GenerationManifestBytes) != record.ManifestHash ||
			!journal.NextLivePresent || HashBytes(journal.NextLiveBytes) != record.ContentHash {
			return projectionLifecycleState{}, fmt.Errorf("%w: recovery generation bytes are invalid", ErrProjectionDrift)
		}
	} else if len(journal.GenerationManifestBytes) != 0 {
		return projectionLifecycleState{}, fmt.Errorf("%w: recovery journal has unexpected generation bytes", ErrProjectionDrift)
	}
	return next, nil
}

func (l *ProjectionLifecycle) writeProjectionRecoveryJournal(
	effect contracts.SkillProjectionEffect,
	relativePath string,
	journal projectionRecoveryJournal,
) error {
	if _, err := readManagedFileAt(l.managed, l.journalRel(effect), maxProjectionRecoveryJournalBytes); err == nil {
		return fmt.Errorf("%w: recovery journal already exists", ErrProjectionDrift)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: inspect recovery journal: %w", ErrProjectionDrift, err)
	}
	if _, err := l.validateProjectionRecoveryJournal(journal, effect, relativePath); err != nil {
		return err
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxProjectionRecoveryJournalBytes {
		return ErrProjectionFileTooLarge
	}
	if err := atomicReplaceManagedAt(l.managed, l.journalRel(effect), data); err != nil {
		return fmt.Errorf("skillpacks: publish recovery journal: %w", err)
	}
	observed, err := readManagedFileAt(l.managed, l.journalRel(effect), maxProjectionRecoveryJournalBytes)
	if err != nil || !constantBytesEqual(observed, data) {
		return fmt.Errorf("%w: recovery journal readback mismatch: %v", ErrProjectionDrift, err)
	}
	var decoded projectionRecoveryJournal
	if err := decodeStrictProjectionJSON(observed, &decoded); err != nil {
		return fmt.Errorf("%w: decode recovery journal readback: %v", ErrProjectionDrift, err)
	}
	if _, err := l.validateProjectionRecoveryJournal(decoded, effect, relativePath); err != nil {
		return err
	}
	return nil
}

func (l *ProjectionLifecycle) readProjectionRecoveryJournal(
	effect contracts.SkillProjectionEffect,
	relativePath string,
) (*projectionRecoveryJournal, *projectionLifecycleState, error) {
	data, err := readManagedFileAt(l.managed, l.journalRel(effect), maxProjectionRecoveryJournalBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read recovery journal: %w", ErrProjectionDrift, err)
	}
	var journal projectionRecoveryJournal
	if err := decodeStrictProjectionJSON(data, &journal); err != nil {
		return nil, nil, fmt.Errorf("%w: decode recovery journal: %v", ErrProjectionDrift, err)
	}
	next, err := l.validateProjectionRecoveryJournal(journal, effect, relativePath)
	if err != nil {
		return nil, nil, err
	}
	return &journal, &next, nil
}

func (l *ProjectionLifecycle) recoverProjectionJournal(
	effect contracts.SkillProjectionEffect,
	relativePath string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	authorityErr error,
) error {
	journal, next, err := l.readProjectionRecoveryJournal(effect, relativePath)
	if err != nil || journal == nil {
		return err
	}
	if authorityErr != nil {
		return l.abortProjectionMutation(effect, relativePath, *journal, authorityErr)
	}
	if err := l.persistRecoveryGeneration(effect, *journal, *next); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	trust, trustErr := l.verifyReplayTrust(effect, *next, rollbackPermit)
	if trustErr != nil {
		return l.abortProjectionMutation(effect, relativePath, *journal, trustErr)
	}
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, next); err != nil {
		return l.abortProjectionMutation(effect, relativePath, *journal, err)
	}
	if err := l.publishRecoveryLive(effect, *journal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, next); err != nil {
		return l.abortProjectionMutation(effect, relativePath, *journal, err)
	}
	if err := l.publishRecoveryState(effect, *journal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.validateProjectionPublicationAuthority(effect, rollbackPermit, trust, next); err != nil {
		return l.abortProjectionMutation(effect, relativePath, *journal, err)
	}
	if err := l.verifyRecoveryTarget(effect, relativePath, *journal); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	if err := l.clearProjectionRecoveryJournal(effect, relativePath, journal.JournalHash); err != nil {
		return errors.Join(ErrProjectionRecoveryPending, err)
	}
	return nil
}

func (l *ProjectionLifecycle) persistRecoveryGeneration(
	effect contracts.SkillProjectionEffect,
	journal projectionRecoveryJournal,
	next projectionLifecycleState,
) error {
	switch effect.Action {
	case contracts.SkillProjectionActionInstall, contracts.SkillProjectionActionRollback:
		record, ok := findProjectionGeneration(next.Generations, effect.Generation)
		if !ok {
			return fmt.Errorf("%w: recovery generation is missing", ErrProjectionDrift)
		}
		return l.persistGeneration(effect, record, journal.GenerationManifestBytes, journal.NextLiveBytes)
	default:
		if len(journal.GenerationManifestBytes) != 0 {
			return fmt.Errorf("%w: recovery journal has unexpected generation bytes", ErrProjectionDrift)
		}
		return nil
	}
}

func (l *ProjectionLifecycle) abortProjectionMutation(
	effect contracts.SkillProjectionEffect,
	relativePath string,
	journal projectionRecoveryJournal,
	reason error,
) error {
	if restoreErr := l.restoreRecoveryPrevious(effect, relativePath, journal); restoreErr != nil {
		return errors.Join(ErrProjectionRecoveryPending, reason, restoreErr)
	}
	if cleanupErr := l.removeRecoveryForwardOnlyGenerations(effect, journal); cleanupErr != nil {
		return errors.Join(ErrProjectionRecoveryPending, reason, cleanupErr)
	}
	if clearErr := l.clearProjectionRecoveryJournal(effect, relativePath, journal.JournalHash); clearErr != nil {
		return errors.Join(ErrProjectionRecoveryPending, reason, clearErr)
	}
	return reason
}

func (l *ProjectionLifecycle) removeRecoveryForwardOnlyGenerations(
	effect contracts.SkillProjectionEffect,
	journal projectionRecoveryJournal,
) error {
	var next projectionLifecycleState
	if err := decodeStrictProjectionJSON(journal.NextStateBytes, &next); err != nil {
		return fmt.Errorf("%w: decode forward recovery state for cleanup: %v", ErrProjectionDrift, err)
	}
	previousGenerations := map[uint64]struct{}{}
	if journal.PreviousStatePresent {
		var previous projectionLifecycleState
		if err := decodeStrictProjectionJSON(journal.PreviousStateBytes, &previous); err != nil {
			return fmt.Errorf("%w: decode previous recovery state for cleanup: %v", ErrProjectionDrift, err)
		}
		for _, record := range previous.Generations {
			previousGenerations[record.Generation] = struct{}{}
		}
	}
	for _, record := range next.Generations {
		if _, retained := previousGenerations[record.Generation]; retained {
			continue
		}
		if err := l.removeManagedGeneration(effect, record); err != nil {
			return err
		}
	}
	return nil
}

func (l *ProjectionLifecycle) removeManagedGeneration(
	effect contracts.SkillProjectionEffect,
	record projectionGeneration,
) error {
	dirRel := filepath.Join(l.generationParentRel(effect), projectionGenerationDirName(record))
	info, err := l.managed.Lstat(dirRel)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrProjectionPathUnsafe
	}
	dir, err := l.managed.Open(dirRel)
	if err != nil {
		return err
	}
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = dir.Close()
		return ErrProjectionPathUnsafe
	}
	entries, readErr := dir.ReadDir(3)
	closeErr := dir.Close()
	if len(entries) > 2 || (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return ErrProjectionPathUnsafe
	}
	expected := map[string]string{
		"skillpack.json": record.ManifestHash,
		"SKILL.md":       record.ContentHash,
	}
	for _, entry := range entries {
		expectedHash, ok := expected[entry.Name()]
		if !ok || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return ErrProjectionPathUnsafe
		}
		data, err := readManagedFileAt(l.managed, filepath.Join(dirRel, entry.Name()), maxProjectionArtifactBytes)
		if err != nil || !constantStringEqual(HashBytes(data), expectedHash) {
			return fmt.Errorf("%w: aborted immutable generation differs", ErrProjectionDrift)
		}
	}
	for _, entry := range entries {
		if err := removeManagedFileAt(l.managed, filepath.Join(dirRel, entry.Name())); err != nil {
			return err
		}
	}
	if err := l.managed.Remove(dirRel); err != nil {
		return fmt.Errorf("skillpacks: remove aborted immutable generation: %w", err)
	}
	return syncManagedDirectoryAt(l.managed, filepath.Dir(dirRel))
}

func (l *ProjectionLifecycle) restoreRecoveryPrevious(
	effect contracts.SkillProjectionEffect,
	relativePath string,
	journal projectionRecoveryJournal,
) error {
	if err := l.restoreRecoveryPreviousLive(effect, relativePath, journal); err != nil {
		return err
	}
	return l.restoreRecoveryPreviousState(effect, journal)
}

func (l *ProjectionLifecycle) restoreRecoveryPreviousLive(
	effect contracts.SkillProjectionEffect,
	relativePath string,
	journal projectionRecoveryJournal,
) error {
	rel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
	present, hash, err := observeManagedFile(l.managed, rel, maxProjectionArtifactBytes)
	if err != nil {
		return fmt.Errorf("%w: observe live projection during recovery restore: %w", ErrProjectionDrift, err)
	}
	if !observationMatches(present, hash, journal.PreviousLivePresent, journal.PreviousLiveHash) &&
		!observationMatches(present, hash, journal.NextLivePresent, journal.NextLiveHash) {
		return fmt.Errorf("%w: live projection does not match recovery restore journal", ErrProjectionDrift)
	}
	if observationMatches(present, hash, journal.PreviousLivePresent, journal.PreviousLiveHash) {
		return nil
	}
	if journal.PreviousLivePresent {
		if err := atomicReplaceManagedAt(l.managed, rel, journal.PreviousLiveBytes); err != nil {
			return err
		}
	} else if err := removeManagedFileAt(l.managed, rel); err != nil {
		return err
	}
	present, hash, err = observeManagedFile(l.managed, rel, maxProjectionArtifactBytes)
	if err != nil || !observationMatches(present, hash, journal.PreviousLivePresent, journal.PreviousLiveHash) {
		return fmt.Errorf("%w: recovery live restore readback mismatch: %v", ErrProjectionDrift, err)
	}
	return nil
}

func (l *ProjectionLifecycle) restoreRecoveryPreviousState(
	effect contracts.SkillProjectionEffect,
	journal projectionRecoveryJournal,
) error {
	present, hash, err := observeManagedFile(l.managed, l.stateRel(effect), maxProjectionLifecycleStateBytes)
	if err != nil {
		return fmt.Errorf("%w: observe projection state during recovery restore: %w", ErrProjectionDrift, err)
	}
	if !observationMatches(present, hash, journal.PreviousStatePresent, journal.PreviousStateHash) &&
		!observationMatches(present, hash, true, journal.NextStateHash) {
		return fmt.Errorf("%w: projection state does not match recovery restore journal", ErrProjectionDrift)
	}
	if observationMatches(present, hash, journal.PreviousStatePresent, journal.PreviousStateHash) {
		return nil
	}
	if journal.PreviousStatePresent {
		if err := l.writeStateBytes(effect, journal.PreviousStateBytes); err != nil {
			return err
		}
	} else if err := removeManagedFileAt(l.managed, l.stateRel(effect)); err != nil {
		return err
	}
	present, hash, err = observeManagedFile(l.managed, l.stateRel(effect), maxProjectionLifecycleStateBytes)
	if err != nil || !observationMatches(present, hash, journal.PreviousStatePresent, journal.PreviousStateHash) {
		return fmt.Errorf("%w: recovery state restore readback mismatch: %v", ErrProjectionDrift, err)
	}
	return nil
}

func (l *ProjectionLifecycle) publishRecoveryLive(effect contracts.SkillProjectionEffect, journal projectionRecoveryJournal) error {
	rel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(journal.RelativePath))
	present, hash, err := observeManagedFile(l.managed, rel, maxProjectionArtifactBytes)
	if err != nil {
		return fmt.Errorf("%w: observe live projection during recovery: %w", ErrProjectionDrift, err)
	}
	if !observationMatches(present, hash, journal.PreviousLivePresent, journal.PreviousLiveHash) &&
		!observationMatches(present, hash, journal.NextLivePresent, journal.NextLiveHash) {
		return fmt.Errorf("%w: live projection does not match recovery journal", ErrProjectionDrift)
	}
	if observationMatches(present, hash, journal.NextLivePresent, journal.NextLiveHash) {
		return nil
	}
	if journal.NextLivePresent {
		if err := atomicReplaceManagedAt(l.managed, rel, journal.NextLiveBytes); err != nil {
			return err
		}
	} else if err := removeManagedFileAt(l.managed, rel); err != nil {
		return err
	}
	present, hash, err = observeManagedFile(l.managed, rel, maxProjectionArtifactBytes)
	if err != nil || !observationMatches(present, hash, journal.NextLivePresent, journal.NextLiveHash) {
		return fmt.Errorf("%w: recovery live readback mismatch: %v", ErrProjectionDrift, err)
	}
	return nil
}

func (l *ProjectionLifecycle) publishRecoveryState(effect contracts.SkillProjectionEffect, journal projectionRecoveryJournal) error {
	present, hash, err := observeManagedFile(l.managed, l.stateRel(effect), maxProjectionLifecycleStateBytes)
	if err != nil {
		return fmt.Errorf("%w: observe projection state during recovery: %w", ErrProjectionDrift, err)
	}
	if !observationMatches(present, hash, journal.PreviousStatePresent, journal.PreviousStateHash) &&
		!observationMatches(present, hash, true, journal.NextStateHash) {
		return fmt.Errorf("%w: projection state does not match recovery journal", ErrProjectionDrift)
	}
	if observationMatches(present, hash, true, journal.NextStateHash) {
		return nil
	}
	return l.writeStateBytes(effect, journal.NextStateBytes)
}

func (l *ProjectionLifecycle) verifyRecoveryTarget(
	effect contracts.SkillProjectionEffect,
	relativePath string,
	journal projectionRecoveryJournal,
) error {
	state, err := l.readState(effect, relativePath)
	if err != nil {
		return err
	}
	if state == nil || HashBytes(journal.NextStateBytes) != journal.NextStateHash {
		return fmt.Errorf("%w: recovered projection state is missing", ErrProjectionDrift)
	}
	observedState, err := readManagedFileAt(l.managed, l.stateRel(effect), maxProjectionLifecycleStateBytes)
	if err != nil || HashBytes(observedState) != journal.NextStateHash {
		return fmt.Errorf("%w: recovered projection state hash mismatch: %v", ErrProjectionDrift, err)
	}
	if err := l.verifyManagedState(*state); err != nil {
		return err
	}
	return nil
}

func (l *ProjectionLifecycle) clearProjectionRecoveryJournal(
	effect contracts.SkillProjectionEffect,
	relativePath, expectedHash string,
) error {
	journal, _, err := l.readProjectionRecoveryJournal(effect, relativePath)
	if err != nil {
		return err
	}
	if journal == nil || !constantStringEqual(journal.JournalHash, expectedHash) {
		return fmt.Errorf("%w: recovery journal changed before clear", ErrProjectionDrift)
	}
	return removeManagedFileAt(l.managed, l.journalRel(effect))
}

func observeManagedFile(root *os.Root, rel string, maxBytes int64) (bool, string, error) {
	data, err := readManagedFileAt(root, rel, maxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, HashBytes(data), nil
}

func observationMatches(present bool, hash string, expectedPresent bool, expectedHash string) bool {
	return present == expectedPresent && ((!present && expectedHash == "") || (present && hash == expectedHash))
}

func (l *ProjectionLifecycle) runProjectionMutationHook(stage string) error {
	if l.mutationHook == nil {
		return nil
	}
	return l.mutationHook(stage)
}

func (l *ProjectionLifecycle) persistGeneration(
	effect contracts.SkillProjectionEffect,
	record projectionGeneration,
	manifestBytes, contentBytes []byte,
) error {
	if err := validateProjectionGeneration(record); err != nil {
		return err
	}
	trustState := projectionLifecycleState{
		TenantID: effect.TenantID, WorkspaceID: effect.WorkspaceID,
		SkillID: effect.SkillID, AgentTarget: effect.AgentTarget,
	}
	if !projectionGenerationMatchesTrustEffect(trustState, record) {
		return fmt.Errorf("%w: projection generation trust effect mismatch", ErrProjectionDrift)
	}
	root := l.managed
	if root == nil {
		return fmt.Errorf("skillpacks: projection lifecycle is closed")
	}
	parentRel := l.generationParentRel(effect)
	if err := ensureManagedDirAt(root, parentRel); err != nil {
		return err
	}
	finalRel := filepath.Join(parentRel, projectionGenerationDirName(record))
	if err := validateManagedPathAt(root, finalRel, true); err != nil {
		return err
	}
	if info, statErr := root.Lstat(finalRel); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrProjectionPathUnsafe
		}
		storedManifest, storedContent, readErr := l.readGeneration(effect, record)
		if readErr != nil || !constantBytesEqual(storedManifest, manifestBytes) || !constantBytesEqual(storedContent, contentBytes) {
			return fmt.Errorf("%w: immutable generation differs", ErrProjectionDrift)
		}
		if err := syncManagedDirectoryAt(root, parentRel); err != nil {
			return fmt.Errorf("skillpacks: sync existing immutable generation parent: %w", err)
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}

	stageName, err := projectionRandomName(".projection-stage-")
	if err != nil {
		return err
	}
	stageRel := filepath.Join(parentRel, stageName)
	if err := root.Mkdir(stageRel, 0o755); err != nil {
		return err
	}
	defer cleanupManagedStage(root, stageRel)
	if err := writeExclusiveManagedFileAt(root, filepath.Join(stageRel, "skillpack.json"), manifestBytes); err != nil {
		return err
	}
	if err := writeExclusiveManagedFileAt(root, filepath.Join(stageRel, "SKILL.md"), contentBytes); err != nil {
		return err
	}
	if err := syncManagedDirectoryAt(root, stageRel); err != nil {
		return fmt.Errorf("skillpacks: sync staged immutable generation: %w", err)
	}
	if err := root.Rename(stageRel, finalRel); err != nil {
		if _, statErr := root.Stat(finalRel); statErr == nil {
			storedManifest, storedContent, readErr := l.readGeneration(effect, record)
			if readErr == nil && constantBytesEqual(storedManifest, manifestBytes) && constantBytesEqual(storedContent, contentBytes) {
				if syncErr := syncManagedDirectoryAt(root, parentRel); syncErr != nil {
					return fmt.Errorf("skillpacks: sync raced immutable generation parent: %w", syncErr)
				}
				return nil
			}
		}
		return fmt.Errorf("skillpacks: commit immutable generation: %w", err)
	}
	if err := syncManagedDirectoryAt(root, parentRel); err != nil {
		return fmt.Errorf("skillpacks: sync immutable generation parent: %w", err)
	}
	storedManifest, storedContent, err := l.readGeneration(effect, record)
	if err != nil || !constantBytesEqual(storedManifest, manifestBytes) || !constantBytesEqual(storedContent, contentBytes) {
		return fmt.Errorf("%w: immutable generation readback mismatch", ErrProjectionDrift)
	}
	return nil
}

func (l *ProjectionLifecycle) readGeneration(
	effect contracts.SkillProjectionEffect,
	record projectionGeneration,
) ([]byte, []byte, error) {
	if err := validateProjectionGeneration(record); err != nil {
		return nil, nil, err
	}
	dirRel := filepath.Join(l.generationParentRel(effect), projectionGenerationDirName(record))
	root := l.managed
	if root == nil {
		return nil, nil, fmt.Errorf("skillpacks: projection lifecycle is closed")
	}
	if err := validateManagedPathAt(root, dirRel, false); err != nil {
		return nil, nil, err
	}
	entries, err := fs.ReadDir(root.FS(), filepath.ToSlash(dirRel))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read immutable generation: %v", ErrProjectionDrift, err)
	}
	if len(entries) != 2 || entries[0].Name() != "SKILL.md" || entries[1].Name() != "skillpack.json" {
		return nil, nil, fmt.Errorf("%w: immutable generation has unexpected files", ErrProjectionDrift)
	}
	manifestBytes, err := readManagedFileAt(root, filepath.Join(dirRel, "skillpack.json"), maxProjectionArtifactBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read immutable generation manifest: %w", ErrProjectionDrift, err)
	}
	contentBytes, err := readManagedFileAt(root, filepath.Join(dirRel, "SKILL.md"), maxProjectionArtifactBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read immutable generation content: %w", ErrProjectionDrift, err)
	}
	manifestHash, contentHash := HashBytes(manifestBytes), HashBytes(contentBytes)
	artifactHash, hashErr := contracts.ComputeSkillProjectionArtifactHash(manifestHash, contentHash)
	if hashErr != nil || manifestHash != record.ManifestHash || contentHash != record.ContentHash || artifactHash != record.ArtifactHash {
		return nil, nil, fmt.Errorf("%w: immutable generation hash mismatch", ErrProjectionDrift)
	}
	return manifestBytes, contentBytes, nil
}

func (l *ProjectionLifecycle) immutableProjectionArtifactExists(
	effect contracts.SkillProjectionEffect,
	artifactHash string,
) (bool, error) {
	parentRel := l.generationParentRel(effect)
	info, err := l.managed.Lstat(parentRel)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, ErrProjectionPathUnsafe
	}
	dir, err := l.managed.Open(parentRel)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false, ErrProjectionPathUnsafe
	}
	wantDigest := strings.TrimPrefix(artifactHash, "sha256:")
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			name := entry.Name()
			if len(name) != 20+1+64 || name[20] != '-' || name[21:] != wantDigest {
				continue
			}
			if _, err := strconv.ParseUint(name[:20], 10, 64); err != nil || !entry.IsDir() {
				return false, ErrProjectionPathUnsafe
			}
			return true, nil
		}
		if errors.Is(readErr, io.EOF) {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

func (l *ProjectionLifecycle) verifyManagedState(state projectionLifecycleState) error {
	record, ok := findProjectionGeneration(state.Generations, state.ArchiveGeneration)
	if !ok {
		return fmt.Errorf("%w: archive generation is missing", ErrProjectionDrift)
	}
	if err := l.verifyProjectionStateTrustReceipts(state); err != nil {
		return err
	}
	effect := contracts.SkillProjectionEffect{TenantID: state.TenantID, WorkspaceID: state.WorkspaceID, SkillID: state.SkillID, AgentTarget: state.AgentTarget}
	for _, retained := range state.Generations {
		if _, _, err := l.readGeneration(effect, retained); err != nil {
			return err
		}
	}
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(state.RelativePath))
	data, err := readManagedFileAt(l.managed, fullRel, maxProjectionArtifactBytes)
	if state.Status == projectionStatusRevoked {
		if err == nil {
			return fmt.Errorf("%w: revoked projection reappeared", ErrProjectionDrift)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err != nil {
		return fmt.Errorf("%w: live projection read failed: %w", ErrProjectionDrift, err)
	}
	if HashBytes(data) != record.ContentHash {
		return fmt.Errorf("%w: live content hash mismatch", ErrProjectionDrift)
	}
	return nil
}

func (l *ProjectionLifecycle) verifyProjectionStateTrustReceipts(state projectionLifecycleState) error {
	for _, retained := range state.Generations {
		if !projectionGenerationMatchesTrustEffect(state, retained) {
			return fmt.Errorf("%w: retained generation trust effect mismatch", ErrProjectionDrift)
		}
		if err := l.verifyStoredProjectionTrustSignature(
			retained.TrustDecisionHash, retained.TrustBindingHash, retained.TrustVerifierID,
			retained.TrustKeyID, retained.TrustDecisionSignature,
		); err != nil {
			return fmt.Errorf("%w: retained generation trust receipt: %v", ErrProjectionDrift, err)
		}
	}
	for _, replay := range state.Replays {
		if err := l.verifyStoredProjectionTrustSignature(
			replay.Result.TrustDecisionHash, replay.Result.TrustBindingHash, replay.Result.TrustVerifierID,
			replay.Result.TrustKeyID, replay.Result.TrustDecisionSignature,
		); err != nil {
			return fmt.Errorf("%w: replay trust receipt: %v", ErrProjectionDrift, err)
		}
	}
	return nil
}

func (l *ProjectionLifecycle) verifyProjectionAbsent(effect contracts.SkillProjectionEffect, relativePath string) error {
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
	_, err := readManagedFileAt(l.managed, fullRel, maxProjectionArtifactBytes)
	if err == nil {
		return ErrUnmanagedProjection
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (l *ProjectionLifecycle) readState(effect contracts.SkillProjectionEffect, relativePath string) (*projectionLifecycleState, error) {
	data, err := readManagedFileAt(l.managed, l.stateRel(effect), maxProjectionLifecycleStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read projection state: %w", ErrProjectionDrift, err)
	}
	var state projectionLifecycleState
	if err := decodeStrictProjectionJSON(data, &state); err != nil {
		return nil, fmt.Errorf("skillpacks: decode projection state: %w", err)
	}
	if err := l.verifyProjectionLifecycleState(state); err != nil {
		return nil, err
	}
	if err := validateProjectionStateIdentity(state, effect, relativePath); err != nil {
		return nil, err
	}
	return &state, nil
}

func (l *ProjectionLifecycle) marshalProjectionLifecycleState(state projectionLifecycleState) (projectionLifecycleState, []byte, error) {
	sealed, err := sealProjectionLifecycleState(state, l.verifierKey)
	if err != nil {
		return projectionLifecycleState{}, nil, err
	}
	data, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return projectionLifecycleState{}, nil, err
	}
	if len(data) > maxProjectionLifecycleStateBytes {
		return projectionLifecycleState{}, nil, ErrProjectionFileTooLarge
	}
	return sealed, data, nil
}

func (l *ProjectionLifecycle) writeStateBytes(effect contracts.SkillProjectionEffect, data []byte) error {
	if len(data) == 0 || len(data) > maxProjectionLifecycleStateBytes {
		return ErrProjectionFileTooLarge
	}
	if err := atomicReplaceManagedAt(l.managed, l.stateRel(effect), data); err != nil {
		return err
	}
	observed, err := readManagedFileAt(l.managed, l.stateRel(effect), maxProjectionLifecycleStateBytes)
	if err != nil || !constantBytesEqual(observed, data) {
		return fmt.Errorf("%w: projection state readback mismatch: %v", ErrProjectionDrift, err)
	}
	return nil
}

func (l *ProjectionLifecycle) workspaceRel(effect contracts.SkillProjectionEffect) string {
	return filepath.Join("tenants", effect.TenantID, "workspaces", effect.WorkspaceID)
}

func (l *ProjectionLifecycle) managedBaseRel(effect contracts.SkillProjectionEffect) string {
	parts := strings.Split(effect.SkillID, "/")
	return filepath.Join(l.workspaceRel(effect), ".helm", "skillpacks", "projections", effect.AgentTarget, parts[0], parts[1])
}

func (l *ProjectionLifecycle) stateRel(effect contracts.SkillProjectionEffect) string {
	return filepath.Join(l.managedBaseRel(effect), "state.json")
}

func (l *ProjectionLifecycle) journalRel(effect contracts.SkillProjectionEffect) string {
	return filepath.Join(l.managedBaseRel(effect), "recovery.json")
}

func (l *ProjectionLifecycle) generationParentRel(effect contracts.SkillProjectionEffect) string {
	return filepath.Join(l.managedBaseRel(effect), "generations")
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

func projectionGenerationDirName(record projectionGeneration) string {
	return fmt.Sprintf("%020d-%s", record.Generation, strings.TrimPrefix(record.ArtifactHash, "sha256:"))
}

func newProjectionState(effect contracts.SkillProjectionEffect, relativePath string, current *projectionLifecycleState) projectionLifecycleState {
	if current != nil {
		return cloneProjectionState(*current)
	}
	return projectionLifecycleState{
		SchemaVersion: projectionLifecycleStateSchemaV1,
		TenantID:      effect.TenantID, WorkspaceID: effect.WorkspaceID,
		SkillID: effect.SkillID, AgentTarget: effect.AgentTarget,
		RelativePath: relativePath,
		Generations:  []projectionGeneration{}, Replays: []projectionReplay{}, Attempts: []projectionAttempt{},
	}
}

func cloneProjectionState(state projectionLifecycleState) projectionLifecycleState {
	clone := state
	clone.Generations = append([]projectionGeneration(nil), state.Generations...)
	for i := range clone.Generations {
		clone.Generations[i].CertificationRefs = append([]string(nil), state.Generations[i].CertificationRefs...)
	}
	clone.Replays = append([]projectionReplay(nil), state.Replays...)
	clone.Attempts = append([]projectionAttempt(nil), state.Attempts...)
	return clone
}

func validateProjectionStateIdentity(state projectionLifecycleState, effect contracts.SkillProjectionEffect, relativePath string) error {
	if state.SchemaVersion != projectionLifecycleStateSchemaV1 ||
		state.TenantID != effect.TenantID || state.WorkspaceID != effect.WorkspaceID ||
		state.SkillID != effect.SkillID || state.AgentTarget != effect.AgentTarget ||
		state.RelativePath != relativePath || state.Generation == 0 || state.Generation > 9007199254740991 ||
		state.ArchiveGeneration == 0 || state.ArchiveGeneration > state.Generation ||
		(state.Status != projectionStatusActive && state.Status != projectionStatusRevoked) {
		return fmt.Errorf("%w: projection state identity mismatch", ErrProjectionDrift)
	}
	if len(state.Generations) == 0 || len(state.Generations) > maxProjectionGenerationEntries {
		return fmt.Errorf("%w: projection generation window is invalid", ErrProjectionDrift)
	}
	for i := range state.Generations {
		if err := validateProjectionGeneration(state.Generations[i]); err != nil ||
			(i > 0 && state.Generations[i-1].Generation >= state.Generations[i].Generation) {
			return fmt.Errorf("%w: projection generation history is invalid", ErrProjectionDrift)
		}
	}
	if len(state.Replays) > maxProjectionReplayEntries || len(state.Attempts) != len(state.Replays) {
		return fmt.Errorf("%w: projection replay window is invalid", ErrProjectionDrift)
	}
	seenReplayKeys := make(map[string]struct{}, len(state.Replays))
	seenAttemptIDs := make(map[string]struct{}, len(state.Attempts))
	for i, replay := range state.Replays {
		if err := verifyProjectionLifecycleResult(replay.Result); err != nil ||
			replay.IdempotencyKey == "" || replay.IdempotencyKey != replay.Result.IdempotencyKey ||
			replay.RequestHash != replay.Result.CanonicalRequestHash ||
			replay.Result.SchemaVersion != ProjectionLifecycleResultSchemaV1 ||
			replay.Result.TenantID != state.TenantID || replay.Result.WorkspaceID != state.WorkspaceID ||
			replay.Result.SkillID != state.SkillID || replay.Result.AgentTarget != state.AgentTarget ||
			replay.Result.RelativePath != state.RelativePath {
			return fmt.Errorf("%w: replay result is invalid", ErrProjectionDrift)
		}
		if _, ok := seenReplayKeys[replay.IdempotencyKey]; ok {
			return fmt.Errorf("%w: duplicate replay idempotency key", ErrProjectionDrift)
		}
		seenReplayKeys[replay.IdempotencyKey] = struct{}{}
		attempt := state.Attempts[i]
		if !validProjectionTrustToken(attempt.AttemptID, 512) || !validProjectionTrustToken(attempt.IdempotencyKey, 512) ||
			!validProjectionSHA256(attempt.RequestHash) || attempt.AttemptID != replay.Result.AttemptID ||
			attempt.IdempotencyKey != replay.IdempotencyKey || attempt.RequestHash != replay.RequestHash {
			return fmt.Errorf("%w: replay attempt binding is invalid", ErrProjectionDrift)
		}
		if _, ok := seenAttemptIDs[attempt.AttemptID]; ok {
			return fmt.Errorf("%w: duplicate replay attempt", ErrProjectionDrift)
		}
		seenAttemptIDs[attempt.AttemptID] = struct{}{}
	}
	return nil
}

func validateProjectionGeneration(record projectionGeneration) error {
	if record.Generation == 0 || record.Generation > 9007199254740991 || record.SkillVersion == "" ||
		!validProjectionSHA256(record.ArtifactHash) || !validProjectionSHA256(record.ContentHash) ||
		!validProjectionSHA256(record.ManifestHash) || !validProjectionSHA256(record.PolicyHash) ||
		record.SchemaHash != contracts.SkillProjectionArtifactSchemaHashV1 ||
		record.SandboxProfile != contracts.SkillProjectionSandboxProfileV1 || len(record.CertificationRefs) == 0 ||
		len(record.CertificationRefs) > 16 || !validProjectionTrustToken(record.SkillVersion, 128) ||
		!validProjectionSHA256(record.TrustVerificationRef) || !validProjectionSHA256(record.TrustDecisionHash) ||
		!validProjectionSHA256(record.TrustCanonicalHash) || !validProjectionSHA256(record.TrustBindingHash) ||
		!validProjectionTrustIdentity(record.TrustVerifierID) || !validProjectionTrustIdentity(record.TrustKeyID) ||
		!validProjectionTrustSignature(record.TrustDecisionSignature) {
		return fmt.Errorf("%w: projection generation binding is invalid", ErrProjectionDrift)
	}
	for i, ref := range record.CertificationRefs {
		if !validProjectionTrustToken(ref, 512) || (i > 0 && record.CertificationRefs[i-1] >= ref) {
			return fmt.Errorf("%w: projection certification refs are invalid", ErrProjectionDrift)
		}
	}
	expectedArtifactHash, err := contracts.ComputeSkillProjectionArtifactHash(record.ManifestHash, record.ContentHash)
	if err != nil || expectedArtifactHash != record.ArtifactHash {
		return fmt.Errorf("%w: projection artifact binding is invalid", ErrProjectionDrift)
	}
	if record.TrustAction != contracts.SkillProjectionActionInstall && record.TrustAction != contracts.SkillProjectionActionRollback {
		return fmt.Errorf("%w: projection generation trust effect mismatch", ErrProjectionDrift)
	}
	return nil
}

func validProjectionSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	digest := strings.TrimPrefix(value, "sha256:")
	if strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32
}

func validProjectionAction(action string) bool {
	switch action {
	case contracts.SkillProjectionActionInstall, contracts.SkillProjectionActionReadback,
		contracts.SkillProjectionActionRevoke, contracts.SkillProjectionActionRollback:
		return true
	default:
		return false
	}
}

func projectionEffectMatchesGeneration(effect contracts.SkillProjectionEffect, record projectionGeneration) bool {
	return effect.SkillVersion == record.SkillVersion && effect.ArtifactHash == record.ArtifactHash &&
		effect.ContentHash == record.ContentHash && effect.ManifestHash == record.ManifestHash &&
		effect.PolicyHash == record.PolicyHash && effect.SchemaHash == record.SchemaHash &&
		effect.SandboxProfile == record.SandboxProfile && equalStrings(effect.CertificationRefs, record.CertificationRefs)
}

func currentProjectionGeneration(state *projectionLifecycleState) (uint64, projectionGeneration) {
	if state == nil {
		return 0, projectionGeneration{}
	}
	record, _ := findProjectionGeneration(state.Generations, state.ArchiveGeneration)
	return state.Generation, record
}

func findProjectionGeneration(generations []projectionGeneration, generation uint64) (projectionGeneration, bool) {
	for i := range generations {
		if generations[i].Generation == generation {
			return generations[i], true
		}
	}
	return projectionGeneration{}, false
}

func findProjectionReplay(replays []projectionReplay, key string) (projectionReplay, bool) {
	for i := range replays {
		if replays[i].IdempotencyKey == key {
			return replays[i], true
		}
	}
	return projectionReplay{}, false
}

func findProjectionAttempt(attempts []projectionAttempt, id string) (projectionAttempt, bool) {
	for i := range attempts {
		if attempts[i].AttemptID == id {
			return attempts[i], true
		}
	}
	return projectionAttempt{}, false
}

func appendProjectionReplay(state *projectionLifecycleState, effect contracts.SkillProjectionEffect, result ProjectionLifecycleResult) {
	if len(state.Replays) >= maxProjectionReplayEntries {
		start := len(state.Replays) - maxProjectionReplayEntries + 1
		state.Replays = append([]projectionReplay(nil), state.Replays[start:]...)
	}
	if len(state.Attempts) >= maxProjectionReplayEntries {
		start := len(state.Attempts) - maxProjectionReplayEntries + 1
		state.Attempts = append([]projectionAttempt(nil), state.Attempts[start:]...)
	}
	state.Replays = append(state.Replays, projectionReplay{IdempotencyKey: effect.IdempotencyKey, RequestHash: effect.CanonicalRequestHash, Result: result})
	state.Attempts = append(state.Attempts, projectionAttempt{AttemptID: effect.AttemptID, IdempotencyKey: effect.IdempotencyKey, RequestHash: effect.CanonicalRequestHash})
}

func appendProjectionGeneration(state *projectionLifecycleState, record projectionGeneration) {
	if len(state.Generations) >= maxProjectionGenerationEntries {
		start := len(state.Generations) - maxProjectionGenerationEntries + 1
		state.Generations = append([]projectionGeneration(nil), state.Generations[start:]...)
	}
	state.Generations = append(state.Generations, record)
}

func validateProjectionStateTransition(
	previous *projectionLifecycleState,
	next projectionLifecycleState,
	effect contracts.SkillProjectionEffect,
	relativePath string,
	result ProjectionLifecycleResult,
) error {
	expected := newProjectionState(effect, relativePath, previous)
	switch effect.Action {
	case contracts.SkillProjectionActionInstall:
		expectedGeneration := uint64(1)
		if previous != nil {
			expectedGeneration = previous.Generation + 1
		}
		if effect.Generation != expectedGeneration {
			return fmt.Errorf("%w: install recovery generation transition is invalid", ErrProjectionDrift)
		}
		record, ok := findProjectionGeneration(next.Generations, effect.Generation)
		if !ok || !projectionEffectMatchesGeneration(effect, record) || record.TrustAction != effect.Action {
			return fmt.Errorf("%w: install recovery generation is invalid", ErrProjectionDrift)
		}
		expected.Status = projectionStatusActive
		expected.Generation = effect.Generation
		expected.ArchiveGeneration = effect.Generation
		appendProjectionGeneration(&expected, record)
	case contracts.SkillProjectionActionReadback:
		if previous == nil || effect.Generation != previous.Generation {
			return fmt.Errorf("%w: readback recovery generation transition is invalid", ErrProjectionDrift)
		}
		record, ok := findProjectionGeneration(previous.Generations, previous.ArchiveGeneration)
		if !ok || !projectionEffectMatchesGeneration(effect, record) {
			return fmt.Errorf("%w: readback recovery artifact transition is invalid", ErrProjectionDrift)
		}
	case contracts.SkillProjectionActionRevoke:
		if previous == nil || previous.Status != projectionStatusActive || effect.Generation != previous.Generation+1 {
			return fmt.Errorf("%w: revoke recovery generation transition is invalid", ErrProjectionDrift)
		}
		record, ok := findProjectionGeneration(previous.Generations, previous.ArchiveGeneration)
		if !ok || !projectionEffectMatchesGeneration(effect, record) ||
			!projectionResultMatchesGenerationTrust(result, record) {
			return fmt.Errorf("%w: revoke recovery artifact transition is invalid", ErrProjectionDrift)
		}
		expected.Status = projectionStatusRevoked
		expected.Generation = effect.Generation
	case contracts.SkillProjectionActionRollback:
		if previous == nil || effect.Generation != previous.Generation+1 {
			return fmt.Errorf("%w: rollback recovery generation transition is invalid", ErrProjectionDrift)
		}
		target, ok := findProjectionGeneration(previous.Generations, result.RestoredFromGeneration)
		if !ok || !projectionEffectMatchesGeneration(effect, target) {
			return fmt.Errorf("%w: rollback recovery target transition is invalid", ErrProjectionDrift)
		}
		restored, ok := findProjectionGeneration(next.Generations, effect.Generation)
		if !ok || !projectionEffectMatchesGeneration(effect, restored) || restored.TrustAction != effect.Action {
			return fmt.Errorf("%w: rollback recovery generation is invalid", ErrProjectionDrift)
		}
		expected.Status = projectionStatusActive
		expected.Generation = effect.Generation
		expected.ArchiveGeneration = effect.Generation
		appendProjectionGeneration(&expected, restored)
	default:
		return fmt.Errorf("%w: recovery action transition is invalid", ErrProjectionDrift)
	}
	appendProjectionReplay(&expected, effect, result)
	expected.StateVerifierID = next.StateVerifierID
	expected.StateKeyID = next.StateKeyID
	expectedHash, err := hashProjectionLifecycleState(expected)
	if err != nil || !constantStringEqual(expectedHash, next.StateHash) {
		return fmt.Errorf("%w: recovery journal is not a legal one-step state transition", ErrProjectionDrift)
	}
	return nil
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

func decodeStrictProjectionJSON(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validateManagedRelative(rel string) error {
	if rel == "" || filepath.IsAbs(rel) {
		return ErrProjectionPathUnsafe
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return ErrProjectionPathUnsafe
	}
	return nil
}

func readManagedFileAt(root *os.Root, rel string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, ErrProjectionPathUnsafe
	}
	if err := validateManagedPathAt(root, rel, false); err != nil {
		return nil, err
	}
	lstat, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, ErrProjectionPathUnsafe
	}
	file, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	fstat, err := file.Stat()
	if err != nil || !os.SameFile(lstat, fstat) || !fstat.Mode().IsRegular() {
		return nil, ErrProjectionPathUnsafe
	}
	if fstat.Size() < 0 || fstat.Size() > maxBytes {
		return nil, ErrProjectionFileTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrProjectionFileTooLarge
	}
	return data, nil
}

func atomicReplaceManagedAt(root *os.Root, rel string, data []byte) error {
	if err := validateManagedRelative(rel); err != nil {
		return err
	}
	dirRel := filepath.Dir(rel)
	if err := ensureManagedDirAt(root, dirRel); err != nil {
		return err
	}
	if info, statErr := root.Lstat(rel); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrProjectionPathUnsafe
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	tmpName, err := projectionRandomName(".projection-write-")
	if err != nil {
		return err
	}
	tmpRel := filepath.Join(dirRel, tmpName)
	tmp, err := root.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmpRel) }()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmpRel, rel); err != nil {
		return fmt.Errorf("skillpacks: atomic projection replace: %w", err)
	}
	if err := syncManagedDirectoryAt(root, dirRel); err != nil {
		return fmt.Errorf("skillpacks: sync projection parent after replace: %w", err)
	}
	if err := validateManagedPathAt(root, rel, false); err != nil {
		return err
	}
	return nil
}

func openManagedRoot(path string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("skillpacks: open managed projection root: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() {
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrProjectionPathUnsafe
	}
	return root, nil
}

func validateManagedPathAt(root *os.Root, rel string, allowMissing bool) error {
	if root == nil {
		return ErrProjectionPathUnsafe
	}
	if err := validateManagedRelative(rel); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.Clean(rel), string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrProjectionPathUnsafe
		}
	}
	return nil
}

func ensureManagedDirAt(root *os.Root, rel string) error {
	if rel == "." {
		return nil
	}
	if err := validateManagedRelative(rel); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.Clean(rel), string(os.PathSeparator)) {
		parent := current
		if parent == "" {
			parent = "."
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		created := false
		if errors.Is(err, os.ErrNotExist) {
			mkdirErr := root.Mkdir(current, 0o755)
			if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			created = mkdirErr == nil
			info, err = root.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrProjectionPathUnsafe
		}
		if created {
			if err := syncManagedDirectoryAt(root, parent); err != nil {
				return fmt.Errorf("skillpacks: sync managed directory parent: %w", err)
			}
		}
	}
	return nil
}

func syncManagedDirectoryAt(root *os.Root, rel string) error {
	dir, err := root.Open(rel)
	if err != nil {
		return err
	}
	info, statErr := dir.Stat()
	if statErr != nil || !info.IsDir() {
		_ = dir.Close()
		if statErr != nil {
			return statErr
		}
		return ErrProjectionPathUnsafe
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func removeManagedFileAt(root *os.Root, rel string) error {
	if root == nil {
		return ErrProjectionPathUnsafe
	}
	if err := validateManagedPathAt(root, rel, false); err != nil {
		return err
	}
	info, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrProjectionPathUnsafe
	}
	if err := root.Remove(rel); err != nil {
		return fmt.Errorf("skillpacks: remove managed projection file: %w", err)
	}
	return syncManagedDirectoryAt(root, filepath.Dir(rel))
}

func projectionRandomName(prefix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random[:]), nil
}

func writeExclusiveManagedFileAt(root *os.Root, rel string, data []byte) error {
	file, err := root.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func cleanupManagedStage(root *os.Root, rel string) {
	_ = root.Remove(filepath.Join(rel, "skillpack.json"))
	_ = root.Remove(filepath.Join(rel, "SKILL.md"))
	_ = root.Remove(rel)
}

func constantStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func constantBytesEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
