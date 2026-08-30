package skillpacks

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	ProjectionLifecycleResultSchemaV1 = "helm.skill-projection-result.v1"
	ProjectionTrustRequestSchemaV1    = "helm.skill-projection-trust-request.v1"
	ProjectionTrustDecisionSchemaV1   = "helm.skill-projection-trust-decision.v1"
	projectionLifecycleStateSchemaV1  = "helm.skill-projection-state.v1"
	projectionLifecycleLockRel        = ".helm/skillpacks/projection-lifecycle.lock"

	projectionStatusActive  = "active"
	projectionStatusRevoked = "revoked"

	maxProjectionArtifactBytes = 1 << 20
	// Lifecycle state contains append-only generation, replay, and attempt
	// metadata. Each V1 mutation can retain 16 bounded certification refs plus
	// an exact replay result and attempt binding; 16 MiB gives that metadata a
	// distinct operational envelope while keeping reads and writes bounded.
	maxProjectionLifecycleStateBytes = 16 << 20
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

	Publisher         string   `json:"publisher"`
	ManifestStatus    string   `json:"manifest_status"`
	PolicyRef         string   `json:"policy_ref"`
	CertificationRefs []string `json:"certification_refs"`

	VerifiedAt      time.Time `json:"verified_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	VerificationRef string    `json:"verification_ref"`
	DecisionHash    string    `json:"decision_hash,omitempty"`
}

// ProjectionTrustVerifier is mandatory for every lifecycle instance. A
// concrete verifier may live in the runner, but the lifecycle cannot project,
// read back, revoke, roll back, or replay without a current exact-hash decision.
type ProjectionTrustVerifier interface {
	VerifyProjectionTrust(ProjectionTrustRequest) (ProjectionTrustDecision, error)
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

	CanonicalRequestHash string `json:"canonical_request_hash"`
	IdempotencyKey       string `json:"idempotency_key"`
	AttemptID            string `json:"attempt_id"`
	ConsumedPermitRef    string `json:"consumed_permit_ref"`
	RollbackPermitRef    string `json:"rollback_permit_ref,omitempty"`
	TrustVerificationRef string `json:"trust_verification_ref"`
	TrustDecisionHash    string `json:"trust_decision_hash"`

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
	root     string
	verifier ProjectionTrustVerifier
	clock    func() time.Time
	mu       sync.Mutex
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

	Generations []projectionGeneration `json:"generations"`
	Replays     []projectionReplay     `json:"replays"`
	Attempts    []projectionAttempt    `json:"attempts"`
	StateHash   string                 `json:"state_hash,omitempty"`
}

type projectionGeneration struct {
	Generation           uint64   `json:"generation"`
	SkillVersion         string   `json:"skill_version"`
	ArtifactHash         string   `json:"artifact_hash"`
	ContentHash          string   `json:"content_hash"`
	ManifestHash         string   `json:"manifest_hash"`
	PolicyHash           string   `json:"policy_hash"`
	SchemaHash           string   `json:"schema_hash"`
	CertificationRefs    []string `json:"certification_refs"`
	SandboxProfile       string   `json:"sandbox_profile"`
	TrustVerificationRef string   `json:"trust_verification_ref"`
	TrustDecisionHash    string   `json:"trust_decision_hash"`
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

func NewProjectionLifecycle(root string, verifier ProjectionTrustVerifier) (*ProjectionLifecycle, error) {
	if verifier == nil {
		return nil, fmt.Errorf("%w: configured verifier is required", ErrProjectionTrustRejected)
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
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("skillpacks: projection root is not a directory")
	}
	return &ProjectionLifecycle{root: resolved, verifier: verifier, clock: func() time.Time { return time.Now().UTC() }}, nil
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
	now := l.clock().UTC()
	if err := validateProjectionAuthority(effect, consumedPermitRef, rollbackPermit, now); err != nil {
		return ProjectionLifecycleResult{}, err
	}

	var installGeneration projectionGeneration
	var manifestBytes, contentBytes []byte
	var err error
	if effect.Action == contracts.SkillProjectionActionInstall {
		installGeneration, manifestBytes, contentBytes, err = validateProjectionArtifact(effect, artifact)
		if err != nil {
			return ProjectionLifecycleResult{}, err
		}
	} else if artifact != nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: artifact is only valid for install")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
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
	now = l.clock().UTC()
	if err := validateProjectionAuthority(effect, consumedPermitRef, rollbackPermit, now); err != nil {
		return ProjectionLifecycleResult{}, err
	}

	projection, err := projectionRelativePath(effect.SkillID, effect.AgentTarget)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	relativePath := filepath.ToSlash(projection.Path)
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
			if err := l.verifyReplayTrust(effect, *state, now); err != nil {
				return ProjectionLifecycleResult{}, err
			}
			return replay.Result, nil
		}
		if attempt, ok := findProjectionAttempt(state.Attempts, effect.AttemptID); ok &&
			(attempt.IdempotencyKey != effect.IdempotencyKey || attempt.RequestHash != effect.CanonicalRequestHash) {
			return ProjectionLifecycleResult{}, ErrProjectionReplayConflict
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
		return l.applyInstall(effect, state, relativePath, installGeneration, manifestBytes, contentBytes, now)
	case contracts.SkillProjectionActionReadback:
		return l.applyReadback(effect, state, relativePath, now)
	case contracts.SkillProjectionActionRevoke:
		return l.applyRevoke(effect, state, relativePath, now)
	case contracts.SkillProjectionActionRollback:
		return l.applyRollback(effect, state, relativePath, *rollbackPermit, now)
	default:
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: unsupported projection action")
	}
}

func validateProjectionAuthority(
	effect contracts.SkillProjectionEffect,
	consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	now time.Time,
) error {
	if err := effect.ValidateAt(now); err != nil {
		return err
	}
	if !constantStringEqual(effect.ConsumedPermitRef, consumedPermitRef) {
		return fmt.Errorf("skillpacks: consumed permit reference mismatch")
	}
	if effect.Action == contracts.SkillProjectionActionRollback {
		if rollbackPermit == nil {
			return fmt.Errorf("skillpacks: rollback permit is required")
		}
		return effect.ValidateRollbackPermit(*rollbackPermit, now)
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
	now time.Time,
) (ProjectionLifecycleResult, error) {
	if current != nil {
		for _, retained := range current.Generations {
			if constantStringEqual(retained.ArtifactHash, generation.ArtifactHash) {
				return ProjectionLifecycleResult{}, ErrProjectionRollbackRequired
			}
		}
	}
	trust, err := l.verifyProjectionTrust(effect, generation, manifestBytes, contentBytes, now)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	generation.TrustVerificationRef = trust.VerificationRef
	generation.TrustDecisionHash = trust.DecisionHash
	if err := l.persistGeneration(effect, generation, manifestBytes, contentBytes); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if err := l.replaceProjection(effect, relativePath, contentBytes); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if err := l.verifyLiveContent(effect, relativePath, generation.ContentHash); err != nil {
		_ = l.restoreProjection(effect, relativePath, current)
		return ProjectionLifecycleResult{}, err
	}

	next := newProjectionState(effect, relativePath, current)
	previousGeneration, previous := currentProjectionGeneration(current)
	next.Status = projectionStatusActive
	next.Generation = effect.Generation
	next.ArchiveGeneration = effect.Generation
	next.Generations = append(next.Generations, generation)
	status := "installed"
	if current != nil && current.Status == projectionStatusActive {
		status = "upgraded"
	}
	result := newProjectionResult(effect, relativePath, status, previousGeneration, previous, generation)
	result.ObservedArtifactHash = generation.ArtifactHash
	result.ObservedContentHash = generation.ContentHash
	result.ObservedManifestHash = generation.ManifestHash
	bindProjectionResultTrust(&result, trust)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		_ = l.restoreProjection(effect, relativePath, current)
		return ProjectionLifecycleResult{}, err
	}
	appendProjectionReplay(&next, effect, sealed)
	if err := l.writeState(effect, next); err != nil {
		if restoreErr := l.restoreProjection(effect, relativePath, current); restoreErr != nil {
			return ProjectionLifecycleResult{}, fmt.Errorf("%v; restore projection: %w", err, restoreErr)
		}
		return ProjectionLifecycleResult{}, err
	}
	return sealed, nil
}

func (l *ProjectionLifecycle) applyReadback(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
	now time.Time,
) (ProjectionLifecycleResult, error) {
	record, ok := findProjectionGeneration(current.Generations, current.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: readback binding mismatch")
	}
	manifestBytes, contentBytes, err := l.readGeneration(effect, record)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	trust, err := l.verifyProjectionTrust(effect, record, manifestBytes, contentBytes, now)
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
	bindProjectionResultTrust(&result, trust)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	next := cloneProjectionState(*current)
	appendProjectionReplay(&next, effect, sealed)
	if err := l.writeState(effect, next); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	return sealed, nil
}

func (l *ProjectionLifecycle) applyRevoke(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
	now time.Time,
) (ProjectionLifecycleResult, error) {
	if current == nil || current.Status != projectionStatusActive {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: only an active projection can be revoked")
	}
	record, ok := findProjectionGeneration(current.Generations, current.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: revoke binding mismatch")
	}
	manifestBytes, contentBytes, err := l.readGeneration(effect, record)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	trust, err := l.verifyProjectionTrust(effect, record, manifestBytes, contentBytes, now)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if err := l.removeProjection(effect, relativePath); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	next := cloneProjectionState(*current)
	next.Status = projectionStatusRevoked
	next.Generation = effect.Generation
	result := newProjectionResult(effect, relativePath, projectionStatusRevoked, current.Generation, record, projectionGeneration{})
	bindProjectionResultTrust(&result, trust)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		_ = l.replaceProjection(effect, relativePath, contentBytes)
		return ProjectionLifecycleResult{}, err
	}
	appendProjectionReplay(&next, effect, sealed)
	if err := l.writeState(effect, next); err != nil {
		if restoreErr := l.replaceProjection(effect, relativePath, contentBytes); restoreErr != nil {
			return ProjectionLifecycleResult{}, fmt.Errorf("%v; restore projection: %w", err, restoreErr)
		}
		return ProjectionLifecycleResult{}, err
	}
	return sealed, nil
}

func (l *ProjectionLifecycle) applyRollback(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
	permit contracts.SkillProjectionRollbackPermit,
	now time.Time,
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
	trust, err := l.verifyProjectionTrust(effect, target, manifestBytes, contentBytes, now)
	if err != nil {
		return ProjectionLifecycleResult{}, err
	}
	restored := target
	restored.Generation = effect.Generation
	restored.TrustVerificationRef = trust.VerificationRef
	restored.TrustDecisionHash = trust.DecisionHash
	if err := l.persistGeneration(effect, restored, manifestBytes, contentBytes); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if err := l.replaceProjection(effect, relativePath, contentBytes); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if err := l.verifyLiveContent(effect, relativePath, target.ContentHash); err != nil {
		_ = l.restoreProjection(effect, relativePath, current)
		return ProjectionLifecycleResult{}, err
	}
	previousGeneration, previous := currentProjectionGeneration(current)
	next := cloneProjectionState(*current)
	next.Status = projectionStatusActive
	next.Generation = effect.Generation
	next.ArchiveGeneration = effect.Generation
	next.Generations = append(next.Generations, restored)
	result := newProjectionResult(effect, relativePath, "rolled_back", previousGeneration, previous, restored)
	result.RestoredFromGeneration = permit.TargetGeneration
	result.RollbackPermitRef = permit.PermitRef
	result.ObservedArtifactHash = restored.ArtifactHash
	result.ObservedContentHash = restored.ContentHash
	result.ObservedManifestHash = restored.ManifestHash
	bindProjectionResultTrust(&result, trust)
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil {
		_ = l.restoreProjection(effect, relativePath, current)
		return ProjectionLifecycleResult{}, err
	}
	appendProjectionReplay(&next, effect, sealed)
	if err := l.writeState(effect, next); err != nil {
		if restoreErr := l.restoreProjection(effect, relativePath, current); restoreErr != nil {
			return ProjectionLifecycleResult{}, fmt.Errorf("%v; restore projection: %w", err, restoreErr)
		}
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
	now time.Time,
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

	request := ProjectionTrustRequest{
		SchemaVersion:  ProjectionTrustRequestSchemaV1,
		Effect:         cloneProjectionEffect(effect),
		Manifest:       cloneProjectionManifest(manifest),
		ManifestBytes:  append([]byte(nil), manifestBytes...),
		ContentBytes:   append([]byte(nil), contentBytes...),
		EvaluationTime: now,
	}
	decision, err := l.verifier.VerifyProjectionTrust(request)
	if err != nil {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: %v", ErrProjectionTrustRejected, err)
	}
	if err := validateProjectionTrustDecision(decision, effect, manifest, now); err != nil {
		return ProjectionTrustDecision{}, err
	}
	return decision, nil
}

func validateProjectionTrustDecision(
	decision ProjectionTrustDecision,
	effect contracts.SkillProjectionEffect,
	manifest Manifest,
	now time.Time,
) error {
	if err := verifyProjectionTrustDecisionIntegrity(decision); err != nil {
		return err
	}
	if decision.SchemaVersion != ProjectionTrustDecisionSchemaV1 || decision.Verdict != VerdictAllow ||
		decision.Action != effect.Action || decision.TenantID != effect.TenantID ||
		decision.WorkspaceID != effect.WorkspaceID || decision.SkillID != effect.SkillID ||
		decision.SkillVersion != effect.SkillVersion || decision.AgentTarget != effect.AgentTarget ||
		decision.CanonicalRequestHash != effect.CanonicalRequestHash ||
		decision.ArtifactHash != effect.ArtifactHash || decision.ContentHash != effect.ContentHash ||
		decision.ManifestHash != effect.ManifestHash || decision.PolicyHash != effect.PolicyHash ||
		decision.SchemaHash != effect.SchemaHash || decision.Publisher != manifest.Publisher ||
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

func (l *ProjectionLifecycle) verifyReplayTrust(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
	now time.Time,
) error {
	for _, record := range state.Generations {
		if !projectionEffectMatchesGeneration(effect, record) {
			continue
		}
		manifestBytes, contentBytes, err := l.readGeneration(effect, record)
		if err != nil {
			return err
		}
		_, err = l.verifyProjectionTrust(effect, record, manifestBytes, contentBytes, now)
		return err
	}
	return fmt.Errorf("%w: replay has no retained trust material", ErrProjectionDrift)
}

func bindProjectionResultTrust(result *ProjectionLifecycleResult, decision ProjectionTrustDecision) {
	result.TrustVerificationRef = decision.VerificationRef
	result.TrustDecisionHash = decision.DecisionHash
}

func (l *ProjectionLifecycle) persistGeneration(
	effect contracts.SkillProjectionEffect,
	record projectionGeneration,
	manifestBytes, contentBytes []byte,
) error {
	if err := validateProjectionGeneration(record); err != nil {
		return err
	}
	root, err := openManagedRoot(l.root)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
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
	root, err := openManagedRoot(l.root)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
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
	manifestBytes, err := readManagedFile(l.root, filepath.Join(dirRel, "skillpack.json"), maxProjectionArtifactBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read immutable generation manifest: %w", ErrProjectionDrift, err)
	}
	contentBytes, err := readManagedFile(l.root, filepath.Join(dirRel, "SKILL.md"), maxProjectionArtifactBytes)
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

func (l *ProjectionLifecycle) verifyManagedState(state projectionLifecycleState) error {
	record, ok := findProjectionGeneration(state.Generations, state.ArchiveGeneration)
	if !ok {
		return fmt.Errorf("%w: archive generation is missing", ErrProjectionDrift)
	}
	effect := contracts.SkillProjectionEffect{TenantID: state.TenantID, WorkspaceID: state.WorkspaceID, SkillID: state.SkillID, AgentTarget: state.AgentTarget}
	for _, retained := range state.Generations {
		if _, _, err := l.readGeneration(effect, retained); err != nil {
			return err
		}
	}
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(state.RelativePath))
	data, err := readManagedFile(l.root, fullRel, maxProjectionArtifactBytes)
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

func (l *ProjectionLifecycle) verifyProjectionAbsent(effect contracts.SkillProjectionEffect, relativePath string) error {
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
	_, err := readManagedFile(l.root, fullRel, maxProjectionArtifactBytes)
	if err == nil {
		return ErrUnmanagedProjection
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (l *ProjectionLifecycle) verifyLiveContent(effect contracts.SkillProjectionEffect, relativePath, expectedHash string) error {
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
	data, err := readManagedFile(l.root, fullRel, maxProjectionArtifactBytes)
	if err != nil {
		return fmt.Errorf("%w: projection readback failed: %w", ErrProjectionDrift, err)
	}
	if HashBytes(data) != expectedHash {
		return fmt.Errorf("%w: projection readback mismatch", ErrProjectionDrift)
	}
	return nil
}

func (l *ProjectionLifecycle) replaceProjection(effect contracts.SkillProjectionEffect, relativePath string, data []byte) error {
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
	return atomicReplaceManaged(l.root, fullRel, data)
}

func (l *ProjectionLifecycle) removeProjection(effect contracts.SkillProjectionEffect, relativePath string) error {
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
	return removeManagedFile(l.root, fullRel)
}

func (l *ProjectionLifecycle) restoreProjection(effect contracts.SkillProjectionEffect, relativePath string, state *projectionLifecycleState) error {
	if state == nil || state.Status == projectionStatusRevoked {
		fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
		removeErr := removeManagedFile(l.root, fullRel)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		return nil
	}
	record, ok := findProjectionGeneration(state.Generations, state.ArchiveGeneration)
	if !ok {
		return fmt.Errorf("skillpacks: restore generation missing")
	}
	_, content, err := l.readGeneration(effect, record)
	if err != nil {
		return err
	}
	return l.replaceProjection(effect, relativePath, content)
}

func (l *ProjectionLifecycle) readState(effect contracts.SkillProjectionEffect, relativePath string) (*projectionLifecycleState, error) {
	data, err := readManagedFile(l.root, l.stateRel(effect), maxProjectionLifecycleStateBytes)
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
	if err := verifyProjectionLifecycleState(state); err != nil {
		return nil, err
	}
	if err := validateProjectionStateIdentity(state, effect, relativePath); err != nil {
		return nil, err
	}
	return &state, nil
}

func (l *ProjectionLifecycle) writeState(effect contracts.SkillProjectionEffect, state projectionLifecycleState) error {
	sealed, err := sealProjectionLifecycleState(state)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxProjectionLifecycleStateBytes {
		return ErrProjectionFileTooLarge
	}
	return atomicReplaceManaged(l.root, l.stateRel(effect), data)
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

func (l *ProjectionLifecycle) generationParentRel(effect contracts.SkillProjectionEffect) string {
	return filepath.Join(l.managedBaseRel(effect), "generations")
}

func (l *ProjectionLifecycle) acquireRootLock() (func() error, error) {
	root, err := openManagedRoot(l.root)
	if err != nil {
		return nil, err
	}
	lockRel := filepath.FromSlash(projectionLifecycleLockRel)
	if err := ensureManagedDirAt(root, filepath.Dir(lockRel)); err != nil {
		_ = root.Close()
		return nil, err
	}
	lockFile, created, err := openManagedLockFileAt(root, lockRel)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if created {
		if err := syncManagedDirectoryAt(root, filepath.Dir(lockRel)); err != nil {
			_ = lockFile.Close()
			_ = root.Close()
			return nil, err
		}
	}
	releaseLock, err := lockProjectionFile(lockFile)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return func() error {
		return errors.Join(releaseLock(), root.Close())
	}, nil
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
	for i := range state.Generations {
		if err := validateProjectionGeneration(state.Generations[i]); err != nil ||
			(i > 0 && state.Generations[i-1].Generation >= state.Generations[i].Generation) {
			return fmt.Errorf("%w: projection generation history is invalid", ErrProjectionDrift)
		}
	}
	for _, replay := range state.Replays {
		if err := verifyProjectionLifecycleResult(replay.Result); err != nil ||
			replay.IdempotencyKey == "" || replay.IdempotencyKey != replay.Result.IdempotencyKey ||
			replay.RequestHash != replay.Result.CanonicalRequestHash ||
			replay.Result.SchemaVersion != ProjectionLifecycleResultSchemaV1 ||
			replay.Result.TenantID != state.TenantID || replay.Result.WorkspaceID != state.WorkspaceID ||
			replay.Result.SkillID != state.SkillID || replay.Result.AgentTarget != state.AgentTarget ||
			replay.Result.RelativePath != state.RelativePath {
			return fmt.Errorf("%w: replay result is invalid", ErrProjectionDrift)
		}
	}
	return nil
}

func validateProjectionGeneration(record projectionGeneration) error {
	if record.Generation == 0 || record.Generation > 9007199254740991 || record.SkillVersion == "" ||
		!validProjectionSHA256(record.ArtifactHash) || !validProjectionSHA256(record.ContentHash) ||
		!validProjectionSHA256(record.ManifestHash) || !validProjectionSHA256(record.PolicyHash) ||
		record.SchemaHash != contracts.SkillProjectionArtifactSchemaHashV1 ||
		record.SandboxProfile != contracts.SkillProjectionSandboxProfileV1 || len(record.CertificationRefs) == 0 ||
		!validProjectionSHA256(record.TrustVerificationRef) || !validProjectionSHA256(record.TrustDecisionHash) {
		return fmt.Errorf("%w: projection generation binding is invalid", ErrProjectionDrift)
	}
	for i, ref := range record.CertificationRefs {
		if ref == "" || (i > 0 && record.CertificationRefs[i-1] >= ref) {
			return fmt.Errorf("%w: projection certification refs are invalid", ErrProjectionDrift)
		}
	}
	expectedArtifactHash, err := contracts.ComputeSkillProjectionArtifactHash(record.ManifestHash, record.ContentHash)
	if err != nil || expectedArtifactHash != record.ArtifactHash {
		return fmt.Errorf("%w: projection artifact binding is invalid", ErrProjectionDrift)
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
	// ponytail: linear replay history is sufficient for repo-local skill counts;
	// add indexed compaction only when measured histories make lookup material.
	state.Replays = append(state.Replays, projectionReplay{IdempotencyKey: effect.IdempotencyKey, RequestHash: effect.CanonicalRequestHash, Result: result})
	state.Attempts = append(state.Attempts, projectionAttempt{AttemptID: effect.AttemptID, IdempotencyKey: effect.IdempotencyKey, RequestHash: effect.CanonicalRequestHash})
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

func ensureManagedDir(root, rel string) (string, error) {
	managed, err := openManagedRoot(root)
	if err != nil {
		return "", err
	}
	defer func() { _ = managed.Close() }()
	if err := ensureManagedDirAt(managed, rel); err != nil {
		return "", err
	}
	return filepath.Join(root, filepath.Clean(rel)), nil
}

func managedPath(root, rel string, createParent bool) (string, error) {
	if err := validateManagedRelative(rel); err != nil {
		return "", err
	}
	if createParent {
		if _, err := ensureManagedDir(root, filepath.Dir(rel)); err != nil {
			return "", err
		}
	}
	candidate := filepath.Join(root, filepath.Clean(rel))
	relToRoot, err := filepath.Rel(root, candidate)
	if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(os.PathSeparator)) {
		return "", ErrProjectionPathUnsafe
	}
	current := root
	for _, part := range strings.Split(filepath.Clean(rel), string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", ErrProjectionPathUnsafe
		}
	}
	return candidate, nil
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

func readManagedFile(root, rel string, maxBytes int64) ([]byte, error) {
	managed, err := openManagedRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = managed.Close() }()
	return readManagedFileAt(managed, rel, maxBytes)
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

func atomicReplaceManaged(root, rel string, data []byte) error {
	managed, err := openManagedRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = managed.Close() }()
	return atomicReplaceManagedAt(managed, rel, data)
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

func removeManagedFile(rootPath, rel string) error {
	root, err := openManagedRoot(rootPath)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
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

func openManagedLockFileAt(root *os.Root, rel string) (*os.File, bool, error) {
	file, err := root.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		return file, true, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, false, err
	}
	lstat, err := root.Lstat(rel)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, false, ErrProjectionPathUnsafe
	}
	file, err = root.OpenFile(rel, os.O_RDWR, 0)
	if err != nil {
		return nil, false, err
	}
	fstat, err := file.Stat()
	if err != nil || !os.SameFile(lstat, fstat) || fstat.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, false, ErrProjectionPathUnsafe
	}
	return file, false, nil
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

func syncProjectionDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- path is derived from the validated projection root
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

func writeExclusiveFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
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
