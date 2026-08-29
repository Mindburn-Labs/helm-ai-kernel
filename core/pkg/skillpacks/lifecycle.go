package skillpacks

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	projectionLifecycleStateSchemaV1  = "helm.skill-projection-state.v1"
	projectionLifecycleLockRel        = ".helm/skillpacks/projection-lifecycle.lock"

	projectionStatusActive  = "active"
	projectionStatusRevoked = "revoked"

	maxProjectionArtifactBytes = 1 << 20
)

var (
	ErrProjectionDrift           = errors.New("skillpacks: managed projection drift")
	ErrUnmanagedProjection       = errors.New("skillpacks: unmanaged projection exists")
	ErrProjectionReplayConflict  = errors.New("skillpacks: projection replay conflict")
	ErrProjectionPathUnsafe      = errors.New("skillpacks: unsafe managed path")
	ErrProjectionLockContended   = errors.New("skillpacks: projection root lock contended")
	ErrProjectionLockUnsupported = errors.New("skillpacks: projection root lock unsupported")
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

	CanonicalRequestHash string `json:"canonical_request_hash"`
	IdempotencyKey       string `json:"idempotency_key"`
	AttemptID            string `json:"attempt_id"`
	ConsumedPermitRef    string `json:"consumed_permit_ref"`
	RollbackPermitRef    string `json:"rollback_permit_ref,omitempty"`

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
	root  string
	clock func() time.Time
	mu    sync.Mutex
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
	Generation        uint64   `json:"generation"`
	SkillVersion      string   `json:"skill_version"`
	ArtifactHash      string   `json:"artifact_hash"`
	ContentHash       string   `json:"content_hash"`
	ManifestHash      string   `json:"manifest_hash"`
	PolicyHash        string   `json:"policy_hash"`
	SchemaHash        string   `json:"schema_hash"`
	CertificationRefs []string `json:"certification_refs"`
	SandboxProfile    string   `json:"sandbox_profile"`
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

func NewProjectionLifecycle(root string) (*ProjectionLifecycle, error) {
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
	return &ProjectionLifecycle{root: resolved, clock: func() time.Time { return time.Now().UTC() }}, nil
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
	if err := effect.ValidateAt(now); err != nil {
		return ProjectionLifecycleResult{}, err
	}
	if !constantStringEqual(effect.ConsumedPermitRef, consumedPermitRef) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: consumed permit reference mismatch")
	}
	if effect.Action == contracts.SkillProjectionActionRollback {
		if rollbackPermit == nil {
			return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: rollback permit is required")
		}
		if err := effect.ValidateRollbackPermit(*rollbackPermit, now); err != nil {
			return ProjectionLifecycleResult{}, err
		}
	} else if rollbackPermit != nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: rollback permit is only valid for rollback")
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

func (l *ProjectionLifecycle) applyInstall(
	effect contracts.SkillProjectionEffect,
	current *projectionLifecycleState,
	relativePath string,
	generation projectionGeneration,
	manifestBytes, contentBytes []byte,
) (ProjectionLifecycleResult, error) {
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
) (ProjectionLifecycleResult, error) {
	record, ok := findProjectionGeneration(current.Generations, current.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: readback binding mismatch")
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
) (ProjectionLifecycleResult, error) {
	if current == nil || current.Status != projectionStatusActive {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: only an active projection can be revoked")
	}
	record, ok := findProjectionGeneration(current.Generations, current.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: revoke binding mismatch")
	}
	_, contentBytes, err := l.readGeneration(effect, record)
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
	restored := target
	restored.Generation = effect.Generation
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

func (l *ProjectionLifecycle) persistGeneration(
	effect contracts.SkillProjectionEffect,
	record projectionGeneration,
	manifestBytes, contentBytes []byte,
) error {
	if err := validateProjectionGeneration(record); err != nil {
		return err
	}
	parentRel := l.generationParentRel(effect)
	parent, err := ensureManagedDir(l.root, parentRel)
	if err != nil {
		return err
	}
	finalRel := filepath.Join(parentRel, projectionGenerationDirName(record))
	final, err := managedPath(l.root, finalRel, false)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(final); statErr == nil {
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

	stage, err := os.MkdirTemp(parent, ".projection-stage-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := writeExclusiveFile(filepath.Join(stage, "skillpack.json"), manifestBytes); err != nil {
		return err
	}
	if err := writeExclusiveFile(filepath.Join(stage, "SKILL.md"), contentBytes); err != nil {
		return err
	}
	if err := syncProjectionDirectory(stage); err != nil {
		return fmt.Errorf("skillpacks: sync staged immutable generation: %w", err)
	}
	if err := os.Rename(stage, final); err != nil {
		if _, statErr := os.Stat(final); statErr == nil {
			storedManifest, storedContent, readErr := l.readGeneration(effect, record)
			if readErr == nil && constantBytesEqual(storedManifest, manifestBytes) && constantBytesEqual(storedContent, contentBytes) {
				return nil
			}
		}
		return fmt.Errorf("skillpacks: commit immutable generation: %w", err)
	}
	if err := syncProjectionDirectory(parent); err != nil {
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
	dir, err := managedPath(l.root, dirRel, false)
	if err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read immutable generation: %v", ErrProjectionDrift, err)
	}
	if len(entries) != 2 || entries[0].Name() != "SKILL.md" || entries[1].Name() != "skillpack.json" {
		return nil, nil, fmt.Errorf("%w: immutable generation has unexpected files", ErrProjectionDrift)
	}
	manifestBytes, err := readManagedFile(l.root, filepath.Join(dirRel, "skillpack.json"))
	if err != nil {
		return nil, nil, err
	}
	contentBytes, err := readManagedFile(l.root, filepath.Join(dirRel, "SKILL.md"))
	if err != nil {
		return nil, nil, err
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
	data, err := readManagedFile(l.root, fullRel)
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
		return fmt.Errorf("%w: live projection missing: %v", ErrProjectionDrift, err)
	}
	if HashBytes(data) != record.ContentHash {
		return fmt.Errorf("%w: live content hash mismatch", ErrProjectionDrift)
	}
	return nil
}

func (l *ProjectionLifecycle) verifyProjectionAbsent(effect contracts.SkillProjectionEffect, relativePath string) error {
	fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
	_, err := readManagedFile(l.root, fullRel)
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
	data, err := readManagedFile(l.root, fullRel)
	if err != nil || HashBytes(data) != expectedHash {
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
	path, err := managedPath(l.root, fullRel, false)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrProjectionPathUnsafe
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("skillpacks: revoke projection: %w", err)
	}
	if err := syncProjectionDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("skillpacks: sync projection parent after revoke: %w", err)
	}
	return nil
}

func (l *ProjectionLifecycle) restoreProjection(effect contracts.SkillProjectionEffect, relativePath string, state *projectionLifecycleState) error {
	if state == nil || state.Status == projectionStatusRevoked {
		fullRel := filepath.Join(l.workspaceRel(effect), filepath.FromSlash(relativePath))
		path, err := managedPath(l.root, fullRel, false)
		if err != nil {
			return err
		}
		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		if removeErr == nil {
			if err := syncProjectionDirectory(filepath.Dir(path)); err != nil {
				return err
			}
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
	data, err := readManagedFile(l.root, l.stateRel(effect))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
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
	lockPath, err := managedPath(l.root, filepath.FromSlash(projectionLifecycleLockRel), true)
	if err != nil {
		return nil, err
	}
	return lockProjectionFile(lockPath)
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
		record.SandboxProfile != contracts.SkillProjectionSandboxProfileV1 || len(record.CertificationRefs) == 0 {
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
	if err := validateManagedRelative(rel); err != nil {
		return "", err
	}
	current := root
	for _, part := range strings.Split(filepath.Clean(rel), string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		created := false
		if errors.Is(err, os.ErrNotExist) {
			mkdirErr := os.Mkdir(current, 0o755)
			if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return "", mkdirErr
			}
			created = mkdirErr == nil
			info, err = os.Lstat(current)
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", ErrProjectionPathUnsafe
		}
		if created {
			if err := syncProjectionDirectory(filepath.Dir(current)); err != nil {
				return "", fmt.Errorf("skillpacks: sync managed directory parent: %w", err)
			}
		}
	}
	return current, nil
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

func readManagedFile(root, rel string) ([]byte, error) {
	path, err := managedPath(root, rel, false)
	if err != nil {
		return nil, err
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, ErrProjectionPathUnsafe
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	fstat, err := file.Stat()
	if err != nil || !os.SameFile(lstat, fstat) || !fstat.Mode().IsRegular() {
		return nil, ErrProjectionPathUnsafe
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func atomicReplaceManaged(root, rel string, data []byte) error {
	path, err := managedPath(root, rel, true)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrProjectionPathUnsafe
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".projection-write-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
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
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("skillpacks: atomic projection replace: %w", err)
	}
	if err := syncProjectionDirectory(dir); err != nil {
		return fmt.Errorf("skillpacks: sync projection parent after replace: %w", err)
	}
	return nil
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
