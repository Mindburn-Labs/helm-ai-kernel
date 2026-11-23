package skillpacks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

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
