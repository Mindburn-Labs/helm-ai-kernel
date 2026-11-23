package skillpacks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

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
	journal, err := l.readProjectionRecoveryJournalRecord(effect)
	if err != nil || journal == nil {
		return nil, nil, err
	}
	next, err := l.validateProjectionRecoveryJournal(*journal, effect, relativePath)
	if err != nil {
		return nil, nil, err
	}
	return journal, &next, nil
}

func (l *ProjectionLifecycle) readProjectionRecoveryJournalRecord(
	effect contracts.SkillProjectionEffect,
) (*projectionRecoveryJournal, error) {
	data, err := readManagedFileAt(l.managed, l.journalRel(effect), maxProjectionRecoveryJournalBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read recovery journal: %w", ErrProjectionDrift, err)
	}
	var journal projectionRecoveryJournal
	if err := decodeStrictProjectionJSON(data, &journal); err != nil {
		return nil, fmt.Errorf("%w: decode recovery journal: %v", ErrProjectionDrift, err)
	}
	return &journal, nil
}

func (l *ProjectionLifecycle) hasPendingProjectionRecoveryJournal(
	lookup contracts.SkillProjectionEffect,
	relativePath string,
) (bool, error) {
	journal, err := l.readProjectionRecoveryJournalRecord(lookup)
	if err != nil || journal == nil {
		return false, err
	}
	if err := l.verifyProjectionRecoveryJournal(*journal); err != nil {
		return false, err
	}
	if journal.SchemaVersion != projectionRecoveryJournalSchemaV1 ||
		journal.TenantID != lookup.TenantID || journal.WorkspaceID != lookup.WorkspaceID ||
		journal.SkillID != lookup.SkillID || journal.AgentTarget != lookup.AgentTarget ||
		journal.RelativePath != relativePath || len(journal.NextStateBytes) == 0 ||
		len(journal.NextStateBytes) > maxProjectionLifecycleStateBytes ||
		!validProjectionSHA256(journal.NextStateHash) || HashBytes(journal.NextStateBytes) != journal.NextStateHash {
		return false, fmt.Errorf("%w: recovery journal projection binding is invalid", ErrProjectionDrift)
	}

	var next projectionLifecycleState
	if err := decodeStrictProjectionJSON(journal.NextStateBytes, &next); err != nil {
		return false, fmt.Errorf("%w: decode recovery state: %v", ErrProjectionDrift, err)
	}
	if err := l.verifyProjectionLifecycleState(next); err != nil {
		return false, fmt.Errorf("%w: recovery state integrity: %v", ErrProjectionDrift, err)
	}
	if err := validateProjectionStateIdentity(next, lookup, relativePath); err != nil {
		return false, err
	}
	replay, ok := findProjectionReplay(next.Replays, journal.IdempotencyKey)
	if !ok || replay.RequestHash != journal.CanonicalRequestHash ||
		replay.Result.ResultHash != journal.ResultHash || !validProjectionSHA256(replay.Result.ConsumedPermitRef) {
		return false, fmt.Errorf("%w: recovery journal replay binding is invalid", ErrProjectionDrift)
	}
	if (journal.Action == contracts.SkillProjectionActionRollback && !validProjectionSHA256(replay.Result.RollbackPermitRef)) ||
		(journal.Action != contracts.SkillProjectionActionRollback && replay.Result.RollbackPermitRef != "") {
		return false, fmt.Errorf("%w: recovery journal replay binding is invalid", ErrProjectionDrift)
	}

	var record projectionGeneration
	found := false
	for i := range next.Generations {
		candidate := next.Generations[i]
		if candidate.SkillVersion == journal.SkillVersion &&
			candidate.ArtifactHash == replay.Result.TrustArtifactHash &&
			candidate.ContentHash == replay.Result.TrustContentHash &&
			candidate.ManifestHash == replay.Result.TrustManifestHash &&
			candidate.PolicyHash == replay.Result.TrustPolicyHash &&
			candidate.SchemaHash == replay.Result.TrustSchemaHash &&
			projectionCertificationRefsHash(candidate.CertificationRefs) == replay.Result.TrustCertificationHash &&
			candidate.SandboxProfile == replay.Result.TrustSandboxProfile {
			record = candidate
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("%w: recovery journal generation binding is invalid", ErrProjectionDrift)
	}

	pendingEffect := contracts.SkillProjectionEffect{
		SchemaVersion:        contracts.SkillProjectionEffectSchemaV1,
		ContractVersion:      contracts.SkillProjectionEffectContractV1,
		Action:               journal.Action,
		TenantID:             journal.TenantID,
		WorkspaceID:          journal.WorkspaceID,
		SkillID:              journal.SkillID,
		SkillVersion:         journal.SkillVersion,
		AgentTarget:          journal.AgentTarget,
		ArtifactHash:         record.ArtifactHash,
		ContentHash:          record.ContentHash,
		ManifestHash:         record.ManifestHash,
		PolicyHash:           record.PolicyHash,
		SchemaHash:           record.SchemaHash,
		CertificationRefs:    append([]string(nil), record.CertificationRefs...),
		ConsumedPermitRef:    replay.Result.ConsumedPermitRef,
		IdempotencyKey:       journal.IdempotencyKey,
		AttemptID:            journal.AttemptID,
		Generation:           replay.Result.NewGeneration,
		SandboxProfile:       record.SandboxProfile,
		CanonicalRequestHash: journal.CanonicalRequestHash,
	}
	if _, err := l.validateProjectionRecoveryJournal(*journal, pendingEffect, relativePath); err != nil {
		return false, err
	}
	return true, nil
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

func observationMatches(present bool, hash string, expectedPresent bool, expectedHash string) bool {
	return present == expectedPresent && ((!present && expectedHash == "") || (present && hash == expectedHash))
}

func (l *ProjectionLifecycle) runProjectionMutationHook(stage string) error {
	if l.mutationHook == nil {
		return nil
	}
	return l.mutationHook(stage)
}
