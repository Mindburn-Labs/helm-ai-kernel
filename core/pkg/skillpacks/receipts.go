package skillpacks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func NewReceipt(kind, skillID, verdict, reasonCode, contentHash, policyHash string, paths []Projection) Receipt {
	receipt := Receipt{
		Type:             kind,
		SkillID:          skillID,
		Verdict:          verdict,
		ReasonCode:       reasonCode,
		SkillContentHash: contentHash,
		PolicyHash:       policyHash,
		ProjectionPaths:  paths,
		CreatedAt:        time.Now().UTC(),
	}
	receipt.ID = "receipt:" + hashCanonical(receipt)
	return receipt
}

func WriteReceipt(repoRoot string, receipt Receipt) (string, error) {
	dir := filepath.Join(repoRoot, ".helm", "skillpacks", "receipts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := sanitizePathSegment(receipt.ID) + ".json"
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", err
	}
	return path, atomicWrite(path, data)
}

// SealProjectionTrustDecision returns the canonical decision hash a configured
// verifier must supply to the projection lifecycle.
func SealProjectionTrustDecision(decision ProjectionTrustDecision) (ProjectionTrustDecision, error) {
	decision.DecisionHash = ""
	decision.Signature = ""
	hash, err := canonicalize.CanonicalHash(decision)
	if err != nil {
		return ProjectionTrustDecision{}, fmt.Errorf("skillpacks: seal projection trust decision: %w", err)
	}
	decision.DecisionHash = "sha256:" + hash
	return decision, nil
}

func verifyProjectionTrustDecisionIntegrity(decision ProjectionTrustDecision) error {
	if !validProjectionSHA256(decision.DecisionHash) || !validProjectionTrustSignature(decision.Signature) {
		return fmt.Errorf("%w: trust decision hash is required", ErrProjectionTrustRejected)
	}
	sealed, err := SealProjectionTrustDecision(decision)
	if err != nil || !constantStringEqual(sealed.DecisionHash, decision.DecisionHash) {
		return fmt.Errorf("%w: trust decision integrity mismatch", ErrProjectionTrustRejected)
	}
	return nil
}

func sealProjectionLifecycleResult(result ProjectionLifecycleResult) (ProjectionLifecycleResult, error) {
	result.ResultHash = ""
	hash, err := canonicalize.CanonicalHash(result)
	if err != nil {
		return ProjectionLifecycleResult{}, fmt.Errorf("skillpacks: seal projection result: %w", err)
	}
	result.ResultHash = "sha256:" + hash
	return result, nil
}

func verifyProjectionLifecycleResult(result ProjectionLifecycleResult) error {
	if result.ResultHash == "" || !validProjectionSHA256(result.TrustVerificationRef) ||
		!validProjectionSHA256(result.TrustDecisionHash) || !validProjectionTrustIdentity(result.TrustVerifierID) ||
		!validProjectionSHA256(result.TrustBindingHash) || !validProjectionTrustIdentity(result.TrustKeyID) ||
		!validProjectionTrustSignature(result.TrustDecisionSignature) || !validProjectionSHA256(result.TrustArtifactHash) ||
		!validProjectionSHA256(result.TrustContentHash) || !validProjectionSHA256(result.TrustManifestHash) ||
		!validProjectionSHA256(result.TrustPolicyHash) || result.TrustSchemaHash != contracts.SkillProjectionArtifactSchemaHashV1 ||
		!validProjectionSHA256(result.TrustCertificationHash) ||
		result.TrustSandboxProfile != contracts.SkillProjectionSandboxProfileV1 || !projectionResultMatchesTrustEffect(result) {
		return fmt.Errorf("skillpacks: projection result hash is required")
	}
	sealed, err := sealProjectionLifecycleResult(result)
	if err != nil || sealed.ResultHash != result.ResultHash {
		return fmt.Errorf("skillpacks: projection result integrity mismatch")
	}
	return nil
}

func sealProjectionLifecycleState(state projectionLifecycleState) (projectionLifecycleState, error) {
	state.StateHash = ""
	hash, err := canonicalize.CanonicalHash(state)
	if err != nil {
		return projectionLifecycleState{}, fmt.Errorf("skillpacks: seal projection state: %w", err)
	}
	state.StateHash = "sha256:" + hash
	return state, nil
}

func verifyProjectionLifecycleState(state projectionLifecycleState) error {
	if state.StateHash == "" {
		return fmt.Errorf("skillpacks: projection state hash is required")
	}
	sealed, err := sealProjectionLifecycleState(state)
	if err != nil || sealed.StateHash != state.StateHash {
		return fmt.Errorf("skillpacks: projection state integrity mismatch")
	}
	return nil
}

func sealProjectionRecoveryJournal(journal projectionRecoveryJournal) (projectionRecoveryJournal, error) {
	journal.JournalHash = ""
	hash, err := canonicalize.CanonicalHash(journal)
	if err != nil {
		return projectionRecoveryJournal{}, fmt.Errorf("skillpacks: seal projection recovery journal: %w", err)
	}
	journal.JournalHash = "sha256:" + hash
	return journal, nil
}

func verifyProjectionRecoveryJournalIntegrity(journal projectionRecoveryJournal) error {
	if !validProjectionSHA256(journal.JournalHash) {
		return fmt.Errorf("%w: recovery journal hash is required", ErrProjectionDrift)
	}
	sealed, err := sealProjectionRecoveryJournal(journal)
	if err != nil || !constantStringEqual(sealed.JournalHash, journal.JournalHash) {
		return fmt.Errorf("%w: recovery journal integrity mismatch", ErrProjectionDrift)
	}
	return nil
}
