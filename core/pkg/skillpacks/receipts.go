package skillpacks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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
	if result.ResultHash == "" {
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
