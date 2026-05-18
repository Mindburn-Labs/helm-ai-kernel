package skillpacks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
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
