package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type ReconcileStatus string

const (
	ReconcileRequired ReconcileStatus = "required"
	ReconcileClean    ReconcileStatus = "clean"
)

type Plan struct {
	Provider       string            `json:"provider"`
	LaunchID       string            `json:"launch_id"`
	DryRun         bool              `json:"dry_run"`
	IdempotencyKey string            `json:"idempotency_key"`
	Resources      map[string]string `json:"resources"`
}

type Outcome struct {
	Status          ReconcileStatus `json:"status"`
	Ambiguous       bool            `json:"ambiguous"`
	RequiresRetry   bool            `json:"requires_retry"`
	ReconciledFirst bool            `json:"reconciled_first"`
}

func IdempotencyKey(provider, launchID, planHash string) string {
	payload, _ := json.Marshal(map[string]string{
		"provider":  provider,
		"launch_id": launchID,
		"plan_hash": planHash,
	})
	sum := sha256.Sum256(payload)
	return provider + ":" + hex.EncodeToString(sum[:])
}

func ReconcileBeforeRetry(ambiguous bool) Outcome {
	if ambiguous {
		return Outcome{Status: ReconcileRequired, Ambiguous: true, RequiresRetry: false, ReconciledFirst: true}
	}
	return Outcome{Status: ReconcileClean, Ambiguous: false, RequiresRetry: true, ReconciledFirst: true}
}
