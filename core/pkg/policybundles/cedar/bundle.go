// Package cedar provides the Cedar policy front-end for HELM policy
// bundles. Cedar policies are parsed via cedar-go, signed identically
// to CEL and Rego bundles, and evaluated against the same internal
// DecisionRequest shape so the kernel never branches on language at
// decision time.
//
// Workstream B / B2 — Phase 2 of the helm-oss 100% SOTA execution plan.
package cedar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Language is the manifest tag identifying this front-end.
const Language = "cedar"

// CompiledBundle is a Cedar policy compiled into a deterministic,
// persistable form. The PolicySet field holds the original Cedar source;
// Hash is the SHA-256 of the canonical signing payload and is used as
// the artifact digest for signing.
type CompiledBundle struct {
	BundleID    string    `json:"bundle_id"`
	Name        string    `json:"name"`
	Version     int       `json:"version"`
	Language    string    `json:"language"`
	PolicySet   string    `json:"policy_set"`
	EntitiesDoc string    `json:"entities,omitempty"`
	Hash        string    `json:"hash"`
	CompiledAt  time.Time `json:"compiled_at"`
}

// DecisionRequest is the input shape shared across CEL, Rego, and Cedar
// evaluators. The cedar evaluator normalizes this into Cedar's entity-shape
// model (principal/action/resource entity UIDs + context record) before
// dispatch.
type DecisionRequest struct {
	Principal string                 `json:"principal"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Tool      string                 `json:"tool,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// Decision is the verdict returned by all front-ends.
type Decision struct {
	Verdict     string                 `json:"verdict"`
	Reason      string                 `json:"reason,omitempty"`
	Obligations map[string]interface{} `json:"obligations,omitempty"`
	PolicyID    string                 `json:"policy_id,omitempty"`
}

const (
	VerdictAllow    = "ALLOW"
	VerdictDeny     = "DENY"
	VerdictEscalate = "ESCALATE"
)

// computeHash returns the canonical SHA-256 digest of a CompiledBundle's
// signing payload.
func computeHash(b *CompiledBundle) (string, error) {
	payload := struct {
		BundleID    string `json:"bundle_id"`
		Name        string `json:"name"`
		Version     int    `json:"version"`
		Language    string `json:"language"`
		PolicySet   string `json:"policy_set"`
		EntitiesDoc string `json:"entities,omitempty"`
	}{
		BundleID:    b.BundleID,
		Name:        b.Name,
		Version:     b.Version,
		Language:    b.Language,
		PolicySet:   b.PolicySet,
		EntitiesDoc: b.EntitiesDoc,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("cedar: canonicalize signing payload: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
