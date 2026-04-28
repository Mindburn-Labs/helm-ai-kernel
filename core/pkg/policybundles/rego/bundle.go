// Package rego provides the OPA/Rego policy front-end for HELM policy
// bundles. A Rego module is compiled to a deterministic, persistable
// representation, signed identically to CEL bundles, and evaluated
// against the same internal DecisionRequest shape so the kernel never
// branches on language at decision time.
//
// Workstream B / B1 — Phase 2 of the helm-oss 100% SOTA execution plan.
package rego

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Language is the manifest tag identifying this front-end.
const Language = "rego"

// CompiledBundle is a Rego policy compiled into a deterministic, persistable
// form. The Module field holds the original Rego source; Query is the
// pre-prepared decision query (e.g. "data.helm.policy.decision"); Hash is
// the SHA-256 of the canonical signing payload (Module + Query + Capabilities)
// and is used as the artifact digest for signing.
type CompiledBundle struct {
	BundleID     string    `json:"bundle_id"`
	Name         string    `json:"name"`
	Version      int       `json:"version"`
	Language     string    `json:"language"`
	Module       string    `json:"module"`
	Query        string    `json:"query"`
	Capabilities []byte    `json:"capabilities,omitempty"`
	Hash         string    `json:"hash"`
	CompiledAt   time.Time `json:"compiled_at"`
}

// DecisionRequest is the input shape shared across CEL, Rego, and Cedar
// evaluators. Loaders normalize incoming requests into this struct before
// dispatching to the language-specific evaluator.
type DecisionRequest struct {
	Principal string                 `json:"principal"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Tool      string                 `json:"tool,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// Decision is the verdict returned by all front-ends. Verdict values are
// exactly "ALLOW", "DENY", or "ESCALATE" so the kernel can compare results
// across languages byte-identically.
type Decision struct {
	Verdict     string                 `json:"verdict"`
	Reason      string                 `json:"reason,omitempty"`
	Obligations map[string]interface{} `json:"obligations,omitempty"`
	PolicyID    string                 `json:"policy_id,omitempty"`
}

// Verdict constants kept in sync with policybundles and bundles packages.
const (
	VerdictAllow    = "ALLOW"
	VerdictDeny     = "DENY"
	VerdictEscalate = "ESCALATE"
)

// computeHash returns the canonical SHA-256 digest of a CompiledBundle's
// signing payload. Mirrors policybundles.ComputeBundleHash semantics:
// metadata-only fields (CompiledAt, Hash itself) are excluded.
func computeHash(b *CompiledBundle) (string, error) {
	payload := struct {
		BundleID     string `json:"bundle_id"`
		Name         string `json:"name"`
		Version      int    `json:"version"`
		Language     string `json:"language"`
		Module       string `json:"module"`
		Query        string `json:"query"`
		Capabilities []byte `json:"capabilities,omitempty"`
	}{
		BundleID:     b.BundleID,
		Name:         b.Name,
		Version:      b.Version,
		Language:     b.Language,
		Module:       b.Module,
		Query:        b.Query,
		Capabilities: b.Capabilities,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("rego: canonicalize signing payload: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
