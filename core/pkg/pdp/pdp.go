// Package pdp defines the Policy Decision Point abstraction.
//
// HELM's enforcement kernel (Guardian) delegates policy evaluation
// to a PDP backend. The default backend uses HELM's built-in
// Proof Requirement Graph (PRG) evaluation with CEL expressions.
//
// Every PDP implementation MUST:
//   - Be fail-closed (deny on error/timeout)
//   - Produce deterministic decision hashes (JCS canonical JSON → SHA-256)
//   - Return a stable PolicyRef for receipt binding
package pdp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Backend identifies the policy engine.
type Backend string

const (
	BackendHELM Backend = "helm"
)

// ErrPDPHashFailure marks infrastructure failures while binding a policy
// response to its deterministic receipt hash. Callers must fail closed when
// this error is returned, even when a deny response is also present.
var ErrPDPHashFailure = errors.New("pdp: decision hash failure")

// DecisionRequest is the canonical structured input to a policy evaluation.
type DecisionRequest struct {
	Principal   string            `json:"principal"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	Context     map[string]any    `json:"context,omitempty"`
	SchemaHash  string            `json:"schema_hash,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// DecisionResponse is the canonical output of a policy evaluation.
type DecisionResponse struct {
	Allow        bool   `json:"allow"`
	ReasonCode   string `json:"reason_code"`
	PolicyRef    string `json:"policy_ref"`
	DecisionHash string `json:"decision_hash"` // SHA-256 of JCS-canonical decision
}

// PolicyDecisionPoint is the stable interface for policy evaluation.
// Guardian delegates to this interface when a PDP backend is configured.
type PolicyDecisionPoint interface {
	// Evaluate runs the policy evaluation. MUST be fail-closed.
	Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error)

	// Backend returns the backend identifier.
	Backend() Backend

	// PolicyHash returns a content-addressed hash of the active policy set.
	PolicyHash() string
}

// ComputeDecisionHash produces a deterministic SHA-256 hash of the decision
// using JCS canonicalization. This hash is bound into receipts.
func ComputeDecisionHash(resp *DecisionResponse) (string, error) {
	if resp == nil {
		return "", fmt.Errorf("%w: nil decision response", ErrPDPHashFailure)
	}

	// Exclude the hash field itself from the canonical form
	hashInput := struct {
		Allow      bool   `json:"allow"`
		ReasonCode string `json:"reason_code"`
		PolicyRef  string `json:"policy_ref"`
	}{
		Allow:      resp.Allow,
		ReasonCode: resp.ReasonCode,
		PolicyRef:  resp.PolicyRef,
	}

	canonical, err := canonicalize.JCS(hashInput)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalization failed: %v", ErrPDPHashFailure, err)
	}

	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

var computeDecisionHash = ComputeDecisionHash

func attachDecisionHash(resp *DecisionResponse) error {
	hash, err := computeDecisionHash(resp)
	if err != nil {
		if errors.Is(err, ErrPDPHashFailure) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrPDPHashFailure, err)
	}
	resp.DecisionHash = hash
	return nil
}

func denyForHashFailure(policyRef string, err error) (*DecisionResponse, error) {
	if err == nil {
		err = ErrPDPHashFailure
	} else if !errors.Is(err, ErrPDPHashFailure) {
		err = fmt.Errorf("%w: %v", ErrPDPHashFailure, err)
	}
	return &DecisionResponse{
		Allow:      false,
		ReasonCode: string(contracts.ReasonPDPError),
		PolicyRef:  policyRef,
	}, err
}

func normalizeDecisionReasonCode(allow bool, candidate string) string {
	if allow {
		return ""
	}
	if contracts.IsCanonicalReasonCode(candidate) {
		return candidate
	}
	return string(contracts.ReasonPDPDeny)
}
