// Package evidence provides the Evidence Registry — the runtime engine
// that manages EvidenceContracts and verifies evidence submissions against them.
//
// Per HELM 2030 Spec — Proof-carrying operations:
//   - Every action class has defined evidence requirements
//   - The registry enforces evidence completeness before or after execution
//   - Missing evidence produces a fail-closed denial
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// Registry manages evidence contracts and verifies submissions.
type Registry struct {
	mu        sync.RWMutex
	contracts map[string]*contracts.EvidenceContract // keyed by action_class
	manifest  *contracts.EvidenceContractManifest
	clock     func() time.Time
}

// NewRegistry creates a new evidence registry.
func NewRegistry() *Registry {
	return &Registry{
		contracts: make(map[string]*contracts.EvidenceContract),
		clock:     time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (r *Registry) WithClock(clock func() time.Time) *Registry {
	r.clock = clock
	return r
}

// LoadManifest loads a versioned evidence contract manifest.
func (r *Registry) LoadManifest(manifest *contracts.EvidenceContractManifest) error {
	if manifest == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	contractMap := make(map[string]*contracts.EvidenceContract, len(manifest.Contracts))
	for i := range manifest.Contracts {
		c := &manifest.Contracts[i]
		if c.ActionClass == "" {
			return fmt.Errorf("contract %q has empty action_class", c.ContractID)
		}
		contractMap[c.ActionClass] = c
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.contracts = contractMap
	r.manifest = manifest

	return nil
}

// GetContract returns the evidence contract for an action class.
// Returns nil if no contract is defined (meaning no evidence is required).
func (r *Registry) GetContract(actionClass string) *contracts.EvidenceContract {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.contracts[actionClass]
}

// CheckBefore verifies that all "before" evidence requirements are satisfied.
// Returns a verdict indicating which requirements are met and which are missing.
// Fail-closed: if a required "before" evidence is missing, the verdict is unsatisfied.
func (r *Registry) CheckBefore(
	ctx context.Context,
	actionClass string,
	submissions []contracts.EvidenceSubmission,
) (*contracts.EvidenceVerdict, error) {
	_ = ctx
	return r.check(actionClass, "before", submissions)
}

// CheckAfter verifies that all "after" evidence requirements are satisfied.
func (r *Registry) CheckAfter(
	ctx context.Context,
	actionClass string,
	submissions []contracts.EvidenceSubmission,
) (*contracts.EvidenceVerdict, error) {
	_ = ctx
	return r.check(actionClass, "after", submissions)
}

func (r *Registry) check(actionClass, phase string, submissions []contracts.EvidenceSubmission) (*contracts.EvidenceVerdict, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	contract, ok := r.contracts[actionClass]
	if !ok {
		// No contract → no evidence required → satisfied
		return &contracts.EvidenceVerdict{
			Satisfied:  true,
			VerifiedAt: r.clock(),
		}, nil
	}

	// Filter requirements for this phase
	requiredSpecs := make([]contracts.EvidenceSpec, 0)
	for _, req := range contract.Requirements {
		if req.Required && (req.When == phase || req.When == "both") {
			requiredSpecs = append(requiredSpecs, req)
		}
	}

	// Build a map of submissions by evidence type
	submissionsByType := make(map[string][]contracts.EvidenceSubmission)
	for _, sub := range submissions {
		submissionsByType[sub.EvidenceType] = append(submissionsByType[sub.EvidenceType], sub)
	}

	// Check each requirement
	var missing []contracts.EvidenceSpec
	var verified []contracts.EvidenceSubmission

	for _, spec := range requiredSpecs {
		subs, found := submissionsByType[spec.EvidenceType]
		if !found || len(subs) == 0 {
			missing = append(missing, spec)
			continue
		}

		// Check issuer constraint if present
		if spec.IssuerConstraint != "" {
			matched := false
			for _, sub := range subs {
				if sub.IssuerID == spec.IssuerConstraint && sub.Verified {
					verified = append(verified, sub)
					matched = true
					break
				}
			}
			if !matched {
				missing = append(missing, spec)
			}
		} else {
			// Any verified submission of the right type is sufficient
			matched := false
			for _, sub := range subs {
				if sub.Verified {
					verified = append(verified, sub)
					matched = true
					break
				}
			}
			if !matched {
				missing = append(missing, spec)
			}
		}
	}

	return &contracts.EvidenceVerdict{
		Satisfied:  len(missing) == 0,
		Missing:    missing,
		Verified:   verified,
		ContractID: contract.ContractID,
		VerifiedAt: r.clock(),
	}, nil
}

// ManifestVersion returns the loaded manifest version.
func (r *Registry) ManifestVersion() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.manifest == nil {
		return "unloaded"
	}
	return r.manifest.Version
}

// ComputeManifestHash computes the content hash of an evidence contract manifest.
func ComputeManifestHash(manifest *contracts.EvidenceContractManifest) (string, error) {
	hashable := struct {
		Version   string                       `json:"version"`
		Contracts []contracts.EvidenceContract `json:"contracts"`
	}{
		Version:   manifest.Version,
		Contracts: manifest.Contracts,
	}

	data, err := json.Marshal(hashable)
	if err != nil {
		return "", fmt.Errorf("failed to marshal manifest for hashing: %w", err)
	}

	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}
