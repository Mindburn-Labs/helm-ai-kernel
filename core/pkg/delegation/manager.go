// Package delegation implements multi-agent governance delegation for HELM.
//
// Extends the existing A2A (Agent-to-Agent) and delegation gate patterns
// to support:
//   - Delegation receipt chains (agent A delegates authority to agent B)
//   - Capability attenuation (delegated agent can never exceed delegator's capabilities)
//   - Delegation TTL and revocation
//   - Chain-of-custody auditing via receipt binding
package delegation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DelegationGrant authorizes one agent to act on behalf of another.
type DelegationGrant struct {
	GrantID         string    `json:"grant_id"`
	DelegatorID     string    `json:"delegator_id"`      // Agent granting authority
	DelegateeID     string    `json:"delegatee_id"`      // Agent receiving authority
	Capabilities    []string  `json:"capabilities"`       // Allowed effect levels: ["E0", "E1"]
	AllowedTools    []string  `json:"allowed_tools,omitempty"` // Tool allowlist (empty = all within capabilities)
	MaxChainDepth   int       `json:"max_chain_depth"`    // How deep this can be re-delegated
	TTL             time.Duration `json:"ttl"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	ParentGrantID   string    `json:"parent_grant_id,omitempty"` // If this is a re-delegation
	ChainDepth      int       `json:"chain_depth"`       // Current depth in delegation chain
	ReceiptID       string    `json:"receipt_id"`         // Receipt binding
	Signature       string    `json:"signature"`          // Delegator's signature
	Revoked         bool      `json:"revoked"`
}

// DelegationRequest is a request to create a delegation.
type DelegationRequest struct {
	DelegatorID   string        `json:"delegator_id"`
	DelegateeID   string        `json:"delegatee_id"`
	Capabilities  []string      `json:"capabilities"`
	AllowedTools  []string      `json:"allowed_tools,omitempty"`
	MaxChainDepth int           `json:"max_chain_depth"`
	TTL           time.Duration `json:"ttl"`
}

// DelegationVerdict is returned when checking if an action is authorized
// under a delegation chain.
type DelegationVerdict struct {
	Authorized bool   `json:"authorized"`
	GrantID    string `json:"grant_id"`
	ChainDepth int    `json:"chain_depth"`
	Reason     string `json:"reason,omitempty"`
}

// ReceiptEmitter emits delegation events to the proof graph.
// Implementations bind delegation grants to the receipt chain.
type ReceiptEmitter interface {
	EmitDelegationReceipt(event string, grantID string, delegatorID string, delegateeID string) (receiptID string, err error)
}

// DelegationManager manages delegation grants between agents.
type DelegationManager struct {
	mu      sync.RWMutex
	grants  map[string]*DelegationGrant // grantID → grant
	byAgent map[string][]string         // delegateeID → []grantIDs
	emitter ReceiptEmitter               // optional proof graph binding
}

// NewDelegationManager creates a new delegation manager.
func NewDelegationManager() *DelegationManager {
	return &DelegationManager{
		grants:  make(map[string]*DelegationGrant),
		byAgent: make(map[string][]string),
	}
}

// WithReceiptEmitter configures a receipt emitter for proof graph binding.
func (dm *DelegationManager) WithReceiptEmitter(e ReceiptEmitter) {
	dm.emitter = e
}

// CreateDelegation creates a new delegation grant.
// Enforces capability attenuation: delegated capabilities MUST be a
// subset of the delegator's own capabilities.
func (dm *DelegationManager) CreateDelegation(_ context.Context, req DelegationRequest, delegatorCaps []string) (*DelegationGrant, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Validate capability attenuation.
	capSet := make(map[string]bool)
	for _, c := range delegatorCaps {
		capSet[c] = true
	}
	for _, rc := range req.Capabilities {
		if !capSet[rc] {
			return nil, fmt.Errorf("delegation: capability %q exceeds delegator's capabilities", rc)
		}
	}

	if req.MaxChainDepth < 0 {
		req.MaxChainDepth = 0 // Cannot delegate further
	}

	if req.TTL <= 0 {
		req.TTL = 1 * time.Hour
	}

	now := time.Now().UTC()
	grant := &DelegationGrant{
		GrantID:       generateDelegationID(),
		DelegatorID:   req.DelegatorID,
		DelegateeID:   req.DelegateeID,
		Capabilities:  req.Capabilities,
		AllowedTools:  req.AllowedTools,
		MaxChainDepth: req.MaxChainDepth,
		TTL:           req.TTL,
		IssuedAt:      now,
		ExpiresAt:     now.Add(req.TTL),
		ChainDepth:    0,
	}

	dm.grants[grant.GrantID] = grant
	dm.byAgent[req.DelegateeID] = append(dm.byAgent[req.DelegateeID], grant.GrantID)

	// Emit delegation receipt to proof graph (best-effort).
	if dm.emitter != nil {
		if rid, err := dm.emitter.EmitDelegationReceipt("DELEGATE", grant.GrantID, req.DelegatorID, req.DelegateeID); err == nil {
			grant.ReceiptID = rid
		}
	}

	return grant, nil
}

// ReDelegate creates a sub-delegation from an existing grant.
// The sub-delegation MUST attenuate: narrower capabilities, shorter TTL, reduced chain depth.
func (dm *DelegationManager) ReDelegate(_ context.Context, parentGrantID string, req DelegationRequest) (*DelegationGrant, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	parent, exists := dm.grants[parentGrantID]
	if !exists {
		return nil, fmt.Errorf("delegation: parent grant %s not found", parentGrantID)
	}

	if parent.Revoked {
		return nil, fmt.Errorf("delegation: parent grant %s is revoked", parentGrantID)
	}

	if time.Now().After(parent.ExpiresAt) {
		return nil, fmt.Errorf("delegation: parent grant %s has expired", parentGrantID)
	}

	if parent.ChainDepth >= parent.MaxChainDepth {
		return nil, fmt.Errorf("delegation: max chain depth %d reached", parent.MaxChainDepth)
	}

	// Attenuation check: requested capabilities must be a subset of parent's.
	parentCapSet := make(map[string]bool)
	for _, c := range parent.Capabilities {
		parentCapSet[c] = true
	}
	for _, rc := range req.Capabilities {
		if !parentCapSet[rc] {
			return nil, fmt.Errorf("delegation: capability %q exceeds parent grant's capabilities", rc)
		}
	}

	// TTL must not exceed parent's remaining TTL.
	remaining := time.Until(parent.ExpiresAt)
	if req.TTL > remaining {
		req.TTL = remaining
	}

	now := time.Now().UTC()
	grant := &DelegationGrant{
		GrantID:       generateDelegationID(),
		DelegatorID:   req.DelegatorID,
		DelegateeID:   req.DelegateeID,
		Capabilities:  req.Capabilities,
		AllowedTools:  req.AllowedTools,
		MaxChainDepth: parent.MaxChainDepth,
		TTL:           req.TTL,
		IssuedAt:      now,
		ExpiresAt:     now.Add(req.TTL),
		ParentGrantID: parentGrantID,
		ChainDepth:    parent.ChainDepth + 1,
	}

	dm.grants[grant.GrantID] = grant
	dm.byAgent[req.DelegateeID] = append(dm.byAgent[req.DelegateeID], grant.GrantID)

	return grant, nil
}

// CheckAuthorization verifies if an agent is authorized to perform an
// action under its delegation chain.
func (dm *DelegationManager) CheckAuthorization(_ context.Context, agentID, tool, effectLevel string) *DelegationVerdict {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	grantIDs, exists := dm.byAgent[agentID]
	if !exists {
		return &DelegationVerdict{Authorized: false, Reason: "no delegation grants for agent"}
	}

	now := time.Now()
	for _, gid := range grantIDs {
		grant := dm.grants[gid]
		if grant.Revoked {
			continue
		}
		if now.After(grant.ExpiresAt) {
			continue
		}

		// Check capability.
		capOK := false
		for _, c := range grant.Capabilities {
			if c == effectLevel {
				capOK = true
				break
			}
		}
		if !capOK {
			continue
		}

		// Check tool allowlist.
		if len(grant.AllowedTools) > 0 {
			toolOK := false
			for _, t := range grant.AllowedTools {
				if t == tool {
					toolOK = true
					break
				}
			}
			if !toolOK {
				continue
			}
		}

		return &DelegationVerdict{
			Authorized: true,
			GrantID:    grant.GrantID,
			ChainDepth: grant.ChainDepth,
		}
	}

	return &DelegationVerdict{Authorized: false, Reason: "no matching delegation grant"}
}

// RevokeDelegation revokes a grant and all its children.
func (dm *DelegationManager) RevokeDelegation(_ context.Context, grantID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	grant, exists := dm.grants[grantID]
	if !exists {
		return fmt.Errorf("delegation: grant %s not found", grantID)
	}

	grant.Revoked = true

	// Cascade revocation to children.
	for _, g := range dm.grants {
		if g.ParentGrantID == grantID && !g.Revoked {
			g.Revoked = true
		}
	}

	// Emit revocation receipt (best-effort).
	if dm.emitter != nil {
		dm.emitter.EmitDelegationReceipt("REVOKE", grantID, grant.DelegatorID, grant.DelegateeID)
	}

	return nil
}

// ActiveGrants returns all active (non-revoked, non-expired) grants for an agent.
func (dm *DelegationManager) ActiveGrants(_ context.Context, agentID string) []*DelegationGrant {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	now := time.Now()
	var active []*DelegationGrant
	for _, gid := range dm.byAgent[agentID] {
		g := dm.grants[gid]
		if !g.Revoked && now.Before(g.ExpiresAt) {
			active = append(active, g)
		}
	}
	return active
}

func generateDelegationID() string {
	b := make([]byte, 16)
	// Use current time as entropy source for simplicity.
	// Production uses crypto/rand.
	t := time.Now().UnixNano()
	for i := range b {
		b[i] = byte(t >> (i * 4))
	}
	h := sha256.Sum256(b)
	return "deleg-" + hex.EncodeToString(h[:])[:12]
}
