// Package simulation provides canonical simulation primitives for HELM.
//
// Per HELM 2030 Spec §5.8 / §6.1.14:
//
//	The simulation layer enables policy validation, rollout planning,
//	and what-if analysis against an org twin — a snapshot of the
//	organization's current governance state.
package simulation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// OrgTwinStatus indicates the freshness of the twin snapshot.
type OrgTwinStatus string

const (
	TwinStatusCurrent  OrgTwinStatus = "CURRENT"
	TwinStatusStale    OrgTwinStatus = "STALE"
	TwinStatusDraft    OrgTwinStatus = "DRAFT"
)

// PolicyRule is a simplified view of a policy for simulation purposes.
type PolicyRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Expression  string `json:"expression"` // CEL or policy DSL
	EffectTypes []string `json:"effect_types"`
	Enabled     bool   `json:"enabled"`
}

// RoleSnapshot captures the roles in the org at snapshot time.
type RoleSnapshot struct {
	RoleID      string   `json:"role_id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	ActorCount  int      `json:"actor_count"`
}

// BudgetSnapshot captures budget state at snapshot time.
type BudgetSnapshot struct {
	BudgetID       string `json:"budget_id"`
	Name           string `json:"name"`
	AllocatedCents int64  `json:"allocated_cents"`
	SpentCents     int64  `json:"spent_cents"`
	Currency       string `json:"currency"`
}

// AuthoritySnapshot captures authority hierarchy.
type AuthoritySnapshot struct {
	PrincipalID string   `json:"principal_id"`
	Role        string   `json:"role"`
	Delegates   []string `json:"delegates,omitempty"`
}

// OrgTwin is a point-in-time snapshot of an organization's governance state.
// It enables policy simulation without affecting production state.
type OrgTwin struct {
	ID          string              `json:"id"`
	TenantID    string              `json:"tenant_id"`
	Status      OrgTwinStatus       `json:"status"`
	SnapshotAt  time.Time           `json:"snapshot_at"`
	Policies    []PolicyRule        `json:"policies"`
	Roles       []RoleSnapshot      `json:"roles"`
	Budgets     []BudgetSnapshot    `json:"budgets"`
	Authorities []AuthoritySnapshot `json:"authorities"`
	ContentHash string              `json:"content_hash"`
}

// NewOrgTwin creates a twin snapshot.
func NewOrgTwin(id, tenantID string, policies []PolicyRule, roles []RoleSnapshot, budgets []BudgetSnapshot, authorities []AuthoritySnapshot) *OrgTwin {
	ot := &OrgTwin{
		ID:          id,
		TenantID:    tenantID,
		Status:      TwinStatusCurrent,
		SnapshotAt:  time.Now().UTC(),
		Policies:    policies,
		Roles:       roles,
		Budgets:     budgets,
		Authorities: authorities,
	}
	ot.ContentHash = ot.computeHash()
	return ot
}

// OrgTwinDelta represents the diff between two org states.
type OrgTwinDelta struct {
	BaseID        string   `json:"base_id"`
	CompareID     string   `json:"compare_id"`
	AddedPolicies []string `json:"added_policies,omitempty"`
	RemovedPolicies []string `json:"removed_policies,omitempty"`
	ChangedPolicies []string `json:"changed_policies,omitempty"`
	AddedRoles    []string `json:"added_roles,omitempty"`
	RemovedRoles  []string `json:"removed_roles,omitempty"`
	BudgetDeltas  []BudgetDelta `json:"budget_deltas,omitempty"`
}

// BudgetDelta tracks change in a budget between snapshots.
type BudgetDelta struct {
	BudgetID        string `json:"budget_id"`
	AllocatedChange int64  `json:"allocated_change_cents"`
	SpentChange     int64  `json:"spent_change_cents"`
}

// Compare produces a delta between two org twins.
func Compare(base, target *OrgTwin) *OrgTwinDelta {
	delta := &OrgTwinDelta{
		BaseID:    base.ID,
		CompareID: target.ID,
	}

	basePolicies := make(map[string]PolicyRule)
	for _, p := range base.Policies {
		basePolicies[p.ID] = p
	}
	for _, p := range target.Policies {
		if _, exists := basePolicies[p.ID]; !exists {
			delta.AddedPolicies = append(delta.AddedPolicies, p.ID)
		}
		delete(basePolicies, p.ID)
	}
	for id := range basePolicies {
		delta.RemovedPolicies = append(delta.RemovedPolicies, id)
	}

	baseRoles := make(map[string]bool)
	for _, r := range base.Roles {
		baseRoles[r.RoleID] = true
	}
	for _, r := range target.Roles {
		if !baseRoles[r.RoleID] {
			delta.AddedRoles = append(delta.AddedRoles, r.RoleID)
		}
		delete(baseRoles, r.RoleID)
	}
	for id := range baseRoles {
		delta.RemovedRoles = append(delta.RemovedRoles, id)
	}

	return delta
}

func (ot *OrgTwin) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		Policies int    `json:"policy_count"`
		Roles    int    `json:"role_count"`
		Budgets  int    `json:"budget_count"`
	}{ot.ID, ot.TenantID, len(ot.Policies), len(ot.Roles), len(ot.Budgets)})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
