package provision

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// Applied is the plan the gateway last applied for an organization, as its
// authority_provisions row holds it.
type Applied struct {
	OrgRef     string
	Digest     string
	VersionRef string
	Stage      string
	// Provisioner is the service principal that requested the applied plan.
	Provisioner string
	// Principals are the principals the plan listed, which the next plan may
	// disable.
	Principals []AppliedPrincipal
	// Nodes are the plan's mandate nodes and the mandates they became, in the
	// plan's order.
	Nodes     []AppliedNode
	AttemptID string
	Revision  int64
	AppliedAt time.Time
}

// AppliedPrincipal is a principal an applied plan listed.
type AppliedPrincipal struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// AppliedNode is a plan node and the mandate it became.
type AppliedNode struct {
	Node       string `json:"node"`
	MandateID  string `json:"mandate_id"`
	HolderID   string `json:"holder_id"`
	ParentNode string `json:"parent_node"`
}

func (a *Applied) node(name string) (AppliedNode, bool) {
	for _, n := range a.Nodes {
		if n.Node == name {
			return n, true
		}
	}
	return AppliedNode{}, false
}

func (a *Applied) principal(id string) (AppliedPrincipal, bool) {
	for _, p := range a.Principals {
		if p.ID == id {
			return p, true
		}
	}
	return AppliedPrincipal{}, false
}

const provisionColumns = `plan_digest, version_ref, stage, nodes, principals, requested_by, attempt_id, revision, applied_at`

// LoadApplied reads the organization's applied plan in tx, which is bound to
// one tenant. It returns nil, nil when the organization has none. With lock the
// row is locked FOR UPDATE, for a transaction that will replace it.
func LoadApplied(ctx context.Context, tx *sql.Tx, tenantID, orgRef string, lock bool) (*Applied, error) {
	query := `SELECT ` + provisionColumns + ` FROM authority_provisions WHERE tenant_id = $1 AND org_ref = $2`
	if lock {
		query += ` FOR UPDATE`
	}
	a := &Applied{OrgRef: orgRef}
	var nodes, principals []byte
	err := tx.QueryRowContext(ctx, query, tenantID, orgRef).Scan(&a.Digest, &a.VersionRef, &a.Stage, &nodes, &principals,
		&a.Provisioner, &a.AttemptID, &a.Revision, &a.AppliedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.AppliedAt = a.AppliedAt.UTC()
	if err := json.Unmarshal(nodes, &a.Nodes); err != nil {
		return nil, fmt.Errorf("authority_provisions.nodes of %s: %w", orgRef, err)
	}
	if err := json.Unmarshal(principals, &a.Principals); err != nil {
		return nil, fmt.Errorf("authority_provisions.principals of %s: %w", orgRef, err)
	}
	return a, nil
}

// Provisioning is what GetProvisioning returns: the applied plan with the
// current state of each mandate it made.
type Provisioning struct {
	Applied
	// Status is one entry per node of Applied.Nodes, in that order.
	Status []NodeStatus
}

// NodeStatus is the live state of the mandate a node became.
type NodeStatus struct {
	Active  bool
	Version int64
}

// ErrNotProvisioned reports an organization the tenant never provisioned.
var ErrNotProvisioned = errors.New("the organization has no applied plan in this tenant")

// GetProvisioning reads the organization's applied plan and the status of each
// of its mandates, in one transaction of the tenant.
func GetProvisioning(ctx context.Context, rows *authorityrows.Store, tenantID, orgRef string) (*Provisioning, error) {
	var out *Provisioning
	err := rows.InTenant(ctx, tenantID, func(tx *authorityrows.Tx) error {
		applied, err := LoadApplied(ctx, tx.SQL(), tenantID, orgRef, false)
		if err != nil {
			return err
		}
		if applied == nil {
			return ErrNotProvisioned
		}
		out = &Provisioning{Applied: *applied, Status: make([]NodeStatus, len(applied.Nodes))}
		for i, n := range applied.Nodes {
			id, err := uuid.Parse(n.MandateID)
			if err != nil {
				return fmt.Errorf("authority_provisions.nodes of %s: %w", orgRef, err)
			}
			m, err := tx.Mandate(ctx, id)
			if errors.Is(err, authorityrows.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			out.Status[i] = NodeStatus{Active: m.Active, Version: m.Version}
		}
		return nil
	})
	return out, err
}

// evidence is the SHA-256 the read-back reports for what it read.
func (a *Applied) evidence() []byte {
	body, _ := json.Marshal(struct {
		OrgRef    string        `json:"org_ref"`
		Digest    string        `json:"plan_digest"`
		Revision  int64         `json:"revision"`
		AttemptID string        `json:"attempt_id"`
		Nodes     []AppliedNode `json:"nodes"`
	}{a.OrgRef, a.Digest, a.Revision, a.AttemptID, a.Nodes})
	sum := sha256.Sum256(body)
	return sum[:]
}
