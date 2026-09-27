// Package mandates is the read side of the authority rows (HELM-750,
// ADR-0001 §2) that admission depends on: the schema, a mandate's typed terms
// and the narrowing rule between them, mandate conditions, and the delegation
// chain read under FOR SHARE locks. The effect gateway's admission transaction
// (HELM-751) imports it; authorityrows, the store that writes the rows,
// builds on it.
package mandates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

var (
	// ErrNotFound reports a row that does not exist in the caller's tenant.
	ErrNotFound = errors.New("authority rows: not found")
	// ErrWidens reports a delegation or narrowing that would widen authority.
	ErrWidens = errors.New("authority rows: would widen authority")
)

// PrincipalKind is what a principal is.
type PrincipalKind string

const (
	PrincipalHuman   PrincipalKind = "human"
	PrincipalAgent   PrincipalKind = "agent"
	PrincipalService PrincipalKind = "service"
)

// RiskClass is an effect type's risk. High and irreversible effects escalate
// to approval at admission (ADR-0001 §4).
type RiskClass string

const (
	RiskLow          RiskClass = "low"
	RiskMedium       RiskClass = "medium"
	RiskHigh         RiskClass = "high"
	RiskIrreversible RiskClass = "irreversible"
)

// WidensError names the term that a child mandate or a narrowing would widen.
type WidensError struct {
	Field string
}

func (e *WidensError) Error() string { return fmt.Sprintf("%v: %s", ErrWidens, e.Field) }

func (e *WidensError) Unwrap() error { return ErrWidens }

// Mandate is a stored mandate.
type Mandate struct {
	ID       uuid.UUID
	ParentID *uuid.UUID // nil for a root mandate
	Depth    int
	HolderID string
	Terms    Terms
	Active   bool
	// CreatedBy requested a root mandate, or delegated a child one.
	CreatedBy string
	// ApprovedBy approved a root mandate; it is empty for a delegated one.
	ApprovedBy string
	Version    int64
}

// Terms are a mandate's typed grant. Amounts are integer minor units of the
// effect's resource; a nil PerCallLimit or ApprovalThreshold sets none.
type Terms struct {
	// EffectTypes is the scope: the effect types the mandate may admit.
	EffectTypes []string
	// PerCallLimit caps the amount of one call.
	PerCallLimit *int64
	// ApprovalThreshold is the approval rule: a call whose amount is at least
	// this needs an approval (0 means every call). Without it, approval
	// follows the effect type's risk class alone.
	ApprovalThreshold *int64
	// ValidFrom and ValidUntil bound the mandate, [ValidFrom, ValidUntil).
	ValidFrom  time.Time
	ValidUntil time.Time
	// Targets allowlists the targets the mandate may act on, as exact
	// strings. Nil allows any target.
	Targets []string
	// Condition is a CEL condition over the effect: input.args (the argument
	// object), input.target and input.effect_type. Empty sets none. It is
	// compiled when the mandate is activated, delegated or narrowed; a
	// condition that does not compile is refused there, never at admission.
	Condition string
	// ApprovalRequired lists the effect types for which every call under
	// this mandate needs approval, whatever their risk class.
	ApprovalRequired []string
	// RiskClasses raises the effect type row's risk class for this mandate,
	// per effect type. A high or irreversible class escalates to approval.
	RiskClasses map[string]RiskClass
}

// MaxConditionBytes bounds a mandate condition.
const MaxConditionBytes = 4096

// ConditionAction is the action name a compiled condition snapshot decides.
const ConditionAction = "helm.mandate.condition"

// CompileCondition compiles a mandate condition into an authority snapshot
// with the kernel's CEL environment and cost limit (authority.Compile). Decide
// the snapshot with Action ConditionAction.
func CompileCondition(condition string) (*authority.Snapshot, error) {
	graph := prg.NewGraph()
	graph.Rules[ConditionAction] = prg.RequirementSet{
		ID:           "mandate.condition",
		Logic:        prg.AND,
		Requirements: []prg.Requirement{{ID: "condition", Expression: condition}},
	}
	return authority.Compile(graph)
}

// riskRank orders risk classes; unset ranks below low.
func riskRank(class RiskClass) int {
	switch class {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskIrreversible:
		return 4
	}
	return 0
}

// HigherRisk returns the higher of two risk classes.
func HigherRisk(a, b RiskClass) RiskClass {
	if riskRank(b) > riskRank(a) {
		return b
	}
	return a
}

// Within returns nil when t grants nothing outer does not: its scope is a
// subset, its per-call limit and approval threshold are no higher (and present
// wherever outer's are), and its validity window lies inside outer's. Otherwise
// it returns a *WidensError naming the first term that widens.
func (t Terms) Within(outer Terms) error {
	allowed := make(map[string]struct{}, len(outer.EffectTypes))
	for _, effectType := range outer.EffectTypes {
		allowed[effectType] = struct{}{}
	}
	for _, effectType := range t.EffectTypes {
		if _, ok := allowed[effectType]; !ok {
			return &WidensError{Field: "effect_types"}
		}
	}
	if !amountWithin(t.PerCallLimit, outer.PerCallLimit) {
		return &WidensError{Field: "per_call_limit"}
	}
	if !amountWithin(t.ApprovalThreshold, outer.ApprovalThreshold) {
		return &WidensError{Field: "approval_threshold"}
	}
	if t.ValidFrom.Before(outer.ValidFrom) {
		return &WidensError{Field: "valid_from"}
	}
	if t.ValidUntil.After(outer.ValidUntil) {
		return &WidensError{Field: "valid_until"}
	}
	if outer.Targets != nil {
		if t.Targets == nil {
			return &WidensError{Field: "targets"}
		}
		permitted := make(map[string]struct{}, len(outer.Targets))
		for _, target := range outer.Targets {
			permitted[target] = struct{}{}
		}
		for _, target := range t.Targets {
			if _, ok := permitted[target]; !ok {
				return &WidensError{Field: "targets"}
			}
		}
	}
	for _, effectType := range t.EffectTypes {
		if riskRank(t.RiskClasses[effectType]) < riskRank(outer.RiskClasses[effectType]) {
			return &WidensError{Field: "risk_classes"}
		}
		if slices.Contains(outer.ApprovalRequired, effectType) && !slices.Contains(t.ApprovalRequired, effectType) {
			return &WidensError{Field: "approval_required"}
		}
	}
	// Conditions are not compared: admission requires every link's condition
	// to hold, so a child's condition can only narrow.
	return nil
}

// amountWithin: a bound narrows another when the other sets none, or when it is
// set and no higher. For a per-call limit, lower is tighter; for an approval
// threshold, lower asks for approval on more calls, which is also tighter.
func amountWithin(inner, outer *int64) bool {
	if outer == nil {
		return true
	}
	return inner != nil && *inner <= *outer
}

const MandateColumns = `m.mandate_id, m.parent_id, m.depth, m.holder_id, m.effect_types, m.per_call_limit, m.approval_threshold,
	m.valid_from, m.valid_until, m.status, m.created_by, m.approved_by, m.version, m.targets, m.condition, m.risk_classes, m.approval_required`

type rowScanner interface {
	Scan(dest ...any) error
}

func ScanMandate(row rowScanner) (Mandate, error) {
	var m Mandate
	var parent uuid.NullUUID
	var perCall, threshold sql.NullInt64
	var status string
	var approvedBy, condition sql.NullString
	var targets, approvalRequired pq.StringArray
	var risks []byte
	err := row.Scan(&m.ID, &parent, &m.Depth, &m.HolderID, pq.Array(&m.Terms.EffectTypes), &perCall, &threshold,
		&m.Terms.ValidFrom, &m.Terms.ValidUntil, &status, &m.CreatedBy, &approvedBy, &m.Version, &targets, &condition, &risks, &approvalRequired)
	if errors.Is(err, sql.ErrNoRows) {
		return Mandate{}, fmt.Errorf("%w: mandate", ErrNotFound)
	} else if err != nil {
		return Mandate{}, err
	}
	if parent.Valid {
		m.ParentID = &parent.UUID
	}
	if perCall.Valid {
		m.Terms.PerCallLimit = &perCall.Int64
	}
	if threshold.Valid {
		m.Terms.ApprovalThreshold = &threshold.Int64
	}
	m.Terms.ValidFrom = m.Terms.ValidFrom.UTC()
	m.Terms.ValidUntil = m.Terms.ValidUntil.UTC()
	m.Active = status == "active"
	m.ApprovedBy = approvedBy.String
	if targets != nil {
		m.Terms.Targets = []string(targets)
	}
	m.Terms.Condition = condition.String
	if approvalRequired != nil {
		m.Terms.ApprovalRequired = []string(approvalRequired)
	}
	if len(risks) > 0 {
		if err := json.Unmarshal(risks, &m.Terms.RiskClasses); err != nil {
			return Mandate{}, fmt.Errorf("authority rows: mandate %s risk classes: %w", m.ID, err)
		}
	}
	return m, nil
}

// readChain returns mandateID and its ancestors, root first, optionally
// locking them FOR SHARE in that order (the global lock order of ADR-0001 §1).
// The walk follows parent_id one depth at a time, so it ends even on a
// corrupted row.
func readChain(ctx context.Context, tx *sql.Tx, tenantID string, mandateID uuid.UUID, lock bool) ([]Mandate, error) {
	query := `WITH RECURSIVE chain AS (
			SELECT mandate_id, parent_id, depth FROM authority_mandates WHERE tenant_id = $1 AND mandate_id = $2
			UNION ALL
			SELECT p.mandate_id, p.parent_id, p.depth FROM authority_mandates p
			JOIN chain c ON p.mandate_id = c.parent_id AND p.depth = c.depth - 1
			WHERE p.tenant_id = $1)
		SELECT ` + MandateColumns + ` FROM authority_mandates m
		WHERE m.tenant_id = $1 AND m.mandate_id IN (SELECT mandate_id FROM chain)
		ORDER BY m.depth`
	if lock {
		query += ` FOR SHARE OF m`
	}
	rows, err := tx.QueryContext(ctx, query, tenantID, mandateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var chain []Mandate
	for rows.Next() {
		m, err := ScanMandate(rows)
		if err != nil {
			return nil, err
		}
		chain = append(chain, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: mandate %s", ErrNotFound, mandateID)
	}
	for i, m := range chain {
		linked := (i == 0 && m.ParentID == nil) || (i > 0 && m.ParentID != nil && *m.ParentID == chain[i-1].ID)
		if m.Depth != i || !linked {
			return nil, fmt.Errorf("authority rows: mandate %s has a broken delegation chain", mandateID)
		}
	}
	if chain[len(chain)-1].ID != mandateID {
		return nil, fmt.Errorf("authority rows: mandate %s has a broken delegation chain", mandateID)
	}
	return chain, nil
}

// ChainInTx returns mandateID and every mandate above it, root first, in the
// caller's transaction, which must be bound to tenantID. With lock it holds
// FOR SHARE on each link in that order, the ADR-0001 §1 lock order the
// effect gateway's admission transaction follows.
func ChainInTx(ctx context.Context, tx *sql.Tx, tenantID string, mandateID uuid.UUID, lock bool) ([]Mandate, error) {
	return readChain(ctx, tx, tenantID, mandateID, lock)
}
