package provision

// This read model uses actual provision membership and the native model-call
// ledger. Copied counters are enforcement state, not additional spending.
// quantum_posture: EvidenceDigest hashes the read snapshot; it is not a signed
// receipt, a verification verdict, or a new cryptographic control.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	maxBudgetMembers  = 256
	maxBudgetAttempts = 10000
)

var (
	ErrBudgetReader  = errors.New("budget reads require an active service principal")
	ErrBudgetBinding = errors.New("the requested budget binding is not current")
)

// BudgetBinding is the exact applied authority the CP retained from gateway
// readback. CP-only identifiers and token identity are not supplied here.
type BudgetBinding struct {
	OrgRef       string `json:"org_ref"`
	VersionRef   string `json:"version_ref"`
	PlanDigest   string `json:"plan_digest"`
	Revision     int64  `json:"revision"`
	Node         string `json:"node"`
	MandateID    string `json:"mandate_id"`
	LimitID      string `json:"limit_id"`
	LimitVersion int64  `json:"limit_version"`
}

// BudgetAmounts are integer USD micros. SpentFinal is confirmed billable
// usage; SetAside includes unclaimed holds and unresolved model calls.
type BudgetAmounts struct {
	Cap        int64 `json:"cap,string"`
	SpentFinal int64 `json:"spent_final,string"`
	SetAside   int64 `json:"set_aside,string"`
}

// BudgetSnapshot omits amounts whenever the cohort cannot be proved complete.
// Activity is no_runs_yet only after a complete, empty native ledger read.
type BudgetSnapshot struct {
	Binding              BudgetBinding  `json:"binding"`
	AsOf                 time.Time      `json:"as_of"`
	CoverageComplete     bool           `json:"coverage_complete"`
	Activity             string         `json:"activity"`
	Reason               string         `json:"reason,omitempty"`
	Amounts              *BudgetAmounts `json:"amounts,omitempty"`
	OverageDetected      bool           `json:"overage_detected"`
	EnforcementAvailable bool           `json:"enforcement_available"`
	EvidenceDigest       []byte         `json:"evidence_digest,omitempty"`
}

func (b BudgetBinding) valid() bool {
	digest, err := hex.DecodeString(b.PlanDigest)
	m, me := uuid.Parse(b.MandateID)
	l, le := uuid.Parse(b.LimitID)
	return effectargs.ValidOrgRef(b.OrgRef) && b.VersionRef != "" && b.Node != "" &&
		b.Revision > 0 && b.LimitVersion > 0 && err == nil && len(digest) == sha256.Size &&
		hex.EncodeToString(digest) == b.PlanDigest && me == nil && le == nil &&
		m != uuid.Nil && l != uuid.Nil && m.String() == b.MandateID && l.String() == b.LimitID
}

// GetProvisionBudget reads one tenant/workspace snapshot. The server supplies
// all identity arguments from its authenticated read-scoped token. A legacy
// provision with incomplete history cannot be repaired by a later apply.
func GetProvisionBudget(ctx context.Context, store *authorityrows.Store, tenant, workspace, principal string, binding BudgetBinding) (*BudgetSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if !binding.valid() || workspace == "" {
		return nil, authorityrows.ErrInvalid
	}
	out := &BudgetSnapshot{Binding: binding, Activity: "not_reported"}
	err := store.ReadInTenant(ctx, tenant, func(tx *authorityrows.Tx) error {
		p, err := tx.Principal(ctx, principal)
		if errors.Is(err, authorityrows.ErrNotFound) || (err == nil && (!p.Active || p.Kind != authorityrows.PrincipalService)) {
			return ErrBudgetReader
		}
		if err != nil {
			return err
		}
		if err = tx.SQL().QueryRowContext(ctx, `SELECT transaction_timestamp()`).Scan(&out.AsOf); err != nil {
			return err
		}
		applied, err := LoadApplied(ctx, tx.SQL(), tenant, binding.OrgRef, false)
		if err != nil {
			return err
		}
		if applied == nil {
			return ErrNotProvisioned
		}
		node, ok := applied.node(binding.Node)
		if !ok || node.MandateID != binding.MandateID || applied.VersionRef != binding.VersionRef ||
			applied.Digest != binding.PlanDigest || applied.Revision != binding.Revision {
			return ErrBudgetBinding
		}
		limit, err := tx.Limit(ctx, uuid.MustParse(binding.LimitID))
		if errors.Is(err, authorityrows.ErrNotFound) {
			return ErrBudgetBinding
		}
		if err != nil {
			return err
		}
		if limit.Version != binding.LimitVersion || limit.Spec.MandateID == nil || limit.Spec.MandateID.String() != binding.MandateID {
			return ErrBudgetBinding
		}
		if limit.Spec.Unit != "usd_micros" || limit.Spec.Measure != "sum" || limit.Spec.Window != "none" || limit.Spec.Span != 1 {
			out.Reason = "unsupported_budget_window"
			return nil
		}
		var complete bool
		var appliedWorkspace string
		err = tx.SQL().QueryRowContext(ctx, `SELECT p.budget_lineage_complete, a.workspace_id
			FROM authority_provisions p JOIN authority_effect_attempts a
			ON a.tenant_id=p.tenant_id AND a.attempt_id=p.attempt_id
			WHERE p.tenant_id=$1 AND p.org_ref=$2`, tenant, binding.OrgRef).Scan(&complete, &appliedWorkspace)
		if err != nil {
			return err
		}
		if !complete || appliedWorkspace != workspace {
			out.Reason = "incomplete_budget_lineage"
			return nil
		}
		members, reason, err := budgetMembers(ctx, tx, workspace, binding)
		if err != nil || reason != "" {
			out.Reason = reason
			return err
		}
		amounts, active, overage, reason, err := budgetUsage(ctx, tx, workspace, members)
		if err != nil || reason != "" {
			out.Reason = reason
			return err
		}
		amounts.Cap = limit.Spec.Value
		out.Amounts, out.CoverageComplete = amounts, true
		out.OverageDetected, out.EnforcementAvailable = overage, !overage
		out.Activity = "no_runs_yet"
		if active {
			out.Activity = "reported"
		}
		if overage {
			out.Reason = "provider_usage_exceeded_hold"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.AsOf = out.AsOf.UTC()
	body, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	out.EvidenceDigest = digest[:]
	return out, nil
}

func budgetMembers(ctx context.Context, tx *authorityrows.Tx, workspace string, b BudgetBinding) ([]string, string, error) {
	rows, err := tx.SQL().QueryContext(ctx, `SELECT h.limit_id, h.mandate_id, l.mandate_id, a.workspace_id,
		l.measure, l.window_kind, l.span
		FROM authority_provision_limits h
		JOIN authority_limits l ON l.tenant_id=h.tenant_id AND l.limit_id=h.limit_id
		JOIN authority_effect_attempts a ON a.tenant_id=h.tenant_id AND a.attempt_id=h.attempt_id
		WHERE h.tenant_id=$1 AND h.org_ref=$2 AND h.node=$3 AND h.first_revision <= $4
		AND l.unit='usd_micros'
		ORDER BY h.limit_id LIMIT $5`, tx.TenantID(), b.OrgRef, b.Node, b.Revision, maxBudgetMembers+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var ids []string
	found := false
	for rows.Next() {
		var id, memberMandate, actualMandate, originWorkspace string
		var measure, window string
		var span int
		if err := rows.Scan(&id, &memberMandate, &actualMandate, &originWorkspace, &measure, &window, &span); err != nil {
			return nil, "", err
		}
		if originWorkspace != workspace || memberMandate != actualMandate {
			return nil, "incomplete_budget_lineage", nil
		}
		// A window change does not erase earlier spend. This lifetime read
		// cannot claim a complete cohort by filtering incompatible history.
		if measure != "sum" || window != "none" || span != 1 {
			return nil, "unsupported_budget_history", nil
		}
		ids = append(ids, id)
		found = found || id == b.LimitID
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if !found || len(ids) > maxBudgetMembers {
		return nil, "incomplete_budget_lineage", nil
	}
	return ids, "", nil
}

// UNION deduplicates historical exposures and permits before joining model
// calls. Permit versions deliberately need not equal today's limit version:
// narrowing a limit must not erase earlier activity, including zero quotes.
const budgetUsageSQL = `WITH cohort AS (
	SELECT attempt_id FROM authority_exposures WHERE tenant_id=$1 AND limit_id=ANY($2::uuid[])
	UNION
	SELECT p.attempt_id FROM authority_permits p WHERE p.tenant_id=$1 AND EXISTS (
		SELECT 1 FROM jsonb_array_elements(p.authority_versions) v
		WHERE v->>'kind'='limit' AND v->>'key'=ANY($2::text[]))
)
SELECT a.workspace_id, a.effect_type, a.state, a.quote, m.state, m.currency_code,
	m.held_micros, m.estimated_micros, m.confirmed_micros, m.billable_micros,
	e.n, e.min_kind, e.max_kind, e.min_amount, e.max_amount
FROM cohort c JOIN authority_effect_attempts a ON a.tenant_id=$1 AND a.attempt_id=c.attempt_id
LEFT JOIN authority_model_calls m ON m.tenant_id=a.tenant_id AND m.attempt_id=a.attempt_id
LEFT JOIN LATERAL (
	SELECT count(*) n, min(kind) min_kind, max(kind) max_kind, min(amount) min_amount, max(amount) max_amount
	FROM authority_exposures x WHERE x.tenant_id=a.tenant_id AND x.attempt_id=a.attempt_id AND x.limit_id=ANY($2::uuid[])
) e ON true
ORDER BY a.attempt_id LIMIT $3`

type budgetCall struct {
	quote                                          []byte
	workspace, effectType, attemptState            string
	state, currency, minKind, maxKind              sql.NullString
	held, estimated, confirmed, billable, min, max sql.NullInt64
	exposures                                      int64
}

func budgetUsage(ctx context.Context, tx *authorityrows.Tx, workspace string, members []string) (*BudgetAmounts, bool, bool, string, error) {
	rows, err := tx.SQL().QueryContext(ctx, budgetUsageSQL, tx.TenantID(), pq.Array(members), maxBudgetAttempts+1)
	if err != nil {
		return nil, false, false, "", err
	}
	defer rows.Close()
	out := &BudgetAmounts{}
	count, overage := 0, false
	for rows.Next() {
		count++
		var c budgetCall
		if err := rows.Scan(&c.workspace, &c.effectType, &c.attemptState, &c.quote, &c.state, &c.currency,
			&c.held, &c.estimated, &c.confirmed, &c.billable, &c.exposures, &c.minKind, &c.maxKind, &c.min, &c.max); err != nil {
			return nil, false, false, "", err
		}
		if count > maxBudgetAttempts || c.workspace != workspace {
			return nil, false, false, "incomplete_budget_cohort", nil
		}
		spent, held, excess, ok := c.amounts()
		if !ok || spent > math.MaxInt64-out.SpentFinal || held > math.MaxInt64-out.SetAside {
			return nil, false, false, "unreportable_budget_usage", nil
		}
		out.SpentFinal += spent
		out.SetAside += held
		overage = overage || excess
	}
	if err := rows.Err(); err != nil {
		return nil, false, false, "", err
	}
	if out.SpentFinal > math.MaxInt64-out.SetAside {
		return nil, false, false, "unreportable_budget_usage", nil
	}
	return out, count != 0, overage, "", nil
}

func (c budgetCall) amounts() (spent, held int64, overage, ok bool) {
	// This API reports native model spend only. An unrecognized financial
	// effect in this cohort is missing evidence, not a free operation.
	if c.effectType != effectargs.ModelInference || c.minKind != c.maxKind || c.min != c.max {
		return 0, 0, false, false
	}
	if !c.state.Valid {
		switch c.attemptState {
		case "ADMITTED":
			quoted, valid := quotedUSD(c.quote)
			return 0, quoted, false, valid && c.exposureIs("held", quoted)
		case "CANCELLED", "EXPIRED":
			return 0, 0, false, c.exposureIs("released", 0)
		default:
			return 0, 0, false, false
		}
	}
	if c.currency.String != "USD" || !c.held.Valid || !c.billable.Valid || c.held.Int64 < 0 ||
		c.billable.Int64 < 0 || c.billable.Int64 > c.held.Int64 {
		return 0, 0, false, false
	}
	switch c.state.String {
	case "HELD":
		return 0, c.held.Int64, false, c.billable.Int64 == 0 && c.exposureIs("held", c.held.Int64)
	case "ESTIMATED", "UNRESOLVED_FINAL":
		return 0, c.held.Int64, false, c.estimated.Valid && c.estimated.Int64 == c.held.Int64 && c.billable.Int64 == 0 && c.exposureIs("estimated", c.held.Int64)
	case "CONFIRMED":
		billable := min(c.held.Int64, c.confirmed.Int64)
		// Counters retain the provider's reported amount, while billable is
		// capped at the hold. A zero quote can have no exposure row at all.
		exposureOK := c.exposureIs("confirmed", c.confirmed.Int64) || (c.held.Int64 == 0 && c.exposures == 0)
		return billable, 0, c.confirmed.Int64 > c.held.Int64, c.confirmed.Valid && c.confirmed.Int64 >= 0 && c.billable.Int64 == billable && exposureOK
	case "RELEASED":
		return 0, 0, false, c.billable.Int64 == 0 && c.exposureIs("released", 0)
	}
	return 0, 0, false, false
}

func (c budgetCall) exposureIs(kind string, amount int64) bool {
	return (c.exposures == 0 && amount == 0) ||
		(c.exposures > 0 && c.minKind.Valid && c.min.Valid && c.minKind.String == kind && c.min.Int64 == amount)
}

func quotedUSD(raw []byte) (int64, bool) {
	var amounts []struct {
		Unit   string `json:"unit"`
		Amount int64  `json:"amount"`
	}
	if json.Unmarshal(raw, &amounts) != nil {
		return 0, false
	}
	var out int64
	found := false
	for _, amount := range amounts {
		if amount.Unit == "usd_micros" {
			if found || amount.Amount < 0 {
				return 0, false
			}
			out, found = amount.Amount, true
		}
	}
	return out, found
}
