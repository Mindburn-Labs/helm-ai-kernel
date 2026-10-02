package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

type applyInput struct {
	compiled  *Compiled
	requester string
	// approver is the human who approved the attempt. Empty for a plan that
	// needed no approval.
	approver  string
	attemptID string
}

// what applying does to one mandate node.
type action int

const (
	// keep: the node is what the applied plan has. Its mandate keeps its id.
	keep action = iota
	// narrowInPlace: the change only narrows. The mandate keeps its id and its
	// version is bumped.
	narrowInPlace
	// create: a node the applied plan does not have, or whose recorded mandate
	// is missing.
	create
	// recreate: a change that widens. The mandate is revoked and a new one made,
	// and so is every mandate below it.
	recreate
)

// nodeState is what classifying a node found.
type nodeState struct {
	act action
	// old is the node's recorded mandate under the applied plan, including a
	// revoked mandate whose stops and consumed budgets still cover the node.
	old       *authorityrows.Mandate
	oldLimits []authorityrows.Limit
	// termsDiffer is set for narrowInPlace: its terms are not the old ones.
	termsDiffer bool
	// limits are the limits to set on a kept or narrowed mandate: those added
	// or lowered.
	limits []authorityrows.LimitSpec
}

// apply applies a plan in tx, a transaction bound to the plan's tenant, so that
// it applies whole or not at all (docs/architecture/gateway-provisioning-api.md
// "What applying does"). An error that is a *adapters.Refusal, or that maps to
// one (toRefusal), is a definite refusal: nothing was applied. Any other error
// is a failure of the database.
//
// Locks follow ADR-0001 §1 where the algorithm allows it: principals, then
// mandates from the root down, then effect-type rows that change, then limits.
// Two plans for one organization are serialized by an advisory lock, and a plan
// that meets a concurrent admission's locks waits for it, or one of them is
// chosen as a deadlock victim and fails as a database error, which is retried.
func (a *Adapter) apply(ctx context.Context, tx *authorityrows.Tx, in applyInput) error {
	c := in.compiled
	plan := c.Plan
	narrow := plan.Schema == effectargs.AuthorityNarrow
	sqlTx := tx.SQL()

	if _, err := sqlTx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"authority_provisions:"+tx.TenantID()+":"+plan.OrgRef); err != nil {
		return err
	}
	applied, err := LoadApplied(ctx, sqlTx, tx.TenantID(), plan.OrgRef, true)
	if err != nil {
		return err
	}
	if r := Precheck(c, applied, in.requester); r != nil {
		return r
	}
	if applied != nil && applied.Digest == plan.Digest {
		return nil // applied already: a lost response is safe to retry
	}

	// 1. Principals, then the ones the plan disables.
	for _, p := range plan.Principals {
		if err := ensurePrincipal(ctx, tx, p, narrow); err != nil {
			return err
		}
	}
	for _, id := range plan.Disable {
		if _, err := tx.DisablePrincipal(ctx, id); err != nil {
			return err
		}
	}

	// 2. Effect types: register what is missing (a mandate may name only a
	// registered type) and remember the classes to raise, which lock a row that
	// admission locks after the mandates.
	var raise []effectargs.PlanEffectType
	for _, e := range plan.EffectTypes {
		current, err := tx.EffectType(ctx, e.EffectType)
		switch {
		case errors.Is(err, authorityrows.ErrNotFound):
			if narrow {
				return adapters.Refuse(contracts.ReasonPreconditionFailed,
					"effect type %q is not registered: a narrowing plan registers none", e.EffectType)
			}
			if _, err := tx.EnsureEffectType(ctx, e.EffectType, mandates.RiskClass(e.RiskClass)); err != nil {
				return err
			}
		case err != nil:
			return err
		case mandates.HigherRisk(current.Risk, mandates.RiskClass(e.RiskClass)) != current.Risk:
			// The plan's class is higher than the registered one. A class is
			// only ever raised; a lower or equal one leaves it.
			if narrow {
				return adapters.Refuse(contracts.ReasonPreconditionFailed,
					"effect type %q is registered as %s: a narrowing plan does not raise it to %s", e.EffectType, current.Risk, e.RiskClass)
			}
			raise = append(raise, e)
		}
	}

	// 3. Mandates, parents first, and the limits of each.
	final, err := a.applyMandates(ctx, tx, in, applied)
	if err != nil {
		return err
	}

	// 4. Effect-type classes that rise.
	for _, e := range raise {
		if _, err := tx.EnsureEffectType(ctx, e.EffectType, mandates.RiskClass(e.RiskClass)); err != nil {
			return err
		}
	}

	// 5. The record, by compare-and-set on the digest the plan was built on.
	return writeProvision(ctx, sqlTx, tx.TenantID(), in, applied, final)
}

func ensurePrincipal(ctx context.Context, tx *authorityrows.Tx, p effectargs.PlanPrincipal, narrow bool) error {
	spec := authorityrows.PrincipalSpec{ID: p.ID, Kind: authorityrows.PrincipalKind(p.Kind)}
	if p.External != nil {
		spec.External = &authorityrows.ExternalSubject{System: p.External.System, ID: p.External.ID}
	}
	if !narrow && !p.EnsureOnly {
		_, err := tx.UpsertPrincipal(ctx, spec)
		return err
	}
	// A principal that must exist, or that the plan may create only when it is
	// missing, is read and never changed.
	current, err := tx.Principal(ctx, p.ID)
	switch {
	case errors.Is(err, authorityrows.ErrNotFound):
		if narrow || (spec.Kind == authorityrows.PrincipalHuman && spec.External == nil) {
			return adapters.Refuse(contracts.ReasonPreconditionFailed, "principal %q is not registered", p.ID)
		}
		_, err = tx.UpsertPrincipal(ctx, spec)
		return err
	case err != nil:
		return err
	case current.Kind != spec.Kind:
		return fmt.Errorf("%w: principal %q is a %s, and a kind never changes", authorityrows.ErrIdentityConflict, p.ID, current.Kind)
	case !current.Active:
		return fmt.Errorf("%w: %q is disabled", authorityrows.ErrPrincipalInactive, p.ID)
	case spec.External != nil && current.External != nil && *spec.External != *current.External:
		return fmt.Errorf("%w: principal %q has another external subject", authorityrows.ErrIdentityConflict, p.ID)
	}
	return nil
}

// final is the mandate each plan node ended as.
type final map[string]finalNode

type finalNode struct {
	id     uuid.UUID
	holder string
}

func (a *Adapter) applyMandates(ctx context.Context, tx *authorityrows.Tx, in applyInput, applied *Applied) (final, error) {
	c := in.compiled
	narrow := c.Plan.Schema == effectargs.AuthorityNarrow
	out := make(final, len(c.Nodes))
	type replacement struct{ from, to uuid.UUID }
	var replacements []replacement

	// Parents before children, so that a child's parent has its final id.
	order := make([]int, len(c.Nodes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(x, y int) bool { return c.Nodes[order[x]].Depth < c.Nodes[order[y]].Depth })

	// Nodes the applied plan had and this one drops: revoked, shallowest first.
	if applied != nil {
		inPlan := make(map[string]bool, len(c.Nodes))
		for _, n := range c.Nodes {
			inPlan[n.Name] = true
		}
		var removed []authorityrows.Mandate
		for _, old := range applied.Nodes {
			if inPlan[old.Node] {
				continue
			}
			id, err := uuid.Parse(old.MandateID)
			if err != nil {
				return nil, err
			}
			m, err := tx.Mandate(ctx, id)
			if errors.Is(err, authorityrows.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if m.Active {
				removed = append(removed, m)
			}
		}
		sort.SliceStable(removed, func(x, y int) bool { return removed[x].Depth < removed[y].Depth })
		for _, m := range removed {
			if err := tx.Revoke(ctx, m.ID); err != nil {
				return nil, err
			}
		}
	}

	for _, i := range order {
		n := c.Nodes[i]
		var parent *finalNode
		if n.Parent != "" {
			p := out[n.Parent]
			parent = &p
		}
		st, err := a.classify(ctx, tx, applied, n, parent)
		if err != nil {
			return nil, err
		}
		if narrow && (st.act == create || st.act == recreate) {
			return nil, adapters.Refuse(contracts.ReasonDelegationScopeViolation,
				"mandate %q would be created or re-created: a narrowing plan only narrows", n.Name)
		}
		switch st.act {
		case keep:
			out[n.Name] = finalNode{id: st.old.ID, holder: n.Holder}
		case narrowInPlace:
			if st.termsDiffer {
				if _, err := tx.Narrow(ctx, st.old.ID, n.Terms); err != nil {
					return nil, err
				}
			}
			for _, spec := range st.limits {
				spec.MandateID = &st.old.ID
				if _, err := tx.SetLimit(ctx, spec); err != nil {
					return nil, err
				}
			}
			out[n.Name] = finalNode{id: st.old.ID, holder: n.Holder}
		case create, recreate:
			if st.old != nil {
				// A stop ends by a Lift, never by making a new mandate.
				stopped, err := mandateStopped(ctx, tx.SQL(), tx.TenantID(), st.old.ID)
				if err != nil {
					return nil, err
				}
				if stopped {
					return nil, adapters.Refuse(contracts.ReasonEmergencyStopFenced,
						"mandate %s of node %q is stopped: a stop ends by a lift, not by re-creating the mandate", st.old.ID, n.Name)
				}
				if st.old.Active {
					if err := tx.Revoke(ctx, st.old.ID); err != nil {
						return nil, err
					}
				}
			}
			m, err := createMandate(ctx, tx, in, n, parent)
			if err != nil {
				return nil, err
			}
			for _, spec := range n.Limits {
				spec.MandateID = &m.ID
				limit, err := tx.CreateLimit(ctx, spec)
				if err != nil {
					return nil, err
				}
				// The budget the limit replaces keeps counting: a widening does
				// not open a second one.
				for _, old := range st.oldLimits {
					if limitKey(old.Spec) == limitKey(spec) {
						replacements = append(replacements, replacement{from: old.ID, to: limit.ID})
					}
				}
			}
			out[n.Name] = finalNode{id: m.ID, holder: n.Holder}
		}
		if err := rememberLimits(ctx, tx, in, applied, n.Name, out[n.Name].id); err != nil {
			return nil, err
		}
	}
	// Every old mandate's mutation lock is now held. Settlement locks counters
	// in (limit_id, bucket_start) order; follow that order across the whole plan,
	// regardless of its node or limit order, before copying any source bucket.
	sort.Slice(replacements, func(i, j int) bool { return replacements[i].from.String() < replacements[j].from.String() })
	for _, pair := range replacements {
		if err := carryOver(ctx, tx.SQL(), tx.TenantID(), pair.from, pair.to); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// rememberLimits records actual applied limit IDs, not balances. A node may
// have several limits with the same key, and a later plan may remove and then
// re-add it. Keeping all memberships preserves the old attempts in both cases
// without guessing a single predecessor or counting copied counters twice.
func rememberLimits(ctx context.Context, tx *authorityrows.Tx, in applyInput, applied *Applied, node string, mandate uuid.UUID) error {
	limits, err := tx.MandateLimits(ctx, mandate)
	if err != nil {
		return err
	}
	revision := int64(1)
	if applied != nil {
		revision = applied.Revision + 1
	}
	for _, limit := range limits {
		if _, err := tx.SQL().ExecContext(ctx, `INSERT INTO authority_provision_limits
			(tenant_id, limit_id, org_ref, node, mandate_id, first_plan_digest, first_revision, attempt_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (tenant_id, limit_id) DO NOTHING`,
			tx.TenantID(), limit.ID, in.compiled.Plan.OrgRef, node, mandate, in.compiled.Plan.Digest, revision, in.attemptID); err != nil {
			return err
		}
		// A replay keeps the acquisition metadata. It cannot relabel an
		// existing limit owned by another organization or plan node.
		var matches bool
		if err := tx.SQL().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_provision_limits
			WHERE tenant_id = $1 AND limit_id = $2 AND org_ref = $3 AND node = $4 AND mandate_id = $5)`,
			tx.TenantID(), limit.ID, in.compiled.Plan.OrgRef, node, mandate).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return adapters.Refuse(contracts.ReasonPreconditionFailed, "limit %s has another provision binding", limit.ID)
		}
	}
	return nil
}

func createMandate(ctx context.Context, tx *authorityrows.Tx, in applyInput, n Node, parent *finalNode) (authorityrows.Mandate, error) {
	if parent == nil {
		return tx.CreateMandate(ctx, n.Holder, n.Terms, authorityrows.WideningApproval{RequesterID: in.requester, ApproverID: in.approver})
	}
	return tx.Delegate(ctx, parent.id, parent.holder, n.Holder, n.Terms)
}

// classify decides what applying does to a node, from the mandate the applied
// plan made for it and the plan's terms and limits.
func (a *Adapter) classify(ctx context.Context, tx *authorityrows.Tx, applied *Applied, n Node, parent *finalNode) (nodeState, error) {
	if applied == nil {
		return nodeState{act: create}, nil
	}
	old, ok := applied.node(n.Name)
	if !ok {
		return nodeState{act: create}, nil
	}
	id, err := uuid.Parse(old.MandateID)
	if err != nil {
		return nodeState{}, err
	}
	// Hold the old control row before classifying or reading its stops. A
	// concurrent Stop that wins the lock must be seen before recreation; one
	// that loses cannot attach unnoticed while this transaction replaces it.
	m, err := tx.MandateForUpdate(ctx, id)
	if errors.Is(err, authorityrows.ErrNotFound) {
		return nodeState{act: create}, nil
	}
	if err != nil {
		return nodeState{}, err
	}
	limits, err := tx.MandateLimits(ctx, id)
	if err != nil {
		return nodeState{}, err
	}
	st := nodeState{act: recreate, old: &m, oldLimits: limits}
	if !m.Active {
		return st, nil
	}
	if m.HolderID != n.Holder || !sameParent(m.ParentID, parent) {
		return st, nil
	}
	equal := termsEqual(m.Terms, n.Terms)
	if !equal && !narrows(n.Terms, m.Terms) {
		return st, nil
	}
	// Limits: added or lowered ones narrow; one dropped or raised widens.
	oldByKey := make(map[limitID]int64, len(limits))
	for _, l := range limits {
		k := limitKey(l.Spec)
		if v, seen := oldByKey[k]; !seen || l.Spec.Value < v {
			oldByKey[k] = l.Spec.Value
		}
	}
	newByKey := make(map[limitID]int64, len(n.Limits))
	for _, spec := range n.Limits {
		newByKey[limitKey(spec)] = spec.Value
		switch was, had := oldByKey[limitKey(spec)]; {
		case !had:
			st.limits = append(st.limits, spec)
		case spec.Value > was:
			return st, nil // raised: widens
		case spec.Value < was:
			st.limits = append(st.limits, spec)
		}
	}
	for k := range oldByKey {
		if _, kept := newByKey[k]; !kept {
			return st, nil // dropped: widens
		}
	}
	st.termsDiffer = !equal
	st.act = narrowInPlace
	if equal && len(st.limits) == 0 {
		st.act = keep
	}
	return st, nil
}

// narrows: next grants nothing prior does not, and its condition is prior's or
// is added to a mandate that had none (a replaced condition could admit what the
// old one refused).
func narrows(next, prior authorityrows.Terms) bool {
	return next.Within(prior) == nil && (prior.Condition == "" || next.Condition == prior.Condition)
}

func sameParent(have *uuid.UUID, want *finalNode) bool {
	if have == nil || want == nil {
		return have == nil && want == nil
	}
	return *have == want.id
}

func termsEqual(a, b authorityrows.Terms) bool {
	return slices.Equal(sortedCopy(a.EffectTypes), sortedCopy(b.EffectTypes)) &&
		amountEqual(a.PerCallLimit, b.PerCallLimit) && amountEqual(a.ApprovalThreshold, b.ApprovalThreshold) &&
		a.ValidFrom.Equal(b.ValidFrom) && a.ValidUntil.Equal(b.ValidUntil) &&
		(a.Targets == nil) == (b.Targets == nil) && slices.Equal(sortedCopy(a.Targets), sortedCopy(b.Targets)) &&
		a.Condition == b.Condition &&
		slices.Equal(sortedCopy(a.ApprovalRequired), sortedCopy(b.ApprovalRequired)) &&
		maps.Equal(a.RiskClasses, b.RiskClasses)
}

func amountEqual(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	sort.Strings(out)
	return out
}

// mandateStopped reports an active stop on the mandate itself.
func mandateStopped(ctx context.Context, tx *sql.Tx, tenantID string, id uuid.UUID) (bool, error) {
	var stopped bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_stops
		WHERE tenant_id = $1 AND scope_kind = 'mandate' AND scope_key = $2 AND lifted_at IS NULL
		  AND (expires_at IS NULL OR expires_at > now()))`, tenantID, id.String()).Scan(&stopped)
	return stopped, err
}

// carryOver gives a new limit the amounts the limit it replaces has used, in
// every window bucket that exists, and the distinct values it has seen. What
// the old limit holds in reserve is not carried: a reservation is settled by
// its attempt against the limit it was made on.
func carryOver(ctx context.Context, tx *sql.Tx, tenantID string, from, to uuid.UUID) error {
	// A settlement changes an existing counter without locking its mandate.
	// Lock every source bucket before copying, then use a new READ COMMITTED
	// statement snapshot so a settlement that committed while we waited is
	// included. The old mandate's mutation lock, retained by classify, prevents
	// admission from inserting a bucket or distinct value between this scan
	// and the copy; row locks alone would not protect that insertion gap.
	rows, err := tx.QueryContext(ctx, `SELECT bucket_start FROM authority_counters
		WHERE tenant_id = $1 AND limit_id = $2 ORDER BY limit_id, bucket_start FOR UPDATE`, tenantID, from)
	if err != nil {
		return err
	}
	for rows.Next() {
		var bucket any
		if err := rows.Scan(&bucket); err != nil {
			_ = rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_counters (tenant_id, limit_id, bucket_start, used, reserved)
		SELECT tenant_id, $3, bucket_start, used, 0 FROM authority_counters WHERE tenant_id = $1 AND limit_id = $2
		ON CONFLICT DO NOTHING`, tenantID, from, to); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO authority_distinct_values (tenant_id, limit_id, bucket_start, value_digest, attempt_id)
		SELECT tenant_id, $3, bucket_start, value_digest, attempt_id FROM authority_distinct_values
		WHERE tenant_id = $1 AND limit_id = $2 ON CONFLICT DO NOTHING`, tenantID, from, to)
	return err
}

// writeProvision records the applied plan, replacing the applied one only if it
// is still the plan this one was built on.
func writeProvision(ctx context.Context, tx *sql.Tx, tenantID string, in applyInput, applied *Applied, fin final) error {
	plan := in.compiled.Plan
	nodes := make([]AppliedNode, 0, len(in.compiled.Nodes))
	for _, n := range in.compiled.Nodes {
		f := fin[n.Name]
		nodes = append(nodes, AppliedNode{Node: n.Name, MandateID: f.id.String(), HolderID: f.holder, ParentNode: n.Parent})
	}
	principals := make([]AppliedPrincipal, 0, len(plan.Principals))
	for _, p := range plan.Principals {
		principals = append(principals, AppliedPrincipal{ID: p.ID, Kind: p.Kind})
	}
	nodesJSON, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	principalsJSON, err := json.Marshal(principals)
	if err != nil {
		return err
	}
	// A plan that needs no approval never changes the provisioner: it is
	// accepted only from it.
	if applied == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_provisions
				(tenant_id, org_ref, plan_digest, version_ref, stage, nodes, principals, requested_by, attempt_id, revision, budget_lineage_complete)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, true)`,
			tenantID, plan.OrgRef, plan.Digest, plan.VersionRef, plan.Stage, nodesJSON, principalsJSON, in.requester, in.attemptID)
		return provisionWritten(err, 1)
	}
	res, err := tx.ExecContext(ctx, `UPDATE authority_provisions
		SET plan_digest = $4, version_ref = $5, stage = $6, nodes = $7, principals = $8, requested_by = $9, attempt_id = $10,
		    revision = revision + 1, applied_at = now()
		WHERE tenant_id = $1 AND org_ref = $2 AND plan_digest = $3`,
		tenantID, plan.OrgRef, applied.Digest, plan.Digest, plan.VersionRef, plan.Stage, nodesJSON, principalsJSON, in.requester, in.attemptID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	return provisionWritten(nil, n)
}

func provisionWritten(err error, rows int64) error {
	if err != nil {
		return err
	}
	if rows != 1 {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the organization's applied plan changed while this plan was applied")
	}
	return nil
}

// toRefusal turns an error of applying into the definite refusal it is. An
// error that is not one is a failure of the database, whose outcome the
// caller cannot tell.
func toRefusal(err error) (*adapters.Refusal, bool) {
	if r, ok := refusalOf(err); ok {
		return r, true
	}
	reason := contracts.ReasonCode("")
	switch {
	case errors.Is(err, authorityrows.ErrIdentityConflict):
		reason = contracts.ReasonIdentityIsolationViolation
	case errors.Is(err, authorityrows.ErrPrincipalInactive):
		reason = contracts.ReasonPrincipalInactive
	case errors.Is(err, authorityrows.ErrStopped):
		reason = contracts.ReasonEmergencyStopFenced
	case errors.Is(err, authorityrows.ErrWidens):
		reason = contracts.ReasonDelegationScopeViolation
	case errors.Is(err, authorityrows.ErrNotDelegator):
		reason = contracts.ReasonDelegationPrincipalMismatch
	case errors.Is(err, authorityrows.ErrApproverNotDistinct):
		reason = contracts.ReasonApproverNotDistinct
	case errors.Is(err, authorityrows.ErrApproverNotEligible), errors.Is(err, authorityrows.ErrApprovalRequired):
		reason = contracts.ReasonInsufficientPrivilege
	case errors.Is(err, authorityrows.ErrNotFound), errors.Is(err, authorityrows.ErrInactive), errors.Is(err, authorityrows.ErrExists):
		reason = contracts.ReasonPreconditionFailed
	case errors.Is(err, authorityrows.ErrInvalid):
		reason = contracts.ReasonSchemaViolation
	default:
		return nil, false
	}
	return adapters.Refuse(reason, "%v", err), true
}
