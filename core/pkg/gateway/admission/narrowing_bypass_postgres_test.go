package admission

// CTL-046 against real PostgreSQL 16 (listed in scripts/ci/postgres-proofs.txt).
// The narrowing rule is enforced where the rows are written, by
// authorityrows; the schema itself holds no such constraint, so a role that
// can INSERT into authority_mandates can write a child wider than its parent.
// This is the read side's answer: admission re-checks every link of the chain
// it resolves and denies the wider one.

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

func TestPostgresAWiderChildWrittenAroundTheStoreIsDeniedAtAdmission(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	must(t, f.rows.CreatePrincipal(ctx, tenantA, "agent-b", authorityrows.PrincipalAgent))

	childTerms := func(until time.Time) authorityrows.Terms {
		return authorityrows.Terms{EffectTypes: []string{noteType}, ValidFrom: f.now.Add(-30 * time.Minute), ValidUntil: until,
			Targets: []string{"ops"}, Condition: skeletonCondition}
	}
	within := childTerms(f.now.Add(2 * time.Hour))
	wider := childTerms(f.now.Add(48 * time.Hour)) // the root's window ends in 24 hours

	// Through the store, the wider child is refused and the narrower one stored.
	_, err := f.rows.Delegate(ctx, tenantA, f.mandate.ID, "human-a", "agent-a", wider)
	var widens *authorityrows.WidensError
	if !errors.As(err, &widens) || widens.Field != "valid_until" {
		t.Fatalf("the store accepted a child wider than its parent: %v", err)
	}

	// Around the store, both are written, as a role with INSERT on the table can.
	insertChild := func(holder string, terms authorityrows.Terms) {
		t.Helper()
		id, err := uuid.NewV7()
		must(t, err)
		f.exec(tenantA, `INSERT INTO authority_mandates (tenant_id, mandate_id, holder_id, parent_id, depth, effect_types,
				valid_from, valid_until, created_by, targets, condition)
			VALUES ($1, $2, $3, $4, 1, $5, $6, $7, 'human-a', $8, $9)`,
			tenantA, id, holder, f.mandate.ID, pq.Array(terms.EffectTypes), terms.ValidFrom, terms.ValidUntil,
			pq.Array(terms.Targets), terms.Condition)
	}
	insertChild("agent-a", wider)
	insertChild("agent-b", within)

	caller := func(principal string) Caller {
		return Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: principal, ActorID: actor}
	}
	denied := f.propose(caller("agent-a"), note("wider-1"))
	wantState(t, "a note under the wider child", denied, "DENIED", contracts.ReasonDelegationScopeViolation)
	if denied.Permit != nil {
		t.Fatal("a denied attempt carries a permit")
	}
	// The twin: the same effect under a child within its parent is admitted, so
	// the denial is the widening and not the fixture.
	admitted := f.propose(caller("agent-b"), note("within-1"))
	wantState(t, "a note under the narrower child", admitted, "ADMITTED", "")
}
