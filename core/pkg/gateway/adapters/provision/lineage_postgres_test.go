package provision_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

func TestPostgresProvisionLimitMembershipSurvivesRemovalAndReplacement(t *testing.T) {
	f := newProvisionFixture(t)
	oldChild := provisionNodeID(t, f.original, provisionChild)
	oldLimit := f.limit(oldChild, "usd_micros")
	bucket := f.now.Truncate(24 * time.Hour)
	f.seedCounter(oldLimit.ID, bucket, 12, 7)
	if got := f.scalar(`SELECT count(*) FROM authority_provision_limits`); got != 3 {
		t.Fatalf("initial actual limits recorded = %d", got)
	}
	if got := f.scalar(`SELECT count(*) FROM authority_provisions WHERE budget_lineage_complete`); got != 1 {
		t.Fatal("first provision lacks complete history")
	}

	var plan map[string]any
	provisionMust(t, json.Unmarshal(f.plan(effectargs.AuthorityProvision, f.original.Digest, "removed", 100), &plan))
	plan["mandates"] = plan["mandates"].([]any)[:1]
	plan["limits"] = plan["limits"].([]any)[:1]
	raw, err := json.Marshal(plan)
	provisionMust(t, err)
	f.wantSent(f.dispatch(f.effect(raw)))
	if got := f.scalar(`SELECT count(*) FROM authority_provision_limits`); got != 3 {
		t.Fatalf("removed node lost its historical limits: %d", got)
	}
	f.wantCounter(oldLimit.ID, bucket, 12, 7)

	f.wantSent(f.dispatch(f.effect(f.plan(effectargs.AuthorityProvision, f.applied().Digest, "re-added", 100))))
	if got := f.scalar(`SELECT count(*) FROM authority_provision_limits WHERE node = $1`, provisionChild); got != 4 {
		t.Fatalf("re-added node did not retain both sets of actual limits: %d", got)
	}
	current := provisionNodeID(t, f.applied(), provisionChild)
	if current == oldChild {
		t.Fatal("fixture did not re-create the removed node")
	}
	currentLimit := f.limit(current, "usd_micros")
	f.seedCounter(currentLimit.ID, bucket, 8, 3)
	f.wantSent(f.dispatch(f.effect(f.plan(effectargs.AuthorityProvision, f.applied().Digest, "wider", 200))))
	if got := f.scalar(`SELECT count(*) FROM authority_provision_limits`); got != 8 {
		t.Fatalf("widening lost historical memberships: %d", got)
	}
	f.wantCounter(oldLimit.ID, bucket, 12, 7)
	f.wantCounter(currentLimit.ID, bucket, 8, 3)
	newLimit := f.limit(provisionNodeID(t, f.applied(), provisionChild), "usd_micros")
	f.wantCounter(newLimit.ID, bucket, 8, 0)
	if got := f.scalar(`SELECT count(*) FROM authority_provision_limits WHERE first_revision = 1 AND first_plan_digest = $1 AND attempt_id = $2`, f.original.Digest, f.firstID); got != 3 {
		t.Fatalf("later plans rewrote first acquisition metadata: %d", got)
	}
	// The current used counter and its predecessor each contain 8. Those are
	// not two charges. Membership lets the reader select original attempts.
}

func TestPostgresProvisionLimitMembershipReplayNarrowAndRestrictedRole(t *testing.T) {
	f := newProvisionFixture(t)
	f.wantSent(f.dispatch(f.effect(f.first)))
	f.wantSent(f.dispatch(f.effect(f.plan(effectargs.AuthorityNarrow, f.applied().Digest, "narrow", 90))))
	if got := f.scalar(`SELECT count(*) FROM authority_provision_limits WHERE first_revision = 1 AND attempt_id = $1`, f.firstID); got != 3 {
		t.Fatalf("replay or narrowing rewrote/duplicated membership: %d", got)
	}
	var unset int
	provisionMust(t, f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM authority_provision_limits`).Scan(&unset))
	if unset != 0 {
		t.Fatalf("unset tenant saw %d foreign memberships", unset)
	}
	for _, tenant := range []string{"tenant-other"} {
		var n int
		provisionMust(t, f.rows.InTenant(f.ctx, tenant, func(tx *authorityrows.Tx) error {
			return tx.SQL().QueryRowContext(f.ctx, `SELECT count(*) FROM authority_provision_limits`).Scan(&n)
		}))
		if n != 0 {
			t.Fatalf("tenant %q saw %d foreign memberships", tenant, n)
		}
	}
	err := f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		_, err := tx.SQL().ExecContext(f.ctx, `UPDATE authority_provision_limits SET first_revision = 99`)
		return err
	})
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("runtime can rewrite historical membership: %v", err)
	}
}

func TestPostgresProvisionLegacyLimitHistoryStaysIncomplete(t *testing.T) {
	f := newProvisionFixture(t)
	// Emulate a pre-migration database: it has a current provision, but no
	// retained old-limit membership. Only the fixture owner can erase history.
	var schema string
	provisionMust(t, f.db.QueryRowContext(f.ctx, `SELECT current_schema()`).Scan(&schema))
	_, err := f.admin.ExecContext(f.ctx, `DELETE FROM `+pq.QuoteIdentifier(schema)+`.authority_provision_limits`)
	provisionMust(t, err)
	provisionMust(t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		_, err := tx.SQL().ExecContext(f.ctx, `UPDATE authority_provisions SET budget_lineage_complete = false`)
		return err
	}))
	f.wantSent(f.dispatch(f.effect(f.plan(effectargs.AuthorityProvision, f.original.Digest, "v2", 200))))
	if got := f.scalar(`SELECT count(*) FROM authority_provisions WHERE budget_lineage_complete`); got != 0 {
		t.Fatal("applying a new plan falsely repaired lost legacy history")
	}
	if got := f.scalar(`SELECT count(*) FROM authority_provision_limits`); got != 3 {
		t.Fatalf("legacy apply did not record its actual new limits: %d", got)
	}
}
