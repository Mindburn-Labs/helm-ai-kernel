package provision_test

// These proofs exercise the authority adapter over the gateway's real schema
// and a restricted PostgreSQL role. The invocation and approved attempt are
// gateway fixtures; RPC authentication and step-up are tested by their owners.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

const (
	provisionTenant = "tenant-provision"
	provisionOrg    = "org:atomic-recovery"
	provisionChild  = "team:atomic-recovery"
	provisioner     = "svc:helm-org"
	provisionOwner  = "usr_owner"
)

type provisionFixture struct {
	t        *testing.T
	ctx      context.Context
	admin    *sql.DB
	db       *sql.DB
	rows     *authorityrows.Store
	adapter  *provision.Adapter
	appName  string
	now      time.Time
	first    []byte
	firstID  string
	original *provision.Applied
}

func provisionMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newProvisionFixture(t *testing.T) *provisionFixture {
	t.Helper()
	return newProvisionFixtureWithPlan(t, nil)
}

func newProvisionFixtureWithPlan(t *testing.T, initial func(*provisionFixture) []byte) *provisionFixture {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the provisioning transaction proofs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	admin, err := sql.Open("postgres", base)
	provisionMust(t, err)
	schema := fmt.Sprintf("helm_provision_%d", time.Now().UnixNano())
	role := schema + "_role"
	_, err = admin.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema))
	provisionMust(t, err)
	parsed, err := url.Parse(base)
	provisionMust(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	owner, err := sql.Open("postgres", parsed.String())
	provisionMust(t, err)
	provisionMust(t, admission.Migrate(ctx, owner))
	for _, stmt := range []string{
		`CREATE ROLE ` + pq.QuoteIdentifier(role) + ` NOLOGIN NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA ` + pq.QuoteIdentifier(schema) + ` TO ` + pq.QuoteIdentifier(role),
		`GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ` + pq.QuoteIdentifier(schema) + ` TO ` + pq.QuoteIdentifier(role),
		`REVOKE UPDATE ON authority_distinct_values, authority_token_replay, authority_provision_limits FROM ` + pq.QuoteIdentifier(role),
	} {
		_, err = owner.ExecContext(ctx, stmt)
		provisionMust(t, err)
	}
	appName := schema + "_provision"
	query.Set("options", "-c role="+role)
	query.Set("application_name", appName)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("postgres", parsed.String())
	provisionMust(t, err)
	db.SetMaxOpenConns(6)
	t.Cleanup(func() {
		cancel()
		_ = db.Close()
		_ = owner.Close()
		_, _ = admin.Exec(`DROP SCHEMA ` + pq.QuoteIdentifier(schema) + ` CASCADE`)
		_, _ = admin.Exec(`DROP ROLE ` + pq.QuoteIdentifier(role))
		_ = admin.Close()
	})
	a, err := provision.New(db)
	provisionMust(t, err)
	f := &provisionFixture{t: t, ctx: ctx, admin: admin, db: db, rows: a.Store(), adapter: a, appName: appName}
	provisionMust(t, admin.QueryRowContext(ctx, `SELECT now()`).Scan(&f.now))
	f.now = f.now.UTC().Truncate(time.Second)
	provisionMust(t, f.rows.InTenant(ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		if _, _, err := tx.EnsureTenant(ctx); err != nil {
			return err
		}
		for _, p := range []authorityrows.PrincipalSpec{
			{ID: provisioner, Kind: authorityrows.PrincipalService},
			{ID: provisionOwner, Kind: authorityrows.PrincipalHuman,
				External: &authorityrows.ExternalSubject{System: "helm-control-plane", ID: provisionOwner}},
		} {
			if _, err := tx.UpsertPrincipal(ctx, p); err != nil {
				return err
			}
		}
		return nil
	}))
	f.first = f.plan(effectargs.AuthorityProvision, "", "v1", 100)
	if initial != nil {
		f.first = initial(f)
	}
	effect := f.effect(f.first)
	f.firstID = effect.Invocation.AttemptID
	f.wantSent(f.dispatch(effect))
	f.original = f.applied()
	return f
}

func (f *provisionFixture) plan(schema, base, version string, rootBudget int64) []byte {
	f.t.Helper()
	doc := map[string]any{
		"schema": schema, "org_ref": provisionOrg, "version_ref": version, "stage": "constrained-live", "base_plan_digest": base,
		"valid_from": f.now.Add(-time.Minute).Format(time.RFC3339), "valid_until": f.now.Add(24 * time.Hour).Format(time.RFC3339),
		"effect_types":       []any{map[string]any{"effect_type": "ops.note", "risk_class": "low"}},
		"principals":         []any{map[string]any{"id": provisionOrg, "kind": "service"}, map[string]any{"id": provisionChild, "kind": "service"}},
		"disable_principals": []any{},
		"mandates": []any{
			map[string]any{"node": provisionOrg, "holder": provisionOrg, "parent": nil,
				"terms": map[string]any{"effect_types": []string{"ops.note"}, "targets": nil}},
			map[string]any{"node": provisionChild, "holder": provisionChild, "parent": provisionOrg,
				"terms": map[string]any{"effect_types": []string{"ops.note"}, "targets": []string{"resource:one"}}},
		},
		"limits": []any{
			map[string]any{"node": provisionOrg, "unit": "usd_micros", "measure": "sum", "window": "day", "span": 2, "value": rootBudget},
			map[string]any{"node": provisionChild, "unit": "usd_micros", "measure": "sum", "window": "day", "span": 2, "value": 80},
			map[string]any{"node": provisionChild, "unit": "projects", "measure": "distinct", "window": "day", "span": 1, "value": 50},
		},
	}
	raw, err := json.Marshal(doc)
	provisionMust(f.t, err)
	_, err = provision.Check(schema, raw)
	provisionMust(f.t, err)
	return raw
}

// effect records the attempt and approval that the gateway normally commits
// before invoking an adapter. It does not stand in for approval-token tests.
func (f *provisionFixture) effect(raw []byte) adapters.Effect {
	f.t.Helper()
	var doc struct {
		Schema string `json:"schema"`
	}
	provisionMust(f.t, json.Unmarshal(raw, &doc))
	id := uuid.NewString()
	digest := sha256.Sum256(raw)
	provisionMust(f.t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		_, err := tx.SQL().ExecContext(f.ctx, `INSERT INTO authority_effect_attempts
			(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
			 effect_type, target, target_digest, argument_digest, state)
			VALUES ($1, $2::uuid, 'workspace-provision', $2::text, $3, $4, $5, $6, $3, $3, 'DISPATCHING')`,
			provisionTenant, id, digest[:], provisioner, doc.Schema, provisionOrg)
		if err != nil || doc.Schema == effectargs.AuthorityNarrow {
			return err
		}
		_, err = tx.SQL().ExecContext(f.ctx, `INSERT INTO authority_approvals
			(tenant_id, attempt_id, approver_principal_id, decision, approval_digest)
			VALUES ($1, $2, $3, 'APPROVED', $4)`, provisionTenant, id, provisionOwner, digest[:])
		return err
	}))
	return adapters.Effect{EffectType: doc.Schema, Target: provisionOrg, Arguments: raw,
		Invocation: &adapters.Invocation{TenantID: provisionTenant, AttemptID: id, RequesterPrincipalID: provisioner}}
}

func (f *provisionFixture) dispatch(effect adapters.Effect) adapters.DispatchResult {
	digest := sha256.Sum256(effect.Arguments)
	return f.adapter.Dispatch(f.ctx, nil, effect, digest[:])
}

func (f *provisionFixture) wantSent(result adapters.DispatchResult) {
	f.t.Helper()
	if result.Status != adapters.DispatchSent {
		f.t.Fatalf("dispatch = %+v, want SENT", result)
	}
}

func (f *provisionFixture) wantRefused(result adapters.DispatchResult, reason contracts.ReasonCode) {
	f.t.Helper()
	if result.Status != adapters.DispatchNotSent || result.Reason != reason {
		f.t.Fatalf("dispatch = %+v, want NOT_SENT/%s", result, reason)
	}
}

func (f *provisionFixture) applied() *provision.Applied {
	f.t.Helper()
	var out *provision.Applied
	provisionMust(f.t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		var err error
		out, err = provision.LoadApplied(f.ctx, tx.SQL(), provisionTenant, provisionOrg, false)
		return err
	}))
	if out == nil {
		f.t.Fatal("no applied plan")
	}
	return out
}

func provisionNodeID(t *testing.T, applied *provision.Applied, name string) uuid.UUID {
	t.Helper()
	for _, n := range applied.Nodes {
		if n.Node == name {
			id, err := uuid.Parse(n.MandateID)
			provisionMust(t, err)
			return id
		}
	}
	t.Fatal("applied plan lacks node " + name)
	return uuid.Nil
}

func (f *provisionFixture) limit(id uuid.UUID, unit string) authorityrows.Limit {
	f.t.Helper()
	var limits []authorityrows.Limit
	provisionMust(f.t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		var err error
		limits, err = tx.MandateLimits(f.ctx, id)
		return err
	}))
	for _, limit := range limits {
		if limit.Spec.Unit == unit {
			return limit
		}
	}
	f.t.Fatal("missing limit for " + unit)
	return authorityrows.Limit{}
}

func (f *provisionFixture) scalar(query string, args ...any) int64 {
	f.t.Helper()
	var out int64
	provisionMust(f.t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		return tx.SQL().QueryRowContext(f.ctx, query, args...).Scan(&out)
	}))
	return out
}

func (f *provisionFixture) begin() (*sql.Tx, int) {
	f.t.Helper()
	tx, err := f.db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	provisionMust(f.t, err)
	f.t.Cleanup(func() { _ = tx.Rollback() })
	_, err = tx.ExecContext(f.ctx, `SELECT set_config('app.current_tenant', $1, true)`, provisionTenant)
	provisionMust(f.t, err)
	var pid int
	var isolation string
	provisionMust(f.t, tx.QueryRowContext(f.ctx, `SELECT pg_backend_pid(), current_setting('transaction_isolation')`).Scan(&pid, &isolation))
	if isolation != "read committed" {
		f.t.Fatalf("isolation = %s", isolation)
	}
	return tx, pid
}

// waitBlocked verifies the exact competing backend lock, rather than relying
// on a sleep to guess that the tested transaction reached a particular read.
func (f *provisionFixture) waitBlocked(blocker int, table string, completed <-chan adapters.DispatchResult) int {
	f.t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var pid int
		var query string
		err := f.admin.QueryRowContext(f.ctx, `SELECT pid, query FROM pg_stat_activity
			WHERE application_name = $1 AND $2 = ANY(pg_blocking_pids(pid)) AND query LIKE $3 LIMIT 1`,
			f.appName, blocker, "%"+table+"%").Scan(&pid, &query)
		if err == nil {
			f.t.Logf("backend %d waits for %d: %s", pid, blocker, strings.Join(strings.Fields(query), " "))
			return pid
		}
		if !errors.Is(err, sql.ErrNoRows) {
			f.t.Fatal(err)
		}
		select {
		case result := <-completed:
			f.t.Fatalf("dispatch completed before waiting for %s: %+v", table, result)
		case <-deadline.C:
			f.t.Fatalf("no backend waiting for %s on blocker %d", table, blocker)
		case <-f.ctx.Done():
			f.t.Fatal(f.ctx.Err())
		case <-tick.C:
		}
	}
}

func (f *provisionFixture) async(effect adapters.Effect) <-chan adapters.DispatchResult {
	completed := make(chan adapters.DispatchResult, 1)
	go func() { completed <- f.dispatch(effect) }()
	return completed
}

func (f *provisionFixture) stop(id uuid.UUID, expires *time.Time) authorityrows.Stop {
	f.t.Helper()
	stop, err := f.rows.Stop(f.ctx, provisionTenant, authorityrows.StopSpec{
		Scope: authorityrows.Scope{Kind: authorityrows.ScopeMandate, Key: id.String()}, Reason: "regression fence", IssuedBy: provisionOwner, ExpiresAt: expires})
	provisionMust(f.t, err)
	return stop
}

func (f *provisionFixture) seedCounter(limit uuid.UUID, bucket time.Time, used, reserved int64) {
	f.t.Helper()
	provisionMust(f.t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		_, err := tx.SQL().ExecContext(f.ctx, `INSERT INTO authority_counters (tenant_id, limit_id, bucket_start, used, reserved)
			VALUES ($1, $2, $3, $4, $5)`, provisionTenant, limit, bucket, used, reserved)
		return err
	}))
}

func (f *provisionFixture) wantCounter(limit uuid.UUID, bucket time.Time, wantUsed, wantReserved int64) {
	f.t.Helper()
	var used, reserved int64
	provisionMust(f.t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		return tx.SQL().QueryRowContext(f.ctx, `SELECT used, reserved FROM authority_counters WHERE limit_id = $1 AND bucket_start = $2`,
			limit, bucket).Scan(&used, &reserved)
	}))
	if used != wantUsed || reserved != wantReserved {
		f.t.Fatalf("limit %s bucket %s = used %d reserved %d, want %d/%d", limit, bucket, used, reserved, wantUsed, wantReserved)
	}
}

func TestPostgresProvisionRecreateWaitsForConcurrentStop(t *testing.T) {
	f := newProvisionFixture(t)
	old := provisionNodeID(t, f.original, provisionOrg)
	effect := f.effect(f.plan(effectargs.AuthorityProvision, f.original.Digest, "v2", 200))
	stopTx, pid := f.begin()
	defer stopTx.Rollback()
	found, err := mandates.BumpControlRow(f.ctx, stopTx, provisionTenant, "mandate", old.String())
	provisionMust(t, err)
	if !found {
		t.Fatal("stop target not found")
	}
	_, err = stopTx.ExecContext(f.ctx, `INSERT INTO authority_stops (tenant_id, stop_id, scope_kind, scope_key, reason, issued_by)
		VALUES ($1, $2, 'mandate', $3, 'concurrent fence', $4)`, provisionTenant, uuid.NewString(), old.String(), provisionOwner)
	provisionMust(t, err)
	completed := f.async(effect)
	f.waitBlocked(pid, "authority_mandates", completed)
	provisionMust(t, stopTx.Commit())
	f.wantRefused(<-completed, contracts.ReasonEmergencyStopFenced)
	if after := f.applied(); after.Digest != f.original.Digest || after.Revision != 1 || provisionNodeID(t, after, provisionOrg) != old {
		t.Fatalf("stopped plan changed: %+v", after)
	}
	if n := f.scalar(`SELECT count(*) FROM authority_mandates`); n != 2 {
		t.Fatalf("%d mandates after refused recreation", n)
	}
}

func TestPostgresProvisionRevokedNodePreservesFenceAndBudget(t *testing.T) {
	for _, state := range []string{"unstopped", "active-stop", "expired-stop", "lifted-stop", "narrow"} {
		t.Run(state, func(t *testing.T) {
			f := newProvisionFixture(t)
			old := provisionNodeID(t, f.original, provisionChild)
			limit := f.limit(old, "usd_micros")
			bucket := f.now.Truncate(24 * time.Hour)
			f.seedCounter(limit.ID, bucket, 12, 2)
			f.seedCounter(limit.ID, bucket.Add(-24*time.Hour), 8, 1)
			provisionMust(t, f.rows.Revoke(f.ctx, provisionTenant, old))
			if state == "active-stop" || state == "expired-stop" || state == "lifted-stop" {
				var expires *time.Time
				if state == "expired-stop" {
					future := f.now.Add(time.Hour)
					expires = &future
				}
				stop := f.stop(old, expires)
				if state == "expired-stop" {
					// Age the fixture while preserving expires_at > created_at.
					provisionMust(t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
						_, err := tx.SQL().ExecContext(f.ctx, `UPDATE authority_stops SET created_at = now() - interval '2 hours',
							expires_at = now() - interval '1 hour' WHERE stop_id = $1`, stop.ID)
						return err
					}))
				}
				if state == "lifted-stop" {
					provisionMust(t, f.rows.Lift(f.ctx, provisionTenant, stop.ID,
						authorityrows.WideningApproval{RequesterID: provisioner, ApproverID: provisionOwner}))
				}
			}
			version := f.scalar(`SELECT version FROM authority_mandates WHERE mandate_id = $1`, old)
			schema := effectargs.AuthorityProvision
			if state == "narrow" {
				schema = effectargs.AuthorityNarrow
			}
			result := f.dispatch(f.effect(f.plan(schema, f.original.Digest, "v2", 100)))
			if state == "active-stop" || state == "narrow" {
				reason := contracts.ReasonEmergencyStopFenced
				if state == "narrow" {
					reason = contracts.ReasonDelegationScopeViolation
				}
				f.wantRefused(result, reason)
				if after := f.applied(); after.Digest != f.original.Digest || after.Revision != 1 {
					t.Fatalf("refused plan changed: %+v", after)
				}
				if n := f.scalar(`SELECT count(*) FROM authority_mandates`); n != 2 {
					t.Fatalf("%d mandates after refused recreation", n)
				}
			} else {
				f.wantSent(result)
				after := f.applied()
				newID := provisionNodeID(t, after, provisionChild)
				if newID == old || provisionNodeID(t, after, provisionOrg) != provisionNodeID(t, f.original, provisionOrg) || after.Revision != 2 {
					t.Fatalf("incorrect replacement lineage: %+v", after)
				}
				newLimit := f.limit(newID, "usd_micros")
				f.wantCounter(newLimit.ID, bucket, 12, 0)
				f.wantCounter(newLimit.ID, bucket.Add(-24*time.Hour), 8, 0)
			}
			if after := f.scalar(`SELECT version FROM authority_mandates WHERE mandate_id = $1`, old); after != version {
				t.Fatalf("redundant revoke changed old mandate version: %d -> %d", version, after)
			}
			f.wantCounter(limit.ID, bucket, 12, 2)
		})
	}
}

func TestPostgresProvisionCarryOverWaitsForSettlement(t *testing.T) {
	f := newProvisionFixture(t)
	old := provisionNodeID(t, f.original, provisionChild)
	limit := f.limit(old, "usd_micros")
	bucket := f.now.Truncate(24 * time.Hour)
	f.seedCounter(limit.ID, bucket, 13, 7)
	f.seedCounter(limit.ID, bucket.Add(-24*time.Hour), 3, 2)
	distinct := f.limit(old, "projects")
	f.seedCounter(distinct.ID, bucket, 2, 0)
	provisionMust(t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		for _, value := range []string{"project-one", "project-two"} {
			digest := sha256.Sum256([]byte(value))
			if _, err := tx.SQL().ExecContext(f.ctx, `INSERT INTO authority_distinct_values (tenant_id, limit_id, bucket_start, value_digest, attempt_id)
				VALUES ($1, $2, $3, $4, $5)`, provisionTenant, distinct.ID, bucket, digest[:], f.firstID); err != nil {
				return err
			}
		}
		return nil
	}))
	effect := f.effect(f.plan(effectargs.AuthorityProvision, f.original.Digest, "v2", 200))
	settlement, pid := f.begin()
	defer settlement.Rollback()
	// This is settleHeld's counter transition; keep its write uncommitted so
	// the copy must wait, then read the newly committed used amount.
	_, err := settlement.ExecContext(f.ctx, `UPDATE authority_counters SET reserved = reserved - $4, used = used + $4
		WHERE tenant_id = $1 AND limit_id = $2 AND bucket_start = $3`, provisionTenant, limit.ID, bucket, 7)
	provisionMust(t, err)
	completed := f.async(effect)
	applyPID := f.waitBlocked(pid, "authority_counters", completed)
	stopDone := make(chan error, 1)
	go func() {
		_, err := f.rows.Stop(f.ctx, provisionTenant, authorityrows.StopSpec{
			Scope: authorityrows.Scope{Kind: authorityrows.ScopeMandate, Key: old.String()}, Reason: "after classification", IssuedBy: provisionOwner})
		stopDone <- err
	}()
	f.waitBlocked(applyPID, "authority_mandates", nil)
	provisionMust(t, settlement.Commit())
	f.wantSent(<-completed)
	provisionMust(t, <-stopDone)
	after := f.applied()
	newID := provisionNodeID(t, after, provisionChild)
	if newID == old || after.Revision != 2 {
		t.Fatalf("no replacement: %+v", after)
	}
	newLimit := f.limit(newID, "usd_micros")
	f.wantCounter(newLimit.ID, bucket, 20, 0)
	f.wantCounter(newLimit.ID, bucket.Add(-24*time.Hour), 3, 0)
	f.wantCounter(limit.ID, bucket, 20, 0)
	f.wantCounter(limit.ID, bucket.Add(-24*time.Hour), 3, 2)
	newDistinct := f.limit(newID, "projects")
	f.wantCounter(newDistinct.ID, bucket, 2, 0)
	if n := f.scalar(`SELECT count(*) FROM authority_distinct_values WHERE limit_id = $1`, newDistinct.ID); n != 2 {
		t.Fatalf("%d distinct values carried, want 2", n)
	}
}

func TestPostgresProvisionCarryOverSeesNewAdmissionBucket(t *testing.T) {
	f := newProvisionFixture(t)
	old := provisionNodeID(t, f.original, provisionOrg)
	limit := f.limit(old, "usd_micros")
	bucket := f.now.Truncate(24 * time.Hour)
	effect := f.effect(f.plan(effectargs.AuthorityProvision, f.original.Digest, "v2", 200))
	admissionTx, pid := f.begin()
	defer admissionTx.Rollback()
	// Admission holds FOR SHARE on authority before creating its on-demand
	// bucket. A counter-only row lock would miss this uncommitted insertion.
	var version int64
	provisionMust(t, admissionTx.QueryRowContext(f.ctx, `SELECT version FROM authority_mandates
		WHERE tenant_id = $1 AND mandate_id = $2 FOR SHARE`, provisionTenant, old).Scan(&version))
	_, err := admissionTx.ExecContext(f.ctx, `INSERT INTO authority_counters (tenant_id, limit_id, bucket_start, used, reserved)
		VALUES ($1, $2, $3, 9, 1)`, provisionTenant, limit.ID, bucket)
	provisionMust(t, err)
	completed := f.async(effect)
	f.waitBlocked(pid, "authority_mandates", completed)
	provisionMust(t, admissionTx.Commit())
	f.wantSent(<-completed)
	newID := provisionNodeID(t, f.applied(), provisionOrg)
	if newID == old {
		t.Fatal("widening retained old mandate")
	}
	newLimit := f.limit(newID, "usd_micros")
	f.wantCounter(newLimit.ID, bucket, 9, 0)
	f.wantCounter(limit.ID, bucket, 9, 1)
}

func TestPostgresProvisionRollbackAndRestrictedTenantIsolation(t *testing.T) {
	f := newProvisionFixture(t)
	oldRoot := provisionNodeID(t, f.original, provisionOrg)
	oldChild := provisionNodeID(t, f.original, provisionChild)
	f.stop(oldChild, nil)
	// Root recreation occurs before the child fence is reached. Its revoke,
	// replacement, limits and the new principal must all roll back together.
	raw := f.plan(effectargs.AuthorityProvision, f.original.Digest, "v2", 200)
	var doc map[string]any
	provisionMust(t, json.Unmarshal(raw, &doc))
	doc["principals"] = append(doc["principals"].([]any), map[string]any{"id": "svc:rolled-back", "kind": "service"})
	raw, err := json.Marshal(doc)
	provisionMust(t, err)
	f.wantRefused(f.dispatch(f.effect(raw)), contracts.ReasonEmergencyStopFenced)
	if after := f.applied(); after.Revision != 1 || after.Digest != f.original.Digest {
		t.Fatalf("record advanced despite rollback: %+v", after)
	}
	if n := f.scalar(`SELECT count(*) FROM authority_mandates`); n != 2 {
		t.Fatalf("%d mandates after rollback", n)
	}
	if n := f.scalar(`SELECT count(*) FROM authority_limits`); n != 3 {
		t.Fatalf("%d limits after rollback", n)
	}
	if n := f.scalar(`SELECT count(*) FROM authority_provision_limits`); n != 3 {
		t.Fatalf("%d memberships after rollback", n)
	}
	if n := f.scalar(`SELECT count(*) FROM authority_principals WHERE principal_id = 'svc:rolled-back'`); n != 0 {
		t.Fatal("principal escaped rollback")
	}
	if n := f.scalar(`SELECT count(*) FROM authority_mandates WHERE mandate_id = $1 AND status = 'active'`, oldRoot); n != 1 {
		t.Fatal("old root revoke escaped rollback")
	}
	var count int
	provisionMust(t, f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM authority_provisions`).Scan(&count))
	if count != 0 {
		t.Fatalf("unset tenant saw %d provisions", count)
	}
	provisionMust(t, f.rows.InTenant(f.ctx, "tenant-other", func(tx *authorityrows.Tx) error {
		if err := tx.SQL().QueryRowContext(f.ctx, `SELECT count(*) FROM authority_provisions`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Errorf("other tenant saw %d provisions", count)
		}
		_, err := tx.MandateForUpdate(f.ctx, oldRoot)
		if !errors.Is(err, authorityrows.ErrNotFound) {
			t.Errorf("other tenant locked foreign mandate: %v", err)
		}
		return nil
	}))
	var bypass bool
	provisionMust(t, f.db.QueryRowContext(f.ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass))
	if bypass {
		t.Fatal("proof ran as an RLS bypass role")
	}
}

func TestPostgresProvisionReplayAndConcurrentCAS(t *testing.T) {
	f := newProvisionFixture(t)
	f.wantSent(f.dispatch(f.effect(f.first)))
	if after := f.applied(); after.Revision != 1 || after.Digest != f.original.Digest {
		t.Fatalf("replay changed the record: %+v", after)
	}
	if n := f.scalar(`SELECT count(*) FROM authority_mandates`); n != 2 {
		t.Fatalf("replay created %d mandates", n)
	}
	one := f.effect(f.plan(effectargs.AuthorityProvision, f.original.Digest, "v2-a", 200))
	two := f.effect(f.plan(effectargs.AuthorityProvision, f.original.Digest, "v2-b", 300))
	start := make(chan struct{})
	completed := make(chan adapters.DispatchResult, 2)
	for _, effect := range []adapters.Effect{one, two} {
		go func() { <-start; completed <- f.dispatch(effect) }()
	}
	close(start)
	sent, refused := 0, 0
	for range 2 {
		result := <-completed
		if result.Status == adapters.DispatchSent {
			sent++
		} else {
			f.wantRefused(result, contracts.ReasonPreconditionFailed)
			refused++
		}
	}
	if sent != 1 || refused != 1 {
		t.Fatalf("concurrent base digest: %d applied, %d refused", sent, refused)
	}
	if after := f.applied(); after.Revision != 2 {
		t.Fatalf("CAS advanced revision to %d", after.Revision)
	}
	if n := f.scalar(`SELECT count(*) FROM authority_mandates`); n != 4 {
		t.Fatalf("CAS produced %d mandates, want old and new subtrees only", n)
	}
}
