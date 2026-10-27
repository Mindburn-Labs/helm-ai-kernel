package admission

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/google/uuid"
)

// Recovery authority is provisioned through the native propose, step-up approve
// and dispatch producers. Only the true external effect transport is scripted.
func recoveryFixture(t *testing.T) (*fixture, *Service, *scripted, RecoveryBinding) {
	t.Helper()
	f := newPlanFixture(t)
	ctx := context.Background()
	for _, scope := range []struct{ org, team, version string }{{planOrg, planTeam, "recovery-v1"}, {"org:neighbor", "team:neighbor", "neighbor-v1"}} {
		raw := f.plan(effectargs.AuthorityProvision, "", scope.version, nil)
		raw = []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), planOrg, scope.org), planTeam, scope.team))
		in := planProposal("recovery-provision-"+scope.version, effectargs.AuthorityProvision, raw)
		in.Target = scope.org
		a, _, err := f.svc.Propose(ctx, organization, in)
		must(t, err)
		a, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(a, "exact recovery scope"), stepUpProof()))
		must(t, err)
		wantState(t, "native recovery provision approval", a, "ADMITTED", "")
		a, _, err = f.svc.Dispatch(ctx, workload, a.ID)
		must(t, err)
		wantState(t, "native recovery provision", a, "OBSERVED", "")
	}
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	fake := &scripted{}
	return f.fixture, f.withAdapter(fake), fake, RecoveryBinding{OperationID: uuid.NewString(), InstallationID: "fixture-installation", OrgRef: planOrg, OrganizationVersionID: "recovery-v1"}
}

func TestPostgresRecoveryCoversExactCPLifecycleLineage(t *testing.T) {
	f, svc, fake, in := recoveryFixture(t)
	ctx := context.Background()
	applied, err := provision.GetProvisioning(ctx, f.rows, tenantA, in.OrgRef)
	must(t, err)
	in.AuthorityVersionID, in.ExpectedPlanDigest = "recovery-v1", applied.Digest
	in.OrganizationVersionID = "recovery-v2"
	in.CoveredVersionIDs = []string{"recovery-v0", "recovery-v1", "recovery-v2"}
	var held []struct {
		caller  Caller
		attempt Attempt
	}
	for _, version := range in.CoveredVersionIDs {
		worker := episodeWorker("episode-"+version, version)
		held = append(held, struct {
			caller  Caller
			attempt Attempt
		}{worker, f.propose(worker, workerNote("work-"+version))})
	}
	// An exact version set leaves a nonmember version live even in this org's
	// workspace. It is not an inferred organization-wide or tenant-wide stop.
	unlisted := episodeWorker("unlisted", "recovery-v3")
	other := f.propose(unlisted, workerNote("unlisted"))
	foreignWorkspace := episodeWorker("foreign-workspace", "recovery-v2")
	foreignWorkspace.WorkspaceID = "ws-other"
	foreign := f.propose(foreignWorkspace, workerNote("foreign-workspace"))
	bad := in
	bad.ExpectedPlanDigest = strings.Repeat("b", 64)
	_, _, err = svc.FenceRecovery(ctx, operator, stopToken(), bad)
	wantRefusal(t, "different native plan", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	bad = in
	bad.CoveredVersionIDs = []string{"neighbor-v1", "recovery-v1", "recovery-v2"}
	_, _, err = svc.FenceRecovery(ctx, operator, stopToken(), bad)
	wantRefusal(t, "foreign native version in CP set", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	legacy := in
	legacy.AuthorityVersionID, legacy.ExpectedPlanDigest, legacy.CoveredVersionIDs = "", "", nil
	_, _, err = svc.FenceRecovery(ctx, operator, stopToken(), legacy)
	wantRefusal(t, "legacy cannot infer aliases", err, CodeNotFound, "")
	fence, _, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	if fence.InventoryCount != int64(len(held)) || fence.AuthorityVersionID != "recovery-v1" || fence.OrganizationVersionID != "recovery-v2" {
		t.Fatalf("lineage fence=%+v", fence)
	}
	neighborPlan, err := provision.GetProvisioning(ctx, f.rows, tenantA, "org:neighbor")
	must(t, err)
	_, _, err = svc.FenceRecovery(ctx, operator, stopToken(), RecoveryBinding{
		OperationID: uuid.NewString(), InstallationID: in.InstallationID, OrgRef: "org:neighbor", OrganizationVersionID: "neighbor-v2",
		AuthorityVersionID: "neighbor-v1", ExpectedPlanDigest: neighborPlan.Digest,
		CoveredVersionIDs: []string{"neighbor-v1", "neighbor-v2", "recovery-v0"},
	})
	wantRefusal(t, "foreign held alias cannot be reassigned", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	for _, item := range held {
		_, _, err := svc.Dispatch(ctx, item.caller, item.attempt.ID)
		wantRefusal(t, "held lineage claim", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
		if _, _, err := svc.Propose(ctx, item.caller, workerNote("late-"+item.caller.Episode.OrganizationVersionID)); err == nil {
			t.Fatal("new lineage attempt crossed hold")
		}
	}
	for _, item := range []struct {
		caller  Caller
		attempt Attempt
	}{{unlisted, other}, {foreignWorkspace, foreign}} {
		_, _, err := svc.Dispatch(ctx, item.caller, item.attempt.ID)
		must(t, err)
	}
	if fake.dispatched.Load() != 2 {
		t.Fatalf("nonmember transport calls=%d", fake.dispatched.Load())
	}
	ids, err := svc.ListRecoveryAttempts(ctx, operator, fence.RecoveryBinding, "")
	must(t, err)
	if len(ids) != len(held) {
		t.Fatalf("original lineage membership=%v", ids)
	}
	changed := fence.RecoveryBinding
	changed.CoveredVersionIDs = []string{"recovery-v1", "recovery-v2"}
	_, err = svc.GetRecoveryFence(ctx, operator, changed)
	wantRefusal(t, "read requires immutable membership", err, CodeNotFound, "")
	changed.OperationID, changed.Generation = uuid.NewString(), fence.Generation
	_, _, err = svc.FenceRecovery(ctx, operator, stopToken(), changed)
	wantRefusal(t, "new generation cannot release old alias", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	// Generation belongs to the org, even if a new CP lifecycle selector is
	// presented. The exact prior covered set cannot be superseded at generation 0.
	changed = in
	changed.OperationID, changed.OrganizationVersionID = uuid.NewString(), "recovery-v0"
	_, _, err = svc.FenceRecovery(ctx, operator, stopToken(), changed)
	wantRefusal(t, "generation cannot reset under older CP version", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	retry, existing, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	if !existing || retry.CutoffWatermark != fence.CutoffWatermark {
		t.Fatal("exact typed replay changed cutoff")
	}
	_, err = svc.BindRecoveryCheckpoint(ctx, operator, stopToken(), fence.RecoveryBinding, strings.Repeat("a", 64), fence.InventoryWatermark)
	must(t, err)
}

func TestPostgresRecoveryVersionLineageUpgradesLegacySingleton(t *testing.T) {
	f := newPlanFixtureWithFixture(t, newFixtureAtVersion(t, 13))
	ctx := context.Background()
	raw := f.plan(effectargs.AuthorityProvision, "", "legacy-v1", nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("legacy-provision", effectargs.AuthorityProvision, raw))
	must(t, err)
	a, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(a, "legacy native provision"), stepUpProof()))
	must(t, err)
	_, _, err = f.svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	applied := f.provisioning(tenantA)
	emptyMembership := sha256.Sum256([]byte("[]"))
	legacy := RecoveryBinding{OperationID: uuid.NewString(), InstallationID: "legacy-installation", OrgRef: planOrg, OrganizationVersionID: "legacy-v1", Generation: 1}
	// Model the rows an already-installed schema-13 binary committed. The
	// current binary cannot create its new contract against that old schema.
	err = f.svc.inTenant(ctx, tenantA, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO authority_recovery_fences
			(tenant_id,workspace_id,org_ref,organization_version_id,operation_id,installation_id,generation,plan_digest,authority_revision,requested_by,cutoff_watermark)
			VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10)`, tenantA, workspace, planOrg, "legacy-v1", legacy.OperationID, legacy.InstallationID, applied.Digest, applied.Revision, operator.PrincipalID, fmt.Sprintf("%x", emptyMembership))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_recovery_scopes(tenant_id,workspace_id,org_ref,organization_version_id,operation_id,generation) VALUES($1,$2,$3,$4,$5,1)`, tenantA, workspace, planOrg, "legacy-v1", legacy.OperationID)
		return err
	})
	must(t, err)
	// A schema-13 hold already forbids the native transition that could create
	// another current scope at a different version of this same organization.
	// Use the real propose/approve/dispatch path while schema 13 is still active.
	nextPlan := f.plan(effectargs.AuthorityProvision, applied.Digest, "legacy-v2", nil)
	next, _, err := f.svc.Propose(ctx, organization, planProposal("legacy-held-provision-v2", effectargs.AuthorityProvision, nextPlan))
	must(t, err)
	next, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(next, "native held version cannot change"), stepUpProof()))
	must(t, err)
	blocked, _, err := f.svc.Dispatch(ctx, workload, next.ID)
	must(t, err)
	stillApplied := f.provisioning(tenantA)
	if blocked.State != "UNKNOWN" || stillApplied.VersionRef != "legacy-v1" || stillApplied.Digest != applied.Digest || stillApplied.Revision != applied.Revision {
		t.Fatalf("schema-13 hold allowed native plan replacement: attempt=%+v provision=%+v", blocked, stillApplied)
	}
	must(t, Migrate(ctx, f.owner))
	version, err := SchemaVersion(ctx, f.runtime)
	must(t, err)
	if version != 14 {
		t.Fatalf("upgraded schema=%d", version)
	}
	read, err := f.svc.GetRecoveryFence(ctx, operator, legacy)
	must(t, err)
	if recoveryVersionJSON(read.RecoveryBinding) != `["legacy-v1"]` || read.ExpectedPlanDigest != "" {
		t.Fatalf("legacy scope broadened: %+v", read)
	}
	retry := legacy
	retry.Generation = 0
	_, existing, err := f.svc.FenceRecovery(ctx, operator, stopToken(), retry)
	must(t, err)
	if !existing {
		t.Fatal("legacy exact replay lost after migration")
	}
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	svc := f.withAdapter(&scripted{})
	_, _, err = svc.Propose(ctx, episodeWorker("legacy-held", "legacy-v1"), workerNote("legacy-held"))
	if err == nil {
		t.Fatal("migrated singleton did not hold original version")
	}
	typed := legacy
	typed.OperationID, typed.OrganizationVersionID = uuid.NewString(), "legacy-v2"
	typed.AuthorityVersionID, typed.ExpectedPlanDigest = "legacy-v1", applied.Digest
	typed.CoveredVersionIDs = []string{"legacy-v1", "legacy-v2"}
	upgraded, _, err := svc.FenceRecovery(ctx, operator, stopToken(), typed)
	must(t, err)
	if upgraded.Generation != 2 {
		t.Fatalf("upgraded org generation=%d", upgraded.Generation)
	}
	_, err = svc.GetRecoveryFence(ctx, operator, legacy)
	wantRefusal(t, "legacy operation superseded by typed generation", err, CodeNotFound, "")
}

func TestPostgresRecoveryScopeHoldsOriginalAuthorityAndKeepsNeighborsLive(t *testing.T) {
	f, svc, fake, in := recoveryFixture(t)
	ctx := context.Background()
	worker := episodeWorker("recovering", "recovery-v1")
	a := f.propose(worker, workerNote("held"))
	neighbor := f.propose(episodeWorker("neighbor", "neighbor-v1"), workerNote("neighbor"))
	otherWorkspace := episodeWorker("other-workspace", "recovery-v1")
	otherWorkspace.WorkspaceID = "ws-other"
	other := f.propose(otherWorkspace, workerNote("other-workspace"))
	foreignOperator := operator
	foreignOperator.WorkspaceID = "ws-other"
	_, _, err := svc.FenceRecovery(ctx, foreignOperator, stopToken(), in)
	wantRefusal(t, "organization from another workspace", err, CodeNotFound, "")
	fence, existing, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	if existing || fence.Generation != 1 || fence.InventoryCount != 1 || fence.UnresolvedCount != 0 {
		t.Fatalf("fence=%+v existing=%v", fence, existing)
	}
	_, _, err = svc.Dispatch(ctx, worker, a.ID)
	wantRefusal(t, "held claim", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	got, err := svc.Get(ctx, worker, a.ID)
	must(t, err)
	if got.State != "ADMITTED" || got.Permit == nil || got.Permit.ID != a.Permit.ID || got.Permit.ConsumedAt != nil || got.Permit.VoidReasonCode != "" {
		t.Fatalf("recovery changed original authority: %+v", got)
	}
	_, _, err = svc.Propose(ctx, worker, workerNote("late-proposal"))
	if err == nil {
		t.Fatal("late proposal crossed the durable fence")
	}
	// Source admission and database triggers both enforce the hold. An older
	// writer that consumes the permit then updates the attempt rolls back both.
	err = svc.inTenant(ctx, tenantA, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE authority_permits SET consumed_at=now(),claim_id=$3 WHERE tenant_id=$1 AND attempt_id=$2`, tenantA, a.ID, uuid.NewString()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE authority_effect_attempts SET state='DISPATCHING' WHERE tenant_id=$1 AND attempt_id=$2`, tenantA, a.ID)
		return err
	})
	if err == nil {
		t.Fatal("legacy claim crossed the database fence")
	}
	got, err = svc.Get(ctx, worker, a.ID)
	must(t, err)
	if got.Permit.ConsumedAt != nil {
		t.Fatal("refused legacy claim consumed the permit")
	}
	for _, item := range []struct {
		caller  Caller
		attempt Attempt
	}{{episodeWorker("neighbor", "neighbor-v1"), neighbor}, {otherWorkspace, other}} {
		result, _, err := svc.Dispatch(ctx, item.caller, item.attempt.ID)
		must(t, err)
		wantState(t, "neighbor dispatch", result, "OBSERVED", "")
	}
	if fake.dispatched.Load() != 2 {
		t.Fatalf("transport calls=%d", fake.dispatched.Load())
	}
	current := fence.RecoveryBinding
	ids, err := svc.ListRecoveryAttempts(ctx, operator, current, "")
	must(t, err)
	if len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("inventory=%v", ids)
	}
	wrong := operator
	wrong.WorkspaceID = "ws-other"
	_, err = svc.GetRecoveryFence(ctx, wrong, current)
	wantRefusal(t, "foreign workspace", err, CodeNotFound, "")
	wrong = operator
	wrong.TenantID = tenantB
	_, err = svc.GetRecoveryFence(ctx, wrong, current)
	wantRefusal(t, "foreign tenant", err, CodeNotFound, "")
	altered := current
	altered.InstallationID = "other-installation"
	_, err = svc.GetRecoveryFence(ctx, operator, altered)
	wantRefusal(t, "foreign installation", err, CodeNotFound, "")
	_, err = svc.GetRecoveryFence(ctx, worker, current)
	wantRefusal(t, "episode recovery authority", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
}

func TestPostgresRecoveryTracksLateSendUnknownAndCheckpointGeneration(t *testing.T) {
	f, svc, fake, in := recoveryFixture(t)
	ctx := context.Background()
	worker := episodeWorker("in-flight", "recovery-v1")
	a := f.propose(worker, workerNote("in-flight"))
	claimed, send := make(chan struct{}), make(chan struct{})
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		close(claimed)
		<-send
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite}
	}, func(adapters.Effect) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
	})
	done := make(chan error, 1)
	go func() { _, _, err := svc.Dispatch(ctx, worker, a.ID); done <- err }()
	<-claimed // Durable claim already committed; provider application waits.
	fence, _, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	if fence.InventoryCount != 1 || fence.UnresolvedCount != 1 {
		t.Fatalf("late-send inventory=%+v", fence)
	}
	_, err = svc.BindRecoveryCheckpoint(ctx, operator, stopToken(), fence.RecoveryBinding, strings.Repeat("a", 64), fence.InventoryWatermark)
	wantRefusal(t, "checkpoint before late send", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	close(send)
	must(t, <-done)
	// Restart the service against the same durable store. Repeating Dispatch
	// returns the original unknown attempt; Observe reads that exact operation.
	restarted := f.withAdapter(fake)
	again, existing, err := restarted.Dispatch(ctx, worker, a.ID)
	must(t, err)
	if !existing || again.State != "UNKNOWN" || again.ID != a.ID || fake.dispatched.Load() != 1 {
		t.Fatalf("unknown replay=%+v calls=%d", again, fake.dispatched.Load())
	}
	fence, err = restarted.GetRecoveryFence(ctx, operator, fence.RecoveryBinding)
	must(t, err)
	_, err = restarted.BindRecoveryCheckpoint(ctx, operator, stopToken(), fence.RecoveryBinding, strings.Repeat("a", 64), fence.InventoryWatermark)
	wantRefusal(t, "unknown checkpoint", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	fake.set(nil, nil)
	observed, _, err := restarted.Observe(ctx, worker, a.ID)
	must(t, err)
	if observed.ID != a.ID || observed.State != "RECONCILED" || fake.dispatched.Load() != 1 {
		t.Fatalf("original observation=%+v", observed)
	}
	current, err := restarted.GetRecoveryFence(ctx, operator, fence.RecoveryBinding)
	must(t, err)
	_, err = restarted.BindRecoveryCheckpoint(ctx, operator, stopToken(), current.RecoveryBinding, strings.Repeat("a", 64), fence.InventoryWatermark)
	wantRefusal(t, "changed inventory checkpoint", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	checkpoint, err := restarted.BindRecoveryCheckpoint(ctx, operator, stopToken(), current.RecoveryBinding, strings.Repeat("a", 64), current.InventoryWatermark)
	must(t, err)
	if checkpoint.CheckpointDigest == "" {
		t.Fatal("native checkpoint binding missing")
	}
	_, err = restarted.BindRecoveryCheckpoint(ctx, operator, stopToken(), current.RecoveryBinding, strings.Repeat("b", 64), current.InventoryWatermark)
	wantRefusal(t, "checkpoint replacement", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	newer := in
	newer.OperationID = uuid.NewString()
	newer.Generation = 1
	next, _, err := restarted.FenceRecovery(ctx, operator, stopToken(), newer)
	must(t, err)
	if next.Generation != 2 {
		t.Fatalf("new generation=%d", next.Generation)
	}
	_, _, err = restarted.FenceRecovery(ctx, operator, stopToken(), in)
	wantRefusal(t, "old fence replay", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
	_, err = restarted.GetRecoveryFence(ctx, operator, current.RecoveryBinding)
	wantRefusal(t, "old checkpoint scope", err, CodeNotFound, "")
	_, err = restarted.BindRecoveryCheckpoint(ctx, operator, stopToken(), current.RecoveryBinding, strings.Repeat("a", 64), current.InventoryWatermark)
	wantRefusal(t, "old checkpoint bind", err, CodeNotFound, "")
}

func TestPostgresRecoveryConcurrentClaimsHaveOneCutoff(t *testing.T) {
	f, svc, fake, in := recoveryFixture(t)
	ctx := context.Background()
	worker := episodeWorker("race", "recovery-v1")
	var attempts []Attempt
	for i := 0; i < 16; i++ {
		attempts = append(attempts, f.propose(worker, workerNote(uuid.NewString())))
	}
	start := make(chan struct{})
	errs := make(chan error, len(attempts))
	var workers sync.WaitGroup
	for _, a := range attempts {
		workers.Add(1)
		go func(id string) {
			defer workers.Done()
			<-start
			_, _, err := svc.Dispatch(ctx, worker, id)
			errs <- err
		}(a.ID)
	}
	close(start)
	fence, _, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			wantRefusal(t, "racing claim", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
		}
	}
	if fence.InventoryCount != int64(len(attempts)) {
		t.Fatalf("incomplete cutoff inventory: %+v", fence)
	}
	var claimed int32
	for _, a := range attempts {
		got, err := svc.Get(ctx, worker, a.ID)
		must(t, err)
		if got.Permit.ConsumedAt != nil {
			claimed++
		} else if got.State != "ADMITTED" {
			t.Fatalf("held attempt changed: %+v", got)
		}
		_, _, _ = svc.Dispatch(ctx, worker, a.ID)
	}
	if fake.dispatched.Load() != claimed {
		t.Fatalf("claimed=%d calls=%d", claimed, fake.dispatched.Load())
	}
}

func TestPostgresRecoveryHumanHandoffRemainsUnresolved(t *testing.T) {
	f, svc, fake, in := recoveryFixture(t)
	ctx := context.Background()
	worker := episodeWorker("handoff", "recovery-v1")
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite}
	}, func(adapters.Effect) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
	})
	a := f.propose(worker, workerNote("human-handoff"))
	a, _, err := svc.Dispatch(ctx, worker, a.ID)
	must(t, err)
	fence, _, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	resolved, _, err := svc.Reconcile(ctx, tenantA, workspace, a.ID, true)
	must(t, err)
	if !resolved {
		t.Fatal("native final reconciliation did not hand off")
	}
	current, err := svc.Get(ctx, worker, a.ID)
	must(t, err)
	if current.State != "ESCALATED_TO_HUMAN" || current.Permit.ConsumedAt == nil || fake.dispatched.Load() != 1 {
		t.Fatalf("human handoff changed original claim: %+v", current)
	}
	fence, err = svc.GetRecoveryFence(ctx, operator, fence.RecoveryBinding)
	must(t, err)
	if fence.UnresolvedCount != 1 {
		t.Fatal("human handoff was mislabeled as a resolved effect")
	}
	_, err = svc.BindRecoveryCheckpoint(ctx, operator, stopToken(), fence.RecoveryBinding, strings.Repeat("a", 64), fence.InventoryWatermark)
	wantRefusal(t, "unresolved human handoff checkpoint", err, CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
}

func TestPostgresRecoveryCheckpointStorageEnforcesTenantRLS(t *testing.T) {
	f, svc, _, in := recoveryFixture(t)
	ctx := context.Background()
	fence, _, err := svc.FenceRecovery(ctx, operator, stopToken(), in)
	must(t, err)
	_, err = svc.BindRecoveryCheckpoint(ctx, operator, stopToken(), fence.RecoveryBinding, strings.Repeat("a", 64), fence.InventoryWatermark)
	must(t, err)
	var visible int
	must(t, f.runtime.QueryRow(`SELECT count(*) FROM authority_recovery_checkpoints`).Scan(&visible))
	if visible != 0 {
		t.Fatalf("unscoped restricted runtime disclosed %d recovery checkpoints", visible)
	}
	err = svc.inTenant(ctx, tenantB, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM authority_recovery_checkpoints WHERE operation_id=$1`, in.OperationID).Scan(&visible)
	})
	must(t, err)
	if visible != 0 {
		t.Fatal("other tenant read an original recovery checkpoint")
	}
	err = svc.inTenant(ctx, tenantB, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO authority_recovery_checkpoints(tenant_id,operation_id,checkpoint_digest,inventory_watermark) VALUES ($1,$2,$3,$4)`, tenantA, in.OperationID, strings.Repeat("b", 64), fence.InventoryWatermark)
		return err
	})
	if err == nil {
		t.Fatal("other tenant wrote into an existing recovery operation")
	}
}
