package approvalceremony

// quantum_posture: integration tests over classical Ed25519 approval
// signatures; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/lib/pq"
)

// TestPostgresLifecycleSingleIssueAndConsume is the source-owned real-Postgres
// concurrency and isolation proof. The source-owned workflow provisions its
// database URL; local runs skip when HELM_TEST_POSTGRES_URL is absent.
func TestPostgresLifecycleSingleIssueAndConsume(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run approval ceremony concurrency proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_approval_%d", time.Now().UnixNano())
	db := openApprovalTestPostgres(t, postgresURL, schema)
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create approval test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()

	fixtureHold, _, _, fixtureGrant := ceremonyFixtures(t)
	grantPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(grantPrivateKey, "approval-test")
	grantVerifier, err := NewEd25519GrantSignatureVerifier(
		signer.PublicKeyBytes(), fixtureGrant.SigningKeyRef, fixtureGrant.KernelTrustRootID,
	)
	if err != nil {
		t.Fatalf("NewEd25519GrantSignatureVerifier(): %v", err)
	}
	schemaStore := NewPostgresStore(db, grantVerifier)
	if err := schemaStore.Init(ctx); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	stopStore := kernel.NewScopedStopStore(db, time.Now, kernel.WithPostgresScopeLocks())
	if err := stopStore.Init(ctx); err != nil {
		t.Fatalf("initialize emergency-stop store: %v", err)
	}
	runtimeRole := fmt.Sprintf("helm_runtime_%d", time.Now().UnixNano())
	runtimePassword := "helm-approval-test-password"
	quotedRole := pq.QuoteIdentifier(runtimeRole)
	if _, err := db.ExecContext(ctx, `CREATE ROLE `+quotedRole+` WITH
		LOGIN PASSWORD '`+runtimePassword+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatalf("create non-bypass runtime role: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP OWNED BY `+quotedRole)
		_, _ = db.ExecContext(cleanupCtx, `DROP ROLE IF EXISTS `+quotedRole)
	}()
	if _, err := db.ExecContext(ctx, `GRANT USAGE ON SCHEMA `+pq.QuoteIdentifier(schema)+` TO `+quotedRole); err != nil {
		t.Fatalf("grant runtime schema usage: %v", err)
	}
	if _, err := db.ExecContext(ctx, `GRANT SELECT, INSERT, UPDATE ON approval_ceremonies TO `+quotedRole); err != nil {
		t.Fatalf("grant runtime table privileges: %v", err)
	}
	if _, err := db.ExecContext(ctx, `GRANT SELECT, INSERT ON approval_dispatch_admissions TO `+quotedRole); err != nil {
		t.Fatalf("grant runtime dispatch admission privileges: %v", err)
	}
	if _, err := db.ExecContext(ctx, `GRANT SELECT ON emergency_stop_fences TO `+quotedRole); err != nil {
		t.Fatalf("grant runtime emergency-stop read privilege: %v", err)
	}
	var runtimeSuperuser, runtimeBypassRLS bool
	if err := db.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1`, runtimeRole).
		Scan(&runtimeSuperuser, &runtimeBypassRLS); err != nil {
		t.Fatalf("read runtime role attributes: %v", err)
	}
	if runtimeSuperuser || runtimeBypassRLS {
		t.Fatalf("runtime role bypasses RLS: superuser=%t bypassrls=%t", runtimeSuperuser, runtimeBypassRLS)
	}
	runtimeDB := openApprovalTestPostgresAs(t, postgresURL, schema, runtimeRole, runtimePassword)
	defer func() { _ = runtimeDB.Close() }()
	if err := runtimeDB.PingContext(ctx); err != nil {
		t.Fatalf("connect as non-bypass runtime role: %v", err)
	}
	store := NewPostgresStore(runtimeDB, grantVerifier)
	clockNow := fixtureHold.HoldStartedAt
	store.clock = func() time.Time { return clockNow }
	config := ServiceConfig{
		MinHoldDuration: 5 * time.Minute, ChallengeTTL: 10 * time.Minute,
		MaxChallengeLifetime: 20 * time.Minute, GrantTTL: 15 * time.Minute,
		MaxAssertions: 4, ServerIdentity: fixtureHold.Spec.ServerIdentity,
		KernelTrustRootID: fixtureGrant.KernelTrustRootID, SigningKeyRef: fixtureGrant.SigningKeyRef,
	}
	authority, approverKeys := approvalTestAuthority(fixtureHold.Spec, fixtureHold.HoldStartedAt)
	control := &staticControlProvider{identity: controlForSpec(fixtureHold.Spec)}
	consumer := &staticConsumerProvider{identity: consumerForSpec(fixtureHold.Spec)}
	service, err := newService(
		store, staticBindingProvider{spec: fixtureHold.Spec},
		staticAuthorityProvider{store: authority},
		control, consumer, signer,
		func() time.Time { return clockNow }, cryptorand.Reader, config,
	)
	if err != nil {
		t.Fatalf("newService(): %v", err)
	}
	hold, err := service.BeginHold(ctx, fixtureHold.Spec.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold(): %v", err)
	}
	if _, err := service.IssueChallenge(ctx, hold.ApprovalID); !errors.Is(err, ErrHoldPending) {
		t.Fatalf("early IssueChallenge() error = %v, want ErrHoldPending", err)
	}
	clockNow = hold.HoldStartedAt.Add(config.MinHoldDuration)
	challenged, err := service.IssueChallenge(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge(): %v", err)
	}
	if challenged.Challenge == nil || challenged.Challenge.ExpiresAt.Sub(challenged.HoldStartedAt) > config.MaxChallengeLifetime {
		t.Fatalf("challenge lifetime exceeds source-owned ceiling: %+v", challenged.Challenge)
	}
	assertions := approvalTestAssertions(t, *challenged.Challenge, approverKeys)
	clockNow = clockNow.Add(time.Minute)
	verified, err := service.VerifyQuorum(ctx, hold.ApprovalID, assertions)
	if err != nil {
		t.Fatalf("VerifyQuorum(): %v", err)
	}
	if verified.VerifiedRef == nil || !verified.VerifiedRef.VerifiedAt.Equal(clockNow) {
		t.Fatalf("verified record = %+v", verified)
	}

	clockNow = clockNow.Add(time.Minute)
	issued := make(chan Record, 2)
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, issueErr := service.IssueGrant(ctx, hold.ApprovalID)
			if issueErr != nil {
				errorsCh <- issueErr
				return
			}
			issued <- record
		}()
	}
	wg.Wait()
	close(issued)
	close(errorsCh)
	issuedRecords := collectRecords(issued)
	issueErrors := collectErrors(errorsCh)
	if len(issuedRecords) != 1 || len(issueErrors) != 1 || !errors.Is(issueErrors[0], ErrTransitionConflict) {
		t.Fatalf("concurrent issuance results = %d success, %v errors", len(issuedRecords), issueErrors)
	}
	winner := issuedRecords[0]
	if winner.State != StateGrantIssued || winner.Grant == nil {
		t.Fatalf("winning grant record = %+v", winner)
	}
	fenceApprovalTestScope(t, ctx, stopStore, kernel.StopScope{
		TenantID: winner.TenantID, WorkspaceID: "workspace-other",
	}, "approval-cross-workspace-fence")
	assertEmergencyStopRLSVisibility(t, ctx, runtimeDB, winner.TenantID, "workspace-other", 1)
	assertEmergencyStopRLSVisibility(t, ctx, runtimeDB, winner.TenantID, winner.WorkspaceID, 0)

	consumed := make(chan Record, 2)
	consumeErrors := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, consumeErr := service.ConsumeGrant(
				ctx, hold.ApprovalID, winner.Grant.GrantID,
				winner.Grant.GrantHash, winner.Grant.Nonce,
			)
			if consumeErr != nil {
				consumeErrors <- consumeErr
				return
			}
			consumed <- record
		}()
	}
	wg.Wait()
	close(consumed)
	close(consumeErrors)
	consumedRecords := collectRecords(consumed)
	consumptionErrors := collectErrors(consumeErrors)
	if len(consumedRecords) != 1 || len(consumptionErrors) != 1 || !errors.Is(consumptionErrors[0], ErrTransitionConflict) {
		t.Fatalf("concurrent consumption results = %d success, %v errors", len(consumedRecords), consumptionErrors)
	}
	final := consumedRecords[0]
	if final.State != StateConsumed || final.Version != 5 || final.ConsumedAt == nil ||
		final.GrantConsumption == nil || final.GrantConsumption.ConsumptionHash == "" || final.ConsumptionSignature == "" {
		t.Fatalf("final record = %+v", final)
	}
	admitter, err := NewDispatchAdmitter(store, consumer, signer, 30*time.Second)
	if err != nil {
		t.Fatalf("NewDispatchAdmitter(): %v", err)
	}
	dispatchRequest := dispatchAdmissionRequestForConsumption(*final.GrantConsumption)
	admitted, err := admitter.Claim(ctx, dispatchRequest)
	if err != nil {
		t.Fatalf("Claim dispatch admission: %v", err)
	}
	if err := admitted.Admission.ValidateConsumption(*final.GrantConsumption); err != nil {
		t.Fatalf("validate persisted dispatch admission: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE approval_dispatch_admissions
		SET connector_id = 'connector-shadow-tampered'
		WHERE tenant_id = $1 AND workspace_id = $2 AND attempt_id = $3`,
		final.TenantID, final.WorkspaceID, dispatchRequest.AttemptID,
	); err != nil {
		t.Fatalf("tamper dispatch admission storage shadow: %v", err)
	}
	if _, err := admitter.Recover(ctx, dispatchRequest); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("tampered dispatch storage shadow error = %v, want ErrInvalidRecord", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE approval_dispatch_admissions
		SET connector_id = $1
		WHERE tenant_id = $2 AND workspace_id = $3 AND attempt_id = $4`,
		admitted.Admission.ConnectorAuthority.ConnectorID, final.TenantID, final.WorkspaceID, dispatchRequest.AttemptID,
	); err != nil {
		t.Fatalf("restore dispatch admission storage shadow: %v", err)
	}
	exactRetry, err := admitter.Claim(ctx, dispatchRequest)
	if err != nil || !reflect.DeepEqual(exactRetry, admitted) {
		t.Fatalf("exact dispatch retry = %+v, error = %v", exactRetry, err)
	}
	changedDispatch := dispatchRequest
	changedDispatch.IdempotencyKeyHash = shaRef("d")
	if _, err := admitter.Claim(ctx, changedDispatch); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("changed dispatch retry error = %v, want ErrTransitionConflict", err)
	}
	secondAttempt := dispatchRequest
	secondAttempt.AttemptID = "attempt-b"
	if _, err := admitter.Claim(ctx, secondAttempt); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("second attempt for consumed grant error = %v, want ErrTransitionConflict", err)
	}
	assertDispatchAdmissionRLSVisibility(t, ctx, runtimeDB, "tenant-b", final.WorkspaceID, dispatchRequest.AttemptID, 0)
	assertDispatchAdmissionRLSVisibility(t, ctx, runtimeDB, final.TenantID, "workspace-b", dispatchRequest.AttemptID, 0)
	assertDispatchAdmissionRLSVisibility(t, ctx, runtimeDB, final.TenantID, final.WorkspaceID, dispatchRequest.AttemptID, 1)
	recovered, err := service.RecoverGrantConsumption(
		ctx, hold.ApprovalID, winner.Grant.GrantID, winner.Grant.GrantHash, winner.Grant.Nonce,
	)
	if err != nil || recovered.Version != final.Version || !recovered.ConsumedAt.Equal(*final.ConsumedAt) {
		t.Fatalf("RecoverGrantConsumption() record = %+v, error = %v", recovered, err)
	}
	consumer.identity.Subject = "spiffe://helm/data-plane-b"
	if _, err := service.RecoverGrantConsumption(
		ctx, hold.ApprovalID, winner.Grant.GrantID, winner.Grant.GrantHash, winner.Grant.Nonce,
	); !errors.Is(err, ErrConsumerUnavailable) {
		t.Fatalf("cross-consumer recovery error = %v, want ErrConsumerUnavailable", err)
	}
	consumer.identity = consumerForSpec(fixtureHold.Spec)
	if _, err := store.get(ctx, "tenant-b", hold.WorkspaceID, hold.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get() error = %v, want ErrNotFound", err)
	}
	assertApprovalRLSVisibility(t, ctx, runtimeDB, "tenant-b", hold.WorkspaceID, hold.ApprovalID, 0)
	assertApprovalRLSVisibility(t, ctx, runtimeDB, hold.TenantID, "workspace-b", hold.ApprovalID, 0)
	assertApprovalRLSVisibility(t, ctx, runtimeDB, hold.TenantID, hold.WorkspaceID, hold.ApprovalID, 1)
	control.identity.WorkspaceID = "workspace-b"
	if _, err := service.Get(ctx, hold.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("same-tenant cross-workspace Get() error = %v, want ErrNotFound", err)
	}
	control.identity = controlForSpec(fixtureHold.Spec)

	deniedHold, err := service.BeginHold(ctx, fixtureHold.Spec.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() for denial: %v", err)
	}
	denied, err := service.Deny(ctx, deniedHold.ApprovalID)
	if err != nil || denied.State != StateDenied {
		t.Fatalf("Deny() record = %+v, error = %v", denied, err)
	}
	if _, err := service.Deny(ctx, deniedHold.ApprovalID); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("second Deny() error = %v, want ErrTransitionConflict", err)
	}

	tampered := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	result, err := db.ExecContext(ctx, `UPDATE approval_ceremonies
		SET grant_signature = $1
		WHERE tenant_id = $2 AND approval_id = $3`,
		strings.Repeat("0", 128), tampered.TenantID, tampered.ApprovalID,
	)
	if err != nil {
		t.Fatalf("tamper persisted signature: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		t.Fatalf("tamper persisted signature affected %d rows, error = %v", rows, err)
	}
	if _, err := service.ConsumeGrant(
		ctx, tampered.ApprovalID, tampered.Grant.GrantID,
		tampered.Grant.GrantHash, tampered.Grant.Nonce,
	); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("ConsumeGrant() tampered signature error = %v, want ErrGrantSignatureRejected", err)
	}
	if _, err := service.Get(ctx, tampered.ApprovalID); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("Get() tampered signature error = %v, want ErrGrantSignatureRejected", err)
	}
	var persistedState string
	var persistedConsumedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT state, consumed_at
		FROM approval_ceremonies WHERE tenant_id = $1 AND approval_id = $2`,
		tampered.TenantID, tampered.ApprovalID,
	).Scan(&persistedState, &persistedConsumedAt); err != nil {
		t.Fatalf("read tampered grant state: %v", err)
	}
	if persistedState != string(StateGrantIssued) || persistedConsumedAt.Valid {
		t.Fatalf("tampered grant changed state: state = %s, consumed = %v", persistedState, persistedConsumedAt)
	}

	audienceBound := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	consumer.identity.Audience = "helm-data-plane-b"
	if _, err := service.ConsumeGrant(
		ctx, audienceBound.ApprovalID, audienceBound.Grant.GrantID,
		audienceBound.Grant.GrantHash, audienceBound.Grant.Nonce,
	); !errors.Is(err, ErrConsumerUnavailable) {
		t.Fatalf("ConsumeGrant() audience substitution error = %v, want ErrConsumerUnavailable", err)
	}
	consumer.identity = consumerForSpec(fixtureHold.Spec)
	assertApprovalPersistedState(t, ctx, db, audienceBound, StateGrantIssued, false)

	expiryBound := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	extendedExpiry := expiryBound.Grant.ExpiresAt.Add(time.Hour)
	result, err = db.ExecContext(ctx, `UPDATE approval_ceremonies
		SET expires_at = $1
		WHERE tenant_id = $2 AND workspace_id = $3 AND approval_id = $4`,
		extendedExpiry, expiryBound.TenantID, expiryBound.WorkspaceID, expiryBound.ApprovalID,
	)
	if err != nil {
		t.Fatalf("extend mutable expiry shadow: %v", err)
	}
	rows, err = result.RowsAffected()
	if err != nil || rows != 1 {
		t.Fatalf("extend mutable expiry shadow affected %d rows, error = %v", rows, err)
	}
	clockNow = expiryBound.Grant.ExpiresAt.Add(time.Second)
	if _, err := service.ConsumeGrant(
		ctx, expiryBound.ApprovalID, expiryBound.Grant.GrantID,
		expiryBound.Grant.GrantHash, expiryBound.Grant.Nonce,
	); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("ConsumeGrant() extended expiry error = %v, want ErrInvalidRecord", err)
	}
	assertApprovalPersistedState(t, ctx, db, expiryBound, StateGrantIssued, false)

	consumptionTampered := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	consumptionTampered, err = service.ConsumeGrant(
		ctx, consumptionTampered.ApprovalID, consumptionTampered.Grant.GrantID,
		consumptionTampered.Grant.GrantHash, consumptionTampered.Grant.Nonce,
	)
	if err != nil {
		t.Fatalf("ConsumeGrant() for consumption tamper: %v", err)
	}
	result, err = db.ExecContext(ctx, `UPDATE approval_ceremonies
		SET consumption_signature = $1
		WHERE tenant_id = $2 AND workspace_id = $3 AND approval_id = $4`,
		strings.Repeat("0", 128), consumptionTampered.TenantID,
		consumptionTampered.WorkspaceID, consumptionTampered.ApprovalID,
	)
	if err != nil {
		t.Fatalf("tamper persisted consumption signature: %v", err)
	}
	rows, err = result.RowsAffected()
	if err != nil || rows != 1 {
		t.Fatalf("tamper persisted consumption signature affected %d rows, error = %v", rows, err)
	}
	if _, err := service.RecoverGrantConsumption(
		ctx, consumptionTampered.ApprovalID, consumptionTampered.Grant.GrantID,
		consumptionTampered.Grant.GrantHash, consumptionTampered.Grant.Nonce,
	); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("tampered consumption recovery error = %v, want ErrGrantSignatureRejected", err)
	}

	expiryLockedGrant := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	var transitionClock atomic.Int64
	transitionClock.Store(clockNow.UnixMicro())
	store.clock = func() time.Time { return time.UnixMicro(transitionClock.Load()).UTC() }
	assertApprovalConsumeExpiresWhileWaitingForScopeLock(t, ctx, db, service, expiryLockedGrant, &transitionClock)
	store.clock = func() time.Time { return clockNow }
	expiryLockedDispatchGrant := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	expiryLockedDispatch, err := service.ConsumeGrant(
		ctx, expiryLockedDispatchGrant.ApprovalID, expiryLockedDispatchGrant.Grant.GrantID,
		expiryLockedDispatchGrant.Grant.GrantHash, expiryLockedDispatchGrant.Grant.Nonce,
	)
	if err != nil {
		t.Fatalf("consume grant for dispatch expiry lock proof: %v", err)
	}
	transitionClock.Store(clockNow.UnixMicro())
	store.clock = func() time.Time { return time.UnixMicro(transitionClock.Load()).UTC() }
	assertDispatchAdmissionExpiresWhileWaitingForScopeLock(t, ctx, db, admitter, expiryLockedDispatch, &transitionClock)
	store.clock = func() time.Time { return clockNow }
	concurrentDispatchGrant := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	concurrentDispatch, err := service.ConsumeGrant(
		ctx, concurrentDispatchGrant.ApprovalID, concurrentDispatchGrant.Grant.GrantID,
		concurrentDispatchGrant.Grant.GrantHash, concurrentDispatchGrant.Grant.Nonce,
	)
	if err != nil {
		t.Fatalf("consume grant for concurrent dispatch attempts: %v", err)
	}
	assertConcurrentDispatchAttemptsSingleWinner(t, ctx, admitter, concurrentDispatch)

	fencedGrant := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	recoveryGrant := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	recoveryFinal := consumeApprovalTestGrantAfterLockProof(t, ctx, db, service, recoveryGrant)
	raceRequest := dispatchAdmissionRequestForConsumption(*recoveryFinal.GrantConsumption)
	raceRequest.AttemptID = "attempt-fence-race"
	raceAdmission, raceErr := raceDispatchAdmissionAndFence(t, ctx, admitter, stopStore, kernel.StopScope{
		TenantID: fencedGrant.TenantID, WorkspaceID: fencedGrant.WorkspaceID,
	}, raceRequest, "approval-same-workspace-fence")
	if raceErr != nil && !errors.Is(raceErr, ErrEmergencyStopFenced) {
		t.Fatalf("concurrent admission/FENCE error = %v", raceErr)
	}
	if raceErr == nil {
		raceReplay, err := admitter.Claim(ctx, raceRequest)
		if err != nil || !reflect.DeepEqual(raceReplay, raceAdmission) {
			t.Fatalf("admission-first race replay = %+v, error = %v", raceReplay, err)
		}
	}
	assertEmergencyStopRLSVisibility(t, ctx, runtimeDB, fencedGrant.TenantID, fencedGrant.WorkspaceID, 1)
	if _, err := service.ConsumeGrant(
		ctx, fencedGrant.ApprovalID, fencedGrant.Grant.GrantID,
		fencedGrant.Grant.GrantHash, fencedGrant.Grant.Nonce,
	); !errors.Is(err, ErrEmergencyStopFenced) {
		t.Fatalf("fenced ConsumeGrant() error = %v, want ErrEmergencyStopFenced", err)
	}
	assertApprovalPersistedState(t, ctx, db, fencedGrant, StateGrantIssued, false)
	recoveredAfterFence, err := service.RecoverGrantConsumption(
		ctx, recoveryFinal.ApprovalID, recoveryFinal.Grant.GrantID,
		recoveryFinal.Grant.GrantHash, recoveryFinal.Grant.Nonce,
	)
	if err != nil || !reflect.DeepEqual(recoveredAfterFence, recoveryFinal) {
		t.Fatalf("recovery after FENCE = %+v, error = %v", recoveredAfterFence, err)
	}
	if !clockNow.After(admitted.Admission.ExpiresAt) {
		clockNow = admitted.Admission.ExpiresAt.Add(time.Second)
	}
	admittedAfterFence, err := admitter.Claim(ctx, dispatchRequest)
	if err != nil || !reflect.DeepEqual(admittedAfterFence, admitted) {
		t.Fatalf("expired admission-first exact retry after FENCE = %+v, error = %v", admittedAfterFence, err)
	}
	recoveredAdmissionAfterFence, err := admitter.Recover(ctx, dispatchRequest)
	if err != nil || !reflect.DeepEqual(recoveredAdmissionAfterFence, admitted) {
		t.Fatalf("dispatch admission recovery after FENCE = %+v, error = %v", recoveredAdmissionAfterFence, err)
	}
	fencedDispatch := dispatchAdmissionRequestForConsumption(*recoveryFinal.GrantConsumption)
	fencedDispatch.AttemptID = "attempt-fenced"
	if _, err := admitter.Claim(ctx, fencedDispatch); !errors.Is(err, ErrEmergencyStopFenced) {
		t.Fatalf("FENCE-first dispatch error = %v, want ErrEmergencyStopFenced", err)
	}

	expiringHold, err := service.BeginHold(ctx, fixtureHold.Spec.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() for expiration: %v", err)
	}
	clockNow = expiringHold.HoldStartedAt.Add(config.MinHoldDuration)
	expiring, err := service.IssueChallenge(ctx, expiringHold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge() for expiration: %v", err)
	}
	clockNow = expiring.Challenge.ExpiresAt
	expired, err := service.Expire(ctx, expiring.ApprovalID)
	if err != nil || expired.State != StateExpired {
		t.Fatalf("Expire() record = %+v, error = %v", expired, err)
	}
}

type approvalConsumeResult struct {
	record Record
	err    error
}

type dispatchAdmissionResult struct {
	record DispatchAdmissionRecord
	err    error
}

func assertConcurrentDispatchAttemptsSingleWinner(t *testing.T, ctx context.Context, admitter *DispatchAdmitter, consumed Record) {
	t.Helper()
	if consumed.GrantConsumption == nil {
		t.Fatal("concurrent dispatch proof requires a consumed grant")
	}
	requestA := dispatchAdmissionRequestForConsumption(*consumed.GrantConsumption)
	requestA.AttemptID = "attempt-concurrent-a"
	requestB := requestA
	requestB.AttemptID = "attempt-concurrent-b"
	start := make(chan struct{})
	results := make(chan dispatchAdmissionResult, 2)
	for _, request := range []DispatchAdmissionRequest{requestA, requestB} {
		request := request
		go func() {
			<-start
			record, err := admitter.Claim(ctx, request)
			results <- dispatchAdmissionResult{record: record, err: err}
		}()
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		select {
		case result := <-results:
			switch {
			case result.err == nil:
				successes++
			case errors.Is(result.err, ErrTransitionConflict):
				conflicts++
			default:
				t.Fatalf("concurrent dispatch attempt error = %v", result.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent dispatch attempt did not finish")
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent dispatch attempts successes=%d conflicts=%d", successes, conflicts)
	}
}

func assertDispatchAdmissionExpiresWhileWaitingForScopeLock(
	t *testing.T,
	ctx context.Context,
	lockDB *sql.DB,
	admitter *DispatchAdmitter,
	consumed Record,
	transitionClock *atomic.Int64,
) {
	t.Helper()
	if consumed.GrantConsumption == nil {
		t.Fatal("dispatch expiry proof requires a consumed grant")
	}
	request := dispatchAdmissionRequestForConsumption(*consumed.GrantConsumption)
	request.AttemptID = "attempt-expiry-lock"
	tx, err := lockDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
		consumed.TenantID, consumed.WorkspaceID,
	); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	result := make(chan dispatchAdmissionResult, 1)
	go func() {
		record, claimErr := admitter.Claim(ctx, request)
		result <- dispatchAdmissionResult{record: record, err: claimErr}
	}()
	select {
	case early := <-result:
		_ = tx.Rollback()
		t.Fatalf("dispatch admission bypassed held scope lock: %+v", early)
	case <-time.After(100 * time.Millisecond):
	}
	transitionClock.Store(consumed.GrantConsumption.GrantExpiresAt.Add(time.Second).UnixMicro())
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-result:
		if !errors.Is(outcome.err, ErrTransitionConflict) {
			t.Fatalf("dispatch admission after grant expiry = %+v, error = %v", outcome.record, outcome.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch admission did not resume after releasing scope lock")
	}
	var count int
	if err := lockDB.QueryRowContext(ctx, `SELECT count(*) FROM approval_dispatch_admissions
		WHERE tenant_id = $1 AND workspace_id = $2 AND attempt_id = $3`,
		consumed.TenantID, consumed.WorkspaceID, request.AttemptID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired queued dispatch admission persisted %d rows", count)
	}
}

func consumeApprovalTestGrantAfterLockProof(
	t *testing.T,
	ctx context.Context,
	lockDB *sql.DB,
	service *Service,
	grant Record,
) Record {
	t.Helper()
	tx, err := lockDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
		grant.TenantID, grant.WorkspaceID,
	); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	result := make(chan approvalConsumeResult, 1)
	go func() {
		record, consumeErr := service.ConsumeGrant(
			ctx, grant.ApprovalID, grant.Grant.GrantID, grant.Grant.GrantHash, grant.Grant.Nonce,
		)
		result <- approvalConsumeResult{record: record, err: consumeErr}
	}()
	select {
	case early := <-result:
		_ = tx.Rollback()
		t.Fatalf("approval consumption bypassed held scope lock: %+v", early)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case completed := <-result:
		if completed.err != nil {
			t.Fatalf("approval consumption after scope lock release: %v", completed.err)
		}
		return completed.record
	case <-time.After(5 * time.Second):
		t.Fatal("approval consumption did not resume after scope lock release")
	}
	return Record{}
}

func assertApprovalConsumeExpiresWhileWaitingForScopeLock(
	t *testing.T,
	ctx context.Context,
	lockDB *sql.DB,
	service *Service,
	grant Record,
	transitionClock *atomic.Int64,
) {
	t.Helper()
	tx, err := lockDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
		grant.TenantID, grant.WorkspaceID,
	); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, consumeErr := service.ConsumeGrant(
			ctx, grant.ApprovalID, grant.Grant.GrantID, grant.Grant.GrantHash, grant.Grant.Nonce,
		)
		result <- consumeErr
	}()
	select {
	case early := <-result:
		_ = tx.Rollback()
		t.Fatalf("approval consumption bypassed held scope lock: %v", early)
	case <-time.After(100 * time.Millisecond):
	}
	transitionClock.Store(grant.Grant.ExpiresAt.UnixMicro())
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case consumeErr := <-result:
		if !errors.Is(consumeErr, ErrTransitionConflict) {
			t.Fatalf("approval consumption after grant expiry = %v, want ErrTransitionConflict", consumeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("approval consumption did not resume after scope lock release")
	}
	assertApprovalPersistedState(t, ctx, lockDB, grant, StateGrantIssued, false)
}

type approvalFenceResult struct {
	replayed bool
	err      error
}

func raceDispatchAdmissionAndFence(
	t *testing.T,
	ctx context.Context,
	admitter *DispatchAdmitter,
	store *kernel.ScopedStopStore,
	scope kernel.StopScope,
	request DispatchAdmissionRequest,
	commandID string,
) (DispatchAdmissionRecord, error) {
	t.Helper()
	start := make(chan struct{})
	admissionResult := make(chan dispatchAdmissionResult, 1)
	fenceResult := make(chan approvalFenceResult, 1)
	go func() {
		<-start
		record, err := admitter.Claim(ctx, request)
		admissionResult <- dispatchAdmissionResult{record: record, err: err}
	}()
	go func() {
		<-start
		_, replayed, err := store.Fence(
			ctx, approvalTestFenceCommand(scope, commandID), approvalTestFenceAcknowledgement(),
		)
		fenceResult <- approvalFenceResult{replayed: replayed, err: err}
	}()
	close(start)
	var admitted dispatchAdmissionResult
	select {
	case admitted = <-admissionResult:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent dispatch admission did not finish")
	}
	select {
	case fenced := <-fenceResult:
		if fenced.err != nil || fenced.replayed {
			t.Fatalf("concurrent FENCE replayed=%t error=%v", fenced.replayed, fenced.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent FENCE did not finish")
	}
	return admitted.record, admitted.err
}

func fenceApprovalTestScopeAfterLockProof(
	t *testing.T,
	ctx context.Context,
	lockDB *sql.DB,
	store *kernel.ScopedStopStore,
	scope kernel.StopScope,
	commandID string,
) {
	t.Helper()
	tx, err := lockDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
		scope.TenantID, scope.WorkspaceID,
	); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	result := make(chan approvalFenceResult, 1)
	go func() {
		_, replayed, fenceErr := store.Fence(
			ctx, approvalTestFenceCommand(scope, commandID), approvalTestFenceAcknowledgement(),
		)
		result <- approvalFenceResult{replayed: replayed, err: fenceErr}
	}()
	select {
	case early := <-result:
		_ = tx.Rollback()
		t.Fatalf("FENCE bypassed held scope lock: %+v", early)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case completed := <-result:
		if completed.err != nil || completed.replayed {
			t.Fatalf("FENCE after scope lock release: replayed=%t error=%v", completed.replayed, completed.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FENCE did not resume after scope lock release")
	}
}

func fenceApprovalTestScope(
	t *testing.T,
	ctx context.Context,
	store *kernel.ScopedStopStore,
	scope kernel.StopScope,
	commandID string,
) {
	t.Helper()
	_, replayed, err := store.Fence(
		ctx, approvalTestFenceCommand(scope, commandID), approvalTestFenceAcknowledgement(),
	)
	if err != nil || replayed {
		t.Fatalf("Fence(%+v) replayed=%t error=%v", scope, replayed, err)
	}
}

func approvalTestFenceCommand(scope kernel.StopScope, commandID string) kernel.FenceCommand {
	now := time.Now().UTC()
	return kernel.FenceCommand{
		ContractVersion: kernel.EmergencyStopFenceContractVersion,
		Audience:        "approval-postgres-test", KeyID: "control-plane-test", CommandID: commandID,
		TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, Epoch: 1,
		ActorID: "operator-test", Reason: "approval containment proof",
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
}

func approvalTestFenceAcknowledgement() kernel.AcknowledgementIdentity {
	return kernel.AcknowledgementIdentity{
		KeyID: "kernel-test", SignerProfile: kernel.EmergencyStopSignerClassical,
		PublicKey: strings.Repeat("a", 64),
	}
}

func assertApprovalRLSVisibility(t *testing.T, ctx context.Context, db *sql.DB, tenantID, workspaceID, approvalID string, want int) {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin RLS visibility transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		t.Fatalf("set RLS visibility tenant: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, workspaceID); err != nil {
		t.Fatalf("set RLS visibility workspace: %v", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approval_ceremonies WHERE approval_id = $1`, approvalID).Scan(&count); err != nil {
		t.Fatalf("query RLS visibility: %v", err)
	}
	if count != want {
		t.Fatalf("RLS visibility for tenant %q workspace %q = %d, want %d", tenantID, workspaceID, count, want)
	}
}

func assertDispatchAdmissionRLSVisibility(t *testing.T, ctx context.Context, db *sql.DB, tenantID, workspaceID, attemptID string, want int) {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, workspaceID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approval_dispatch_admissions WHERE attempt_id = $1`, attemptID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("dispatch admission RLS visibility for tenant %q workspace %q = %d, want %d", tenantID, workspaceID, count, want)
	}
}

func assertEmergencyStopRLSVisibility(t *testing.T, ctx context.Context, db *sql.DB, tenantID, workspaceID string, want int) {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, workspaceID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM emergency_stop_fences`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("emergency-stop RLS visibility for tenant %q workspace %q = %d, want %d", tenantID, workspaceID, count, want)
	}
}

func assertApprovalPersistedState(t *testing.T, ctx context.Context, db *sql.DB, record Record, want State, consumed bool) {
	t.Helper()
	var persistedState string
	var persistedConsumedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT state, consumed_at FROM approval_ceremonies
		WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3`,
		record.TenantID, record.WorkspaceID, record.ApprovalID,
	).Scan(&persistedState, &persistedConsumedAt); err != nil {
		t.Fatalf("read persisted approval state: %v", err)
	}
	if persistedState != string(want) || persistedConsumedAt.Valid != consumed {
		t.Fatalf("persisted approval state = %s consumed=%t, want %s consumed=%t",
			persistedState, persistedConsumedAt.Valid, want, consumed)
	}
}

func issueApprovalTestGrant(
	t *testing.T,
	ctx context.Context,
	service *Service,
	spec ChallengeSpec,
	approverKeys map[string]ed25519.PrivateKey,
	clockNow *time.Time,
	config ServiceConfig,
) Record {
	t.Helper()
	hold, err := service.BeginHold(ctx, spec.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold(): %v", err)
	}
	*clockNow = hold.HoldStartedAt.Add(config.MinHoldDuration)
	challenged, err := service.IssueChallenge(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge(): %v", err)
	}
	assertions := approvalTestAssertions(t, *challenged.Challenge, approverKeys)
	*clockNow = clockNow.Add(time.Minute)
	if _, err := service.VerifyQuorum(ctx, hold.ApprovalID, assertions); err != nil {
		t.Fatalf("VerifyQuorum(): %v", err)
	}
	*clockNow = clockNow.Add(time.Minute)
	granted, err := service.IssueGrant(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueGrant(): %v", err)
	}
	return granted
}

type staticAuthorityProvider struct {
	store approvalverify.TrustStore
}

type staticBindingProvider struct {
	spec ChallengeSpec
}

type staticConsumerProvider struct {
	identity ConsumerIdentity
}

type staticControlProvider struct {
	identity ControlIdentity
}

func (p staticControlProvider) LoadControlIdentity(context.Context) (ControlIdentity, error) {
	return p.identity, nil
}

func (p staticConsumerProvider) LoadConsumerIdentity(context.Context) (ConsumerIdentity, error) {
	return p.identity, nil
}

func (p staticBindingProvider) LoadApprovalBinding(_ context.Context, _, _, _ string) (ChallengeSpec, error) {
	return p.spec, nil
}

func (p staticAuthorityProvider) LoadApprovalAuthority(_ context.Context, _, _, _, _, _ string) (approvalverify.TrustStore, error) {
	return p.store, nil
}

func approvalTestAuthority(spec ChallengeSpec, holdStarted time.Time) (approvalverify.TrustStore, map[string]ed25519.PrivateKey) {
	privateKeys := map[string]ed25519.PrivateKey{
		"key-a": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)),
		"key-b": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)),
	}
	keys := make(map[string]approvalverify.TrustedApproverKey, len(privateKeys))
	for index, keyID := range []string{"key-a", "key-b"} {
		suffix := string(rune('a' + index))
		keys[keyID] = approvalverify.TrustedApproverKey{
			KeyID: keyID, TenantID: spec.TenantID, PrincipalID: "principal-" + suffix,
			CredentialID: "credential-" + suffix, DeviceID: "device-" + suffix,
			PublicKey:    privateKeys[keyID].Public().(ed25519.PublicKey),
			WorkspaceIDs: []string{spec.WorkspaceID}, Roles: []string{spec.RequiredRole},
			Actions: []string{spec.Action}, Audiences: []string{spec.Audience}, Enabled: true,
			NotBefore: holdStarted.Add(-time.Hour), NotAfter: holdStarted.Add(2 * time.Hour),
		}
	}
	return approvalverify.TrustStore{
		AuthoritySource: spec.AuthoritySource, AuthorityVersion: spec.AuthorityVersion,
		AuthoritySnapshotHash: spec.AuthoritySnapshotHash, Keys: keys,
	}, privateKeys
}

func approvalTestAssertions(t *testing.T, challenge contracts.ApprovalChallenge, privateKeys map[string]ed25519.PrivateKey) []contracts.ApprovalAssertion {
	t.Helper()
	assertions := make([]contracts.ApprovalAssertion, 0, len(privateKeys))
	for _, keyID := range []string{"key-a", "key-b"} {
		assertion := contracts.ApprovalAssertion{
			Domain: contracts.ApprovalAssertionDomainV1, SchemaVersion: contracts.ApprovalAssertionSchemaV1,
			ContractVersion: contracts.ApprovalAssertionContractV1,
			ChallengeID:     challenge.ChallengeID, ChallengeHash: challenge.ChallengeHash,
			KeyID: keyID, Algorithm: contracts.ApprovalAssertionEd25519,
		}
		digest, err := assertion.SigningDigest()
		if err != nil {
			t.Fatalf("ApprovalAssertion.SigningDigest(): %v", err)
		}
		assertion.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKeys[keyID], digest))
		assertions = append(assertions, assertion)
	}
	return assertions
}

func openApprovalTestPostgres(t *testing.T, rawURL, schema string) *sql.DB {
	return openApprovalTestPostgresAs(t, rawURL, schema, "", "")
}

func openApprovalTestPostgresAs(t *testing.T, rawURL, schema, username, password string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style Postgres DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	if username != "" {
		parsed.User = url.UserPassword(username, password)
	}
	db, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatalf("open Postgres: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	return db
}

func collectRecords(channel <-chan Record) []Record {
	result := make([]Record, 0)
	for record := range channel {
		result = append(result, record)
	}
	return result
}

func collectErrors(channel <-chan error) []error {
	result := make([]error, 0)
	for err := range channel {
		result = append(result, err)
	}
	return result
}
