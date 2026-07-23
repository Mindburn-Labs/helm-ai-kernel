package approvalceremony

// quantum_posture: integration test over classical Ed25519 effect-reservation
// and connector release-authority evidence; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
	"github.com/lib/pq"
)

func TestPostgresEffectReservationOrdersFenceRevocationAndLifecycle(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run effect reservation PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	suffix := time.Now().UnixNano()
	schema := fmt.Sprintf("helm_effect_reservation_%d", suffix)
	ownerDB := openApprovalTestPostgres(t, postgresURL, schema)
	defer ownerDB.Close()
	if _, err := ownerDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = ownerDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	}()

	approvalKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	approvalSigner := crypto.NewEd25519SignerFromKey(approvalKey, "effect-reservation-approval-test")
	grantVerifier, err := NewEd25519GrantSignatureVerifier(approvalSigner.PublicKeyBytes(), "kms://helm/approval-a", "kernel-root-a")
	if err != nil {
		t.Fatal(err)
	}
	ownerStore := NewPostgresStore(ownerDB, grantVerifier)
	if err := ownerStore.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ownerStore.Init(ctx); err != nil {
		t.Fatalf("idempotent effect close schema init: %v", err)
	}
	stopStore := kernel.NewScopedStopStore(ownerDB, time.Now, kernel.WithPostgresScopeLocks())
	if err := stopStore.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connectorregistry.ApplyConnectorReleaseAuthorityMigrations(ctx, ownerDB); err != nil {
		t.Fatal(err)
	}

	runtimeRole := fmt.Sprintf("helm_effect_runtime_%d", suffix)
	runtimePassword := "helm-effect-reservation-test"
	quotedRole := pq.QuoteIdentifier(runtimeRole)
	if _, err := ownerDB.ExecContext(ctx, `CREATE ROLE `+quotedRole+` WITH LOGIN PASSWORD '`+runtimePassword+`'
		NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = ownerDB.ExecContext(cleanupCtx, `DROP OWNED BY `+quotedRole)
		_, _ = ownerDB.ExecContext(cleanupCtx, `DROP ROLE IF EXISTS `+quotedRole)
	}()
	if _, err := ownerDB.ExecContext(ctx, `GRANT USAGE ON SCHEMA `+pq.QuoteIdentifier(schema)+` TO `+quotedRole); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{
		`GRANT SELECT ON approval_dispatch_admissions TO ` + quotedRole,
		`GRANT SELECT, INSERT ON approval_effect_reservation_events TO ` + quotedRole,
		`GRANT SELECT, INSERT ON approval_effect_closures TO ` + quotedRole,
		`GRANT SELECT, INSERT ON approval_effect_dispositions TO ` + quotedRole,
		`GRANT SELECT ON connector_release_authorities TO ` + quotedRole,
		`GRANT SELECT ON emergency_stop_fences TO ` + quotedRole,
	} {
		if _, err := ownerDB.ExecContext(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}

	releaseKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, ed25519.SeedSize))
	releaseSigner := crypto.NewEd25519SignerFromKey(releaseKey, "effect-reservation-release-test")
	acknowledgementKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, ed25519.SeedSize))
	acknowledgementSigner := crypto.NewEd25519SignerFromKey(acknowledgementKey, "effect-acknowledgement-test")
	dispositionKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{45}, ed25519.SeedSize))
	dispositionSigner := crypto.NewEd25519SignerFromKey(dispositionKey, "effect-disposition-test")
	now := time.Now().UTC().Truncate(time.Microsecond)
	keyNotBefore := now.Add(-time.Hour)
	keyNotAfter := now.Add(time.Hour)
	releaseVerifier, err := connectorregistry.NewEd25519ReleaseAuthorityVerifier("connector-registry-a", []connectorregistry.TrustedReleaseAuthorityKey{{
		AuthorityID: "connector-registry-a", SigningKeyRef: "kms://helm/connectors-a",
		PublicKey: releaseKey.Public().(ed25519.PublicKey), Enabled: true,
		NotBefore: keyNotBefore, NotAfter: keyNotAfter,
	}})
	if err != nil {
		t.Fatal(err)
	}
	dispositionVerifier, err := NewEd25519EffectDispositionCommandVerifier([]TrustedEffectDispositionCommandKey{{
		AuthorityID: "spiffe://helm/control-plane", SigningKeyRef: "kms://helm/control-plane/disposition-a",
		Audience: "packs.lifecycle", PublicKey: dispositionSigner.PublicKeyBytes(), Enabled: true,
		NotBefore: keyNotBefore, NotAfter: keyNotAfter,
	}})
	if err != nil {
		t.Fatal(err)
	}
	validUntil := now.Add(30 * time.Minute)
	release, err := (contracts.ConnectorReleaseAuthority{
		SchemaVersion: contracts.ConnectorReleaseAuthoritySchemaV1, ContractVersion: contracts.ConnectorReleaseAuthorityContractV1,
		AuthorityID: "connector-registry-a", SigningKeyRef: "kms://helm/connectors-a",
		Algorithm: contracts.ConnectorReleaseAuthorityAlgorithmV1, RegistryRevision: 1,
		ScopeKind:   contracts.ConnectorReleaseAuthorityScopeGlobal,
		ConnectorID: "connector-a", ConnectorVersion: "1.0.0", State: contracts.ConnectorReleaseAuthorityStateCertified,
		ConnectorExecutorKind: "digital", ConnectorSandboxProfile: "sandbox-pack-lifecycle-v1",
		ConnectorDriftPolicyRef: "policy://connector-drift/v1", ConnectorBinaryHash: shaRef("7"),
		ConnectorSignatureRef: "sigstore://connector-a/1.0.0", ConnectorSignatureHash: shaRef("6"),
		ConnectorSignerID: "publisher-a", CertificationRef: "cert://connector-a/1.0.0",
		CertificationHash: shaRef("8"), CertificationAuthority: "spiffe://helm/certification-authority",
		SignedAt: now.Add(-time.Minute), ValidFrom: now.Add(-30 * time.Second), ValidUntil: &validUntil,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, err := connectorregistry.SignConnectorReleaseAuthority(release, releaseSigner)
	if err != nil {
		t.Fatal(err)
	}
	releaseAdmin, err := connectorregistry.NewPostgresReleaseAuthorityAdminStore(ownerDB, releaseVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := releaseAdmin.Append(ctx, releaseEnvelope); err != nil {
		t.Fatal(err)
	}

	runtimeDB := openApprovalTestPostgresAs(t, postgresURL, schema, runtimeRole, runtimePassword)
	defer runtimeDB.Close()
	runtimeStore := NewPostgresStore(runtimeDB, grantVerifier)
	releaseRuntime, err := connectorregistry.NewPostgresReleaseAuthorityStore(runtimeDB, releaseVerifier)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgementVerifier, err := NewEd25519EffectAcknowledgementVerifier([]TrustedEffectAcknowledgementKey{{
		IssuerID: "publisher-a", SigningKeyRef: "kms://helm/connector-ack-a",
		ConnectorID: "connector-a", ConnectorVersion: "1.0.0",
		PublicKey: acknowledgementSigner.PublicKeyBytes(), Enabled: true,
		NotBefore: keyNotBefore, NotAfter: keyNotAfter,
	}})
	if err != nil {
		t.Fatal(err)
	}
	consumer := ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-a", TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
	}
	admitter, err := NewEffectReservationAdmitter(runtimeStore, staticConsumerProvider{identity: consumer}, releaseRuntime)
	if err != nil {
		t.Fatal(err)
	}
	evidencePackHash := shaRef("e")
	closer, err := NewEffectCloser(
		runtimeStore,
		staticConsumerProvider{identity: consumer},
		releaseRuntime,
		acknowledgementVerifier,
		dispositionVerifier,
		staticEffectEvidencePackVerifier{ref: "evidence-pack-a", hash: evidencePackHash},
		approvalSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	dispositions, err := NewEffectDispositionService(
		runtimeStore, staticConsumerProvider{identity: consumer}, releaseRuntime, dispositionVerifier, approvalSigner,
	)
	if err != nil {
		t.Fatal(err)
	}

	first := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-a", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, first)
	admitted, err := admitter.Admit(ctx, first)
	if err != nil {
		t.Fatalf("Admit(): %v", err)
	}
	if admitted.State != EffectReservationStateAdmitted || admitted.Sequence != 1 {
		t.Fatalf("admitted event = %+v", admitted)
	}
	replayed, err := admitter.Admit(ctx, first)
	if err != nil || replayed.Sequence != admitted.Sequence || !replayed.OccurredAt.Equal(admitted.OccurredAt) {
		t.Fatalf("Admit() replay = %+v, %v", replayed, err)
	}
	startedMeta := EffectTransitionMeta{ConnectorExecutionRef: "github-request-a", ProofSessionRef: "proof-session-a", IntentRef: "intent-a"}
	started, err := admitter.MarkStarted(ctx, first.Admission.AdmissionID, startedMeta)
	if err != nil || started.State != EffectReservationStateStarted || started.Sequence != 2 {
		t.Fatalf("MarkStarted() = %+v, %v", started, err)
	}
	if replay, err := admitter.MarkStarted(ctx, first.Admission.AdmissionID, startedMeta); !errors.Is(err, ErrEffectReservationAlreadyStarted) || replay.Sequence != 2 {
		t.Fatalf("MarkStarted() duplicate claim = %+v, %v", replay, err)
	}
	assertEffectReservationRejectsStartedRefRewrite(t, ctx, runtimeStore, started)
	if _, err := admitter.MarkUncertain(ctx, first.Admission.AdmissionID, EffectTransitionMeta{
		ReasonCode: "CONNECTOR_ACK_MISSING", ConnectorExecutionRef: "other-execution",
	}); !errors.Is(err, ErrEffectReservationConflict) {
		t.Fatalf("STARTED reference substitution error = %v", err)
	}
	uncertainMeta := EffectTransitionMeta{
		ReasonCode: "CONNECTOR_ACK_MISSING", EffectRef: "effect-a",
	}
	uncertain, err := admitter.MarkUncertain(ctx, first.Admission.AdmissionID, uncertainMeta)
	if err != nil || uncertain.State != EffectReservationStateUncertain || uncertain.Sequence != 3 {
		t.Fatalf("MarkUncertain() = %+v, %v", uncertain, err)
	}
	if uncertain.ConnectorExecutionRef != started.ConnectorExecutionRef || uncertain.ProofSessionRef != started.ProofSessionRef ||
		uncertain.IntentRef != started.IntentRef || uncertain.EffectRef != uncertainMeta.EffectRef {
		t.Fatalf("UNCERTAIN refs = %+v, want STARTED continuity plus effect ref", uncertain)
	}
	if _, err := admitter.MarkNotStarted(ctx, first.Admission.AdmissionID, EffectTransitionMeta{ReasonCode: "TOO_LATE"}); !errors.Is(err, ErrEffectReservationTerminal) {
		t.Fatalf("terminal transition error = %v", err)
	}

	second := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-b", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, second)
	if _, err := admitter.Admit(ctx, second); err != nil {
		t.Fatal(err)
	}
	notStarted, err := admitter.MarkNotStarted(ctx, second.Admission.AdmissionID, EffectTransitionMeta{ReasonCode: "CONNECTOR_PRECHECK_DENIED"})
	if err != nil || notStarted.State != EffectReservationStateNotStarted {
		t.Fatalf("MarkNotStarted() = %+v, %v", notStarted, err)
	}

	fenceStartConsumer := consumer
	fenceStartConsumer.WorkspaceID = "workspace-fence-start"
	fenceStartAdmitter, err := NewEffectReservationAdmitter(
		runtimeStore,
		staticConsumerProvider{identity: fenceStartConsumer},
		releaseRuntime,
	)
	if err != nil {
		t.Fatal(err)
	}
	fenceStart := effectReservationAdmissionFixture(t, approvalSigner, release, fenceStartConsumer, "attempt-fence-start", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, fenceStart)
	if _, err := fenceStartAdmitter.Admit(ctx, fenceStart); err != nil {
		t.Fatal(err)
	}
	fenceStartMeta := EffectTransitionMeta{ConnectorExecutionRef: "github-request-fence-start", IntentRef: "intent-fence-start"}
	fenceStartGate := make(chan struct{})
	fenceStartResult := make(chan error, 1)
	fenceResult := make(chan error, 1)
	go func() {
		<-fenceStartGate
		_, startErr := fenceStartAdmitter.MarkStarted(ctx, fenceStart.Admission.AdmissionID, fenceStartMeta)
		fenceStartResult <- startErr
	}()
	go func() {
		<-fenceStartGate
		command := approvalTestFenceCommand(
			kernel.StopScope{TenantID: fenceStartConsumer.TenantID, WorkspaceID: fenceStartConsumer.WorkspaceID},
			"fence-effect-start-race",
		)
		_, _, fenceErr := stopStore.Fence(ctx, command, approvalTestFenceAcknowledgement())
		fenceResult <- fenceErr
	}()
	close(fenceStartGate)
	if err := <-fenceResult; err != nil {
		t.Fatalf("concurrent start fence: %v", err)
	}
	fenceStartErr := <-fenceStartResult
	if fenceStartErr == nil {
		if recovered, err := fenceStartAdmitter.Recover(ctx, fenceStart.Admission.AdmissionID); err != nil || recovered.State != EffectReservationStateStarted {
			t.Fatalf("start-first fence ordering = %+v, %v", recovered, err)
		}
	} else {
		if !errors.Is(fenceStartErr, ErrEffectReservationStartDenied) || !errors.Is(fenceStartErr, ErrEmergencyStopFenced) {
			t.Fatalf("fence-first start error = %v, want typed emergency-stop start denial", fenceStartErr)
		}
		closed, err := fenceStartAdmitter.MarkNotStarted(ctx, fenceStart.Admission.AdmissionID, EffectTransitionMeta{
			ReasonCode: "START_INTERLOCK_FENCED",
			IntentRef:  fenceStartMeta.IntentRef,
		})
		if err != nil || closed.State != EffectReservationStateNotStarted {
			t.Fatalf("close fence-denied start = %+v, %v", closed, err)
		}
	}

	startClaim := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-start-claim", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, startClaim)
	if _, err := admitter.Admit(ctx, startClaim); err != nil {
		t.Fatal(err)
	}
	claimMeta := EffectTransitionMeta{ConnectorExecutionRef: "github-request-start-claim", IntentRef: "intent-start-claim"}
	claimGate := make(chan struct{})
	claimResults := make(chan error, 2)
	for range 2 {
		go func() {
			<-claimGate
			_, claimErr := admitter.MarkStarted(ctx, startClaim.Admission.AdmissionID, claimMeta)
			claimResults <- claimErr
		}()
	}
	close(claimGate)
	claimed, rejected := 0, 0
	for range 2 {
		switch claimErr := <-claimResults; {
		case claimErr == nil:
			claimed++
		case errors.Is(claimErr, ErrEffectReservationAlreadyStarted):
			rejected++
		default:
			t.Fatalf("concurrent STARTED claim error = %v", claimErr)
		}
	}
	if claimed != 1 || rejected != 1 {
		t.Fatalf("concurrent STARTED claims = success:%d rejected:%d, want 1/1", claimed, rejected)
	}
	if _, err := admitter.MarkUncertain(ctx, startClaim.Admission.AdmissionID, EffectTransitionMeta{
		ReasonCode: "TEST_RECONCILIATION_REQUIRED", ConnectorExecutionRef: claimMeta.ConnectorExecutionRef, IntentRef: claimMeta.IntentRef,
	}); err != nil {
		t.Fatal(err)
	}
	startClaimUncertain, err := admitter.Recover(ctx, startClaim.Admission.AdmissionID)
	if err != nil {
		t.Fatal(err)
	}
	preFenceDisposition := effectDispositionTestEnvelope(
		t, dispositionSigner, startClaimUncertain, kernel.FenceState{
			StopScope: kernel.StopScope{TenantID: consumer.TenantID, WorkspaceID: consumer.WorkspaceID},
			CommandID: "not-yet-fenced", CommandHash: shaRef("1"), Epoch: 1, ReceiptHash: shaRef("2"),
		}, 1, "", contracts.EffectDispositionActionHold, time.Now().UTC().Truncate(time.Microsecond),
	)
	if _, err := dispositions.Record(ctx, preFenceDisposition); !errors.Is(err, ErrEffectDispositionRequiresFence) {
		t.Fatalf("pre-FENCE disposition error = %v", err)
	}
	directCloseAdmission := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-direct-close", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, directCloseAdmission)
	if _, err := admitter.Admit(ctx, directCloseAdmission); err != nil {
		t.Fatal(err)
	}
	directCloseStarted, err := admitter.MarkStarted(ctx, directCloseAdmission.Admission.AdmissionID, EffectTransitionMeta{
		ConnectorExecutionRef: "github-request-direct-close", IntentRef: "intent-direct-close",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertEffectReservationRejectsCompletionWithoutClosure(t, ctx, runtimeStore, directCloseStarted)
	directAcknowledgement, err := (contracts.ConnectorEffectAcknowledgement{
		SchemaVersion:     contracts.ConnectorEffectAcknowledgementSchemaV1,
		ContractVersion:   contracts.ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: "effect-ack-direct-close", AdmissionID: directCloseAdmission.Admission.AdmissionID,
		AttemptID: directCloseAdmission.Admission.AttemptID,
		TenantID:  consumer.TenantID, WorkspaceID: consumer.WorkspaceID, Audience: consumer.Audience,
		ConnectorID: release.ConnectorID, ConnectorVersion: release.ConnectorVersion,
		ConnectorAction:       directCloseAdmission.Admission.ConnectorAuthority.ConnectorAction,
		ConnectorExecutionRef: directCloseStarted.ConnectorExecutionRef, IntentRef: directCloseStarted.IntentRef,
		IdempotencyKeyHash: directCloseAdmission.Admission.IdempotencyKeyHash,
		EffectHash:         directCloseAdmission.Admission.EffectHash,
		Outcome:            contracts.ConnectorEffectOutcomeNotApplied, ResponseHash: shaRef("d"),
		IssuerID: release.ConnectorSignerID, SigningKeyRef: "kms://helm/connector-ack-a",
		Algorithm:  contracts.ConnectorEffectAcknowledgementAlgorithm,
		ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	directAcknowledgementEnvelope, err := SignConnectorEffectAcknowledgement(directAcknowledgement, acknowledgementSigner)
	if err != nil {
		t.Fatal(err)
	}
	directCloseRequest := EffectCloseRequest{
		AdmissionID:     directCloseAdmission.Admission.AdmissionID,
		Acknowledgement: directAcknowledgementEnvelope,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: evidencePackHash,
	}
	directCloseGate := make(chan struct{})
	directCloseResults := make(chan EffectClosureRecord, 2)
	directCloseErrors := make(chan error, 2)
	for range 2 {
		go func() {
			<-directCloseGate
			record, closeErr := closer.Close(ctx, directCloseRequest)
			directCloseResults <- record
			directCloseErrors <- closeErr
		}()
	}
	close(directCloseGate)
	var directCloseHash string
	for range 2 {
		record, closeErr := <-directCloseResults, <-directCloseErrors
		if closeErr != nil {
			t.Fatalf("concurrent direct Close(): %v", closeErr)
		}
		if directCloseHash == "" {
			directCloseHash = record.Receipt.ReceiptHash
		} else if record.Receipt.ReceiptHash != directCloseHash {
			t.Fatalf("concurrent direct close hashes differ: %s != %s", record.Receipt.ReceiptHash, directCloseHash)
		}
	}
	if recovered, err := admitter.Recover(ctx, directCloseAdmission.Admission.AdmissionID); err != nil ||
		recovered.State != EffectReservationStateCompleted || recovered.Sequence != 3 ||
		recovered.Outcome != contracts.ConnectorEffectOutcomeNotApplied || recovered.EffectRef != "" {
		t.Fatalf("direct completed reservation = %+v, %v", recovered, err)
	}
	admittedOnly := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-admitted-only", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, admittedOnly)
	if admitted, err := admitter.Admit(ctx, admittedOnly); err != nil || admitted.State != EffectReservationStateAdmitted {
		t.Fatalf("admitted-only reservation = %+v, %v", admitted, err)
	}
	active, err := admitter.ListActive(ctx)
	activeIDs := map[string]bool{}
	for _, event := range active {
		activeIDs[event.Admission.Admission.AdmissionID] = true
	}
	if err != nil || len(active) != 3 || !activeIDs[first.Admission.AdmissionID] || !activeIDs[startClaim.Admission.AdmissionID] ||
		!activeIDs[admittedOnly.Admission.AdmissionID] {
		t.Fatalf("ListActive() = %+v, %v", active, err)
	}

	third := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-c", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, third)
	revokeStartConsumer := consumer
	revokeStartConsumer.WorkspaceID = "workspace-revoke-start"
	revokeStartAdmitter, err := NewEffectReservationAdmitter(
		runtimeStore,
		staticConsumerProvider{identity: revokeStartConsumer},
		releaseRuntime,
	)
	if err != nil {
		t.Fatal(err)
	}
	revokeStart := effectReservationAdmissionFixture(t, approvalSigner, release, revokeStartConsumer, "attempt-revoke-start", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, revokeStart)
	if _, err := revokeStartAdmitter.Admit(ctx, revokeStart); err != nil {
		t.Fatal(err)
	}
	revokeStartMeta := EffectTransitionMeta{ConnectorExecutionRef: "github-request-revoke-start", IntentRef: "intent-revoke-start"}

	revoked := release
	revoked.RegistryRevision = 2
	revoked.State = contracts.ConnectorReleaseAuthorityStateRevoked
	revoked.PreviousAuthorityHash = release.AuthorityHash
	revoked.RevokesAuthorityHash = release.AuthorityHash
	revoked.ValidUntil = nil
	revoked.SignedAt = now.Add(2 * time.Second)
	revoked.ValidFrom = now.Add(2 * time.Second)
	revoked.AuthorityHash = ""
	revoked, err = revoked.Seal()
	if err != nil {
		t.Fatal(err)
	}
	revokedEnvelope, err := connectorregistry.SignConnectorReleaseAuthority(revoked, releaseSigner)
	if err != nil {
		t.Fatal(err)
	}
	startRace := make(chan struct{})
	revokeResult := make(chan error, 1)
	admitResult := make(chan error, 1)
	revokeStartResult := make(chan error, 1)
	go func() {
		<-startRace
		_, appendErr := releaseAdmin.Append(ctx, revokedEnvelope)
		revokeResult <- appendErr
	}()
	go func() {
		<-startRace
		_, admitErr := admitter.Admit(ctx, third)
		admitResult <- admitErr
	}()
	go func() {
		<-startRace
		_, startErr := revokeStartAdmitter.MarkStarted(ctx, revokeStart.Admission.AdmissionID, revokeStartMeta)
		revokeStartResult <- startErr
	}()
	close(startRace)
	if err := <-revokeResult; err != nil {
		t.Fatalf("concurrent revocation: %v", err)
	}
	concurrentAdmitErr := <-admitResult
	if concurrentAdmitErr == nil {
		if recovered, err := admitter.Recover(ctx, third.Admission.AdmissionID); err != nil || recovered.State != EffectReservationStateAdmitted {
			t.Fatalf("admission-first release ordering = %+v, %v", recovered, err)
		}
	} else if !errors.Is(concurrentAdmitErr, connectorregistry.ErrReleaseAuthorityRejected) {
		t.Fatalf("revocation-first admission error = %v, want current-release rejection", concurrentAdmitErr)
	}
	concurrentStartErr := <-revokeStartResult
	if concurrentStartErr == nil {
		if recovered, err := revokeStartAdmitter.Recover(ctx, revokeStart.Admission.AdmissionID); err != nil || recovered.State != EffectReservationStateStarted {
			t.Fatalf("start-first release ordering = %+v, %v", recovered, err)
		}
	} else {
		if !errors.Is(concurrentStartErr, ErrEffectReservationStartDenied) ||
			!errors.Is(concurrentStartErr, connectorregistry.ErrReleaseAuthorityRejected) {
			t.Fatalf("revocation-first start error = %v, want typed current-release start denial", concurrentStartErr)
		}
		closed, err := revokeStartAdmitter.MarkNotStarted(ctx, revokeStart.Admission.AdmissionID, EffectTransitionMeta{
			ReasonCode: "START_INTERLOCK_RELEASE_REVOKED",
			IntentRef:  revokeStartMeta.IntentRef,
		})
		if err != nil || closed.State != EffectReservationStateNotStarted {
			t.Fatalf("close release-denied start = %+v, %v", closed, err)
		}
	}

	fourth := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-d", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, fourth)
	if _, err := admitter.Admit(ctx, fourth); err == nil {
		t.Fatal("revoked release admitted a new effect reservation")
	}

	fenceCommand := approvalTestFenceCommand(kernel.StopScope{TenantID: consumer.TenantID, WorkspaceID: consumer.WorkspaceID}, "fence-effect-reservation-a")
	if _, replayed, err := stopStore.Fence(ctx, fenceCommand, approvalTestFenceAcknowledgement()); err != nil || replayed {
		t.Fatalf("Fence() replayed=%t error=%v", replayed, err)
	}
	fenceState, fenced, err := stopStore.IsFenced(ctx, fenceCommand.Scope())
	if err != nil || !fenced {
		t.Fatalf("active disposition FENCE = %+v fenced=%t error=%v", fenceState, fenced, err)
	}
	preRotationCandidates, err := dispositions.ListReconciliationCandidates(ctx)
	if err != nil {
		t.Fatalf("ListReconciliationCandidates() before disposition = %v", err)
	}
	if preRotationCandidates.ExecutionAuthority != contracts.EffectDispositionExecutionAuthorityNone ||
		preRotationCandidates.Fence.CommandID != fenceState.CommandID ||
		preRotationCandidates.Fence.CommandHash != fenceState.CommandHash ||
		preRotationCandidates.Fence.Epoch != fenceState.Epoch ||
		preRotationCandidates.Fence.ReceiptHash != fenceState.ReceiptHash ||
		len(preRotationCandidates.Candidates) != 2 {
		t.Fatalf("pre-rotation candidates = %+v", preRotationCandidates)
	}
	firstCandidate := reconciliationCandidateForAdmission(t, preRotationCandidates, first.Admission.AdmissionID)
	startClaimCandidate := reconciliationCandidateForAdmission(t, preRotationCandidates, startClaim.Admission.AdmissionID)
	if firstCandidate.ReservationState != string(EffectReservationStateUncertain) ||
		startClaimCandidate.ReservationState != string(EffectReservationStateUncertain) ||
		firstCandidate.NextDispositionSequence != 1 || firstCandidate.PreviousReceiptHash != "" ||
		startClaimCandidate.NextDispositionSequence != 1 || startClaimCandidate.PreviousReceiptHash != "" {
		t.Fatalf("pre-rotation candidate chain = first:%+v start-claim:%+v", firstCandidate, startClaimCandidate)
	}
	for _, candidate := range preRotationCandidates.Candidates {
		if candidate.AdmissionID == admittedOnly.Admission.AdmissionID || candidate.ReservationState == string(EffectReservationStateAdmitted) {
			t.Fatalf("ADMITTED reservation leaked into reconciliation candidates: %+v", candidate)
		}
	}
	wrongScopeConsumer := consumer
	wrongScopeConsumer.WorkspaceID = "workspace-wrong-candidate-scope"
	wrongScopeDispositions, err := NewEffectDispositionService(
		runtimeStore, staticConsumerProvider{identity: wrongScopeConsumer}, releaseRuntime, dispositionVerifier, approvalSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongScopeDispositions.ListReconciliationCandidates(ctx); !errors.Is(err, ErrEffectDispositionRequiresFence) {
		t.Fatalf("wrong-scope reconciliation candidates error = %v", err)
	}
	if historicalClose, err := closer.Recover(ctx, directCloseAdmission.Admission.AdmissionID); err != nil ||
		historicalClose.Receipt.ReceiptHash != directCloseHash {
		t.Fatalf("recover pre-FENCE close after FENCE = %+v, %v", historicalClose, err)
	}
	noDispositionAcknowledgement := effectAcknowledgementTestEnvelope(
		t, acknowledgementSigner, release, startClaimUncertain, "effect-ack-no-disposition",
		contracts.ConnectorEffectOutcomeNotApplied, shaRef("4"), "reconciliation-no-disposition", "",
	)
	if _, err := closer.Close(ctx, EffectCloseRequest{
		AdmissionID: startClaim.Admission.AdmissionID, Acknowledgement: noDispositionAcknowledgement,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: evidencePackHash,
	}); !errors.Is(err, ErrEffectCloseConflict) {
		t.Fatalf("close under FENCE without disposition error = %v", err)
	}
	firstDispositionEnvelope := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, fenceState, 1, "",
		contracts.EffectDispositionActionReconcileSource, time.Now().UTC().Truncate(time.Microsecond),
	)
	wrongScopeRecord := effectDispositionRecordFixture(
		t, approvalSigner, uncertain, fenceState, firstDispositionEnvelope, time.Now().UTC().Truncate(time.Microsecond),
	)
	assertEffectDispositionWrongScopeInsert(t, ctx, runtimeStore, consumer, wrongScopeRecord)
	firstDisposition, err := dispositions.Record(ctx, firstDispositionEnvelope)
	if err != nil {
		t.Fatalf("Record first disposition: %v", err)
	}
	if firstDisposition.Receipt.ExecutionAuthority != contracts.EffectDispositionExecutionAuthorityNone ||
		firstDisposition.Receipt.ReservationHeadHash != firstDispositionEnvelope.Command.ReservationHeadHash {
		t.Fatalf("first disposition receipt = %+v", firstDisposition.Receipt)
	}
	if replay, err := dispositions.Record(ctx, firstDispositionEnvelope); err != nil ||
		replay.Receipt.ReceiptHash != firstDisposition.Receipt.ReceiptHash || !replay.CreatedAt.Equal(firstDisposition.CreatedAt) {
		t.Fatalf("Record disposition replay = %+v, %v", replay, err)
	}
	conflictingDisposition := firstDispositionEnvelope
	conflictingDisposition.Command.Reason = "changed reason"
	if _, err := dispositions.Record(ctx, conflictingDisposition); !errors.Is(err, ErrEffectDispositionCommandRejected) {
		t.Fatalf("mutated disposition replay error = %v", err)
	}
	secondDispositionEnvelope := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, fenceState, 2, firstDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionRequestCancel, time.Now().UTC().Truncate(time.Microsecond),
	)
	secondDisposition, err := dispositions.Record(ctx, secondDispositionEnvelope)
	if err != nil || secondDisposition.Receipt.DispositionSequence != 2 ||
		secondDisposition.Receipt.PreviousReceiptHash != firstDisposition.Receipt.ReceiptHash {
		t.Fatalf("Record chained disposition = %+v, %v", secondDisposition, err)
	}
	if recovered, err := dispositions.Recover(ctx, secondDispositionEnvelope.Command.CommandID); err != nil ||
		recovered.Receipt.ReceiptHash != secondDisposition.Receipt.ReceiptHash {
		t.Fatalf("Recover disposition = %+v, %v", recovered, err)
	}
	listedDispositions, err := dispositions.ListForEffect(ctx, first.Admission.AdmissionID)
	if err != nil || len(listedDispositions) != 2 ||
		listedDispositions[0].Receipt.ReceiptHash != firstDisposition.Receipt.ReceiptHash ||
		listedDispositions[1].Receipt.ReceiptHash != secondDisposition.Receipt.ReceiptHash {
		t.Fatalf("ListForEffect dispositions = %+v, %v", listedDispositions, err)
	}
	candidatesAfterChain, err := dispositions.ListReconciliationCandidates(ctx)
	if err != nil {
		t.Fatalf("ListReconciliationCandidates() after chain = %v", err)
	}
	firstCandidate = reconciliationCandidateForAdmission(t, candidatesAfterChain, first.Admission.AdmissionID)
	if firstCandidate.NextDispositionSequence != 3 || firstCandidate.PreviousReceiptHash != secondDisposition.Receipt.ReceiptHash {
		t.Fatalf("chained reconciliation candidate = %+v", firstCandidate)
	}
	type dispositionRaceResult struct {
		record EffectDispositionRecord
		err    error
	}
	thirdDispositionA := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, fenceState, 3, secondDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionHold, time.Now().UTC().Truncate(time.Microsecond),
	)
	thirdDispositionB := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, fenceState, 3, secondDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionRequestCompensate, time.Now().UTC().Truncate(time.Microsecond),
	)
	dispositionRaceGate := make(chan struct{})
	dispositionRaceResults := make(chan dispositionRaceResult, 2)
	for _, envelope := range []contracts.EffectDispositionCommandEnvelope{thirdDispositionA, thirdDispositionB} {
		envelope := envelope
		go func() {
			<-dispositionRaceGate
			record, recordErr := dispositions.Record(ctx, envelope)
			dispositionRaceResults <- dispositionRaceResult{record: record, err: recordErr}
		}()
	}
	close(dispositionRaceGate)
	var thirdDisposition EffectDispositionRecord
	dispositionRaceSuccesses, dispositionRaceConflicts := 0, 0
	for range 2 {
		result := <-dispositionRaceResults
		switch {
		case result.err == nil:
			dispositionRaceSuccesses++
			thirdDisposition = result.record
		case errors.Is(result.err, ErrEffectDispositionConflict):
			dispositionRaceConflicts++
		default:
			t.Fatalf("concurrent disposition error = %v", result.err)
		}
	}
	if dispositionRaceSuccesses != 1 || dispositionRaceConflicts != 1 {
		t.Fatalf("concurrent disposition results = success:%d conflict:%d", dispositionRaceSuccesses, dispositionRaceConflicts)
	}

	newFenceCommand := approvalTestFenceCommand(fenceCommand.Scope(), "fence-effect-reservation-b")
	newFenceCommand.Epoch = fenceCommand.Epoch + 1
	newFenceState, fenceReplayed, err := stopStore.Fence(ctx, newFenceCommand, approvalTestFenceAcknowledgement())
	if err != nil || fenceReplayed {
		t.Fatalf("advance disposition FENCE = %+v replayed=%t error=%v", newFenceState, fenceReplayed, err)
	}
	postRotationCandidates, err := dispositions.ListReconciliationCandidates(ctx)
	if err != nil {
		t.Fatalf("ListReconciliationCandidates() after FENCE rotation = %v", err)
	}
	if postRotationCandidates.Fence.CommandID != newFenceState.CommandID ||
		postRotationCandidates.Fence.CommandHash != newFenceState.CommandHash ||
		postRotationCandidates.Fence.Epoch != newFenceState.Epoch ||
		postRotationCandidates.Fence.ReceiptHash != newFenceState.ReceiptHash ||
		postRotationCandidates.Fence.ReceiptHash == preRotationCandidates.Fence.ReceiptHash {
		t.Fatalf("current FENCE candidate projection = %+v", postRotationCandidates.Fence)
	}
	firstCandidate = reconciliationCandidateForAdmission(t, postRotationCandidates, first.Admission.AdmissionID)
	if firstCandidate.NextDispositionSequence != 4 || firstCandidate.PreviousReceiptHash != thirdDisposition.Receipt.ReceiptHash {
		t.Fatalf("post-rotation candidate chain = %+v", firstCandidate)
	}
	forgedDispositionEnvelope := effectDispositionTestEnvelope(
		t, dispositionSigner, startClaimUncertain, newFenceState, 1, "",
		contracts.EffectDispositionActionReconcileSource, time.Now().UTC().Truncate(time.Microsecond),
	)
	forgedDisposition := insertForgedEffectDispositionForTest(
		t, ctx, runtimeStore, consumer, startClaimUncertain, newFenceState, forgedDispositionEnvelope,
	)
	forgedSuccessor := effectDispositionTestEnvelope(
		t, dispositionSigner, startClaimUncertain, newFenceState, 2, forgedDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionHold, time.Now().UTC().Truncate(time.Microsecond),
	)
	if _, err := dispositions.Record(ctx, forgedSuccessor); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("append after forged disposition row error = %v", err)
	}
	forgedAcknowledgement, err := (contracts.ConnectorEffectAcknowledgement{
		SchemaVersion:     contracts.ConnectorEffectAcknowledgementSchemaV1,
		ContractVersion:   contracts.ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: "effect-ack-forged-disposition", AdmissionID: startClaim.Admission.AdmissionID,
		AttemptID: startClaim.Admission.AttemptID,
		TenantID:  consumer.TenantID, WorkspaceID: consumer.WorkspaceID, Audience: consumer.Audience,
		ConnectorID: release.ConnectorID, ConnectorVersion: release.ConnectorVersion,
		ConnectorAction:       startClaim.Admission.ConnectorAuthority.ConnectorAction,
		ConnectorExecutionRef: startClaimUncertain.ConnectorExecutionRef,
		ProofSessionRef:       startClaimUncertain.ProofSessionRef, IntentRef: startClaimUncertain.IntentRef,
		IdempotencyKeyHash: startClaim.Admission.IdempotencyKeyHash, EffectHash: startClaim.Admission.EffectHash,
		Outcome: contracts.ConnectorEffectOutcomeNotApplied, ResponseHash: shaRef("6"),
		ReconciliationRef:      forgedDispositionEnvelope.Command.DispositionRef,
		DispositionReceiptHash: forgedDisposition.Receipt.ReceiptHash, IssuerID: release.ConnectorSignerID,
		SigningKeyRef: "kms://helm/connector-ack-a",
		Algorithm:     contracts.ConnectorEffectAcknowledgementAlgorithm,
		ObservedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	forgedAcknowledgementEnvelope, err := SignConnectorEffectAcknowledgement(forgedAcknowledgement, acknowledgementSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closer.Close(ctx, EffectCloseRequest{
		AdmissionID: startClaim.Admission.AdmissionID, Acknowledgement: forgedAcknowledgementEnvelope,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: evidencePackHash,
	}); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("close trusted forged disposition row error = %v", err)
	}
	staleFenceDisposition := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, fenceState, 4, thirdDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionHold, time.Now().UTC().Truncate(time.Microsecond),
	)
	if _, err := dispositions.Record(ctx, staleFenceDisposition); !errors.Is(err, ErrEffectDispositionConflict) {
		t.Fatalf("stale-FENCE disposition error = %v", err)
	}
	staleFenceAcknowledgement := effectAcknowledgementTestEnvelope(
		t, acknowledgementSigner, release, uncertain, "effect-ack-stale-fence-disposition",
		contracts.ConnectorEffectOutcomeApplied, shaRef("5"), thirdDisposition.Command.Command.DispositionRef,
		thirdDisposition.Receipt.ReceiptHash,
	)
	if _, err := closer.Close(ctx, EffectCloseRequest{
		AdmissionID: first.Admission.AdmissionID, Acknowledgement: staleFenceAcknowledgement,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: evidencePackHash,
	}); !errors.Is(err, ErrEffectCloseConflict) {
		t.Fatalf("close with pre-rotation disposition error = %v", err)
	}
	fourthDispositionEnvelope := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, newFenceState, 4, thirdDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionHold, time.Now().UTC().Truncate(time.Microsecond),
	)
	fourthDisposition, err := dispositions.Record(ctx, fourthDispositionEnvelope)
	if err != nil || fourthDisposition.Receipt.FenceReceiptHash != newFenceState.ReceiptHash {
		t.Fatalf("new-FENCE disposition = %+v, %v", fourthDisposition, err)
	}
	holdAcknowledgement := effectAcknowledgementTestEnvelope(
		t, acknowledgementSigner, release, uncertain, "effect-ack-hold-disposition",
		contracts.ConnectorEffectOutcomeApplied, shaRef("7"), fourthDispositionEnvelope.Command.DispositionRef,
		fourthDisposition.Receipt.ReceiptHash,
	)
	if _, err := closer.Close(ctx, EffectCloseRequest{
		AdmissionID: first.Admission.AdmissionID, Acknowledgement: holdAcknowledgement,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: evidencePackHash,
	}); !errors.Is(err, ErrEffectCloseConflict) {
		t.Fatalf("close under HOLD disposition error = %v", err)
	}
	fifthDispositionEnvelope := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, newFenceState, 5, fourthDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionReconcileSource, time.Now().UTC().Truncate(time.Microsecond),
	)
	fifthDisposition, err := dispositions.Record(ctx, fifthDispositionEnvelope)
	if err != nil || fifthDisposition.Receipt.PreviousReceiptHash != fourthDisposition.Receipt.ReceiptHash {
		t.Fatalf("post-HOLD reconciliation disposition = %+v, %v", fifthDisposition, err)
	}
	expiredDisposition := effectDispositionTestEnvelope(
		t, dispositionSigner, uncertain, newFenceState, 6, fifthDisposition.Receipt.ReceiptHash,
		contracts.EffectDispositionActionHold, time.Now().UTC().Add(-6*time.Minute).Truncate(time.Microsecond),
	)
	if _, err := dispositions.Record(ctx, expiredDisposition); !errors.Is(err, ErrEffectDispositionCommandRejected) {
		t.Fatalf("expired disposition error = %v", err)
	}
	listedDispositions, err = dispositions.ListForEffect(ctx, first.Admission.AdmissionID)
	if err != nil || len(listedDispositions) != 5 ||
		listedDispositions[4].Receipt.ReceiptHash != fifthDisposition.Receipt.ReceiptHash {
		t.Fatalf("chained disposition history = %+v, %v", listedDispositions, err)
	}
	fifth := effectReservationAdmissionFixture(t, approvalSigner, release, consumer, "attempt-e", now)
	persistDispatchAdmissionForEffectTest(t, ctx, ownerDB, fifth)
	if _, err := admitter.Admit(ctx, fifth); !errors.Is(err, ErrEmergencyStopFenced) {
		t.Fatalf("fenced Admit() error = %v", err)
	}
	if recovered, err := admitter.Recover(ctx, first.Admission.AdmissionID); err != nil || recovered.State != EffectReservationStateUncertain {
		t.Fatalf("Recover() after fence/revoke = %+v, %v", recovered, err)
	}

	acknowledgedAt := time.Now().UTC().Truncate(time.Microsecond)
	acknowledgement, err := (contracts.ConnectorEffectAcknowledgement{
		SchemaVersion:     contracts.ConnectorEffectAcknowledgementSchemaV1,
		ContractVersion:   contracts.ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: "effect-ack-a", AdmissionID: first.Admission.AdmissionID,
		AttemptID: first.Admission.AttemptID,
		TenantID:  consumer.TenantID, WorkspaceID: consumer.WorkspaceID, Audience: consumer.Audience,
		ConnectorID: release.ConnectorID, ConnectorVersion: release.ConnectorVersion,
		ConnectorAction:       first.Admission.ConnectorAuthority.ConnectorAction,
		ConnectorExecutionRef: started.ConnectorExecutionRef,
		ProofSessionRef:       started.ProofSessionRef, IntentRef: started.IntentRef,
		IdempotencyKeyHash: first.Admission.IdempotencyKeyHash, EffectHash: first.Admission.EffectHash,
		Outcome: contracts.ConnectorEffectOutcomeApplied, ResponseHash: shaRef("9"), EffectRef: uncertain.EffectRef,
		ReconciliationRef:      fifthDispositionEnvelope.Command.DispositionRef,
		DispositionReceiptHash: fifthDisposition.Receipt.ReceiptHash, IssuerID: release.ConnectorSignerID,
		SigningKeyRef: "kms://helm/connector-ack-a",
		Algorithm:     contracts.ConnectorEffectAcknowledgementAlgorithm, ObservedAt: acknowledgedAt,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	acknowledgementEnvelope, err := SignConnectorEffectAcknowledgement(acknowledgement, acknowledgementSigner)
	if err != nil {
		t.Fatal(err)
	}
	missingDispositionBinding := acknowledgement
	missingDispositionBinding.DispositionReceiptHash = ""
	missingDispositionBinding.AcknowledgementHash = ""
	missingDispositionBinding, err = missingDispositionBinding.Seal()
	if err != nil {
		t.Fatal(err)
	}
	missingDispositionEnvelope, err := SignConnectorEffectAcknowledgement(missingDispositionBinding, acknowledgementSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closer.Close(ctx, EffectCloseRequest{
		AdmissionID: first.Admission.AdmissionID, Acknowledgement: missingDispositionEnvelope,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: evidencePackHash,
	}); !errors.Is(err, ErrEffectCloseConflict) {
		t.Fatalf("close without latest disposition receipt error = %v", err)
	}
	closeRequest := EffectCloseRequest{
		AdmissionID: first.Admission.AdmissionID, Acknowledgement: acknowledgementEnvelope,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: evidencePackHash,
	}
	closed, err := closer.Close(ctx, closeRequest)
	if err != nil {
		t.Fatalf("Close() after fence/revocation: %v", err)
	}
	if closed.Receipt.PriorState != contracts.EffectClosePriorStateUncertain ||
		closed.Receipt.Outcome != contracts.ConnectorEffectOutcomeApplied ||
		closed.Receipt.ReservationSequence != uncertain.Sequence ||
		closed.Receipt.AcknowledgementHash != acknowledgement.AcknowledgementHash {
		t.Fatalf("effect close receipt = %+v", closed.Receipt)
	}
	if err := grantVerifier.VerifyEffectCloseReceiptSignature(
		closed.Receipt, closed.SignatureAlgorithm, closed.Signature,
	); err != nil {
		t.Fatalf("effect close receipt signature: %v", err)
	}
	replayedClose, err := closer.Close(ctx, closeRequest)
	if err != nil || replayedClose.Receipt.ReceiptHash != closed.Receipt.ReceiptHash ||
		!replayedClose.CreatedAt.Equal(closed.CreatedAt) {
		t.Fatalf("Close() replay = %+v, %v", replayedClose, err)
	}
	conflictingClose := closeRequest
	conflictingClose.EvidencePackHash = shaRef("f")
	if _, err := closer.Close(ctx, conflictingClose); !errors.Is(err, ErrEffectCloseConflict) {
		t.Fatalf("conflicting Close() error = %v", err)
	}
	recoveredClose, err := closer.Recover(ctx, first.Admission.AdmissionID)
	if err != nil || recoveredClose.Receipt.ReceiptHash != closed.Receipt.ReceiptHash {
		t.Fatalf("Recover close = %+v, %v", recoveredClose, err)
	}
	if recovered, err := admitter.Recover(ctx, first.Admission.AdmissionID); err != nil ||
		recovered.State != EffectReservationStateCompleted || recovered.Sequence != 4 ||
		recovered.CloseReceiptHash != closed.Receipt.ReceiptHash {
		t.Fatalf("Recover() completed reservation = %+v, %v", recovered, err)
	}
	activeAfterClose, err := admitter.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range activeAfterClose {
		if event.Admission.Admission.AdmissionID == first.Admission.AdmissionID {
			t.Fatalf("completed reservation remained active: %+v", event)
		}
	}

	assertEffectReservationRLSIsolation(t, ctx, runtimeDB, "tenant-b", consumer.WorkspaceID)
	assertEffectReservationAppendOnly(t, ctx, ownerDB, consumer, first.Admission.AdmissionID)
	assertEffectClosureAppendOnly(t, ctx, ownerDB, consumer, first.Admission.AdmissionID)
	assertEffectDispositionAppendOnly(t, ctx, ownerDB, consumer, first.Admission.AdmissionID)
}

type staticEffectEvidencePackVerifier struct {
	ref  string
	hash string
}

func (v staticEffectEvidencePackVerifier) VerifyEffectEvidencePack(
	_ context.Context,
	identity ConsumerIdentity,
	ref, hash string,
	acknowledgement contracts.ConnectorEffectAcknowledgementEnvelope,
) error {
	if identity.TenantID != acknowledgement.Acknowledgement.TenantID ||
		identity.WorkspaceID != acknowledgement.Acknowledgement.WorkspaceID ||
		ref != v.ref || hash != v.hash {
		return ErrEffectCloseConflict
	}
	return nil
}

func reconciliationCandidateForAdmission(
	t *testing.T,
	projection contracts.EffectReconciliationCandidates,
	admissionID string,
) contracts.EffectReconciliationCandidate {
	t.Helper()
	for _, candidate := range projection.Candidates {
		if candidate.AdmissionID == admissionID {
			return candidate
		}
	}
	t.Fatalf("candidate for admission %q is absent from %+v", admissionID, projection)
	return contracts.EffectReconciliationCandidate{}
}

func effectReservationAdmissionFixture(
	t *testing.T,
	signer crypto.Signer,
	release contracts.ConnectorReleaseAuthority,
	consumer ConsumerIdentity,
	attemptID string,
	issuedAt time.Time,
) DispatchAdmissionRecord {
	t.Helper()
	authority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion: contracts.ApprovalConnectorAuthoritySchemaV1, ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State: contracts.ApprovalConnectorAuthorityStateV1, BindingRef: "binding-a",
		TenantID: consumer.TenantID, WorkspaceID: consumer.WorkspaceID,
		PackID: "pack-a", PackVersion: "1.0.0", PackManifestHash: shaRef("a"),
		Action: contracts.ApprovalGrantActionInstall, ConnectorAction: contracts.ApprovalGrantActionInstall,
		EffectHash: shaRef("1"), PolicyHash: shaRef("3"),
		ConnectorID: release.ConnectorID, ConnectorVersion: release.ConnectorVersion,
		ReleaseScopeKind: release.ScopeKind, ReleaseAuthorityID: release.AuthorityID,
		ReleaseRegistryRevision: release.RegistryRevision, ReleaseAuthorityHash: release.AuthorityHash,
		ConnectorExecutorKind: release.ConnectorExecutorKind, ConnectorBinaryHash: release.ConnectorBinaryHash,
		ConnectorSignatureRef: release.ConnectorSignatureRef, ConnectorSignatureHash: release.ConnectorSignatureHash,
		ConnectorSignerID: release.ConnectorSignerID, ConnectorSandboxProfile: release.ConnectorSandboxProfile,
		ConnectorDriftPolicyRef: release.ConnectorDriftPolicyRef, CertificationRef: release.CertificationRef,
		CertificationHash: release.CertificationHash, CertificationAuthority: release.CertificationAuthority,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt = issuedAt.UTC().Truncate(time.Microsecond)
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion: contracts.ApprovalDispatchAdmissionSchemaV1, ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage:    contracts.ApprovalDispatchAdmissionCoverageV1,
		AdmissionID: "dispatch-admission-" + attemptID, AttemptID: attemptID, State: contracts.ApprovalDispatchAdmissionStateV1,
		ApprovalID: "approval-" + attemptID, GrantID: "grant-" + attemptID,
		GrantHash: effectReservationSHARef("grant-" + attemptID), ConsumptionHash: effectReservationSHARef("consumption-" + attemptID),
		TenantID: consumer.TenantID, WorkspaceID: consumer.WorkspaceID, Audience: consumer.Audience, AdmittedBy: consumer.Subject,
		IdempotencyKeyHash: effectReservationSHARef("idempotency-" + attemptID), EffectHash: authority.EffectHash,
		Action: authority.Action, ConnectorAuthority: authority,
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Minute),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignApprovalDispatchAdmission(admission, signer)
	if err != nil {
		t.Fatal(err)
	}
	return DispatchAdmissionRecord{
		Admission: admission, SignatureAlgorithm: GrantSignatureEd25519, Signature: signature,
		CreatedAt: issuedAt, UpdatedAt: issuedAt,
	}
}

func effectReservationSHARef(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func persistDispatchAdmissionForEffectTest(t *testing.T, ctx context.Context, db *sql.DB, record DispatchAdmissionRecord) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	a := record.Admission
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, a.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, a.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approval_dispatch_admissions (
		tenant_id, workspace_id, attempt_id, approval_id, consumption_hash,
		idempotency_key_hash, effect_hash, connector_id, action, admitted_by,
		state, admission_json, signature_algorithm, signature,
		issued_at, expires_at, created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$15,$15)`,
		a.TenantID, a.WorkspaceID, a.AttemptID, a.ApprovalID, a.ConsumptionHash,
		a.IdempotencyKeyHash, a.EffectHash, a.ConnectorAuthority.ConnectorID, a.Action, a.AdmittedBy,
		a.State, payload, record.SignatureAlgorithm, record.Signature, a.IssuedAt, a.ExpiresAt,
	); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func assertEffectReservationRLSIsolation(t *testing.T, ctx context.Context, db *sql.DB, tenantID, workspaceID string) {
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
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approval_effect_reservation_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cross-tenant effect reservation visibility = %d, want 0", count)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approval_effect_closures`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cross-tenant effect closure visibility = %d, want 0", count)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM approval_effect_dispositions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cross-tenant effect disposition visibility = %d, want 0", count)
	}
}

func assertEffectReservationAppendOnly(t *testing.T, ctx context.Context, db *sql.DB, consumer ConsumerIdentity, admissionID string) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, consumer.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, consumer.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE approval_effect_reservation_events SET state = state
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3`, consumer.TenantID, consumer.WorkspaceID, admissionID); err == nil {
		t.Fatal("append-only effect reservation history accepted UPDATE")
	}
}

func assertEffectClosureAppendOnly(t *testing.T, ctx context.Context, db *sql.DB, consumer ConsumerIdentity, admissionID string) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, consumer.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, consumer.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE approval_effect_closures SET outcome = outcome
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3`, consumer.TenantID, consumer.WorkspaceID, admissionID); err == nil {
		t.Fatal("append-only effect closure accepted UPDATE")
	}
}

func assertEffectDispositionAppendOnly(t *testing.T, ctx context.Context, db *sql.DB, consumer ConsumerIdentity, admissionID string) {
	t.Helper()
	beginScope := func() *sql.Tx {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, consumer.TenantID); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, consumer.WorkspaceID); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		return tx
	}
	updateTx := beginScope()
	if _, err := updateTx.ExecContext(ctx, `UPDATE approval_effect_dispositions SET action = action
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3`, consumer.TenantID, consumer.WorkspaceID, admissionID); err == nil {
		_ = updateTx.Rollback()
		t.Fatal("append-only effect disposition accepted UPDATE")
	}
	_ = updateTx.Rollback()

	deleteTx := beginScope()
	if _, err := deleteTx.ExecContext(ctx, `DELETE FROM approval_effect_dispositions
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3`, consumer.TenantID, consumer.WorkspaceID, admissionID); err == nil {
		_ = deleteTx.Rollback()
		t.Fatal("append-only effect disposition accepted DELETE")
	}
	_ = deleteTx.Rollback()
}

func effectDispositionTestEnvelope(
	t *testing.T,
	signer crypto.Signer,
	reservation EffectReservationEvent,
	fence kernel.FenceState,
	sequence uint64,
	previousReceiptHash string,
	action string,
	issuedAt time.Time,
) contracts.EffectDispositionCommandEnvelope {
	t.Helper()
	headHash, err := effectReservationHeadHash(reservation)
	if err != nil {
		t.Fatal(err)
	}
	a := reservation.Admission.Admission
	command, err := (contracts.EffectDispositionCommand{
		SchemaVersion:       contracts.EffectDispositionCommandSchemaV1,
		ContractVersion:     contracts.EffectDispositionCommandContractV1,
		CommandID:           fmt.Sprintf("effect-disposition-%s-%d", a.AttemptID, sequence),
		DispositionSequence: sequence, PreviousReceiptHash: previousReceiptHash,
		TenantID: a.TenantID, WorkspaceID: a.WorkspaceID, Audience: a.Audience,
		FenceCommandID: fence.CommandID, FenceCommandHash: fence.CommandHash,
		FenceEpoch: fence.Epoch, FenceReceiptHash: fence.ReceiptHash,
		AdmissionID: a.AdmissionID, AttemptID: a.AttemptID,
		ReservationSequence: reservation.Sequence, ReservationHeadHash: headHash,
		ReservationState: string(reservation.State),
		ConnectorID:      a.ConnectorAuthority.ConnectorID, ConnectorVersion: a.ConnectorAuthority.ConnectorVersion,
		ConnectorAction:       a.ConnectorAuthority.ConnectorAction,
		ConnectorExecutionRef: reservation.ConnectorExecutionRef,
		ProofSessionRef:       reservation.ProofSessionRef, IntentRef: reservation.IntentRef, EffectRef: reservation.EffectRef,
		IdempotencyKeyHash: a.IdempotencyKeyHash, EffectHash: a.EffectHash,
		Action: action, DispositionRef: fmt.Sprintf("disposition-workflow-%s-%d", a.AttemptID, sequence),
		ActorID: "operator-a", Reason: "emergency-stop active-work disposition",
		AuthorityID: "spiffe://helm/control-plane", SigningKeyRef: "kms://helm/control-plane/disposition-a",
		Algorithm: contracts.EffectDispositionAlgorithmV1,
		IssuedAt:  issuedAt, ExpiresAt: issuedAt.Add(5 * time.Minute),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignEffectDispositionCommand(command, signer)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func effectAcknowledgementTestEnvelope(
	t *testing.T,
	signer crypto.Signer,
	release contracts.ConnectorReleaseAuthority,
	reservation EffectReservationEvent,
	acknowledgementID, outcome, responseHash, reconciliationRef, dispositionReceiptHash string,
) contracts.ConnectorEffectAcknowledgementEnvelope {
	t.Helper()
	a := reservation.Admission.Admission
	acknowledgement := contracts.ConnectorEffectAcknowledgement{
		SchemaVersion:     contracts.ConnectorEffectAcknowledgementSchemaV1,
		ContractVersion:   contracts.ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: acknowledgementID, AdmissionID: a.AdmissionID, AttemptID: a.AttemptID,
		TenantID: a.TenantID, WorkspaceID: a.WorkspaceID, Audience: a.Audience,
		ConnectorID: release.ConnectorID, ConnectorVersion: release.ConnectorVersion,
		ConnectorAction:       a.ConnectorAuthority.ConnectorAction,
		ConnectorExecutionRef: reservation.ConnectorExecutionRef,
		ProofSessionRef:       reservation.ProofSessionRef, IntentRef: reservation.IntentRef,
		IdempotencyKeyHash: a.IdempotencyKeyHash, EffectHash: a.EffectHash,
		Outcome: outcome, ResponseHash: responseHash, ReconciliationRef: reconciliationRef,
		DispositionReceiptHash: dispositionReceiptHash, IssuerID: release.ConnectorSignerID,
		SigningKeyRef: "kms://helm/connector-ack-a",
		Algorithm:     contracts.ConnectorEffectAcknowledgementAlgorithm,
		ObservedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	if outcome == contracts.ConnectorEffectOutcomeApplied {
		acknowledgement.EffectRef = reservation.EffectRef
	}
	sealed, err := acknowledgement.Seal()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignConnectorEffectAcknowledgement(sealed, signer)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func effectDispositionRecordFixture(
	t *testing.T,
	signer crypto.Signer,
	reservation EffectReservationEvent,
	fence kernel.FenceState,
	envelope contracts.EffectDispositionCommandEnvelope,
	acceptedAt time.Time,
) EffectDispositionRecord {
	t.Helper()
	command := envelope.Command
	receiptID, err := deterministicEffectDispositionReceiptID(command)
	if err != nil {
		t.Fatal(err)
	}
	a := reservation.Admission.Admission
	receipt, err := (contracts.EffectDispositionReceipt{
		SchemaVersion: contracts.EffectDispositionReceiptSchemaV1, ContractVersion: contracts.EffectDispositionReceiptContractV1,
		ReceiptID: receiptID, State: contracts.EffectDispositionReceiptStateAccepted,
		ExecutionAuthority: contracts.EffectDispositionExecutionAuthorityNone,
		CommandID:          command.CommandID, CommandHash: command.CommandHash,
		DispositionSequence: command.DispositionSequence, PreviousReceiptHash: command.PreviousReceiptHash,
		TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, Audience: command.Audience,
		FenceCommandID: command.FenceCommandID, FenceCommandHash: command.FenceCommandHash,
		FenceEpoch: command.FenceEpoch, FenceReceiptHash: command.FenceReceiptHash,
		AdmissionID: command.AdmissionID, ReservationSequence: command.ReservationSequence,
		ReservationHeadHash: command.ReservationHeadHash, ReservationState: command.ReservationState,
		Action: command.Action, DispositionRef: command.DispositionRef,
		KernelTrustRootID: a.KernelTrustRootID, SigningKeyRef: a.SigningKeyRef,
		AcceptedBy: a.AdmittedBy, AcceptedAt: acceptedAt,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignEffectDispositionReceipt(receipt, signer)
	if err != nil {
		t.Fatal(err)
	}
	return EffectDispositionRecord{
		Command: envelope, Fence: fence, Receipt: receipt,
		SignatureAlgorithm: GrantSignatureEd25519, Signature: signature, CreatedAt: acceptedAt,
	}
}

func assertEffectDispositionWrongScopeInsert(
	t *testing.T,
	ctx context.Context,
	store *PostgresStore,
	consumer ConsumerIdentity,
	record EffectDispositionRecord,
) {
	t.Helper()
	tx, err := store.beginScopeTx(ctx, "tenant-b", consumer.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertEffectDispositionRecord(ctx, tx, record); err == nil {
		_ = tx.Rollback()
		t.Fatal("wrong-scope direct disposition INSERT succeeded")
	}
	_ = tx.Rollback()

	checkTx, err := store.beginScopeTx(ctx, consumer.TenantID, consumer.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = checkTx.Rollback() }()
	var count int
	if err := checkTx.QueryRowContext(ctx, `SELECT count(*) FROM approval_effect_dispositions
		WHERE command_id = $1`, record.Command.Command.CommandID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("wrong-scope direct disposition INSERT persisted %d rows", count)
	}
}

func insertForgedEffectDispositionForTest(
	t *testing.T,
	ctx context.Context,
	store *PostgresStore,
	consumer ConsumerIdentity,
	reservation EffectReservationEvent,
	fence kernel.FenceState,
	envelope contracts.EffectDispositionCommandEnvelope,
) EffectDispositionRecord {
	t.Helper()
	command := envelope.Command
	acceptedAt := time.Now().UTC().Truncate(time.Microsecond)
	receiptID, err := deterministicEffectDispositionReceiptID(command)
	if err != nil {
		t.Fatal(err)
	}
	a := reservation.Admission.Admission
	receipt, err := (contracts.EffectDispositionReceipt{
		SchemaVersion: contracts.EffectDispositionReceiptSchemaV1, ContractVersion: contracts.EffectDispositionReceiptContractV1,
		ReceiptID: receiptID, State: contracts.EffectDispositionReceiptStateAccepted,
		ExecutionAuthority: contracts.EffectDispositionExecutionAuthorityNone,
		CommandID:          command.CommandID, CommandHash: command.CommandHash,
		DispositionSequence: command.DispositionSequence, PreviousReceiptHash: command.PreviousReceiptHash,
		TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, Audience: command.Audience,
		FenceCommandID: command.FenceCommandID, FenceCommandHash: command.FenceCommandHash,
		FenceEpoch: command.FenceEpoch, FenceReceiptHash: command.FenceReceiptHash,
		AdmissionID: command.AdmissionID, ReservationSequence: command.ReservationSequence,
		ReservationHeadHash: command.ReservationHeadHash, ReservationState: command.ReservationState,
		Action: command.Action, DispositionRef: command.DispositionRef,
		KernelTrustRootID: a.KernelTrustRootID, SigningKeyRef: a.SigningKeyRef,
		AcceptedBy: consumer.Subject, AcceptedAt: acceptedAt,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	record := EffectDispositionRecord{
		Command: envelope, Fence: fence, Receipt: receipt,
		SignatureAlgorithm: GrantSignatureEd25519,
		Signature:          strings.Repeat("00", ed25519.SignatureSize),
		CreatedAt:          acceptedAt,
	}
	tx, err := store.beginScopeTx(ctx, consumer.TenantID, consumer.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	created, err := insertEffectDispositionRecord(ctx, tx, record)
	if err != nil {
		t.Fatalf("insert structurally valid forged disposition: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return created
}

func assertEffectReservationRejectsStartedRefRewrite(t *testing.T, ctx context.Context, store *PostgresStore, started EffectReservationEvent) {
	t.Helper()
	identity := ConsumerIdentity{TenantID: started.Admission.Admission.TenantID, WorkspaceID: started.Admission.Admission.WorkspaceID}
	tx, err := store.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	tampered := started
	tampered.Sequence = 3
	tampered.State = EffectReservationStateUncertain
	tampered.OccurredAt = started.OccurredAt.Add(time.Microsecond)
	tampered.ResolvedAt = timePointer(tampered.OccurredAt)
	tampered.ReasonCode = "TAMPERED_EXECUTION_REF"
	tampered.ConnectorExecutionRef = "other-execution"
	if _, err := insertEffectReservationEvent(ctx, tx, tampered); err == nil {
		t.Fatal("database trigger accepted STARTED execution-ref rewrite")
	}
}

func assertEffectReservationRejectsCompletionWithoutClosure(
	t *testing.T,
	ctx context.Context,
	store *PostgresStore,
	started EffectReservationEvent,
) {
	t.Helper()
	identity := ConsumerIdentity{TenantID: started.Admission.Admission.TenantID, WorkspaceID: started.Admission.Admission.WorkspaceID}
	tx, err := store.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	completed := started
	completed.Sequence++
	completed.State = EffectReservationStateCompleted
	completed.ResolvedAt = timePointer(started.OccurredAt.Add(time.Microsecond))
	completed.OccurredAt = *completed.ResolvedAt
	completed.EffectRef = "forged-effect"
	completed.ClosePriorState = contracts.EffectClosePriorStateStarted
	completed.AcknowledgementHash = shaRef("a")
	completed.CloseReceiptHash = shaRef("b")
	completed.Outcome = contracts.ConnectorEffectOutcomeApplied
	completed.EvidencePackRef = "forged-evidence-pack"
	completed.EvidencePackHash = shaRef("c")
	if _, err := insertEffectReservationEvent(ctx, tx, completed); err == nil {
		t.Fatal("database accepted COMPLETED event without atomic signed closure")
	}
}
