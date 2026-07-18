package approvalceremony

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
		staticEffectEvidencePackVerifier{ref: "evidence-pack-a", hash: evidencePackHash},
		approvalSigner,
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
	active, err := admitter.ListActive(ctx)
	activeIDs := map[string]bool{}
	for _, event := range active {
		activeIDs[event.Admission.Admission.AdmissionID] = true
	}
	if err != nil || len(active) != 2 || !activeIDs[first.Admission.AdmissionID] || !activeIDs[startClaim.Admission.AdmissionID] {
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
		ReconciliationRef: "reconciliation-a", IssuerID: release.ConnectorSignerID,
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
