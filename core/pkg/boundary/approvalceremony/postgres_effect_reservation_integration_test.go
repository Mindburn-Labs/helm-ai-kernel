package approvalceremony

// quantum_posture: integration test over classical Ed25519 effect-reservation
// and connector release-authority evidence; no post-quantum claim.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

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
