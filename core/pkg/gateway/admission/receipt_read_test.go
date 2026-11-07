package admission

// quantum_posture: reads back fixed-seed classical Ed25519 test receipts
// through a mocked ledger; no post-quantum claim.

import (
	"bytes"
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

func mockedService(t *testing.T) (*Service, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{ReceiptSigner: testReceiptSigner})
	must(t, err)
	return svc, mock
}

// The refusals of ExportReceiptChain come from the token and the request
// alone: a workspace other than the token's, an episode token and a range
// out of bounds are refused before the ledger is read (CTL-059).
func TestReceiptExportRefusesBeforeReadingTheLedger(t *testing.T) {
	svc, mock := mockedService(t)
	worker := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a", Episode: &Episode{EpisodeID: "ep-1", WorkItemID: "work-1"}}
	for name, test := range map[string]struct {
		caller Caller
		in     ExportInput
		code   Code
	}{
		"another workspace": {human, ExportInput{WorkspaceID: "ws-b", FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
		"no workspace":      {human, ExportInput{FromSeq: 1, ToSeq: 1}, CodeInvalidArgument},
		"an episode token":  {worker, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
		"no tenant":         {Caller{WorkspaceID: workspace, PrincipalID: "human-a"}, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
		"sequence zero":     {human, ExportInput{WorkspaceID: workspace, FromSeq: 0, ToSeq: 1}, CodeInvalidArgument},
		"reversed":          {human, ExportInput{WorkspaceID: workspace, FromSeq: 2, ToSeq: 1}, CodeInvalidArgument},
		"over the cap":      {human, ExportInput{WorkspaceID: workspace, FromSeq: 10, ToSeq: 10 + MaxExportReceipts}, CodeInvalidArgument},
	} {
		_, err := svc.ExportReceiptChain(context.Background(), test.caller, test.in)
		wantReadRefusal(t, name, err, test.code)
	}
	if _, err := svc.GetReceipts(context.Background(), human, "not-a-uuid"); err == nil {
		t.Fatal("a malformed attempt id was read")
	}
	must(t, mock.ExpectationsWereMet())
}

func signedRows(t *testing.T, seqs ...int64) (*sqlmock.Rows, []receiptverify.GatewayReceipt) {
	t.Helper()
	rows := sqlmock.NewRows([]string{"receipt_id", "chain_id", "seq", "digest", "key_id", "format", "state", "attempt_version", "envelope", "binding"})
	var stored []receiptverify.GatewayReceipt
	prev := ""
	for i := int64(1); i <= seqs[len(seqs)-1]; i++ {
		d := sampleDecision()
		id := "0190a5b4-0000-7000-8000-00000000010" + string(rune('0'+i))
		r, binding, err := buildDecisionReceipt(d, id, uint64(i), prev)
		must(t, err)
		envelope, digest, err := sealReceipt(testReceiptSigner, r)
		must(t, err)
		prev = digest
		for _, want := range seqs {
			if want == i {
				rows.AddRow(id, receiptChainID(tenantA, workspace), i, digest, testReceiptSigner.GetKeyID(), ReceiptFormat, d.State, d.Version, envelope, binding)
				stored = append(stored, receiptverify.GatewayReceipt{ReceiptID: id, Envelope: envelope, Binding: binding})
			}
		}
	}
	return rows, stored
}

func expectExport(mock sqlmock.Sqlmock, head int64, from, to int64, rows *sqlmock.Rows) {
	chain := receiptChainID(tenantA, workspace)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant'`).WithArgs(tenantA).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT seq FROM authority_receipt_chains WHERE tenant_id = \$1 AND chain_id = \$2`).
		WithArgs(tenantA, chain).WillReturnRows(sqlmock.NewRows([]string{"seq"}).AddRow(head))
	if rows != nil {
		mock.ExpectQuery(`FROM authority_receipts\s+WHERE tenant_id = \$1 AND chain_id = \$2 AND workspace_id = \$3 AND seq BETWEEN \$4 AND \$5 ORDER BY seq`).
			WithArgs(tenantA, chain, workspace, from, to).WillReturnRows(rows)
	}
}

// An export is the ledger's rows in chain order as one verifiable document,
// read in the caller's tenant and workspace only; a range the ledger cannot
// return whole is an error, never a partial export (CTL-059).
func TestReceiptExportIsTheWholeRangeOrNothing(t *testing.T) {
	svc, mock := mockedService(t)
	rows, stored := signedRows(t, 1, 2, 3)
	expectExport(mock, 3, 1, 3, rows)
	mock.ExpectCommit()
	export, err := svc.ExportReceiptChain(context.Background(), human, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 3})
	must(t, err)
	want, err := receiptverify.EncodeGatewayBundle(stored)
	must(t, err)
	if !bytes.Equal(export.Bundle, want) || export.HeadSeq != 3 || len(export.Receipts) != 3 {
		t.Fatalf("export = head %d, %d receipts, bundle %s", export.HeadSeq, len(export.Receipts), export.Bundle)
	}
	if got := receiptverify.VerifyJSON(export.Bundle, []byte(`{"keys":{"`+testReceiptSigner.GetKeyID()+`":"`+testReceiptSigner.PublicKey()+`"}}`)); got.Verdict != receiptverify.VerdictVerified {
		t.Fatalf("export does not verify: %+v", got)
	}

	// A gap in the rows the ledger returns, even when the count is right.
	gap, _ := signedRows(t, 1, 2, 4)
	expectExport(mock, 4, 1, 3, gap)
	mock.ExpectCommit()
	if export, err := svc.ExportReceiptChain(context.Background(), human, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 3}); err == nil || export.Bundle != nil {
		t.Fatalf("a range with a gap exported: %v", err)
	}
	// A short read at the end of the range.
	short, _ := signedRows(t, 1, 2)
	expectExport(mock, 3, 1, 3, short)
	mock.ExpectCommit()
	if export, err := svc.ExportReceiptChain(context.Background(), human, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 3}); err == nil || export.Bundle != nil {
		t.Fatalf("a short range exported: %v", err)
	}
	// A range past the head is not found, and nothing is read beyond the head.
	expectExport(mock, 2, 1, 3, nil)
	mock.ExpectRollback()
	_, err = svc.ExportReceiptChain(context.Background(), human, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 3})
	wantReadRefusal(t, "past the head", err, CodeNotFound)
	must(t, mock.ExpectationsWereMet())
}

// GetReceipts is held to what Get reads: the attempt must be visible in the
// caller's tenant, workspace and episode scope before any receipt is read.
func TestAttemptReceiptsAreReadOnlyForAVisibleAttempt(t *testing.T) {
	svc, mock := mockedService(t)
	worker := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a", Episode: &Episode{EpisodeID: "ep-1", WorkItemID: "work-1"}}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant'`).WithArgs(tenantA).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT true FROM authority_effect_attempts\s+WHERE tenant_id = \$1 AND attempt_id = \$2 AND workspace_id = \$3\s+AND \(\$4 = '' OR \(episode_id = \$4 AND requester_principal_id = \$5\)\)`).
		WithArgs(tenantA, sampleAttempt, workspace, "ep-1", "agent-a").WillReturnRows(sqlmock.NewRows([]string{"bool"}))
	mock.ExpectRollback()
	_, err := svc.GetReceipts(context.Background(), worker, sampleAttempt)
	wantReadRefusal(t, "an attempt outside the episode", err, CodeNotFound)

	rows, stored := signedRows(t, 1)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant'`).WithArgs(tenantA).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT true FROM authority_effect_attempts`).
		WithArgs(tenantA, sampleAttempt, workspace, "", "human-a").WillReturnRows(sqlmock.NewRows([]string{"bool"}).AddRow(true))
	mock.ExpectQuery(`FROM authority_receipts\s+WHERE tenant_id = \$1 AND attempt_id = \$2 AND workspace_id = \$3 ORDER BY attempt_version, seq`).
		WithArgs(tenantA, sampleAttempt, workspace).WillReturnRows(rows)
	mock.ExpectCommit()
	receipts, err := svc.GetReceipts(context.Background(), human, sampleAttempt)
	must(t, err)
	if len(receipts) != 1 || !bytes.Equal(receipts[0].Envelope, stored[0].Envelope) || !bytes.Equal(receipts[0].Binding, stored[0].Binding) ||
		receipts[0].Ref.Seq != 1 || receipts[0].Ref.State != "ADMITTED" {
		t.Fatalf("receipts = %+v", receipts)
	}
	must(t, mock.ExpectationsWereMet())
}
