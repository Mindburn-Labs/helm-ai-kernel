package approvalceremony

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestScanRecordRestoresOptionalSandboxDraftSource(t *testing.T) {
	proposal := sandboxDraftProposalForTest()
	spec, err := proposal.challengeSpec()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	sourceRecord := Record{
		ApprovalID: "approval-a", TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID,
		State: StateHoldPending, HoldStartedAt: now, Spec: spec,
		SandboxDraftSource: &SandboxDraftEvidenceSourceSnapshot{
			ControlIdentity: ControlIdentity{Subject: proposal.Subject, TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID},
			Proposal:        proposal,
		},
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	payload, err := json.Marshal(sourceRecord.SandboxDraftSource)
	if err != nil {
		t.Fatal(err)
	}

	got, err := scanRecord(recordScannerForTest{values: scanValuesForRecord(t, sourceRecord, sql.NullString{String: string(payload), Valid: true})})
	if err != nil {
		t.Fatalf("scanRecord() error = %v", err)
	}
	if !reflect.DeepEqual(got.SandboxDraftSource, sourceRecord.SandboxDraftSource) {
		t.Fatalf("scanned source snapshot = %#v, want %#v", got.SandboxDraftSource, sourceRecord.SandboxDraftSource)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("scanned source record Validate() error = %v", err)
	}

	legacy, _, _, _ := ceremonyFixtures(t)
	got, err = scanRecord(recordScannerForTest{values: scanValuesForRecord(t, legacy, sql.NullString{})})
	if err != nil {
		t.Fatalf("scanRecord() legacy error = %v", err)
	}
	if got.SandboxDraftSource != nil {
		t.Fatalf("legacy source snapshot = %#v, want nil", got.SandboxDraftSource)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("legacy record Validate() error = %v", err)
	}
}

type recordScannerForTest struct {
	values []any
}

func (s recordScannerForTest) Scan(dest ...any) error {
	if len(dest) != len(s.values) {
		return fmt.Errorf("scan destinations = %d, values = %d", len(dest), len(s.values))
	}
	for index, value := range s.values {
		reflect.ValueOf(dest[index]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}

func scanValuesForRecord(t *testing.T, record Record, source sql.NullString) []any {
	t.Helper()
	specJSON, err := json.Marshal(record.Spec)
	if err != nil {
		t.Fatal(err)
	}
	return []any{
		record.ApprovalID, record.TenantID, record.WorkspaceID, string(record.State), record.HoldStartedAt,
		string(specJSON), source, sql.NullString{}, sql.NullString{}, sql.NullString{},
		sql.NullString{}, sql.NullString{}, sql.NullString{}, sql.NullString{}, sql.NullString{},
		record.CreatedAt, record.UpdatedAt, sql.NullTime{}, sql.NullTime{}, sql.NullString{}, record.Version,
	}
}
