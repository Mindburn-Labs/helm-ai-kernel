package trust

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Masterminds/semver/v3"
)

func TestCoveragePostgresTrustStoreMetadata(t *testing.T) {
	db, mock, cleanup := newTrustCoverageSQLMock(t)
	defer cleanup()
	store := NewPostgresTrustStore(db)
	if store.db != db {
		t.Fatal("NewPostgresTrustStore did not retain db")
	}

	for range []string{"root", "timestamp", "snapshot", "targets"} {
		mock.ExpectQuery("SELECT json_data FROM trust_metadata").WillReturnError(sql.ErrNoRows)
	}
	if metadata, err := store.Load(); err != nil || metadata != nil {
		t.Fatalf("empty metadata load got %+v err=%v", metadata, err)
	}

	root := trustCoverageSignedRole(t, "root")
	timestamp := trustCoverageSignedRole(t, "timestamp")
	snapshot := trustCoverageSignedRole(t, "snapshot")
	targets := trustCoverageSignedRole(t, "targets")
	for _, role := range []*SignedRole{root, timestamp, snapshot, targets} {
		data, err := json.Marshal(role)
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery("SELECT json_data FROM trust_metadata").WillReturnRows(sqlmock.NewRows([]string{"json_data"}).AddRow(data))
	}
	metadata, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if metadata.Root == nil || metadata.Timestamp == nil || metadata.Snapshot == nil || metadata.Targets == nil {
		t.Fatalf("expected all roles, got %+v", metadata)
	}

	mock.ExpectQuery("SELECT json_data FROM trust_metadata").WillReturnError(errors.New("select failed"))
	if _, err := store.Load(); err == nil {
		t.Fatal("expected metadata query error")
	}
	mock.ExpectQuery("SELECT json_data FROM trust_metadata").WillReturnRows(sqlmock.NewRows([]string{"json_data"}).AddRow([]byte(`{`)))
	if _, err := store.Load(); err == nil {
		t.Fatal("expected metadata decode error")
	}

	if err := store.Save(nil); err != nil {
		t.Fatalf("Save nil: %v", err)
	}
	mock.ExpectExec("INSERT INTO trust_metadata").WithArgs("root", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.Save(&TUFMetadata{Root: root}); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	mock.ExpectExec("INSERT INTO trust_metadata").WithArgs("root", sqlmock.AnyArg()).WillReturnError(errors.New("insert failed"))
	if err := store.Save(&TUFMetadata{Root: root}); err == nil {
		t.Fatal("expected metadata save error")
	}
	if err := store.Save(&TUFMetadata{Root: &SignedRole{Signed: json.RawMessage(`{`)}}); err == nil {
		t.Fatal("expected metadata marshal error")
	}
}

func TestCoveragePostgresTrustStoreVersionsAndKeys(t *testing.T) {
	db, mock, cleanup := newTrustCoverageSQLMock(t)
	defer cleanup()
	store := NewPostgresTrustStore(db)

	mock.ExpectQuery("SELECT version FROM trust_versions").WithArgs("missing").WillReturnError(sql.ErrNoRows)
	version, err := store.GetInstalledVersion("missing")
	if err != nil || version != nil {
		t.Fatalf("missing version got %+v err=%v", version, err)
	}
	mock.ExpectQuery("SELECT version FROM trust_versions").WithArgs("pack").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow("1.2.3"))
	version, err = store.GetInstalledVersion("pack")
	if err != nil || version.String() != "1.2.3" {
		t.Fatalf("version got %+v err=%v", version, err)
	}
	mock.ExpectQuery("SELECT version FROM trust_versions").WithArgs("bad").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow("not-semver"))
	if _, err := store.GetInstalledVersion("bad"); err == nil {
		t.Fatal("expected invalid semver error")
	}
	mock.ExpectQuery("SELECT version FROM trust_versions").WithArgs("error").WillReturnError(errors.New("version query failed"))
	if _, err := store.GetInstalledVersion("error"); err == nil {
		t.Fatal("expected version query error")
	}

	nextVersion, err := semver.NewVersion("2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("INSERT INTO trust_versions").WithArgs("pack", "2.0.0").WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.SetInstalledVersion("pack", nextVersion); err != nil {
		t.Fatalf("SetInstalledVersion: %v", err)
	}
	mock.ExpectExec("INSERT INTO trust_versions").WithArgs("pack", "2.0.0").WillReturnError(errors.New("version insert failed"))
	if err := store.SetInstalledVersion("pack", nextVersion); err == nil {
		t.Fatal("expected version set error")
	}

	mock.ExpectQuery("SELECT status FROM trust_key_status").WithArgs("default-active").WillReturnError(sql.ErrNoRows)
	if status, err := store.GetKeyStatus("default-active"); err != nil || status != KeyStatusActive {
		t.Fatalf("default key status got %s err=%v", status, err)
	}
	mock.ExpectQuery("SELECT status FROM trust_key_status").WithArgs("revoked").WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(string(KeyStatusRevoked)))
	if status, err := store.GetKeyStatus("revoked"); err != nil || status != KeyStatusRevoked {
		t.Fatalf("revoked key status got %s err=%v", status, err)
	}
	mock.ExpectQuery("SELECT status FROM trust_key_status").WithArgs("error").WillReturnError(errors.New("status failed"))
	if _, err := store.GetKeyStatus("error"); err == nil {
		t.Fatal("expected key status query error")
	}

	mock.ExpectQuery("FROM trust_quarantine_overrides").WithArgs("none").WillReturnError(sql.ErrNoRows)
	override, err := store.GetQuarantineOverride("none")
	if err != nil || override != nil {
		t.Fatalf("missing override got %+v err=%v", override, err)
	}
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	mock.ExpectQuery("FROM trust_quarantine_overrides").WithArgs("key-1").
		WillReturnRows(sqlmock.NewRows([]string{"reason", "authorized_by", "expires_at", "signatures"}).
			AddRow("emergency", "{alice,bob}", expires, "{sig1,sig2}"))
	override, err = store.GetQuarantineOverride("key-1")
	if err != nil {
		t.Fatalf("GetQuarantineOverride: %v", err)
	}
	if override.PublisherKeyID != "key-1" || override.Reason != "emergency" || len(override.AuthorizedBy) != 2 || len(override.Signatures) != 2 || override.ExpiresAt != expires.Format(time.RFC3339) {
		t.Fatalf("unexpected override: %+v", override)
	}
	mock.ExpectQuery("FROM trust_quarantine_overrides").WithArgs("error").WillReturnError(errors.New("override failed"))
	if _, err := store.GetQuarantineOverride("error"); err == nil {
		t.Fatal("expected override query error")
	}
}

func TestCoverageTrustSchemaAndInstallRegistryBranches(t *testing.T) {
	db, mock, cleanup := newTrustCoverageSQLMock(t)
	defer cleanup()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS trust_metadata").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS trust_metadata").WillReturnError(errors.New("schema failed"))
	if err := InitSchema(context.Background(), db); err == nil {
		t.Fatal("expected schema init error")
	}

	now := time.Unix(1700000000, 0).UTC()
	registry := NewInstallRegistry().WithClock(func() time.Time { return now })
	receipt, err := registry.RecordInstall("org.example/pack", "1.0.0", "sha256:abc", "tenant", "agent")
	if err != nil {
		t.Fatalf("RecordInstall: %v", err)
	}
	if !receipt.InstalledAt.Equal(now) {
		t.Fatalf("WithClock was not used: %+v", receipt)
	}
	if got, err := registry.GetReceipt(receipt.ReceiptID); err != nil || got.ReceiptID != receipt.ReceiptID {
		t.Fatalf("GetReceipt got %+v err=%v", got, err)
	}
	if _, err := registry.GetReceipt("missing"); err == nil {
		t.Fatal("expected missing receipt error")
	}
	score := &PackTrustScore{PackName: "org.example/pack", Score: 77}
	registry.SetTrustScore(score)
	if got, err := registry.GetTrustScore("org.example/pack"); err != nil || got.Score != 77 {
		t.Fatalf("GetTrustScore got %+v err=%v", got, err)
	}
	if _, err := registry.GetTrustScore("missing"); err == nil {
		t.Fatal("expected missing trust score error")
	}
}

func newTrustCoverageSQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return db, mock, func() {
		t.Helper()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("sqlmock expectations: %v", err)
		}
		_ = db.Close()
	}
}

func trustCoverageSignedRole(t *testing.T, role string) *SignedRole {
	t.Helper()
	signed, err := json.Marshal(RoleMetadata{
		Type:        role,
		Version:     1,
		Expires:     time.Now().UTC().Add(time.Hour),
		SpecVersion: "1.0.31",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &SignedRole{
		Signed:     signed,
		Signatures: []TUFSignature{{KeyID: "key-" + role, Signature: "sig-" + role}},
	}
}
