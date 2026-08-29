package postgresmigration

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestValidateRuntimeRejectsMissingSchemaWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT table_name\n\t\tFROM information_schema.tables")).
		WillReturnRows(sqlmock.NewRows([]string{"table_name"}).AddRow("obligations"))

	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil {
		t.Fatal("ValidateRuntime accepted a missing Kernel schema")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}

func TestValidateRuntimeRejectsSchemaOwnerWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT table_name\n\t\tFROM information_schema.tables")).
		WillReturnRows(sqlmock.NewRows([]string{"table_name"}).
			AddRow("obligations").AddRow("receipts").AddRow("principal_bindings").
			AddRow("registry_bundles").AddRow("registry_rollouts").AddRow("registry_installations").
			AddRow("boundary_surface_snapshots").AddRow("boundary_surface_events").AddRow("boundary_records_index"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT current_user,")).
		WillReturnRows(sqlmock.NewRows([]string{"current_user", "session_user", "rolsuper", "rolbypassrls", "rolcreaterole", "rolcreatedb", "has_schema_privilege", "owns_objects", "has_replication_role"}).
			AddRow("helm_owner", "helm_owner", false, false, false, false, true, false, false))

	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "runtime role") {
		t.Fatalf("ValidateRuntime accepted schema-owner role, err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}
