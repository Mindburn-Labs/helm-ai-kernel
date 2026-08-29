package postgresmigration

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

var baseRuntimeTables = []string{
	"kernel_schema_migrations",
	"obligations",
	"receipts",
	"principal_bindings",
	"registry_bundles",
	"registry_rollouts",
	"registry_installations",
	"boundary_surface_snapshots",
	"boundary_surface_events",
	"boundary_records_index",
}

var baseRuntimeColumns = []struct {
	table  string
	column string
}{
	{"kernel_schema_migrations", "version"},
	{"kernel_schema_migrations", "name"},
	{"kernel_schema_migrations", "applied_at"},
	{"obligations", "id"},
	{"obligations", "created_at"},
	{"obligations", "hash"},
	{"obligations", "tenant_id"},
	{"receipts", "receipt_id"},
	{"receipts", "decision_id"},
	{"receipts", "timestamp"},
	{"receipts", "append_sequence"},
	{"principal_bindings", "tenant_id"},
	{"principal_bindings", "principal_id"},
	{"principal_bindings", "created_at"},
	{"registry_bundles", "name"},
	{"registry_bundles", "version"},
	{"registry_bundles", "bundle_json"},
	{"registry_bundles", "created_at"},
	{"registry_rollouts", "name"},
	{"registry_rollouts", "updated_at"},
	{"registry_installations", "tenant_id"},
	{"registry_installations", "pack_id"},
	{"registry_installations", "installed_at"},
	{"boundary_surface_snapshots", "id"},
	{"boundary_surface_snapshots", "snapshot_json"},
	{"boundary_surface_snapshots", "updated_at"},
	{"boundary_surface_events", "sequence"},
	{"boundary_surface_events", "event_kind"},
	{"boundary_surface_events", "object_json"},
	{"boundary_surface_events", "created_at"},
	{"boundary_records_index", "record_id"},
	{"boundary_records_index", "verdict"},
	{"boundary_records_index", "policy_epoch"},
	{"boundary_records_index", "record_hash"},
	{"boundary_records_index", "created_at"},
}

func expectRuntimeTables(mock sqlmock.Sqlmock, options RuntimeOptions) {
	rows := sqlmock.NewRows([]string{"table_name"})
	for _, table := range baseRuntimeTables {
		rows.AddRow(table)
	}
	if options.EmergencyStops {
		rows.AddRow("emergency_stop_fences")
	}
	if options.ApprovalConsumption {
		rows.AddRow("approval_ceremonies")
		rows.AddRow("approval_dispatch_admissions")
		rows.AddRow("approval_effect_reservation_events")
		rows.AddRow("approval_effect_closures")
		rows.AddRow("approval_effect_dispositions")
	}
	if options.GeneratedSpecApproval {
		rows.AddRow("generated_spec_approval_ceremonies")
	}
	if options.ReleaseAuthority {
		rows.AddRow("connector_release_authorities")
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT table_name\n\t\tFROM information_schema.tables")).WillReturnRows(rows)
}

func expectRuntimeVersion(mock sqlmock.Sqlmock, count, min, max int) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*), COALESCE(MIN(version), 0), COALESCE(MAX(version), 0) FROM kernel_schema_migrations")).
		WillReturnRows(sqlmock.NewRows([]string{"count", "min", "max"}).AddRow(count, min, max))
}

func expectRuntimeColumns(mock sqlmock.Sqlmock, omit ...struct{ table, column string }) {
	omitted := make(map[struct{ table, column string }]struct{}, len(omit))
	for _, column := range omit {
		omitted[column] = struct{}{}
	}
	rows := sqlmock.NewRows([]string{"table_name", "column_name"})
	for _, column := range baseRuntimeColumns {
		if _, skip := omitted[struct{ table, column string }{column.table, column.column}]; !skip {
			rows.AddRow(column.table, column.column)
		}
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT table_name, column_name\n\t\tFROM information_schema.columns")).WillReturnRows(rows)
}

func expectRuntimeRole(mock sqlmock.Sqlmock, canLogin, createRole, trigger bool) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT current_user,")).
		WillReturnRows(sqlmock.NewRows([]string{
			"current_user", "session_user", "rolcanlogin", "rolsuper", "rolbypassrls",
			"rolcreaterole", "rolcreatedb", "has_schema_privilege", "owns_objects",
			"has_trigger", "has_replication_role",
		}).AddRow("helm_runtime", "helm_runtime", canLogin, false, false, createRole, false, false, false, trigger, false))
}

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

func TestValidateRuntimeRejectsBehindSchemaVersionWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersion(mock, 0, 0, 0)
	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "exact version") {
		t.Fatalf("ValidateRuntime accepted behind schema version, err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}

func TestValidateRuntimeRejectsAheadSchemaVersionWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersion(mock, 2, 1, 2)
	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "exact version") {
		t.Fatalf("ValidateRuntime accepted ahead schema version, err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}

func TestValidateRuntimeRejectsMissingRequiredColumnWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersion(mock, 1, 1, 1)
	expectRuntimeColumns(mock, struct{ table, column string }{"obligations", "hash"})
	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "obligations.hash") {
		t.Fatalf("ValidateRuntime accepted missing required column, err=%v", err)
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

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersion(mock, 1, 1, 1)
	expectRuntimeColumns(mock)
	expectRuntimeRole(mock, true, true, false)

	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "runtime role") {
		t.Fatalf("ValidateRuntime accepted schema-owner role, err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}

func TestValidateRuntimeRejectsNonLoginTriggerRoleWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersion(mock, 1, 1, 1)
	expectRuntimeColumns(mock)
	expectRuntimeRole(mock, false, false, true)

	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "direct non-superuser login") {
		t.Fatalf("ValidateRuntime accepted non-login/TRIGGER role, err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}
