package postgresmigration

import (
	"context"
	"regexp"
	"sort"
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
	"credentials",
	"credential_audit_log",
	"boundary_surface_snapshots",
	"boundary_surface_events",
	"boundary_records_index",
}

func expectRuntimeTables(mock sqlmock.Sqlmock, options RuntimeOptions) {
	expectRuntimeTablesForOptions(mock, options)
}

func expectRuntimeTablesForOptions(mock sqlmock.Sqlmock, options RuntimeOptions, omit ...string) {
	omitted := make(map[string]struct{}, len(omit))
	for _, table := range omit {
		omitted[table] = struct{}{}
	}
	rows := sqlmock.NewRows([]string{"table_name"})
	for _, table := range baseRuntimeTables {
		if _, skip := omitted[table]; skip {
			continue
		}
		rows.AddRow(table)
	}
	if options.EmergencyStops {
		if _, skip := omitted["emergency_stop_fences"]; !skip {
			rows.AddRow("emergency_stop_fences")
		}
	}
	if options.ApprovalConsumption {
		for _, table := range []string{
			"approval_ceremonies", "approval_dispatch_admissions", "approval_effect_reservation_events",
			"approval_effect_closures", "approval_effect_dispositions",
		} {
			if _, skip := omitted[table]; !skip {
				rows.AddRow(table)
			}
		}
	}
	if options.GeneratedSpecApproval {
		if _, skip := omitted["generated_spec_approval_ceremonies"]; !skip {
			rows.AddRow("generated_spec_approval_ceremonies")
		}
	}
	if options.ReleaseAuthority {
		if _, skip := omitted["connector_release_authorities"]; !skip {
			rows.AddRow("connector_release_authorities")
		}
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT table_name\n\t\tFROM information_schema.tables")).WillReturnRows(rows)
}

func expectRuntimeVersion(mock sqlmock.Sqlmock, count, min, max int) {
	expectRuntimeVersionNamed(mock, count, min, max, kernelPostgresMigrationName)
}

func expectRuntimeVersionNamed(mock sqlmock.Sqlmock, count, min, max int, name string) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*), COALESCE(MIN(version), 0), COALESCE(MAX(version), 0), COALESCE(MAX(name), '') FROM kernel_schema_migrations")).
		WillReturnRows(sqlmock.NewRows([]string{"count", "min", "max", "name"}).AddRow(count, min, max, name))
}

func expectRuntimeColumns(mock sqlmock.Sqlmock, omit ...struct{ table, column string }) {
	expectRuntimeColumnsForOptions(mock, RuntimeOptions{}, omit...)
}

func expectRuntimeColumnsForOptions(mock sqlmock.Sqlmock, options RuntimeOptions, omit ...struct{ table, column string }) {
	omitted := make(map[struct{ table, column string }]struct{}, len(omit))
	for _, column := range omit {
		omitted[column] = struct{}{}
	}
	rows := sqlmock.NewRows([]string{"table_name", "column_name"})
	tables := make([]string, 0, len(requiredKernelPostgresColumns))
	for table := range requiredKernelPostgresColumns {
		if kernelTableRequired(table, options) {
			tables = append(tables, table)
		}
	}
	sort.Strings(tables)
	for _, table := range tables {
		columns := make([]string, 0, len(requiredKernelPostgresColumns[table]))
		for column := range requiredKernelPostgresColumns[table] {
			columns = append(columns, column)
		}
		sort.Strings(columns)
		for _, column := range columns {
			if _, skip := omitted[struct{ table, column string }{table, column}]; !skip {
				rows.AddRow(table, column)
			}
		}
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT table_name, column_name\n\t\tFROM information_schema.columns")).WillReturnRows(rows)
}

func expectRuntimeRole(mock sqlmock.Sqlmock, canLogin, createRole, trigger bool) {
	expectRuntimeRoleValues(mock, canLogin, createRole, false, trigger)
}

func expectRuntimeRoleValues(mock sqlmock.Sqlmock, canLogin, createRole, replication, trigger bool) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT current_user,")).
		WillReturnRows(sqlmock.NewRows([]string{
			"current_user", "session_user", "rolcanlogin", "rolsuper", "rolbypassrls",
			"rolcreaterole", "rolcreatedb", "rolreplication", "has_schema_privilege", "owns_objects",
			"has_trigger", "has_replication_role",
		}).AddRow("helm_runtime", "helm_runtime", canLogin, false, false, createRole, false, replication, false, false, trigger, false))
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

func TestValidateRuntimeRejectsWrongSchemaJournalNameWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersionNamed(mock, 1, 1, 1, "unrelated_schema")
	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "exact version") {
		t.Fatalf("ValidateRuntime accepted an unrelated schema journal, err=%v", err)
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

func TestValidateRuntimeRejectsMissingActiveWriterColumnsWithoutDDL(t *testing.T) {
	for _, missing := range []struct {
		table  string
		column string
	}{
		{table: "receipts", column: "chain_hash"},
		{table: "boundary_surface_events", column: "object_id"},
		{table: "boundary_records_index", column: "reason_code"},
		{table: "boundary_records_index", column: "tool_name"},
		{table: "boundary_records_index", column: "mcp_server_id"},
		{table: "boundary_records_index", column: "receipt_id"},
	} {
		t.Run(missing.table+"."+missing.column, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			expectRuntimeTables(mock, RuntimeOptions{})
			expectRuntimeVersion(mock, 1, 1, 1)
			expectRuntimeColumns(mock, struct{ table, column string }{missing.table, missing.column})
			if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), missing.table+"."+missing.column) {
				t.Fatalf("ValidateRuntime accepted missing active writer column, err=%v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
			}
		})
	}
}

func TestValidateRuntimeRejectsMissingCredentialColumnWithoutDDL(t *testing.T) {
	for _, missing := range []struct {
		table  string
		column string
	}{
		{table: "credentials", column: "access_token"},
		{table: "credential_audit_log", column: "action"},
	} {
		t.Run(missing.table+"."+missing.column, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			expectRuntimeTables(mock, RuntimeOptions{})
			expectRuntimeVersion(mock, 1, 1, 1)
			expectRuntimeColumns(mock, struct{ table, column string }{missing.table, missing.column})
			if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), missing.table+"."+missing.column) {
				t.Fatalf("ValidateRuntime accepted missing credential column, err=%v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
			}
		})
	}
}

func TestValidateRuntimeRejectsMissingOptionalTableWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	options := RuntimeOptions{ApprovalConsumption: true}
	expectRuntimeTablesForOptions(mock, options, "approval_effect_reservation_events")
	if err := ValidateRuntime(context.Background(), db, options); err == nil || !strings.Contains(err.Error(), "approval_effect_reservation_events") {
		t.Fatalf("ValidateRuntime accepted missing optional table, err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}

func TestValidateRuntimeRejectsMissingOptionalColumnWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	options := RuntimeOptions{ApprovalConsumption: true}
	expectRuntimeTables(mock, options)
	expectRuntimeVersion(mock, 1, 1, 1)
	expectRuntimeColumnsForOptions(mock, options, struct{ table, column string }{"approval_effect_reservation_events", "connector_execution_ref"})
	if err := ValidateRuntime(context.Background(), db, options); err == nil || !strings.Contains(err.Error(), "approval_effect_reservation_events.connector_execution_ref") {
		t.Fatalf("ValidateRuntime accepted missing optional column, err=%v", err)
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

func TestValidateRuntimeRejectsReplicationRoleWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersion(mock, 1, 1, 1)
	expectRuntimeColumns(mock)
	expectRuntimeRoleValues(mock, true, false, true, false)

	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "replication privileges") {
		t.Fatalf("ValidateRuntime accepted replication-capable role, err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}

func TestValidateRuntimeAcceptsRestrictedRoleWithoutDDL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectRuntimeTables(mock, RuntimeOptions{})
	expectRuntimeVersion(mock, 1, 1, 1)
	expectRuntimeColumns(mock)
	expectRuntimeRole(mock, true, false, false)

	if err := ValidateRuntime(context.Background(), db, RuntimeOptions{}); err != nil {
		t.Fatalf("ValidateRuntime rejected restricted role: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("runtime validation issued unexpected SQL (including DDL): %v", err)
	}
}
