// Package postgresmigration owns the Kernel's one-shot Postgres schema
// orchestration. Serving code validates the already-present schema through
// read-only queries and never calls the migration functions.
package postgresmigration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	generatedspecapprovalceremony "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapprovalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/ledger"
)

// RuntimeOptions identifies optional Postgres-backed stores enabled by the
// serving process. The one-shot migration command prepares all optional
// schemas so it needs no serving configuration or owner credential.
type RuntimeOptions struct {
	EmergencyStops        bool
	ApprovalConsumption   bool
	GeneratedSpecApproval bool
	ReleaseAuthority      bool
}

const (
	kernelPostgresSchemaVersion = 1
	kernelPostgresMigrationName = "kernel_postgres_runtime_stores"
)

const kernelPostgresMigrationJournalSchema = `
CREATE TABLE IF NOT EXISTS kernel_schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`

var requiredKernelPostgresColumns = map[string]map[string]struct{}{
	"kernel_schema_migrations":           {"version": {}, "name": {}, "applied_at": {}},
	"obligations":                        {"id": {}, "created_at": {}, "hash": {}, "tenant_id": {}},
	"receipts":                           {"receipt_id": {}, "decision_id": {}, "timestamp": {}, "append_sequence": {}},
	"principal_bindings":                 {"tenant_id": {}, "principal_id": {}, "created_at": {}},
	"registry_bundles":                   {"name": {}, "version": {}, "bundle_json": {}, "created_at": {}},
	"registry_rollouts":                  {"name": {}, "updated_at": {}},
	"registry_installations":             {"tenant_id": {}, "pack_id": {}, "installed_at": {}},
	"boundary_surface_snapshots":         {"id": {}, "snapshot_json": {}, "updated_at": {}},
	"boundary_surface_events":            {"sequence": {}, "event_kind": {}, "object_json": {}, "created_at": {}},
	"boundary_records_index":             {"record_id": {}, "verdict": {}, "policy_epoch": {}, "record_hash": {}, "created_at": {}},
	"emergency_stop_fences":              {"tenant_id": {}, "workspace_id": {}, "command_id": {}, "receipt_hash": {}},
	"approval_ceremonies":                {"tenant_id": {}, "approval_id": {}, "state": {}, "version": {}},
	"approval_dispatch_admissions":       {"tenant_id": {}, "workspace_id": {}, "attempt_id": {}, "admission_json": {}},
	"approval_effect_reservation_events": {"tenant_id": {}, "workspace_id": {}, "admission_id": {}, "sequence": {}},
	"approval_effect_closures":           {"tenant_id": {}, "workspace_id": {}, "admission_id": {}, "close_id": {}},
	"approval_effect_dispositions":       {"tenant_id": {}, "workspace_id": {}, "admission_id": {}, "command_id": {}},
	"generated_spec_approval_ceremonies": {"tenant_id": {}, "workspace_id": {}, "approval_id": {}, "binding_json": {}},
	"connector_release_authorities":      {"scope_kind": {}, "connector_id": {}, "registry_revision": {}, "envelope_json": {}},
}

// Migrate applies every Kernel-owned Postgres schema. It is intended for the
// one-shot `helm-ai-kernel migrate` command, never for request serving.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("kernel postgres migration requires database")
	}
	if _, err := db.ExecContext(ctx, kernelPostgresMigrationJournalSchema); err != nil {
		return fmt.Errorf("create kernel migration journal: %w", err)
	}
	var maxApplied int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM kernel_schema_migrations`).Scan(&maxApplied); err != nil {
		return fmt.Errorf("read kernel migration journal: %w", err)
	}
	if maxApplied > kernelPostgresSchemaVersion {
		return fmt.Errorf("kernel database at schema version %d, newer than binary version %d; refusing to migrate", maxApplied, kernelPostgresSchemaVersion)
	}
	steps := []struct {
		name string
		fn   func(context.Context, *sql.DB) error
	}{
		{"ledger", ledger.MigratePostgres},
		{"receipt store", store.MigratePostgresReceipts},
		{"principal binding store", store.MigratePostgresPrincipalBindings},
		{"registry", registry.MigratePostgres},
		{"connector release authority", connectorregistry.ApplyConnectorReleaseAuthorityMigrations},
		{"boundary surface registry", boundary.MigratePostgresSurfaceRegistry},
		{"scoped emergency-stop store", kernel.MigratePostgres},
		{"approval ceremony stores", approvalceremony.MigratePostgres},
		{"generated spec approval ceremony store", generatedspecapprovalceremony.MigratePostgres},
	}
	for _, step := range steps {
		if err := step.fn(ctx, db); err != nil {
			return fmt.Errorf("%s migration: %w", step.name, err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO kernel_schema_migrations (version, name) VALUES ($1, $2) ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name`, kernelPostgresSchemaVersion, kernelPostgresMigrationName); err != nil {
		return fmt.Errorf("record kernel migration journal: %w", err)
	}
	return nil
}

var kernelPostgresTables = []string{
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
	"emergency_stop_fences",
	"approval_ceremonies",
	"approval_dispatch_admissions",
	"approval_effect_reservation_events",
	"approval_effect_closures",
	"approval_effect_dispositions",
	"generated_spec_approval_ceremonies",
	"connector_release_authorities",
}

// ValidateRuntime checks the schema required by the enabled Kernel stores and
// rejects serving identities that can still alter schema controls. All
// database operations in this function are SELECT-only.
func ValidateRuntime(ctx context.Context, db *sql.DB, options RuntimeOptions) error {
	if db == nil {
		return errors.New("kernel postgres runtime validation requires database")
	}
	rows, err := db.QueryContext(ctx, `SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = current_schema()
		  AND table_name IN (
			'kernel_schema_migrations', 'obligations', 'receipts', 'principal_bindings',
			'registry_bundles', 'registry_rollouts', 'registry_installations',
			'boundary_surface_snapshots', 'boundary_surface_events', 'boundary_records_index',
			'emergency_stop_fences', 'approval_ceremonies', 'approval_dispatch_admissions',
			'approval_effect_reservation_events', 'approval_effect_closures',
			'approval_effect_dispositions', 'generated_spec_approval_ceremonies',
			'connector_release_authorities'
		)`)
	if err != nil {
		return fmt.Errorf("inspect kernel postgres schema: %w", err)
	}
	defer rows.Close()
	observed := make(map[string]struct{}, len(kernelPostgresTables))
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return fmt.Errorf("scan kernel postgres schema: %w", err)
		}
		observed[table] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read kernel postgres schema: %w", err)
	}
	required := []string{
		"kernel_schema_migrations", "obligations", "receipts", "principal_bindings",
		"registry_bundles", "registry_rollouts", "registry_installations",
		"boundary_surface_snapshots", "boundary_surface_events", "boundary_records_index",
	}
	if options.EmergencyStops {
		required = append(required, "emergency_stop_fences")
	}
	if options.ApprovalConsumption {
		required = append(required,
			"approval_ceremonies", "approval_dispatch_admissions", "approval_effect_reservation_events",
			"approval_effect_closures", "approval_effect_dispositions",
		)
	}
	if options.GeneratedSpecApproval {
		required = append(required, "generated_spec_approval_ceremonies")
	}
	if options.ReleaseAuthority {
		required = append(required, "connector_release_authorities")
	}
	missing := make([]string, 0)
	for _, table := range required {
		if _, ok := observed[table]; !ok {
			missing = append(missing, table)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("kernel postgres schema is missing %s; run the owner migration command", missing)
	}
	var journalRows, journalMin, journalMax int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MIN(version), 0), COALESCE(MAX(version), 0) FROM kernel_schema_migrations`).Scan(&journalRows, &journalMin, &journalMax); err != nil {
		return fmt.Errorf("inspect kernel postgres schema version: %w", err)
	}
	if journalRows != kernelPostgresSchemaVersion || journalMin != 1 || journalMax != kernelPostgresSchemaVersion {
		return fmt.Errorf("kernel database at schema version %d with %d journal rows, want exact version %d; run the owner migration command", journalMax, journalRows, kernelPostgresSchemaVersion)
	}
	columns, err := db.QueryContext(ctx, `SELECT table_name, column_name
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name IN (
			'kernel_schema_migrations', 'obligations', 'receipts', 'principal_bindings',
			'registry_bundles', 'registry_rollouts', 'registry_installations',
			'boundary_surface_snapshots', 'boundary_surface_events', 'boundary_records_index',
			'emergency_stop_fences', 'approval_ceremonies', 'approval_dispatch_admissions',
			'approval_effect_reservation_events', 'approval_effect_closures',
			'approval_effect_dispositions', 'generated_spec_approval_ceremonies',
			'connector_release_authorities'
		)`)
	if err != nil {
		return fmt.Errorf("inspect kernel postgres schema columns: %w", err)
	}
	defer columns.Close()
	observedColumns := make(map[string]map[string]struct{}, len(requiredKernelPostgresColumns))
	for columns.Next() {
		var table, column string
		if err := columns.Scan(&table, &column); err != nil {
			return fmt.Errorf("scan kernel postgres schema columns: %w", err)
		}
		if observedColumns[table] == nil {
			observedColumns[table] = make(map[string]struct{})
		}
		observedColumns[table][column] = struct{}{}
	}
	if err := columns.Err(); err != nil {
		return fmt.Errorf("read kernel postgres schema columns: %w", err)
	}
	for table, required := range requiredKernelPostgresColumns {
		if !kernelTableRequired(table, options) {
			continue
		}
		for column := range required {
			if _, ok := observedColumns[table][column]; !ok {
				return fmt.Errorf("kernel postgres schema %s.%s is missing; run the owner migration command", table, column)
			}
		}
	}
	return validateRuntimeRole(ctx, db)
}

func kernelTableRequired(table string, options RuntimeOptions) bool {
	switch table {
	case "emergency_stop_fences":
		return options.EmergencyStops
	case "approval_ceremonies", "approval_dispatch_admissions", "approval_effect_reservation_events", "approval_effect_closures", "approval_effect_dispositions":
		return options.ApprovalConsumption
	case "generated_spec_approval_ceremonies":
		return options.GeneratedSpecApproval
	case "connector_release_authorities":
		return options.ReleaseAuthority
	default:
		return true
	}
}

func validateRuntimeRole(ctx context.Context, db *sql.DB) error {
	var runtimeRole, sessionRole string
	var canLogin, superuser, bypassRLS, createRole, createDB, schemaCreate, ownsObjects, triggerPrivilege, replicationRoleSet bool
	if err := db.QueryRowContext(ctx, `
		SELECT current_user,
		       session_user,
		       role.rolcanlogin,
		       role.rolsuper,
		       role.rolbypassrls,
		       role.rolcreaterole,
		       role.rolcreatedb,
		       pg_catalog.has_schema_privilege(current_user, current_schema(), 'CREATE'),
		       EXISTS (
		           SELECT 1
		           FROM pg_catalog.pg_class AS relation
		           JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
		           WHERE namespace.nspname = current_schema()
		             AND pg_catalog.pg_has_role(current_user, relation.relowner, 'MEMBER')
		       ) OR EXISTS (
		           SELECT 1
		           FROM pg_catalog.pg_proc AS procedure
		           JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
		           WHERE namespace.nspname = current_schema()
		             AND pg_catalog.pg_has_role(current_user, procedure.proowner, 'MEMBER')
		       ),
		       EXISTS (
		           SELECT 1
		           FROM pg_catalog.pg_class AS relation
		           JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
		           WHERE namespace.nspname = current_schema()
		             AND relation.relkind IN ('r', 'p', 'f')
		             AND pg_catalog.has_table_privilege(current_user, relation.oid, 'TRIGGER')
		       ),
		       pg_catalog.has_parameter_privilege(current_user, 'session_replication_role', 'SET')
		FROM pg_catalog.pg_roles AS role
		WHERE role.rolname = current_user
	`).Scan(
		&runtimeRole, &sessionRole, &canLogin, &superuser, &bypassRLS,
		&createRole, &createDB, &schemaCreate, &ownsObjects, &triggerPrivilege,
		&replicationRoleSet,
	); err != nil {
		return fmt.Errorf("validate kernel postgres runtime role: %w", err)
	}
	if runtimeRole != sessionRole || !canLogin || superuser || bypassRLS || createRole || createDB || schemaCreate || ownsObjects || triggerPrivilege || replicationRoleSet {
		return errors.New("kernel postgres runtime role must be a direct non-superuser login without BYPASSRLS, role/database creation, schema CREATE, object ownership/TRIGGER, or session_replication_role SET")
	}
	return nil
}
