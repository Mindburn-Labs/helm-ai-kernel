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

// Migrate applies every Kernel-owned Postgres schema. It is intended for the
// one-shot `helm-ai-kernel migrate` command, never for request serving.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("kernel postgres migration requires database")
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
	return nil
}

var kernelPostgresTables = []string{
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
			'obligations', 'receipts', 'principal_bindings',
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
		"obligations", "receipts", "principal_bindings",
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
	return validateRuntimeRole(ctx, db)
}

func validateRuntimeRole(ctx context.Context, db *sql.DB) error {
	var runtimeRole, sessionRole string
	var superuser, bypassRLS, createRole, createDB, schemaCreate, ownsObjects, replicationRoleSet bool
	if err := db.QueryRowContext(ctx, `
		SELECT current_user,
		       session_user,
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
		       pg_catalog.has_parameter_privilege(current_user, 'session_replication_role', 'SET')
		FROM pg_catalog.pg_roles AS role
		WHERE role.rolname = current_user
	`).Scan(
		&runtimeRole, &sessionRole, &superuser, &bypassRLS, &createRole,
		&createDB, &schemaCreate, &ownsObjects, &replicationRoleSet,
	); err != nil {
		return fmt.Errorf("validate kernel postgres runtime role: %w", err)
	}
	if runtimeRole != sessionRole || superuser || bypassRLS || createRole || createDB || schemaCreate || ownsObjects || replicationRoleSet {
		return errors.New("kernel postgres runtime role must be a direct non-superuser login without BYPASSRLS, role/database creation, schema CREATE, object ownership, or session_replication_role SET")
	}
	return nil
}
