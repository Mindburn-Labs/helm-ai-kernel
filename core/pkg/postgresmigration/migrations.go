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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/credentials"
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

func postgresColumnSet(columns ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		set[column] = struct{}{}
	}
	return set
}

// requiredKernelPostgresColumns mirrors the source-owned schemas and the
// columns read or written by each active runtime store. Keeping the complete
// store contract here makes a behind migration fail at startup instead of on
// the first request that happens to exercise a less common field.
var requiredKernelPostgresColumns = map[string]map[string]struct{}{
	"kernel_schema_migrations": postgresColumnSet("version", "name", "applied_at"),
	"obligations": postgresColumnSet(
		"id", "idempotency_key", "intent", "state", "created_at", "updated_at",
		"leased_by", "leased_until", "hash", "previous_hash", "metadata", "tenant_id",
	),
	"receipts": postgresColumnSet(
		"receipt_id", "decision_id", "effect_id", "external_reference_id", "execution_intent_id",
		"status", "result", "timestamp", "executor_id", "metadata", "signature", "merkle_root",
		"prev_hash", "lamport_clock", "output_hash", "decision_hash", "args_hash", "signature_version",
		"verdict", "reason_code", "policy_hash", "session_id", "causal_session_id", "blob_hash",
		"log_id", "leaf_index", "transparency", "key_id", "public_key_set", "signature_profile",
		"signature_algorithm", "correlation_id", "receipt_envelope", "chain_hash", "append_sequence",
	),
	"principal_bindings":         postgresColumnSet("tenant_id", "principal_id", "created_at"),
	"registry_bundles":           postgresColumnSet("name", "version", "bundle_json", "created_at"),
	"registry_rollouts":          postgresColumnSet("name", "canary_version", "canary_bundle_json", "percentage", "updated_at"),
	"registry_installations":     postgresColumnSet("tenant_id", "pack_id", "installed_at"),
	"boundary_surface_snapshots": postgresColumnSet("id", "snapshot_json", "updated_at"),
	"boundary_surface_events":    postgresColumnSet("sequence", "event_kind", "object_id", "object_json", "created_at"),
	"boundary_records_index": postgresColumnSet(
		"record_id", "verdict", "reason_code", "tool_name", "mcp_server_id", "policy_epoch", "receipt_id", "record_hash", "created_at",
	),
	"emergency_stop_fences": postgresColumnSet(
		"tenant_id", "workspace_id", "contract_version", "audience", "key_id", "command_id", "command_hash",
		"epoch", "actor_id", "reason", "issued_at", "expires_at", "fenced_at", "kernel_key_id",
		"kernel_signer_profile", "kernel_public_key", "receipt_hash",
	),
	"approval_ceremonies": postgresColumnSet(
		"tenant_id", "approval_id", "workspace_id", "state", "hold_started_at", "challenge_spec_json",
		"challenge_json", "challenge_hash", "challenge_nonce", "verified_ref_json", "signer_set_hash",
		"grant_json", "grant_id", "grant_hash", "grant_nonce", "grant_signature_algorithm", "grant_signature",
		"grant_consumption_json", "consumption_signature_algorithm", "consumption_signature", "expires_at",
		"consumed_at", "consumed_by", "created_at", "updated_at", "version",
	),
	"approval_dispatch_admissions": postgresColumnSet(
		"tenant_id", "workspace_id", "attempt_id", "approval_id", "consumption_hash", "idempotency_key_hash",
		"effect_hash", "connector_id", "action", "admitted_by", "state", "admission_json", "signature_algorithm",
		"signature", "issued_at", "expires_at", "created_at", "updated_at",
	),
	"approval_effect_reservation_events": postgresColumnSet(
		"tenant_id", "workspace_id", "admission_id", "sequence", "state", "attempt_id", "approval_id",
		"grant_id", "grant_hash", "consumption_hash", "consumer_subject", "audience", "idempotency_key_hash",
		"effect_hash", "action", "connector_action", "connector_id", "connector_version", "release_scope_kind",
		"release_authority_id", "release_registry_revision", "release_authority_hash", "release_observed_at",
		"admission_json", "release_authority_json", "admitted_at", "started_at", "resolved_at", "occurred_at",
		"reason_code", "connector_execution_ref", "proof_session_ref", "intent_ref", "effect_ref", "close_prior_state",
		"acknowledgement_hash", "close_receipt_hash", "outcome", "evidence_pack_ref", "evidence_pack_hash", "reconciliation_ref",
	),
	"approval_effect_closures": postgresColumnSet(
		"tenant_id", "workspace_id", "admission_id", "close_id", "acknowledgement_hash", "receipt_hash", "outcome",
		"evidence_pack_ref", "evidence_pack_hash", "acknowledgement_json", "receipt_json", "signature_algorithm", "signature", "created_at",
	),
	"approval_effect_dispositions": postgresColumnSet(
		"tenant_id", "workspace_id", "admission_id", "command_id", "disposition_sequence", "command_hash",
		"previous_receipt_hash", "action", "disposition_ref", "fence_command_id", "fence_command_hash", "fence_epoch",
		"fence_receipt_hash", "reservation_sequence", "reservation_head_hash", "reservation_state", "fence_json",
		"command_envelope_json", "receipt_json", "signature_algorithm", "signature", "created_at",
	),
	"generated_spec_approval_ceremonies": postgresColumnSet(
		"tenant_id", "workspace_id", "approval_id", "state", "binding_json", "binding_ref", "audience", "generated_spec_id",
		"generated_spec_hash", "execution_plan_hash", "plan_transaction_hash", "write_set_hash", "verification_scope_hash",
		"policy_envelope_hash", "policy_version", "policy_epoch", "action", "requesting_principal_id", "authority_source",
		"authority_version", "authority_snapshot_hash", "required_role", "quorum", "server_identity", "hold_started_at",
		"challenge_json", "challenge_id", "challenge_hash", "challenge_nonce", "assertions_json", "quorum_verified_at",
		"grant_json", "grant_id", "grant_hash", "grant_nonce", "grant_signature_algorithm", "grant_signature", "consumption_json",
		"consumption_hash", "consumption_audience", "consumption_signature_algorithm", "consumption_signature", "expires_at", "consumed_at",
		"consumed_by", "created_at", "updated_at", "version",
	),
	"connector_release_authorities": postgresColumnSet(
		"scope_kind", "tenant_id", "workspace_id", "connector_id", "connector_version", "registry_revision", "state",
		"authority_hash", "previous_authority_hash", "revokes_authority_hash", "signed_at", "valid_from", "valid_until",
		"envelope_json", "signature", "created_at",
	),
	"credentials": postgresColumnSet(
		"id", "operator_id", "provider", "token_type", "access_token", "refresh_token", "scopes", "email",
		"expires_at", "created_at", "updated_at", "last_used_at",
	),
	"credential_audit_log": postgresColumnSet("id", "operator_id", "provider", "action", "ip_address", "user_agent", "created_at"),
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
		{"credentials", credentials.MigratePostgres},
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
	"credentials",
	"credential_audit_log",
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
			'credentials', 'credential_audit_log',
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
		"credentials", "credential_audit_log",
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
	var journalName string
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MIN(version), 0), COALESCE(MAX(version), 0), COALESCE(MAX(name), '') FROM kernel_schema_migrations`).Scan(&journalRows, &journalMin, &journalMax, &journalName); err != nil {
		return fmt.Errorf("inspect kernel postgres schema version: %w", err)
	}
	if journalRows != kernelPostgresSchemaVersion || journalMin != 1 || journalMax != kernelPostgresSchemaVersion || journalName != kernelPostgresMigrationName {
		return fmt.Errorf("kernel database at schema version %d with %d journal rows, want exact version %d; run the owner migration command", journalMax, journalRows, kernelPostgresSchemaVersion)
	}
	columns, err := db.QueryContext(ctx, `SELECT table_name, column_name
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name IN (
			'kernel_schema_migrations', 'obligations', 'receipts', 'principal_bindings',
			'registry_bundles', 'registry_rollouts', 'registry_installations',
			'credentials', 'credential_audit_log',
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
	var canLogin, superuser, bypassRLS, createRole, createDB, replication, schemaCreate, ownsObjects, triggerPrivilege, replicationRoleSet bool
	if err := db.QueryRowContext(ctx, `
		SELECT current_user,
		       session_user,
		       role.rolcanlogin,
		       role.rolsuper,
		       role.rolbypassrls,
		       role.rolcreaterole,
		       role.rolcreatedb,
		       role.rolreplication,
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
		&createRole, &createDB, &replication, &schemaCreate, &ownsObjects,
		&triggerPrivilege, &replicationRoleSet,
	); err != nil {
		return fmt.Errorf("validate kernel postgres runtime role: %w", err)
	}
	if runtimeRole != sessionRole || !canLogin || superuser || bypassRLS || createRole || createDB || replication || schemaCreate || ownsObjects || triggerPrivilege || replicationRoleSet {
		return errors.New("kernel postgres runtime role must be a direct non-superuser login without BYPASSRLS, role/database/replication privileges, schema CREATE, object ownership/TRIGGER, or session_replication_role SET")
	}
	return nil
}
