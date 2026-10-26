package admission

// Recovery holds use the existing authority transaction and original attempts.
// They neither settle money nor grant permission to restore or resume.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// RecoveryBinding selects one provisioned version, never a tenant-wide hold.
// Tenant and workspace come from the verified caller. InstallationID is an
// exact caller-authorized correlation binding, not an installation credential.
type RecoveryBinding struct {
	OperationID, InstallationID, OrgRef, OrganizationVersionID string
	Generation                                                 int64
}

// RecoveryFence acknowledges a durable claim cutoff. A claim committed before
// it may still send afterwards. InventoryWatermark identifies current original
// attempt state, not a cross-store snapshot or a signed recovery receipt.
type RecoveryFence struct {
	RecoveryBinding
	PlanDigest          string
	AuthorityRevision   int64
	InventoryWatermark  string
	InventoryCount      int64
	UnresolvedCount     int64
	CheckpointDigest    string
	CheckpointWatermark string
	CutoffWatermark     string
}

func validateRecovery(in RecoveryBinding) error {
	if checkAttemptID(in.OperationID) != nil || !claimIDPattern.MatchString(in.InstallationID) ||
		!effectargs.ValidOrgRef(in.OrgRef) || !claimIDPattern.MatchString(in.OrganizationVersionID) || in.Generation < 0 || in.Generation == math.MaxInt64 {
		return refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "invalid recovery operation, installation, organization, version or generation")
	}
	return nil
}

func recoveryOperator(ctx context.Context, tx *sql.Tx, caller Caller) error {
	if caller.Episode != nil || caller.Continuation != nil || caller.Reassignment != nil {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "episode credentials do not control recovery")
	}
	return requireActiveHuman(ctx, tx, caller, "a recovery operator")
}

// FenceRecovery takes existing single-use stop authority, narrowed to an exact
// operation by the authenticated transport. It preserves permits, reservations
// and original attempts. Replaying the current exact operation is idempotent;
// an older generation cannot supersede or acknowledge a newer operation.
func (s *Service) FenceRecovery(ctx context.Context, caller Caller, token Token, in RecoveryBinding) (RecoveryFence, bool, error) {
	if token.Scope != scopeStop {
		return RecoveryFence{}, false, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "recovery fencing requires stop authority")
	}
	if err := checkCaller(caller); err != nil {
		return RecoveryFence{}, false, err
	}
	if err := validateRecovery(in); err != nil {
		return RecoveryFence{}, false, err
	}
	var out RecoveryFence
	var existing bool
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		// No version bump: unrelated permits must remain usable. Claims hold
		// this existing row FOR SHARE through commit, so the following scan sees
		// every pre-cutoff claim, including one whose provider send starts later.
		var unused int64
		if err := tx.QueryRowContext(ctx, `SELECT version FROM authority_tenants WHERE tenant_id=$1 FOR UPDATE`, caller.TenantID).Scan(&unused); err != nil {
			return err
		}
		if err := recoveryOperator(ctx, tx, caller); err != nil {
			return err
		}
		var current int64
		var operation string
		err := tx.QueryRowContext(ctx, `SELECT generation, operation_id::text FROM authority_recovery_scopes
			WHERE tenant_id=$1 AND workspace_id=$2 AND org_ref=$3 AND organization_version_id=$4`,
			caller.TenantID, caller.WorkspaceID, in.OrgRef, in.OrganizationVersionID).Scan(&current, &operation)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if operation == in.OperationID {
			// The request carries the generation it replaced, so an exact retry
			// uses current-1. readRecovery still verifies every scope binding.
			if current != in.Generation+1 {
				return recoveryStale()
			}
			in.Generation = current
			out, err = readRecovery(ctx, tx, caller, in)
			existing = err == nil
			return err
		}
		if current != in.Generation {
			return recoveryStale()
		}
		var digest, version string
		var revision int64
		err = tx.QueryRowContext(ctx, `SELECT p.plan_digest, p.version_ref, p.revision FROM authority_provisions p
			JOIN authority_effect_attempts a ON a.tenant_id=p.tenant_id AND a.attempt_id=p.attempt_id
			WHERE p.tenant_id=$1 AND p.org_ref=$2 AND a.workspace_id=$3 FOR SHARE OF p`, caller.TenantID, in.OrgRef, caller.WorkspaceID).Scan(&digest, &version, &revision)
		if errors.Is(err, sql.ErrNoRows) || err == nil && version != in.OrganizationVersionID {
			return errNotFound
		}
		if err != nil {
			return err
		}
		// Attempts carry a verified version, not org_ref. Refuse an ambiguous
		// version rather than holding another organization's work by accident.
		var owners int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM authority_provisions WHERE tenant_id=$1 AND version_ref=$2`, caller.TenantID, version).Scan(&owners); err != nil {
			return err
		}
		if owners != 1 {
			return refuse(CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "organization version is not unambiguous")
		}
		if err := consumeToken(ctx, tx, caller.TenantID, token); err != nil {
			return err
		}
		in.Generation++
		var membership string
		if err := tx.QueryRowContext(ctx, `SELECT coalesce(jsonb_agg(attempt_id::text ORDER BY attempt_id)::text,'[]') FROM authority_effect_attempts
			WHERE tenant_id=$1 AND workspace_id=$2 AND organization_version_id=$3`, caller.TenantID, caller.WorkspaceID, version).Scan(&membership); err != nil {
			return err
		}
		cutoff := sha256.Sum256([]byte(membership))
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_recovery_fences
			(tenant_id,workspace_id,org_ref,organization_version_id,operation_id,installation_id,generation,plan_digest,authority_revision,requested_by,cutoff_watermark)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, caller.TenantID, caller.WorkspaceID, in.OrgRef, version,
			in.OperationID, in.InstallationID, in.Generation, digest, revision, caller.PrincipalID, hex.EncodeToString(cutoff[:]))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_recovery_scopes (tenant_id,workspace_id,org_ref,organization_version_id,operation_id,generation)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,workspace_id,org_ref,organization_version_id)
			DO UPDATE SET operation_id=EXCLUDED.operation_id,generation=EXCLUDED.generation`,
			caller.TenantID, caller.WorkspaceID, in.OrgRef, version, in.OperationID, in.Generation)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_recovery_members (tenant_id,operation_id,attempt_id)
			SELECT tenant_id,$1,attempt_id FROM authority_effect_attempts WHERE tenant_id=$2 AND workspace_id=$3 AND organization_version_id=$4`,
			in.OperationID, caller.TenantID, caller.WorkspaceID, version)
		if err != nil {
			return err
		}
		out, err = readRecovery(ctx, tx, caller, in)
		return err
	})
	return out, existing, err
}

func recoveryStale() error {
	return refuse(CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "recovery operation or generation is not current")
}

// Called only after acquiring the existing tenant control lock. A recovery
// refusal rolls back admission/claim; unlike Stop it never cancels the attempt,
// voids a permit or releases an exposure.
func allowRecoveryVersion(ctx context.Context, tx *sql.Tx, tenant, workspace, version string) error {
	if version == "" {
		return nil
	}
	var held bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_recovery_scopes WHERE tenant_id=$1 AND workspace_id=$2 AND organization_version_id=$3)`, tenant, workspace, version).Scan(&held); err != nil {
		return err
	}
	if held {
		return refuse(CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "provider recovery holds this organization version")
	}
	return nil
}

func readRecovery(ctx context.Context, tx *sql.Tx, caller Caller, in RecoveryBinding) (RecoveryFence, error) {
	out := RecoveryFence{RecoveryBinding: in}
	err := tx.QueryRowContext(ctx, `SELECT f.plan_digest,f.authority_revision,coalesce(c.checkpoint_digest,''),coalesce(c.inventory_watermark,''),f.cutoff_watermark
		FROM authority_recovery_fences f JOIN authority_recovery_scopes s
		 ON s.tenant_id=f.tenant_id AND s.operation_id=f.operation_id AND s.generation=f.generation
		LEFT JOIN authority_recovery_checkpoints c ON c.tenant_id=f.tenant_id AND c.operation_id=f.operation_id
		WHERE f.tenant_id=$1 AND f.workspace_id=$2 AND f.org_ref=$3 AND f.organization_version_id=$4
		 AND f.operation_id=$5 AND f.installation_id=$6 AND f.generation=$7`,
		caller.TenantID, caller.WorkspaceID, in.OrgRef, in.OrganizationVersionID, in.OperationID, in.InstallationID, in.Generation).
		Scan(&out.PlanDigest, &out.AuthorityRevision, &out.CheckpointDigest, &out.CheckpointWatermark, &out.CutoffWatermark)
	if errors.Is(err, sql.ErrNoRows) {
		return out, errNotFound
	}
	if err != nil {
		return out, err
	}
	// One statement sees one complete current inventory. Only digests and
	// original authority/effect identities enter the watermark; no arguments,
	// provider tokens, secret values or provider response bodies enter it.
	var material string
	err = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE a.state IN ('DISPATCHING','DISPATCHED','UNKNOWN','ESCALATED_TO_HUMAN')
		 OR (p.consumed_at IS NOT NULL AND a.outcome IS NULL)
		 OR m.state IN ('HELD','ESTIMATED','UNRESOLVED_FINAL')),
		coalesce(jsonb_agg(jsonb_build_array(a.attempt_id,a.version,a.state,a.outcome,a.effect_type,a.target,
		 encode(a.argument_digest,'hex'),encode(a.approval_digest,'hex'),a.mandate_id,a.episode_id,a.case_id,
		 a.requester_principal_id,a.requester_actor_id,p.permit_id,p.claim_id,p.consumed_at,p.voided_at,m.state)
		 ORDER BY a.attempt_id)::text,'[]')
		FROM authority_recovery_members r JOIN authority_effect_attempts a ON a.tenant_id=r.tenant_id AND a.attempt_id=r.attempt_id
		LEFT JOIN authority_permits p ON p.tenant_id=a.tenant_id AND p.attempt_id=a.attempt_id
		LEFT JOIN authority_model_calls m ON m.tenant_id=a.tenant_id AND m.attempt_id=a.attempt_id
		WHERE r.tenant_id=$1 AND r.operation_id=$2`, caller.TenantID, in.OperationID).
		Scan(&out.InventoryCount, &out.UnresolvedCount, &material)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256([]byte(material))
	out.InventoryWatermark = hex.EncodeToString(sum[:])
	return out, nil
}

// GetRecoveryFence is a safe read under current active operator authority.
// It cannot observe providers or bypass the original attempt's workload checks.
func (s *Service) GetRecoveryFence(ctx context.Context, caller Caller, in RecoveryBinding) (RecoveryFence, error) {
	if err := checkCaller(caller); err != nil {
		return RecoveryFence{}, err
	}
	if err := validateRecovery(in); err != nil {
		return RecoveryFence{}, err
	}
	var out RecoveryFence
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := recoveryOperator(ctx, tx, caller); err != nil {
			return err
		}
		var err error
		out, err = readRecovery(ctx, tx, caller, in)
		return err
	})
	return out, err
}

// BindRecoveryCheckpoint records a CP content digest against a current native
// watermark. It refuses in-flight or unknown outcomes. This is a correlation
// record only: it proves neither CP snapshot consistency nor restore eligibility.
func (s *Service) BindRecoveryCheckpoint(ctx context.Context, caller Caller, token Token, in RecoveryBinding, digest, watermark string) (RecoveryFence, error) {
	if token.Scope != scopeStop {
		return RecoveryFence{}, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "checkpoint binding requires stop authority")
	}
	if err := checkCaller(caller); err != nil {
		return RecoveryFence{}, err
	}
	if err := validateRecovery(in); err != nil {
		return RecoveryFence{}, err
	}
	for _, value := range []string{digest, watermark} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != value {
			return RecoveryFence{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "checkpoint digests must be lowercase SHA-256")
		}
	}
	var out RecoveryFence
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var unused int64
		if err := tx.QueryRowContext(ctx, `SELECT version FROM authority_tenants WHERE tenant_id=$1 FOR UPDATE`, caller.TenantID).Scan(&unused); err != nil {
			return err
		}
		if err := recoveryOperator(ctx, tx, caller); err != nil {
			return err
		}
		var err error
		out, err = readRecovery(ctx, tx, caller, in)
		if err != nil {
			return err
		}
		if out.UnresolvedCount != 0 || out.InventoryWatermark != watermark {
			return refuse(CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "original effects remain unresolved or inventory changed")
		}
		if out.CheckpointDigest != "" {
			if out.CheckpointDigest == digest && out.CheckpointWatermark == watermark {
				return nil
			}
			return recoveryStale()
		}
		if err := consumeToken(ctx, tx, caller.TenantID, token); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_recovery_checkpoints (tenant_id,operation_id,checkpoint_digest,inventory_watermark) VALUES ($1,$2,$3,$4)`, caller.TenantID, in.OperationID, digest, watermark)
		if err == nil {
			out.CheckpointDigest = digest
			out.CheckpointWatermark = watermark
		}
		return err
	})
	return out, err
}

// ListRecoveryAttempts pages immutable original membership. Each ID remains
// subject to Get/Observe's existing tenant, workspace and workload authority.
func (s *Service) ListRecoveryAttempts(ctx context.Context, caller Caller, in RecoveryBinding, after string) ([]string, error) {
	if err := checkCaller(caller); err != nil {
		return nil, err
	}
	if err := validateRecovery(in); err != nil {
		return nil, err
	}
	if after != "" && checkAttemptID(after) != nil {
		return nil, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "invalid attempt cursor")
	}
	var ids []string
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := recoveryOperator(ctx, tx, caller); err != nil {
			return err
		}
		if _, err := readRecovery(ctx, tx, caller, in); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT attempt_id::text FROM authority_recovery_members WHERE tenant_id=$1 AND operation_id=$2 AND ($3='' OR attempt_id>nullif($3,'')::uuid) ORDER BY attempt_id LIMIT 100`, caller.TenantID, in.OperationID, after)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}
