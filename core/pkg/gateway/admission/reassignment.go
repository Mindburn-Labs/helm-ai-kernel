package admission

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// Reassignment is copied from a verified helm_reassignment episode claim.
// It is a reference, not a list of attempts or independent read authority.
type Reassignment struct {
	GrantID, ManifestDigest, ApplicationDigest, WorkItemID     string
	Generation                                                 int64
	RecipientEpisodeID, RecipientPrincipalID, RecipientActorID string
	RecipientProfile, RecipientClient                          string
}

// CurrentWorkReassignment is the native high-water fence for one work item.
// Revocation leaves its generation and grant ID in place. Present=false is a
// locked native absence, not a CP assignment count or a history scan.
type CurrentWorkReassignment struct {
	Present, Revoked                                            bool
	Generation                                                  int64
	GrantID, ManifestDigest, GrantAttemptID, RevokedByAttemptID string
	RecipientEpisodeID, RecipientSeatID, RecipientPrincipalID   string
	RecipientActorID, RecipientProfile, RecipientClient         string
	RevokedAt                                                   *time.Time
	ExpiresAt                                                   time.Time
}

// GetCurrentWorkReassignment lets an active service reader reconcile the
// Kernel's current generation before preparing or cancelling a CP handoff.
// The tenant and workspace come only from the verified caller. The work lock
// serializes this read with grant installation and revocation; the subsequent
// generation CAS remains mandatory if a new installer races after the read.
func (s *Service) GetCurrentWorkReassignment(ctx context.Context, caller Caller, orgRef, workItemID string) (CurrentWorkReassignment, error) {
	if err := checkCaller(caller); err != nil {
		return CurrentWorkReassignment{}, err
	}
	if caller.Episode != nil || caller.Continuation != nil || caller.Reassignment != nil {
		return CurrentWorkReassignment{}, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
			"an episode credential cannot read a work reassignment fence")
	}
	if !effectargs.ValidOrgRef(orgRef) || !claimIDPattern.MatchString(workItemID) {
		return CurrentWorkReassignment{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"org_ref or work_item_id is invalid")
	}
	var current CurrentWorkReassignment
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var kind, status string
		err := tx.QueryRowContext(ctx, `SELECT kind, status FROM authority_principals
			WHERE tenant_id = $1 AND principal_id = $2 FOR SHARE`, caller.TenantID, caller.PrincipalID).
			Scan(&kind, &status)
		if errors.Is(err, sql.ErrNoRows) || err == nil && kind != "service" {
			return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "the reader is not a registered service principal")
		}
		if err != nil {
			return err
		}
		if status != "active" {
			return refuse(CodePermissionDenied, contracts.ReasonPrincipalInactive, "the service reader is inactive")
		}
		var provisioned bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_provisions
			WHERE tenant_id = $1 AND org_ref = $2)`, caller.TenantID, orgRef).Scan(&provisioned); err != nil {
			return err
		}
		if !provisioned {
			return errNotFound
		}
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(
			hashtextextended(json_build_array($1::text,$2::text,$3::text)::text,754133))`,
			caller.TenantID, caller.WorkspaceID, workItemID); err != nil {
			return err
		}
		var actualOrg, manifest string
		var revokedAt sql.NullTime
		err = tx.QueryRowContext(ctx, `SELECT w.generation, g.grant_id::text, g.org_ref,
			encode(g.manifest_digest,'hex'), g.grant_attempt_id::text,
			g.revoked_at, COALESCE(g.revoked_by,''), g.expires_at,
			g.recipient_episode_id, g.recipient_seat_id, g.recipient_principal_id,
			g.recipient_actor_id, g.recipient_profile, g.recipient_client
			FROM authority_reassignment_work w JOIN authority_reassignment_grants g
			  ON g.tenant_id = w.tenant_id AND g.grant_id = w.grant_id
			WHERE w.tenant_id = $1 AND w.workspace_id = $2 AND w.work_item_id = $3
			FOR SHARE OF w, g`, caller.TenantID, caller.WorkspaceID, workItemID).
			Scan(&current.Generation, &current.GrantID, &actualOrg, &manifest,
				&current.GrantAttemptID, &revokedAt, &current.RevokedByAttemptID,
				&current.ExpiresAt, &current.RecipientEpisodeID, &current.RecipientSeatID,
				&current.RecipientPrincipalID, &current.RecipientActorID,
				&current.RecipientProfile, &current.RecipientClient)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if actualOrg != orgRef {
			return errNotFound
		}
		current.Present = true
		current.Revoked = revokedAt.Valid
		if revokedAt.Valid {
			current.RevokedAt = &revokedAt.Time
		}
		current.ManifestDigest = "sha256:" + manifest
		return nil
	})
	return current, err
}

func validReassignmentCaller(c Caller) bool {
	g := c.Reassignment
	if g == nil {
		return true
	}
	return c.Episode != nil && c.Episode.EpisodeID == g.RecipientEpisodeID &&
		c.Episode.WorkItemID == g.WorkItemID && c.PrincipalID == g.RecipientPrincipalID &&
		c.ActorID == g.RecipientActorID && g.GrantID != "" && g.Generation > 0 &&
		(g.RecipientProfile == "worker" || g.RecipientProfile == "executor") &&
		c.Episode.Profile == g.RecipientProfile
}

// precheckReassignmentGrant avoids asking a human to approve a stale
// organization plan or an inactive recipient. Dispatch checks both again
// under locks before installing any member.
func precheckReassignmentGrant(ctx context.Context, tx *sql.Tx, caller Caller, in ProposeInput) (*adapters.Refusal, error) {
	g, err := effectargs.ParseWorkReassignmentGrant(in.Arguments)
	if err != nil {
		return nil, err
	}
	var digest, version string
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT plan_digest, version_ref, revision FROM authority_provisions
		WHERE tenant_id = $1 AND org_ref = $2`, caller.TenantID, g.OrgRef).Scan(&digest, &version, &revision)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (digest != g.PlanDigest || version != g.OrganizationVersionID || revision != g.AuthorityRevision) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the organization authority binding is stale"), nil
	}
	if err != nil {
		return nil, err
	}
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = $2 AND kind = 'agent' AND status = 'active')`,
		caller.TenantID, g.Recipient.PrincipalID).Scan(&active); err != nil {
		return nil, err
	}
	if !active {
		return adapters.Refuse(contracts.ReasonPrincipalInactive, "the recipient seat is not an active agent"), nil
	}
	return nil, nil
}

// GetReassignment returns only the current result/status of an exact member.
// Ordinary Get and GetContent retain their original episode isolation.
func (s *Service) GetReassignment(ctx context.Context, caller Caller, attemptID string) (Attempt, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, err
	}
	if caller.Reassignment == nil {
		return Attempt{}, errNotFound
	}
	if err := checkAttemptID(attemptID); err != nil {
		return Attempt{}, err
	}
	var attempt Attempt
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var err error
		attempt, err = s.retainedAttempt(ctx, tx, caller, attemptID, nil)
		return err
	})
	return attempt, err
}

// FindRetainedWorkEffect runs before any new ModelGrants quote or admission.
// A listed, exact D8 operation returns its original attempt without creating
// a new hold, permit, approval, dispatch or observation. An unlisted intent
// returns found=false and follows the ordinary new-effect path.
func (s *Service) FindRetainedWorkEffect(ctx context.Context, caller Caller, in ProposeInput) (Attempt, bool, error) {
	if caller.Reassignment == nil {
		return Attempt{}, false, nil
	}
	in, err := prepareWorkEffect(caller, in)
	if err != nil {
		return Attempt{}, false, err
	}
	var attempt Attempt
	var found bool
	err = s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := requireCurrentReassignment(ctx, tx, caller); err != nil {
			return err
		}
		var id string
		err := tx.QueryRowContext(ctx, `SELECT m.attempt_id::text
			FROM authority_reassignment_members m
			JOIN authority_effect_attempts a ON a.tenant_id = m.tenant_id AND a.attempt_id = m.attempt_id
			WHERE m.tenant_id = $1 AND m.grant_id = $2 AND a.workspace_id = $3
			  AND a.case_id = $4 AND a.idempotency_key = $5`,
			caller.TenantID, caller.Reassignment.GrantID, caller.WorkspaceID,
			caller.Episode.WorkItemID, in.IdempotencyKey).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		attempt, err = s.retainedAttemptChecked(ctx, tx, caller, id, workEffectDigest(caller, in))
		found = err == nil
		return err
	})
	return attempt, found, err
}

func (s *Service) retainedAttempt(ctx context.Context, tx *sql.Tx, caller Caller, attemptID string, workDigest []byte) (Attempt, error) {
	if err := requireCurrentReassignment(ctx, tx, caller); err != nil {
		return Attempt{}, err
	}
	return s.retainedAttemptChecked(ctx, tx, caller, attemptID, workDigest)
}

func (s *Service) retainedAttemptChecked(ctx context.Context, tx *sql.Tx, caller Caller, attemptID string, workDigest []byte) (Attempt, error) {
	var sourceEpisode, sourcePrincipal, sourceActor string
	err := tx.QueryRowContext(ctx, `SELECT source_episode_id, source_principal_id, source_actor_id
		FROM authority_reassignment_members WHERE tenant_id = $1 AND grant_id = $2 AND attempt_id = $3`,
		caller.TenantID, caller.Reassignment.GrantID, attemptID).Scan(&sourceEpisode, &sourcePrincipal, &sourceActor)
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, errNotFound
	}
	if err != nil {
		return Attempt{}, err
	}
	a, err := loadAttemptScoped(ctx, tx, caller, attemptID, caller.Episode.WorkItemID, workDigest)
	if err != nil {
		return Attempt{}, err
	}
	if a.Episode == nil || a.Episode.EpisodeID != sourceEpisode ||
		a.RequesterPrincipalID != sourcePrincipal || a.RequesterActorID != sourceActor ||
		a.Episode.OrganizationVersionID != caller.Episode.OrganizationVersionID ||
		!strings.HasPrefix(a.IdempotencyKey, "work:") {
		return Attempt{}, errNotFound
	}
	if err := reassignmentStops(ctx, tx, caller, a); err != nil {
		return Attempt{}, err
	}
	return a, nil
}

// requireCurrentReassignment takes locks on the tenant, recipient and current
// generation. Stop/revocation committed before these locks wins; a later Stop
// waits for this bounded read transaction to finish.
func requireCurrentReassignment(ctx context.Context, tx *sql.Tx, caller Caller) error {
	g := caller.Reassignment
	if g == nil || !validReassignmentCaller(caller) {
		return errNotFound
	}
	var tenantVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT version FROM authority_tenants WHERE tenant_id = $1 FOR SHARE`, caller.TenantID).Scan(&tenantVersion); err != nil {
		return err
	}
	var kind, status string
	err := tx.QueryRowContext(ctx, `SELECT kind, status FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = $2 FOR SHARE`, caller.TenantID, caller.PrincipalID).Scan(&kind, &status)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (kind != "agent" || status != "active") {
		return errNotFound
	}
	if err != nil {
		return err
	}
	var actorStatus string
	err = tx.QueryRowContext(ctx, `SELECT status FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = $2 FOR SHARE`, caller.TenantID, caller.ActorID).Scan(&actorStatus)
	if errors.Is(err, sql.ErrNoRows) || err == nil && actorStatus != "active" {
		return errNotFound
	}
	if err != nil {
		return err
	}
	var generation int64
	var grantID string
	err = tx.QueryRowContext(ctx, `SELECT generation, grant_id::text FROM authority_reassignment_work
		WHERE tenant_id = $1 AND workspace_id = $2 AND work_item_id = $3 FOR SHARE`,
		caller.TenantID, caller.WorkspaceID, caller.Episode.WorkItemID).Scan(&generation, &grantID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (generation != g.Generation || grantID != g.GrantID) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	var manifest []byte
	var orgRef, version, principal, actor, episode, profile, client, planDigest string
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT manifest_digest, org_ref, organization_version_id, recipient_principal_id,
		recipient_actor_id, recipient_episode_id, recipient_profile, recipient_client, plan_digest, authority_revision
		FROM authority_reassignment_grants WHERE tenant_id = $1 AND grant_id = $2 AND revoked_at IS NULL
		  AND expires_at > now() FOR SHARE`, caller.TenantID, g.GrantID).
		Scan(&manifest, &orgRef, &version, &principal, &actor, &episode, &profile, &client, &planDigest, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	want, err := hex.DecodeString(strings.TrimPrefix(g.ManifestDigest, "sha256:"))
	if err != nil || !bytes.Equal(manifest, want) || principal != caller.PrincipalID || actor != caller.ActorID ||
		episode != caller.Episode.EpisodeID || profile != g.RecipientProfile || client != g.RecipientClient ||
		version != caller.Episode.OrganizationVersionID {
		return errNotFound
	}
	var currentDigest, currentVersion string
	var currentRevision int64
	err = tx.QueryRowContext(ctx, `SELECT plan_digest, version_ref, revision FROM authority_provisions
		WHERE tenant_id = $1 AND org_ref = $2 FOR SHARE`, caller.TenantID, orgRef).
		Scan(&currentDigest, &currentVersion, &currentRevision)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (currentDigest != planDigest || currentVersion != version || currentRevision != revision) {
		return errNotFound
	}
	return err
}

func reassignmentStops(ctx context.Context, tx *sql.Tx, caller Caller, a Attempt) error {
	keys := []string{"tenant:" + caller.TenantID, "principal:" + caller.PrincipalID,
		"principal:" + caller.ActorID, "principal:" + a.RequesterPrincipalID,
		"principal:" + a.RequesterActorID, "effect_type:" + a.EffectType}
	if a.MandateID != "" {
		keys = append(keys, "mandate:"+a.MandateID)
	}
	stops, err := stopsOn(ctx, tx, caller.TenantID, keys)
	if err != nil {
		return err
	}
	if len(stops) > 0 {
		return refuse(CodePermissionDenied, contracts.ReasonEmergencyStopFenced, "retained work is stopped")
	}
	return nil
}
