package admission

// quantum_posture: SHA-256 identifies a governed work effect; no signing,
// signature verification or post-quantum claim is made here.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// ProposeWorkEffect admits a worker tool's intent using the verified work item,
// effect type, canonical target and intent digest as its identity (D8). A new
// transport request, session, episode, seat or framework does not authorize a
// second execution. The original attempt and its authority binding stay intact.
// Ordinary Propose and read-by-id retain their existing isolation contracts.
func (s *Service) ProposeWorkEffect(ctx context.Context, caller Caller, in ProposeInput) (Attempt, bool, error) {
	in, err := prepareWorkEffect(caller, in)
	if err != nil {
		return Attempt{}, false, err
	}
	return s.Propose(ctx, caller, in)
}

func prepareWorkEffect(caller Caller, in ProposeInput) (ProposeInput, error) {
	if err := checkCaller(caller); err != nil {
		return ProposeInput{}, err
	}
	if caller.Episode == nil {
		return ProposeInput{}, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "a work effect requires a verified episode claim")
	}
	if in.MandateID != "" || in.CommitmentID != "" || len(in.Distinct) != 0 || in.ApprovalExpiresAt != nil {
		return ProposeInput{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"a work effect accepts only target, arguments, effect type, and quote")
	}
	var err error
	in, err = bindEpisode(caller.Episode, in)
	if err != nil {
		return ProposeInput{}, err
	}
	// Validate the original bytes before canonicalization: duplicate keys must
	// not disappear, and the closed effect schema and size bounds still apply.
	in.IdempotencyKey = "work:pending"
	if _, err := validateProposal(in); err != nil {
		return ProposeInput{}, err
	}
	in.Arguments, err = canonicalize.JCS(json.RawMessage(in.Arguments))
	if err != nil {
		return ProposeInput{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "effect.arguments: %v", err)
	}
	in.workEffect = true
	in.IdempotencyKey = "work:" + hex.EncodeToString(workEffectDigest(caller, in))
	return in, nil
}

func workEffectDigest(caller Caller, in ProposeInput) []byte {
	target := workEffectTarget(in.EffectType, in.Target)
	intent := sha256.Sum256(in.Arguments)
	var m bytes.Buffer
	for _, part := range []string{"helm.gateway.v1.work-effect.v1", caller.TenantID, caller.WorkspaceID,
		caller.Episode.WorkItemID, in.EffectType, target} {
		field(&m, []byte(part))
	}
	field(&m, intent[:])
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}

func workEffectTarget(effectType, target string) string {
	switch effectType {
	case effectargs.GitHubRepositoryGet, effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubGitPush, effectargs.GitHubPullRequestCreateDraft, effectargs.GitHubPullRequestCreate, effectargs.GitHubPullRequestMerge:
		// GitHub owner/repository names are case-insensitive. Do not change
		// the stored target or the target against which mandates are evaluated.
		target = strings.ToLower(target)
	}
	return target
}

// fenceWorkEffect covers both a new INSERT and an idempotency-key conflict.
// The table trigger covers direct inserts, but a duplicate never fires that
// trigger; without this check the old seat could replay its own old attempt
// after a new generation became current. Grant installation and revocation
// take the same advisory lock before changing the work row.
func fenceWorkEffect(ctx context.Context, tx *sql.Tx, caller Caller) error {
	e := caller.Episode
	if e == nil {
		return errNotFound
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(
		hashtextextended(json_build_array($1::text,$2::text,$3::text)::text,754133))`,
		caller.TenantID, caller.WorkspaceID, e.WorkItemID)
	if err != nil {
		return err
	}
	var generation int64
	var grantID, episodeID, principalID, actorID, profile, client, digest string
	err = tx.QueryRowContext(ctx, `SELECT w.generation, g.grant_id::text, g.recipient_episode_id,
		g.recipient_principal_id, g.recipient_actor_id, g.recipient_profile, g.recipient_client,
		encode(g.manifest_digest,'hex')
		FROM authority_reassignment_work w JOIN authority_reassignment_grants g
		ON g.tenant_id = w.tenant_id AND g.grant_id = w.grant_id
		WHERE w.tenant_id = $1 AND w.workspace_id = $2 AND w.work_item_id = $3
		AND g.revoked_at IS NULL AND g.expires_at > now()`,
		caller.TenantID, caller.WorkspaceID, e.WorkItemID).
		Scan(&generation, &grantID, &episodeID, &principalID, &actorID, &profile, &client, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		if caller.Reassignment != nil {
			return errNotFound
		}
		// No installed work generation: the ordinary original episode path.
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM authority_reassignment_work
			WHERE tenant_id = $1 AND workspace_id = $2 AND work_item_id = $3)`,
			caller.TenantID, caller.WorkspaceID, e.WorkItemID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return errNotFound // installed but revoked or expired
		}
		return nil
	}
	if err != nil {
		return err
	}
	g := caller.Reassignment
	if g == nil || g.GrantID != grantID || g.Generation != generation ||
		g.ManifestDigest != "sha256:"+digest || g.WorkItemID != e.WorkItemID ||
		g.RecipientEpisodeID != episodeID || g.RecipientPrincipalID != principalID ||
		g.RecipientActorID != actorID || g.RecipientProfile != profile || g.RecipientClient != client ||
		e.EpisodeID != episodeID || caller.PrincipalID != principalID || caller.ActorID != actorID ||
		e.Profile != profile {
		return errNotFound
	}
	return nil
}
