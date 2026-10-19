// Package reassignment installs Kernel-owned, bounded retained-result grants
// through the existing effect admission, human approval and step-up path.
package reassignment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

const effectType = effectargs.AuthorityWorkReassignmentGrant
const revokeEffectType = effectargs.AuthorityWorkReassignmentRevoke

var declaration = adapters.Declaration{
	EffectType: effectType, RiskClass: adapters.RiskIrreversible,
	Idempotent: adapters.IdempotentConditional, Observable: adapters.ObservableYes,
	Reversible: adapters.ReversibleNo, Mediation: adapters.MediationEnforced,
	Notes:      "Installs a current-generation grant for exact retained work attempts after distinct human approval and WebAuthn step-up. Native membership, provision binding and Stop are checked again at dispatch. No old permit or effect is dispatched.",
	TargetForm: "org:{org_id}", Description: "Authorizes one exact recipient episode to read and replay listed retained work results.",
}

var revokeDeclaration = adapters.Declaration{
	EffectType: revokeEffectType, RiskClass: adapters.RiskMedium,
	Idempotent: adapters.IdempotentConditional, Observable: adapters.ObservableYes,
	Reversible: adapters.ReversibleNo, Mediation: adapters.MediationEnforced,
	Notes:      "Revokes one current Kernel retained-result grant by exact generation. It never authorizes a replacement.",
	TargetForm: "org:{org_id}", Description: "Revokes one exact retained work grant.",
}

// Adapter uses the gateway's existing PostgreSQL ledger. It has no provider
// credential and never reads a CP database or trusts a client-supplied member.
type Adapter struct{ db *sql.DB }

func New(db *sql.DB) (*Adapter, error) {
	if db == nil {
		return nil, errors.New("reassignment adapter requires the gateway database")
	}
	return &Adapter{db: db}, nil
}

func (a *Adapter) Declarations() []adapters.Declaration {
	d := declaration
	d.ArgumentSchema, _ = effectargs.ArgumentSchema(effectType)
	r := revokeDeclaration
	r.ArgumentSchema, _ = effectargs.ArgumentSchema(revokeEffectType)
	return []adapters.Declaration{d, r}
}

func (a *Adapter) Prepare(_ context.Context, _ adapters.TokenSource, effect adapters.Effect) (*adapters.Preparation, error) {
	switch effect.EffectType {
	case effectType:
		g, err := effectargs.ParseWorkReassignmentGrant(effect.Arguments)
		if err != nil || g.OrgRef != effect.Target {
			return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "the grant manifest or target is invalid")
		}
		return &adapters.Preparation{Declaration: a.Declarations()[0], Target: effect.Target}, nil
	case revokeEffectType:
		r, err := effectargs.ParseWorkReassignmentRevoke(effect.Arguments)
		if err != nil || r.OrgRef != effect.Target {
			return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "the revocation or target is invalid")
		}
		return &adapters.Preparation{Declaration: a.Declarations()[1], Target: effect.Target}, nil
	default:
		return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "unsupported reassignment effect")
	}
}

func (a *Adapter) Dispatch(ctx context.Context, _ adapters.TokenSource, effect adapters.Effect, permitDigest []byte) adapters.DispatchResult {
	if r := adapters.CheckPermitDigest(effect.Arguments, permitDigest); r != nil {
		return notSent(r)
	}
	inv := effect.Invocation
	if inv == nil || inv.TenantID == "" || inv.WorkspaceID == "" || inv.AttemptID == "" || inv.RequesterPrincipalID == "" {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "the grant carries no native invocation"))
	}
	if effect.EffectType == revokeEffectType {
		r, err := effectargs.ParseWorkReassignmentRevoke(effect.Arguments)
		if err != nil || r.OrgRef != effect.Target {
			return notSent(adapters.Refuse(contracts.ReasonSchemaViolation, "the revocation or target is invalid"))
		}
		err = a.inTenant(ctx, inv.TenantID, func(tx *sql.Tx) error { return revoke(ctx, tx, inv, r) })
		return dispatchResult(err)
	}
	if effect.EffectType != effectType {
		return notSent(adapters.Refuse(contracts.ReasonSchemaViolation, "unsupported reassignment effect"))
	}
	g, err := effectargs.ParseWorkReassignmentGrant(effect.Arguments)
	if err != nil || g.OrgRef != effect.Target {
		return notSent(adapters.Refuse(contracts.ReasonSchemaViolation, "the grant manifest or target is invalid"))
	}
	err = a.inTenant(ctx, inv.TenantID, func(tx *sql.Tx) error {
		return install(ctx, tx, inv, g)
	})
	return dispatchResult(err)
}

func dispatchResult(err error) adapters.DispatchResult {
	if err == nil {
		return adapters.DispatchResult{Status: adapters.DispatchSent}
	}
	var refusal *adapters.Refusal
	if errors.As(err, &refusal) {
		return notSent(refusal)
	}
	return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Detail: "the Kernel reassignment transaction has an uncertain result"}
}

func (a *Adapter) Observe(ctx context.Context, _ adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	unknown := func() adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonPreconditionFailed,
			Detail: "the Kernel grant readback is unavailable"}
	}
	inv := effect.Invocation
	if inv == nil || inv.TenantID == "" || inv.AttemptID == "" {
		return unknown()
	}
	if effect.EffectType == revokeEffectType {
		return a.observeRevoke(ctx, effect)
	}
	if effect.EffectType != effectType {
		return unknown()
	}
	g, err := effectargs.ParseWorkReassignmentGrant(effect.Arguments)
	if err != nil || g.OrgRef != effect.Target {
		return unknown()
	}
	var storedManifest []byte
	var storedGrantID, approvedBy string
	err = a.inTenant(ctx, inv.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT grant_id::text, manifest_digest, approved_by
			FROM authority_reassignment_grants WHERE tenant_id = $1 AND grant_attempt_id = $2`,
			inv.TenantID, inv.AttemptID).Scan(&storedGrantID, &storedManifest, &approvedBy)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch,
			Detail: "the grant is absent from the Kernel ledger", Absent: true,
			Observation: &adapters.Observation{Source: "gateway.reassignment.readback", TrustClass: "gateway_ledger", ObservedAt: time.Now().UTC()}}
	}
	if err != nil {
		return unknown()
	}
	want, err := digest(g.ManifestDigest)
	if err != nil || storedGrantID != g.ReassignmentID || !bytes.Equal(storedManifest, want) {
		return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch,
			Detail:      "the Kernel grant differs from the reviewed manifest",
			Observation: &adapters.Observation{Source: "gateway.reassignment.readback", TrustClass: "gateway_ledger", ObservedAt: time.Now().UTC()}}
	}
	receipt, _ := json.Marshal(struct {
		GrantID        string `json:"grant_id"`
		ManifestDigest string `json:"manifest_digest"`
		AttemptID      string `json:"attempt_id"`
		ApprovedBy     string `json:"approved_by"`
	}{storedGrantID, g.ManifestDigest, inv.AttemptID, approvedBy})
	sum := sha256.Sum256(receipt)
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded,
		Observation: &adapters.Observation{Source: "gateway.reassignment.readback", TrustClass: "gateway_ledger",
			EvidenceDigest: sum[:], ObservedAt: time.Now().UTC()}}
}

func revoke(ctx context.Context, tx *sql.Tx, inv *adapters.Invocation, r *effectargs.WorkReassignmentRevoke) error {
	var workID string
	err := tx.QueryRowContext(ctx, `SELECT work_item_id FROM authority_reassignment_grants
		WHERE tenant_id = $1 AND workspace_id = $2 AND grant_id = $3`,
		inv.TenantID, inv.WorkspaceID, r.GrantID).Scan(&workID)
	if errors.Is(err, sql.ErrNoRows) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the grant is absent")
	}
	if err != nil {
		return err
	}
	if err := lockWork(ctx, tx, inv.TenantID, inv.WorkspaceID, workID); err != nil {
		return err
	}
	var orgRef string
	var generation int64
	var existing sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT g.org_ref, w.generation, g.revoked_by
		FROM authority_reassignment_grants g
		JOIN authority_reassignment_work w ON w.tenant_id = g.tenant_id
		 AND w.workspace_id = g.workspace_id AND w.work_item_id = g.work_item_id
		 AND w.grant_id = g.grant_id
		WHERE g.tenant_id = $1 AND g.workspace_id = $2 AND g.grant_id = $3
		FOR UPDATE OF w, g`, inv.TenantID, inv.WorkspaceID, r.GrantID).
		Scan(&orgRef, &generation, &existing)
	if errors.Is(err, sql.ErrNoRows) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the current grant is absent")
	}
	if err != nil {
		return err
	}
	if orgRef != r.OrgRef || generation != r.Generation {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the current grant generation or organization changed")
	}
	if existing.Valid {
		if existing.String == inv.AttemptID {
			return nil
		}
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the grant is already revoked")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authority_reassignment_grants
		SET revoked_at = now(), revoked_by = $4, revoke_reason = $5
		WHERE tenant_id = $1 AND workspace_id = $2 AND grant_id = $3`,
		inv.TenantID, inv.WorkspaceID, r.GrantID, inv.AttemptID, r.Reason); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) observeRevoke(ctx context.Context, effect adapters.Effect) adapters.ObserveResult {
	inv := effect.Invocation
	if inv == nil || inv.TenantID == "" || inv.AttemptID == "" {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonPreconditionFailed}
	}
	r, err := effectargs.ParseWorkReassignmentRevoke(effect.Arguments)
	if err != nil || r.OrgRef != effect.Target {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonSchemaViolation}
	}
	var revokedBy, orgRef string
	var generation int64
	err = a.inTenant(ctx, inv.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT revoked_by, org_ref, generation FROM authority_reassignment_grants
			WHERE tenant_id = $1 AND workspace_id = $2 AND grant_id = $3 AND revoked_at IS NOT NULL`,
			inv.TenantID, inv.WorkspaceID, r.GrantID).Scan(&revokedBy, &orgRef, &generation)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch,
			Detail: "the Kernel ledger has no revocation", Absent: true,
			Observation: &adapters.Observation{Source: "gateway.reassignment.readback", TrustClass: "gateway_ledger", ObservedAt: time.Now().UTC()}}
	}
	if err != nil {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonPreconditionFailed}
	}
	if revokedBy != inv.AttemptID || orgRef != r.OrgRef || generation != r.Generation {
		return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch,
			Detail:      "the Kernel revocation differs from this attempt",
			Observation: &adapters.Observation{Source: "gateway.reassignment.readback", TrustClass: "gateway_ledger", ObservedAt: time.Now().UTC()}}
	}
	sum := sha256.Sum256([]byte(r.GrantID + ":" + inv.AttemptID))
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded,
		Observation: &adapters.Observation{Source: "gateway.reassignment.readback", TrustClass: "gateway_ledger",
			EvidenceDigest: sum[:], ObservedAt: time.Now().UTC()}}
}

func (a *Adapter) inTenant(ctx context.Context, tenantID string, fn func(*sql.Tx) error) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func install(ctx context.Context, tx *sql.Tx, inv *adapters.Invocation, g *effectargs.WorkReassignmentGrant) error {
	var tenantVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT version FROM authority_tenants WHERE tenant_id = $1 FOR SHARE`,
		inv.TenantID).Scan(&tenantVersion); err != nil {
		return err
	}
	var approvedBy string
	err := tx.QueryRowContext(ctx, `SELECT approver_principal_id FROM authority_approvals
		WHERE tenant_id = $1 AND attempt_id = $2 AND decision = 'APPROVED'
		  AND step_up_issuer IS NOT NULL AND step_up_jti IS NOT NULL AND step_up_method = 'webauthn'`,
		inv.TenantID, inv.AttemptID).Scan(&approvedBy)
	if errors.Is(err, sql.ErrNoRows) || err == nil && approvedBy == inv.RequesterPrincipalID {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "a distinct human WebAuthn approval is required")
	}
	if err != nil {
		return err
	}
	if err := lockAndCheckPrincipals(ctx, tx, inv.TenantID, inv.RequesterPrincipalID, g); err != nil {
		return err
	}
	var planDigest, version string
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT plan_digest, version_ref, revision FROM authority_provisions
		WHERE tenant_id = $1 AND org_ref = $2 FOR SHARE`, inv.TenantID, g.OrgRef).
		Scan(&planDigest, &version, &revision)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (planDigest != g.PlanDigest || version != g.OrganizationVersionID || revision != g.AuthorityRevision) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the organization authority binding changed")
	}
	if err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT now()`).Scan(&now); err != nil {
		return err
	}
	if !g.ExpiresAt.After(now) || g.ExpiresAt.After(now.Add(24*time.Hour)) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the grant expiry must be future and within 24 hours")
	}
	// ProposeWorkEffect takes the same lock before inserting any new logical
	// operation. The native membership scan below therefore cannot miss a
	// concurrent original attempt that commits just before this grant.
	if err := lockWork(ctx, tx, inv.TenantID, inv.WorkspaceID, g.WorkItemID); err != nil {
		return err
	}
	var currentGeneration int64
	var currentID string
	err = tx.QueryRowContext(ctx, `SELECT generation, grant_id::text FROM authority_reassignment_work
		WHERE tenant_id = $1 AND workspace_id = $2 AND work_item_id = $3 FOR UPDATE`,
		inv.TenantID, inv.WorkspaceID, g.WorkItemID).Scan(&currentGeneration, &currentID)
	if errors.Is(err, sql.ErrNoRows) {
		currentGeneration = 0
	} else if err != nil {
		return err
	}
	if currentID == g.ReassignmentID {
		var stored []byte
		if err := tx.QueryRowContext(ctx, `SELECT manifest_digest FROM authority_reassignment_grants
			WHERE tenant_id = $1 AND grant_id = $2`, inv.TenantID, currentID).Scan(&stored); err != nil {
			return err
		}
		want, _ := digest(g.ManifestDigest)
		if currentGeneration == g.Generation && bytes.Equal(stored, want) {
			return nil
		}
		return adapters.Refuse(contracts.ReasonIdempotencyConflict, "the reassignment ID has different bytes")
	}
	if currentGeneration != g.ExpectedGeneration {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "the current reassignment generation changed")
	}
	if currentGeneration == 0 {
		if g.PredecessorReassignmentID != "" {
			return adapters.Refuse(contracts.ReasonPreconditionFailed, "a first grant has no revoked predecessor")
		}
	} else {
		var revokedAt sql.NullTime
		var revokedBy sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT revoked_at, revoked_by FROM authority_reassignment_grants
			WHERE tenant_id = $1 AND grant_id = $2 FOR SHARE`, inv.TenantID, currentID).
			Scan(&revokedAt, &revokedBy); err != nil {
			return err
		}
		if revokedAt.Valid {
			if !revokedBy.Valid || g.PredecessorReassignmentID != currentID {
				return adapters.Refuse(contracts.ReasonPreconditionFailed, "recovery must name the exact revoked native predecessor")
			}
		} else if g.PredecessorReassignmentID != "" {
			return adapters.Refuse(contracts.ReasonPreconditionFailed, "an active source move has no revoked predecessor")
		}
	}
	members, effects, mandates, err := nativeMembers(ctx, tx, inv, g)
	if err != nil {
		return err
	}
	if err := checkStops(ctx, tx, inv.TenantID, g, effects, mandates); err != nil {
		return err
	}
	manifest, _ := digest(g.ManifestDigest)
	drain, _ := digest(g.DrainDigest)
	terms, _ := digest(g.TermsDigest)
	_, err = tx.ExecContext(ctx, `INSERT INTO authority_reassignment_grants
		(tenant_id, grant_id, grant_attempt_id, workspace_id, org_ref, work_item_id,
		 organization_version_id, commitment_id, terms_digest, manifest_digest, drain_digest,
		 plan_digest, authority_revision, generation, recipient_episode_id, recipient_seat_id,
		 recipient_principal_id, recipient_actor_id, recipient_profile, recipient_client,
		 approved_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		inv.TenantID, g.ReassignmentID, inv.AttemptID, inv.WorkspaceID, g.OrgRef, g.WorkItemID,
		g.OrganizationVersionID, g.CommitmentID, terms, manifest, drain,
		g.PlanDigest, g.AuthorityRevision, g.Generation, g.Recipient.EpisodeID, g.Recipient.SeatID,
		g.Recipient.PrincipalID, g.Recipient.ActorID, g.Recipient.Profile, g.Recipient.Client,
		approvedBy, g.ExpiresAt)
	if err != nil {
		return err
	}
	for _, member := range members {
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_reassignment_members
			(tenant_id, grant_id, attempt_id, source_episode_id, source_principal_id, source_actor_id)
			VALUES ($1,$2,$3,$4,$5,$6)`, inv.TenantID, g.ReassignmentID,
			member.AttemptID, member.EpisodeID, member.PrincipalID, member.ActorID); err != nil {
			return err
		}
	}
	if currentGeneration > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE authority_reassignment_grants SET revoked_at = now()
			WHERE tenant_id = $1 AND grant_id = $2 AND revoked_at IS NULL`, inv.TenantID, currentID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE authority_reassignment_work
			SET generation = $4, grant_id = $5, updated_at = now()
			WHERE tenant_id = $1 AND workspace_id = $2 AND work_item_id = $3`,
			inv.TenantID, inv.WorkspaceID, g.WorkItemID, g.Generation, g.ReassignmentID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_reassignment_work
			(tenant_id, workspace_id, work_item_id, generation, grant_id) VALUES ($1,$2,$3,$4,$5)`,
			inv.TenantID, inv.WorkspaceID, g.WorkItemID, g.Generation, g.ReassignmentID)
	}
	return err
}

type member struct{ AttemptID, EpisodeID, PrincipalID, ActorID string }

func nativeMembers(ctx context.Context, tx *sql.Tx, inv *adapters.Invocation, g *effectargs.WorkReassignmentGrant) ([]member, []string, []string, error) {
	expected := map[string]struct{ Episode, Principal, Actor, Profile string }{}
	for _, source := range g.Sources {
		for _, id := range source.AttemptIDs {
			expected[id] = struct{ Episode, Principal, Actor, Profile string }{source.EpisodeID, source.PrincipalID, source.ActorID, source.Profile}
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT attempt_id::text, episode_id, requester_principal_id,
		requester_actor_id, episode_profile, organization_version_id, state, approval_digest IS NOT NULL,
		effect_type, mandate_id::text
		FROM authority_effect_attempts
		WHERE tenant_id = $1 AND workspace_id = $2 AND case_id = $3 AND idempotency_key LIKE 'work:%'
		ORDER BY attempt_id FOR SHARE`, inv.TenantID, inv.WorkspaceID, g.WorkItemID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []member
	effects, mandates := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var id, principal, actor, version, state, effect string
		var episode, profile, mandate sql.NullString
		var approved bool
		if err := rows.Scan(&id, &episode, &principal, &actor, &profile, &version, &state, &approved, &effect, &mandate); err != nil {
			return nil, nil, nil, err
		}
		want, listed := expected[id]
		if !listed || !episode.Valid || !profile.Valid || version != g.OrganizationVersionID ||
			episode.String != want.Episode || principal != want.Principal || actor != want.Actor || profile.String != want.Profile ||
			state == "DISPATCHING" || state == "ADMITTED" && !approved {
			return nil, nil, nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "native source attempt membership or drain is incomplete")
		}
		out = append(out, member{id, episode.String, principal, actor})
		effects[effect] = true
		if mandate.Valid {
			mandates[mandate.String] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	if len(out) != len(expected) {
		return nil, nil, nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "the source list omits or invents native work attempts")
	}
	return out, sortedKeys(effects), sortedKeys(mandates), nil
}

func lockAndCheckPrincipals(ctx context.Context, tx *sql.Tx, tenantID, requester string, g *effectargs.WorkReassignmentGrant) error {
	ids := map[string]bool{requester: true, g.Recipient.PrincipalID: true, g.Recipient.ActorID: true}
	for _, source := range g.Sources {
		ids[source.PrincipalID] = true
		if source.ActorID != "" {
			ids[source.ActorID] = true
		}
	}
	keys := sortedKeys(ids)
	rows, err := tx.QueryContext(ctx, `SELECT principal_id, kind, status FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = ANY($2::text[]) ORDER BY principal_id FOR SHARE`, tenantID, pq.Array(keys))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	found := map[string]bool{}
	for rows.Next() {
		var id, kind, status string
		if err := rows.Scan(&id, &kind, &status); err != nil {
			return err
		}
		found[id] = true
		if id == g.Recipient.PrincipalID && (kind != "agent" || status != "active") {
			return adapters.Refuse(contracts.ReasonPrincipalInactive, "the recipient is not an active agent")
		}
		if (id == requester || id == g.Recipient.ActorID) && status != "active" {
			return adapters.Refuse(contracts.ReasonPrincipalInactive, "the current authority actor is inactive")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !found[requester] || !found[g.Recipient.PrincipalID] || !found[g.Recipient.ActorID] {
		return adapters.Refuse(contracts.ReasonPrincipalInactive, "a required principal is not registered")
	}
	return nil
}

func checkStops(ctx context.Context, tx *sql.Tx, tenantID string, g *effectargs.WorkReassignmentGrant, effects, mandates []string) error {
	keys := []string{"tenant:" + tenantID, "principal:" + g.Recipient.PrincipalID, "principal:" + g.Recipient.ActorID,
		"effect_type:" + effectType}
	for _, source := range g.Sources {
		keys = append(keys, "principal:"+source.PrincipalID)
		if source.ActorID != "" {
			keys = append(keys, "principal:"+source.ActorID)
		}
	}
	for _, effect := range effects {
		keys = append(keys, "effect_type:"+effect)
	}
	for _, mandate := range mandates {
		keys = append(keys, "mandate:"+mandate)
	}
	var stopped bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_stops
		WHERE tenant_id = $1 AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		AND scope_kind || ':' || scope_key = ANY($2::text[]))`, tenantID, pq.Array(keys)).Scan(&stopped); err != nil {
		return err
	}
	if stopped {
		return adapters.Refuse(contracts.ReasonEmergencyStopFenced, "the source or recipient is stopped")
	}
	return nil
}

func lockWork(ctx context.Context, tx *sql.Tx, tenantID, workspaceID, workID string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(
		hashtextextended(json_build_array($1::text, $2::text, $3::text)::text, 754133))`,
		tenantID, workspaceID, workID)
	return err
}

func digest(ref string) ([]byte, error) { return hex.DecodeString(strings.TrimPrefix(ref, "sha256:")) }

func sortedKeys[K ~string](set map[K]bool) []K {
	keys := make([]K, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func notSent(r *adapters.Refusal) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason, Detail: r.Detail}
}

var _ adapters.Adapter = (*Adapter)(nil)
