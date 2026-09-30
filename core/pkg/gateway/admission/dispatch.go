package admission

// quantum_posture: SHA-256 content addresses for observation results; nothing
// here signs or verifies, and no post-quantum claim is made.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// Credentials is the gateway's connection custody (target architecture §9.6,
// R8): the provider credential for one call on one effect of one tenant. An
// error means there is none, and the adapter answers NOT_SENT.
type Credentials interface {
	Token(ctx context.Context, tenantID string, effect adapters.Effect) (string, error)
}

// Where a gateway-recorded observation (a NOT_SENT dispatch) comes from.
const (
	dispatchSource     = "gateway.dispatch"
	dispatchTrustClass = "adapter_refusal"
)

// Dispatch claims the permit of an ADMITTED attempt and sends the effect
// through its adapter (ADR-0001 §1 "Dispatch claim", target architecture
// §4.1 item 3). The caller is an active workload principal (agent or
// service) of the tenant, never a human.
//
// The claim is one transaction, before any provider I/O: it locks the
// attempt and its permit, re-locks the authority rows FOR SHARE, re-reads
// the stops, and compares every row's version with the permit's. A stop, an
// expired permit, a changed version or a mandate outside its validity
// refuses the claim: the permit is voided, the reservation released and the
// attempt CANCELLED with the reason. Otherwise the permit is consumed once
// and the attempt becomes DISPATCHING with its fence (dispatch_deadline).
//
// The adapter's answer then decides the state: SENT is DISPATCHED and read
// back at once (OBSERVED, or UNKNOWN when inconclusive); NOT_SENT is
// OBSERVED(FAILED) with its reason and the reservation released; INDEFINITE
// is UNKNOWN, for Observe to reconcile. An attempt already CANCELLED,
// DISPATCHING or later is returned unchanged with existing true: nothing is
// dispatched twice.
func (s *Service) Dispatch(ctx context.Context, caller Caller, attemptID string) (Attempt, bool, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, false, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return Attempt{}, false, err
	}
	var c *claimed
	var existing bool
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := requireWorkload(ctx, tx, caller); err != nil {
			return err
		}
		a, err := lockAttempt(ctx, tx, caller, attemptID)
		if err != nil {
			return err
		}
		if !mayExecute(caller.PrincipalID, a.requester, a.requesterActor) {
			return errNotItsWorkload
		}
		switch a.state {
		case "ADMITTED":
		case "PROPOSED", "DENIED", "ESCALATED", "APPROVED", "REJECTED", "EXPIRED":
			return refuse(CodeFailedPrecondition, "", "an attempt in %s cannot be dispatched", a.state)
		default:
			existing = true
			return nil
		}
		adapter, ok := s.adapters[a.effectType]
		if !ok {
			return refuse(CodeFailedPrecondition, "", "no adapter of this gateway performs %s", a.effectType)
		}
		c, err = s.claim(ctx, tx, a, caller)
		if c != nil {
			c.adapter = adapter
		}
		return err
	})
	if err != nil {
		return Attempt{}, false, err
	}
	if c != nil {
		s.send(ctx, c)
	}
	attempt, err := s.Get(ctx, caller, attemptID)
	return attempt, existing, err
}

// claimed is a committed dispatch claim: what the adapter call needs.
type claimed struct {
	tenantID, workspaceID, attemptID string
	effect                           adapters.Effect
	permitDigest                     []byte
	claimID                          uuid.UUID
	adapter                          adapters.Adapter
}

// claim runs the dispatch claim in tx on an ADMITTED attempt. It returns nil
// when the claim was refused (and recorded as CANCELLED).
func (s *Service) claim(ctx context.Context, tx *sql.Tx, a lockedAttempt, dispatcher Caller) (*claimed, error) {
	var permitID string
	var permitDigest, stored []byte
	var expired bool
	var expiresAt time.Time
	err := tx.QueryRowContext(ctx, `SELECT permit_id, argument_digest, authority_versions, expires_at <= now(), expires_at
		FROM authority_permits WHERE tenant_id = $1 AND attempt_id = $2 AND consumed_at IS NULL AND voided_at IS NULL
		FOR UPDATE`, a.tenantID, a.id).Scan(&permitID, &permitDigest, &stored, &expired, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, refuse(CodeFailedPrecondition, "", "the attempt holds no unused permit; a permit is consumed once")
	}
	if err != nil {
		return nil, err
	}
	var permitted []AuthorityVersion
	if err := json.Unmarshal(stored, &permitted); err != nil {
		return nil, err
	}

	// Re-lock the authority rows in the global order, then read the stops
	// (ADR-0001 §1: a stop committed after admission is seen here).
	requester := Caller{TenantID: a.tenantID, WorkspaceID: a.workspaceID, PrincipalID: a.requester, ActorID: a.requesterActor}
	// An authority plan has no mandate; every other admitted attempt has one.
	var leaf uuid.UUID
	var chain []mandates.Mandate
	if !effectargs.IsAuthorityPlan(a.effectType) {
		var err error
		if leaf, err = uuid.Parse(a.mandateID); err != nil {
			return nil, errors.New("an admitted attempt has no mandate")
		}
		if chain, err = mandates.ChainInTx(ctx, tx, a.tenantID, leaf, false); err != nil {
			return nil, err
		}
	}
	auth, err := lockAuthority(ctx, tx, requester, a.effectType, leaf, chain)
	if err != nil {
		return nil, err
	}
	stops, err := activeStops(ctx, tx, a.tenantID, a.effectType, auth)
	if err != nil {
		return nil, err
	}
	// The workload dispatching it, and the workload its token names, are
	// stopped the same way (TA §4.1 item 6).
	dispatcherStops, err := principalStops(ctx, tx, a.tenantID, dispatcher.PrincipalID, dispatcher.ActorID)
	if err != nil {
		return nil, err
	}
	stops = append(stops, dispatcherStops...)
	stops = withoutStop(stops, liftedStop(a.effectType, a.target)) // a lift is not blocked by the stop it lifts
	reason := claimRefusal(claimInput{Stops: stops, Expired: expired, Permitted: permitted, Current: auth.versions,
		Chain: auth.chain, Now: a.now})
	var content []byte
	if reason == "" {
		err := tx.QueryRowContext(ctx, `SELECT arguments FROM authority_attempt_contents WHERE tenant_id = $1 AND attempt_id = $2`,
			a.tenantID, a.id).Scan(&content)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			reason = contracts.ReasonPreconditionFailed
		case err != nil:
			return nil, err
		}
	}
	if reason != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE authority_permits SET voided_at = now(), void_reason_code = $3
			WHERE tenant_id = $1 AND permit_id = $2`, a.tenantID, permitID, string(reason)); err != nil {
			return nil, err
		}
		if err := release(ctx, tx, a.tenantID, a.id, "claim-refused"); err != nil {
			return nil, err
		}
		return nil, transition(ctx, tx, a.tenantID, a.id, "ADMITTED", "CANCELLED", reason)
	}

	// Consume the permit once, and record the attempt and its fence, before
	// any provider I/O (TA §4.1 item 3). The permit row is locked above, and
	// only an unused one was selected.
	claimID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authority_permits
		SET consumed_at = now(), claim_id = $3, claimed_by_principal_id = $4, claimed_by_actor_id = $5
		WHERE tenant_id = $1 AND permit_id = $2`, a.tenantID, permitID, claimID, dispatcher.PrincipalID, dispatcher.ActorID); err != nil {
		return nil, err
	}
	fence := s.cfg.DispatchTimeout + s.cfg.DispatchGrace
	res, err := tx.ExecContext(ctx, `UPDATE authority_effect_attempts
		SET state = 'DISPATCHING', dispatch_deadline = now() + $3 * interval '1 millisecond', version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND attempt_id = $2 AND state = 'ADMITTED'`, a.tenantID, a.id, fence.Milliseconds())
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, errors.New("admission: the attempt changed state during the claim")
	}
	// The reconciliation job, enqueued with the claim (TA §6.2): it drives the
	// attempt to an outcome whatever happens to this process after the commit.
	if err := s.enqueue(ctx, tx, Job{Kind: JobReconcile, TenantID: a.tenantID, WorkspaceID: a.workspaceID, AttemptID: a.id}); err != nil {
		return nil, err
	}
	return &claimed{
		tenantID: a.tenantID, workspaceID: a.workspaceID, attemptID: a.id,
		effect: adapters.Effect{EffectType: a.effectType, Target: a.target, Arguments: content,
			Invocation: invocationFor(a, permitID, claimID.String(), expiresAt)},
		permitDigest: permitDigest, claimID: claimID,
	}, nil
}

func invocationFor(a lockedAttempt, permitID, claimID string, expires time.Time) *adapters.Invocation {
	quote := make([]adapters.Amount, len(a.quote))
	for i, q := range a.quote {
		quote[i] = adapters.Amount{Unit: q.Unit, Amount: q.Amount}
	}
	return &adapters.Invocation{TenantID: a.tenantID, WorkspaceID: a.workspaceID, AttemptID: a.id, PermitID: permitID, ClaimID: claimID, RequesterPrincipalID: a.requester, ExpiresAt: expires, Quote: quote}
}

// claimInput is what the dispatch claim read under its locks.
type claimInput struct {
	Stops     []string
	Expired   bool
	Permitted []AuthorityVersion
	Current   []AuthorityVersion
	Chain     []mandates.Mandate
	Now       time.Time
}

// claimRefusal is the dispatch claim's decision (ADR-0001 §1), pure: why the
// claim is refused, or "" when the permit may be consumed. Order: an active
// stop, the permit's expiry, any change to a row the permit was issued under
// (conservative, ADR-0001 §5.4: even an unrelated widening; the caller
// proposes again), then a link's validity window, which ends without a
// version change.
func claimRefusal(in claimInput) contracts.ReasonCode {
	switch {
	case len(in.Stops) > 0:
		return contracts.ReasonEmergencyStopFenced
	case in.Expired:
		return contracts.ReasonPermitExpired
	case !sameVersions(in.Permitted, in.Current):
		return contracts.ReasonAuthorityChanged
	case !withinValidity(in.Chain, in.Now):
		return contracts.ReasonMandateOutsideValidity
	}
	return ""
}

// afterDispatch is the state an adapter's answer moves a DISPATCHING attempt
// to. Only NOT_SENT is a certain failure; INDEFINITE, or anything an adapter
// should not answer, may have happened and is UNKNOWN (§4.3).
func afterDispatch(status adapters.DispatchStatus) string {
	switch status {
	case adapters.DispatchSent:
		return "DISPATCHED"
	case adapters.DispatchNotSent:
		return "OBSERVED"
	}
	return "UNKNOWN"
}

// sameVersions compares the permit's authority versions with the ones the
// claim locked.
func sameVersions(permitted, current []AuthorityVersion) bool {
	if len(permitted) != len(current) {
		return false
	}
	order := func(v []AuthorityVersion) []AuthorityVersion {
		out := append([]AuthorityVersion(nil), v...)
		sort.Slice(out, func(i, j int) bool {
			if out[i].Kind != out[j].Kind {
				return out[i].Kind < out[j].Kind
			}
			return out[i].Key < out[j].Key
		})
		return out
	}
	p, c := order(permitted), order(current)
	for i := range p {
		if p[i] != c[i] {
			return false
		}
	}
	return true
}

// withinValidity: every link of the chain is valid at now. A validity
// window ends without a version change, so the claim reads it again.
func withinValidity(chain []mandates.Mandate, now time.Time) bool {
	for _, m := range chain {
		if now.Before(m.Terms.ValidFrom) || !now.Before(m.Terms.ValidUntil) {
			return false
		}
	}
	return true
}

// send calls the adapter for a committed claim and records its answer. The
// provider call and the record outlive the caller's request: a client that
// hangs up does not interrupt a dispatch half way.
func (s *Service) send(ctx context.Context, c *claimed) {
	ctx = context.WithoutCancel(ctx)
	call, cancel := context.WithTimeout(ctx, s.cfg.DispatchTimeout)
	result := c.adapter.Dispatch(call, s.tokens(c.tenantID, c.effect), c.effect, c.permitDigest)
	cancel()
	var sent bool
	err := s.inTenant(ctx, c.tenantID, func(tx *sql.Tx) error {
		var err error
		sent, err = recordDispatch(ctx, tx, c, result)
		return err
	})
	if err != nil {
		// The attempt stays DISPATCHING; after its fence Observe makes it
		// UNKNOWN and reconciles it. It is never sent again.
		slog.ErrorContext(ctx, "recording a dispatch failed", "attempt_id", c.attemptID, "status", result.Status, "error", err)
		return
	}
	if sent {
		s.readBack(ctx, observeTarget{tenantID: c.tenantID, workspaceID: c.workspaceID, attemptID: c.attemptID,
			from: "DISPATCHED", effect: c.effect, adapter: c.adapter})
	}
}

// recordDispatch writes the adapter's answer, fenced: only the claim that
// consumed the permit records, and only while the attempt is DISPATCHING.
// It reports whether the attempt became DISPATCHED.
func recordDispatch(ctx context.Context, tx *sql.Tx, c *claimed, result adapters.DispatchResult) (bool, error) {
	var state string
	var claim uuid.NullUUID
	err := tx.QueryRowContext(ctx, `SELECT a.state, p.claim_id FROM authority_effect_attempts a
		JOIN authority_permits p ON p.tenant_id = a.tenant_id AND p.attempt_id = a.attempt_id
		WHERE a.tenant_id = $1 AND a.attempt_id = $2 FOR UPDATE OF a`, c.tenantID, c.attemptID).Scan(&state, &claim)
	if err != nil {
		return false, err
	}
	if state != "DISPATCHING" || claim.UUID != c.claimID {
		slog.WarnContext(ctx, "a dispatch answered after its fence; the attempt moved on and keeps its state",
			"attempt_id", c.attemptID, "state", state, "status", result.Status)
		return false, nil
	}
	switch afterDispatch(result.Status) {
	case "DISPATCHED":
		return true, transition(ctx, tx, c.tenantID, c.attemptID, "DISPATCHING", "DISPATCHED", "")
	case "OBSERVED":
		// Nothing visible was written: the outcome is a certain FAILED.
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_observations (tenant_id, attempt_id, source, trust_class, outcome)
			VALUES ($1, $2, $3, $4, 'FAILED')`, c.tenantID, c.attemptID, dispatchSource, dispatchTrustClass); err != nil {
			return false, err
		}
		if err := release(ctx, tx, c.tenantID, c.attemptID, "not-sent"); err != nil {
			return false, err
		}
		return false, settleState(ctx, tx, c.tenantID, c.attemptID, "DISPATCHING", "OBSERVED", adapters.OutcomeFailed, result.Reason)
	default:
		// The effect may have happened. The reservation stays held.
		return false, transition(ctx, tx, c.tenantID, c.attemptID, "DISPATCHING", "UNKNOWN", result.Reason)
	}
}

// Observe reads a dispatched effect back through its adapter and records one
// observation (target architecture §4.1 item 4). It never dispatches.
//
//   - DISPATCHED becomes OBSERVED with the outcome, or UNKNOWN when the
//     read-back is inconclusive.
//   - UNKNOWN becomes RECONCILED with the outcome, or stays UNKNOWN.
//   - DISPATCHING past its fence (a dispatch that never recorded an answer)
//     becomes UNKNOWN first: it may or may not have reached the provider.
//     Before the fence it may still be in flight and is left alone.
//   - Any other state is returned unchanged with existing true.
//
// A SUCCEEDED outcome confirms the held exposure; a FAILED one releases it
// (ADR-0003, count units: an effect that happened consumed its quote).
func (s *Service) Observe(ctx context.Context, caller Caller, attemptID string) (Attempt, bool, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, false, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return Attempt{}, false, err
	}
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := requireWorkload(ctx, tx, caller); err != nil {
			return err
		}
		a, err := lockAttempt(ctx, tx, caller, attemptID)
		if err != nil {
			return err
		}
		if !mayExecute(caller.PrincipalID, a.requester, a.requesterActor) {
			return errNotItsWorkload
		}
		return nil
	})
	if err != nil {
		return Attempt{}, false, err
	}
	existing, _, err := s.observeAttempt(ctx, caller.TenantID, caller.WorkspaceID, attemptID)
	if err != nil {
		return Attempt{}, false, err
	}
	attempt, err := s.Get(ctx, caller, attemptID)
	return attempt, existing, err
}

// observeAttempt is Observe after authorization, shared with the
// reconciliation job. existing is true when the state admits no read-back;
// fence is the dispatch deadline of a DISPATCHING attempt still inside it.
func (s *Service) observeAttempt(ctx context.Context, tenantID, workspaceID, attemptID string) (existing bool, fence time.Time, err error) {
	var target *observeTarget
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		a, err := lockAttempt(ctx, tx, Caller{TenantID: tenantID, WorkspaceID: workspaceID}, attemptID)
		if err != nil {
			return err
		}
		switch a.state {
		case "DISPATCHED", "UNKNOWN":
		case "DISPATCHING":
			if !a.dispatchDeadline.Valid || a.now.Before(a.dispatchDeadline.Time) {
				existing, fence = true, a.dispatchDeadline.Time
				return nil
			}
			if err := transition(ctx, tx, a.tenantID, a.id, "DISPATCHING", "UNKNOWN", ""); err != nil {
				return err
			}
			a.state = "UNKNOWN"
		default:
			existing = true
			return nil
		}
		adapter, ok := s.adapters[a.effectType]
		if !ok {
			return refuse(CodeFailedPrecondition, "", "no adapter of this gateway performs %s", a.effectType)
		}
		var content []byte
		if err := tx.QueryRowContext(ctx, `SELECT arguments FROM authority_attempt_contents WHERE tenant_id = $1 AND attempt_id = $2`,
			a.tenantID, a.id).Scan(&content); err != nil {
			return err
		}
		invocation := invocationFor(a, "", "", time.Time{})
		if err := tx.QueryRowContext(ctx, `SELECT permit_id, claim_id, expires_at FROM authority_permits
			WHERE tenant_id=$1 AND attempt_id=$2 AND consumed_at IS NOT NULL`, a.tenantID, a.id).
			Scan(&invocation.PermitID, &invocation.ClaimID, &invocation.ExpiresAt); err != nil {
			return err
		}
		target = &observeTarget{tenantID: a.tenantID, workspaceID: a.workspaceID, attemptID: a.id, from: a.state,
			effect: adapters.Effect{EffectType: a.effectType, Target: a.target, Arguments: content, Invocation: invocation}, adapter: adapter}
		return nil
	})
	if err == nil && target != nil {
		s.readBack(ctx, *target)
	}
	return existing, fence, err
}

// observeTarget is an attempt a read-back runs for, in state from.
type observeTarget struct {
	tenantID, workspaceID, attemptID, from string
	effect                                 adapters.Effect
	adapter                                adapters.Adapter
}

// readBack calls the adapter's Observe outside any transaction, then records
// the result if the attempt is still in the state the read-back started from.
func (s *Service) readBack(ctx context.Context, t observeTarget) {
	ctx = context.WithoutCancel(ctx)
	call, cancel := context.WithTimeout(ctx, s.cfg.DispatchTimeout)
	result := t.adapter.Observe(call, s.tokens(t.tenantID, t.effect), t.effect)
	cancel()
	err := s.inTenant(ctx, t.tenantID, func(tx *sql.Tx) error {
		a, err := lockAttempt(ctx, tx, Caller{TenantID: t.tenantID, WorkspaceID: t.workspaceID}, t.attemptID)
		if err != nil {
			return err
		}
		if a.state != t.from {
			return nil // another read-back got there first
		}
		insideFence := !a.dispatchDeadline.Valid || a.now.Before(a.dispatchDeadline.Time)
		return recordObservation(ctx, tx, t, result, insideFence)
	})
	if err != nil {
		slog.ErrorContext(ctx, "recording an observation failed", "attempt_id", t.attemptID, "error", err)
	}
}

// readBackVerdict is what one read-back establishes, pure. established is
// false for an inconclusive read-back, and for a FAILED that rests only on the
// object's absence while the dispatch fence has not passed: the write may
// still be landing at the provider (TA §4.3). consume says whether the held
// exposure is consumed (SUCCEEDED, or a FAILED that found an object
// contradicting the effect, which a write of ours may have made) rather than
// released (a FAILED by absence after the fence: the effect did not happen).
func readBackVerdict(result adapters.ObserveResult, insideFence bool) (established, consume bool) {
	switch {
	case result.Outcome == adapters.OutcomeSucceeded:
		return true, true
	case result.Outcome != adapters.OutcomeFailed:
		return false, false
	case result.Absent && insideFence:
		return false, false
	case result.Absent:
		return true, false
	}
	return true, true
}

// recordObservation writes one read-back. An established outcome settles the
// attempt; an inconclusive one leaves (or makes) it UNKNOWN, except that an
// absence inside the fence leaves a DISPATCHED attempt DISPATCHED.
func recordObservation(ctx context.Context, tx *sql.Tx, t observeTarget, result adapters.ObserveResult, insideFence bool) error {
	established, consume := readBackVerdict(result, insideFence)
	var kind string
	var body []byte
	if established {
		var err error
		if kind, body, err = typedResult(t.effect.EffectType, result.Observation); err != nil {
			slog.ErrorContext(ctx, "an adapter's observation breaks the contract; treated as inconclusive",
				"attempt_id", t.attemptID, "effect_type", t.effect.EffectType, "error", err)
			established = false
		}
	}
	if !established {
		absentInsideFence := result.Absent && result.Outcome == adapters.OutcomeFailed
		if t.from == "DISPATCHED" && !absentInsideFence {
			return transition(ctx, tx, t.tenantID, t.attemptID, "DISPATCHED", "UNKNOWN", result.Reason)
		}
		return nil
	}
	o := result.Observation
	// result_ref is the content address of the typed result, which the row
	// keeps (§5.6): SHA-256 over its RFC 8785 (JCS) form, so it recomputes
	// from the stored or returned JSON. Empty when the effect type defines no
	// result.
	ref := ""
	var resultCol any
	if body != nil {
		sum := sha256.Sum256(body)
		ref, resultCol = "sha256:"+hex.EncodeToString(sum[:]), body
	}
	var evidence any
	if len(o.EvidenceDigest) > 0 {
		evidence = o.EvidenceDigest
	}
	observedAt := o.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_observations
			(tenant_id, attempt_id, source, trust_class, outcome, evidence_digest, observed_at, result_ref, result_kind, result)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		t.tenantID, t.attemptID, o.Source, o.TrustClass, string(result.Outcome), evidence, observedAt, ref, kind, resultCol); err != nil {
		return err
	}
	cause := "observed"
	to := "OBSERVED"
	if t.from == "UNKNOWN" {
		cause, to = "reconciled", "RECONCILED"
	}
	if consume {
		if err := settleHeld(ctx, tx, t.tenantID, t.attemptID, "confirmed", cause); err != nil {
			return err
		}
	} else if err := release(ctx, tx, t.tenantID, t.attemptID, cause); err != nil {
		return err
	}
	if result.Outcome == adapters.OutcomeSucceeded {
		return settleState(ctx, tx, t.tenantID, t.attemptID, t.from, to, adapters.OutcomeSucceeded, "")
	}
	return settleState(ctx, tx, t.tenantID, t.attemptID, t.from, to, adapters.OutcomeFailed, result.Reason)
}

// typedResult checks an established observation against the contract and
// returns its typed result as (result_kind, JSON): exactly the member the
// effect type defines, or none for an effect type that defines none.
func typedResult(effectType string, o *adapters.Observation) (string, []byte, error) {
	if o == nil {
		return "", nil, errors.New("an established outcome carries no observation")
	}
	if n := len(o.EvidenceDigest); n != 0 && n != sha256.Size {
		return "", nil, errors.New("evidence_digest is not a SHA-256 digest")
	}
	if o.Source == "" || o.TrustClass == "" {
		return "", nil, errors.New("the observation names no source or trust class")
	}
	members := map[string]any{}
	if o.GitHubPullRequest != nil {
		members["github_pull_request"] = o.GitHubPullRequest
	}
	if o.GitHubBranch != nil {
		members["github_branch"] = o.GitHubBranch
	}
	if o.GitHubRepository != nil {
		members["github_repository"] = o.GitHubRepository
	}
	want := map[string]string{
		effectargs.GitHubPullRequestCreateDraft:  "github_pull_request",
		effectargs.GitHubBranchCreateFromChanges: "github_branch",
		effectargs.GitHubRepositoryGet:           "github_repository",
	}[effectType]
	switch {
	case want == "" && len(members) == 0:
		return "", nil, nil
	case len(members) != 1 || members[want] == nil:
		return "", nil, errors.New("the typed result is not the one member the effect type defines")
	}
	body, err := canonicalize.JCS(members[want])
	return want, body, err
}

// settleState moves the attempt to OBSERVED or RECONCILED with its outcome.
func settleState(ctx context.Context, tx *sql.Tx, tenantID, attemptID, from, to string, outcome adapters.Outcome, reason contracts.ReasonCode) error {
	basis := "OBSERVED"
	if to == "RECONCILED" {
		basis = "RECONCILED"
	}
	res, err := tx.ExecContext(ctx, `UPDATE authority_effect_attempts
		SET state = $4, outcome = $5, outcome_basis = $6, reason_code = $7, version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND attempt_id = $2 AND state = $3`, tenantID, attemptID, from, to, string(outcome), basis, string(reason))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.New("admission: the attempt changed state while its outcome was recorded")
	}
	return nil
}

// mayExecute: an attempt is dispatched and observed only by the workload it
// was proposed through (coordinator, 2026-09-27): its requester actor (the
// act.sub that carried the Propose, such as the Control Plane runner), or its
// requester principal when that principal is itself the workload.
// requireWorkload has already refused a human caller.
func mayExecute(caller, requester, requesterActor string) bool {
	return caller != "" && (caller == requesterActor || caller == requester)
}

var errNotItsWorkload = refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
	"only the workload the attempt was proposed through dispatches or observes it")

// requireWorkload: helm.gateway.execute is for workload principals only
// (rev 3.4 §4.2), per the gateway's own principal rows, never a human.
func requireWorkload(ctx context.Context, tx *sql.Tx, caller Caller) error {
	var kind, status string
	err := tx.QueryRowContext(ctx, `SELECT kind, status FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2`,
		caller.TenantID, caller.PrincipalID).Scan(&kind, &status)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (kind == string(mandates.PrincipalHuman) || status != "active")) {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
			"Dispatch and Observe are for an active workload principal (agent or service) of the tenant")
	}
	return err
}

// tokens is the TokenSource an adapter asks for one operation's credential.
func (s *Service) tokens(tenantID string, effect adapters.Effect) adapters.TokenSource {
	return tokenSource{creds: s.cfg.Credentials, tenantID: tenantID, effect: effect}
}

type tokenSource struct {
	creds    Credentials
	tenantID string
	effect   adapters.Effect
}

func (t tokenSource) Token(ctx context.Context) (string, error) {
	if t.creds == nil {
		return "", errors.New("the gateway has no provider credentials configured")
	}
	return t.creds.Token(ctx, t.tenantID, t.effect)
}
