package admission

// Model calls (HELM-752, ADR-0003, target architecture §8). A model call is an
// effect attempt of type model.inference that the model gateway proposes,
// claims and settles in one request. This file is the ledger side of that
// path, on the same transactions and rows as every other effect:
//
//   - ModelGrants tells the model gateway what the caller's mandate chain
//     allows for the effect type, so it can price the quote the chain sums and
//     list the routes the caller may use.
//   - ClaimModelCall is the dispatch claim without an adapter: it consumes the
//     permit once, before any provider I/O, and records the call's money row.
//   - SettleModelCall is the one transaction that settles the call's exposure
//     from what the provider reported, moves the attempt, and keeps the
//     response for replay.
//
// The counter arithmetic is ADR-0003's: a hold is lowered only by a settlement
// transition, in the transaction that makes it, and consumption the provider
// reports above the hold is recorded as reported, never clipped.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// UnitUSDMicros is the unit a model call is priced and limited in.
const UnitUSDMicros = "usd_micros"

// The settlement states of a model call, as the proto's SettlementState
// names them without its prefix.
const (
	SettlementHeld            = "HELD"
	SettlementEstimated       = "ESTIMATED"
	SettlementUnresolvedFinal = "UNRESOLVED_FINAL"
	SettlementConfirmed       = "CONFIRMED"
	SettlementReleased        = "RELEASED"
)

// Where the gateway's own observation of a model call comes from.
const (
	modelObservationSource = "gateway.model"
	// modelProviderTrust: the provider's own response, as the gateway read it.
	modelProviderTrust = "provider_response"
)

// maxReplayBytes bounds a stored response: the model gateway stores nothing
// larger, and the ledger refuses it.
const maxReplayBytes = 64 << 20

// ModelCall is the money side of one model call (proto ModelCallSettlement).
type ModelCall struct {
	Route        string
	API          string
	State        string
	CurrencyCode string
	HeldMicros   int64
	// EstimatedMicros is set from ESTIMATED on, ConfirmedMicros from CONFIRMED
	// on. ConfirmedMicros above HeldMicros is an overage: recorded as the
	// provider reported it.
	EstimatedMicros *int64
	ConfirmedMicros *int64
	BillableMicros  int64
	// Usage is the provider-reported usage as the response carried it.
	Usage json.RawMessage
}

// Grants is what a principal's mandates allow for one effect type, read so that
// the model gateway can name the mandate that covers a route, price a quote the
// chain will accept and list the routes the caller may use. It grants nothing:
// admission decides every call again from the locked rows (R3).
type Grants struct {
	PrincipalKind   string
	PrincipalActive bool
	// Leaves are the principal's active mandates that name the effect type, by
	// depth then id: the order Propose picks one in when a request names none.
	Leaves []LeafGrant
	// SumUnits are the units of the sum limits that apply to any of the chains
	// and to the tenant: a quote must carry an amount for each.
	SumUnits []string
}

// LeafGrant is one mandate of the principal and what its whole chain allows.
type LeafGrant struct {
	MandateID string
	// Active is true when every mandate of the chain is active and within its
	// validity now.
	Active bool
	// AnyTarget is true when no link of the chain restricts targets; otherwise
	// Targets is the intersection of the links' target lists.
	AnyTarget bool
	Targets   []string
}

// MandateFor returns the first mandate whose chain lets the principal act on
// target. A principal with several mandates over an effect type (one per grant
// group) needs the request to select the one that covers the target.
func (g Grants) MandateFor(target string) (string, bool) {
	if !g.PrincipalActive {
		return "", false
	}
	for _, l := range g.Leaves {
		if l.Active && (l.AnyTarget || slices.Contains(l.Targets, target)) {
			return l.MandateID, true
		}
	}
	return "", false
}

// Allows reports whether some mandate of the principal covers target.
func (g Grants) Allows(target string) bool {
	_, ok := g.MandateFor(target)
	return ok
}

// maxLeafGrants bounds the mandates a grants read follows.
const maxLeafGrants = 32

// ModelGrants reads the caller's grants for effectType in one transaction.
func (s *Service) ModelGrants(ctx context.Context, caller Caller, effectType string) (Grants, error) {
	if err := checkCaller(caller); err != nil {
		return Grants{}, err
	}
	var g Grants
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT kind, status FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2`,
			caller.TenantID, caller.PrincipalID).Scan(&g.PrincipalKind, &status)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		g.PrincipalActive = status == "active"
		rows, err := tx.QueryContext(ctx, `SELECT mandate_id::text FROM authority_mandates
			WHERE tenant_id = $1 AND holder_id = $2 AND status = 'active' AND $3 = ANY (effect_types)
			ORDER BY depth, mandate_id LIMIT $4`, caller.TenantID, caller.PrincipalID, effectType, maxLeafGrants)
		if err != nil {
			return err
		}
		var leaves []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			leaves = append(leaves, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		var now time.Time
		if err := tx.QueryRowContext(ctx, `SELECT now()`).Scan(&now); err != nil {
			return err
		}
		var chainIDs []string
		for _, leaf := range leaves {
			chain, err := mandates.ChainInTx(ctx, tx, caller.TenantID, leaf, false)
			if err != nil {
				return err
			}
			grant := LeafGrant{MandateID: leaf.String(), Active: true, AnyTarget: true}
			for _, m := range chain {
				chainIDs = append(chainIDs, m.ID.String())
				if !m.Active || now.Before(m.Terms.ValidFrom) || !now.Before(m.Terms.ValidUntil) {
					grant.Active = false
				}
				if m.Terms.Targets == nil {
					continue
				}
				if grant.AnyTarget {
					grant.AnyTarget, grant.Targets = false, slices.Clone(m.Terms.Targets)
					continue
				}
				grant.Targets = slices.DeleteFunc(grant.Targets, func(t string) bool { return !slices.Contains(m.Terms.Targets, t) })
			}
			if !grant.AnyTarget {
				sort.Strings(grant.Targets)
				grant.Targets = slices.Compact(grant.Targets)
				if grant.Targets == nil {
					grant.Targets = []string{}
				}
			}
			g.Leaves = append(g.Leaves, grant)
		}
		units, err := tx.QueryContext(ctx, `SELECT DISTINCT unit FROM authority_limits
			WHERE tenant_id = $1 AND measure = 'sum' AND (mandate_id = ANY ($2::uuid[]) OR mandate_id IS NULL) ORDER BY unit`,
			caller.TenantID, pq.Array(chainIDs))
		if err != nil {
			return err
		}
		defer func() { _ = units.Close() }()
		for units.Next() {
			var unit string
			if err := units.Scan(&unit); err != nil {
				return err
			}
			g.SumUnits = append(g.SumUnits, unit)
		}
		return units.Err()
	})
	return g, err
}

// ModelCallClaim is a committed dispatch claim on a model call: the permit is
// consumed, the attempt is DISPATCHING inside its fence, and the call's money
// row is HELD. It is what SettleModelCall settles.
type ModelCallClaim struct {
	TenantID, WorkspaceID, AttemptID string
	PermitID, ClaimID                string
	// Route and API are what the attempt's admitted arguments name.
	Route, API string
	// HeldMicros is the admitted quote in usd_micros.
	HeldMicros int64
}

// ClaimModelCall claims the permit of an ADMITTED model.inference attempt for
// the workload that proposed it, exactly as Dispatch does and without an
// adapter: one transaction, before any provider I/O, that re-reads the
// authority rows and stops and refuses a stale permit (ADR-0001 §1 "Dispatch
// claim"). fence is how long the call may run before the gateway treats it as
// lost and reconciles it. The claim is nil when the attempt cannot be claimed:
// a refused claim leaves it CANCELLED with the reason, and an attempt that is
// not ADMITTED (already claimed by a concurrent request, or decided otherwise)
// is unchanged. Either way the attempt is returned as stored.
func (s *Service) ClaimModelCall(ctx context.Context, caller Caller, attemptID string, fence time.Duration) (*ModelCallClaim, Attempt, error) {
	if err := checkCaller(caller); err != nil {
		return nil, Attempt{}, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return nil, Attempt{}, err
	}
	if fence <= 0 {
		return nil, Attempt{}, errors.New("admission: a model call needs a positive fence")
	}
	var claim *ModelCallClaim
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := requireWorkload(ctx, tx, caller); err != nil {
			return err
		}
		a, err := lockAttempt(ctx, tx, caller, attemptID)
		if err != nil {
			return err
		}
		if a.effectType != effectargs.ModelInference {
			return refuse(CodeFailedPrecondition, "", "%s is not a model call", a.effectType)
		}
		if !mayExecute(caller.PrincipalID, a.requester, a.requesterActor) {
			return errNotItsWorkload
		}
		if a.state != "ADMITTED" {
			return nil
		}
		a.fence = fence
		c, err := s.claim(ctx, tx, a, caller)
		if err != nil || c == nil {
			return err
		}
		var args effectargs.ModelInferenceArgs
		if err := json.Unmarshal(c.effect.Arguments, &args); err != nil || args.Route == nil || args.API == nil {
			return errors.New("admission: an admitted model call carries no route")
		}
		var held int64
		for _, q := range a.quote {
			if q.Unit == UnitUSDMicros {
				held = q.Amount
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_model_calls (tenant_id, attempt_id, route, api, state, held_micros)
			VALUES ($1, $2, $3, $4, $5, $6)`, a.tenantID, a.id, *args.Route, *args.API, SettlementHeld, held); err != nil {
			return err
		}
		claim = &ModelCallClaim{TenantID: a.tenantID, WorkspaceID: a.workspaceID, AttemptID: a.id,
			PermitID: c.effect.Invocation.PermitID, ClaimID: c.claimID.String(), Route: *args.Route, API: *args.API, HeldMicros: held}
		return nil
	})
	if err != nil {
		return nil, Attempt{}, err
	}
	attempt, err := s.Get(ctx, caller, attemptID)
	return claim, attempt, err
}

// ModelCallResult is what became of a claimed model call.
type ModelCallResult int

const (
	// ModelCallConfirmed: the response completed and the provider reported
	// its usage. The attempt is OBSERVED(SUCCEEDED) and SETTLED: the reported
	// amount is consumed and the remainder of the hold released.
	ModelCallConfirmed ModelCallResult = iota + 1
	// ModelCallEstimated: the response completed and was delivered, but it
	// carried no usage. The attempt is OBSERVED(SUCCEEDED); the hold counts
	// as estimated and nothing is released (ADR-0003 "ESTIMATED").
	ModelCallEstimated
	// ModelCallCut: the response did not complete (the client left, or the
	// provider or the network dropped it), so whether and what the provider
	// generated is not known. The attempt is UNKNOWN with the hold counted as
	// estimated, and it is never dispatched again.
	ModelCallCut
	// ModelCallNotSent: the provider refused the request before generating
	// anything. The attempt is OBSERVED(FAILED) and the hold is released.
	ModelCallNotSent
)

// ModelCallOutcome is the settlement of one claimed call.
type ModelCallOutcome struct {
	Result ModelCallResult
	// Reason is why a NotSent call failed, or why a Cut one is unknown.
	Reason contracts.ReasonCode
	// ConfirmedMicros is the consumption the provider reported, priced by the
	// route, for a Confirmed call.
	ConfirmedMicros int64
	// Usage is the provider-reported usage as it appeared in the response.
	Usage json.RawMessage
	// EvidenceDigest is SHA-256 over the response bytes as delivered.
	EvidenceDigest []byte
	// Replay is the delivered response to keep for replay, when the call
	// completed and the response is small enough to keep.
	Replay *ModelCallReplay
}

// ModelCallReplay is a delivered response, kept so that the same request
// replays it without a second provider call.
type ModelCallReplay struct {
	StatusCode int
	// Headers are the response headers delivered with it.
	Headers    map[string]string
	Body       []byte
	BodySHA256 []byte
	// TTL is how long the body is kept, on store; ExpiresAt is when it stops
	// being replayed, on read.
	TTL       time.Duration
	ExpiresAt time.Time
}

func (o ModelCallOutcome) validate() error {
	switch o.Result {
	case ModelCallConfirmed:
		if o.ConfirmedMicros < 0 {
			return errors.New("admission: a confirmed model call cannot consume a negative amount")
		}
	case ModelCallEstimated, ModelCallCut:
	case ModelCallNotSent:
		if o.Reason == "" {
			return errors.New("admission: a model call that was not sent needs a reason")
		}
	default:
		return errors.New("admission: unknown model call result")
	}
	if n := len(o.EvidenceDigest); n != 0 && n != 32 {
		return errors.New("admission: the evidence digest is not a SHA-256 digest")
	}
	if r := o.Replay; r != nil {
		switch {
		case o.Result != ModelCallConfirmed && o.Result != ModelCallEstimated:
			return errors.New("admission: only a completed model call keeps a response")
		case r.StatusCode < 200 || r.StatusCode > 299 || len(r.BodySHA256) != 32 || len(r.Body) > maxReplayBytes || r.TTL <= 0:
			return errors.New("admission: the stored response is not a bounded success with a digest and a lifetime")
		}
	}
	return nil
}

// SettleModelCall settles a claimed call in one transaction (ADR-0003): it
// locks the attempt row and then the call's money row, moves the attempt's
// held exposure as the outcome says, records the observation and, for a
// completed call, the response to replay. It is idempotent: a call that is
// no longer HELD, or an attempt that has moved on, is returned unchanged.
// A confirmation is accepted while the attempt is UNKNOWN, so a response that
// completes after the fence made it unknown reconciles it. It returns the
// attempt as settled.
func (s *Service) SettleModelCall(ctx context.Context, c *ModelCallClaim, out ModelCallOutcome) (Attempt, error) {
	if c == nil {
		return Attempt{}, errors.New("admission: no model call claim to settle")
	}
	if err := out.validate(); err != nil {
		return Attempt{}, err
	}
	scope := Caller{TenantID: c.TenantID, WorkspaceID: c.WorkspaceID}
	var settled Attempt
	err := s.inTenant(ctx, c.TenantID, func(tx *sql.Tx) error {
		a, err := lockAttempt(ctx, tx, scope, c.AttemptID)
		if err != nil {
			return err
		}
		var claim uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT claim_id FROM authority_permits WHERE tenant_id = $1 AND attempt_id = $2`,
			c.TenantID, c.AttemptID).Scan(&claim); err != nil {
			return err
		}
		if !claim.Valid || claim.UUID.String() != c.ClaimID {
			return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "the settlement is not of the claim that dispatched the call")
		}
		var state string
		var held int64
		err = tx.QueryRowContext(ctx, `SELECT state, held_micros FROM authority_model_calls
			WHERE tenant_id = $1 AND attempt_id = $2 FOR UPDATE`, c.TenantID, c.AttemptID).Scan(&state, &held)
		if err != nil {
			return err
		}
		if state != SettlementHeld || (a.state != "DISPATCHING" && a.state != "DISPATCHED" && a.state != "UNKNOWN") {
			settled, err = loadAttempt(ctx, tx, scope, c.AttemptID)
			return err
		}
		if err := s.settleModelCallTx(ctx, tx, a, held, out); err != nil {
			return err
		}
		settled, err = loadAttempt(ctx, tx, scope, c.AttemptID)
		return err
	})
	return settled, err
}

func (s *Service) settleModelCallTx(ctx context.Context, tx *sql.Tx, a lockedAttempt, held int64, out ModelCallOutcome) error {
	tenantID, attemptID := a.tenantID, a.id
	// A response that completes while the attempt is UNKNOWN reconciles it.
	observedState := "OBSERVED"
	if a.state == "UNKNOWN" {
		observedState = "RECONCILED"
	}
	usage := any(nil)
	if len(out.Usage) > 0 {
		usage = []byte(out.Usage)
	}
	var evidence any
	if len(out.EvidenceDigest) > 0 {
		evidence = out.EvidenceDigest
	}
	observe := func(outcome adapters.Outcome, trust string) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO authority_observations (tenant_id, attempt_id, source, trust_class, outcome, evidence_digest)
			VALUES ($1, $2, $3, $4, $5, $6)`, tenantID, attemptID, modelObservationSource, trust, string(outcome), evidence)
		return err
	}
	setCall := func(state string, estimated, confirmed *int64, billable int64) error {
		_, err := tx.ExecContext(ctx, `UPDATE authority_model_calls
			SET state = $3, estimated_micros = $4, confirmed_micros = $5, billable_micros = $6, usage = $7,
			    version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND attempt_id = $2`, tenantID, attemptID, state, nullInt(estimated), nullInt(confirmed), billable, usage)
		return err
	}

	switch out.Result {
	case ModelCallConfirmed:
		// Consumption above the hold stays on the counter as reported: the
		// settled call's confirmed amount against its held one is the record.
		if err := rebookHeld(ctx, tx, tenantID, attemptID, "confirmed", out.ConfirmedMicros, "model-confirmed"); err != nil {
			return err
		}
		confirmed := out.ConfirmedMicros
		if err := setCall(SettlementConfirmed, nil, &confirmed, min(confirmed, held)); err != nil {
			return err
		}
		if err := observe(adapters.OutcomeSucceeded, modelProviderTrust); err != nil {
			return err
		}
		if err := settleState(ctx, tx, tenantID, attemptID, a.state, observedState, adapters.OutcomeSucceeded, ""); err != nil {
			return err
		}
		if err := transition(ctx, tx, tenantID, attemptID, observedState, "SETTLED", ""); err != nil {
			return err
		}
	case ModelCallEstimated:
		if err := rebookHeld(ctx, tx, tenantID, attemptID, "estimated", 0, "model-estimated"); err != nil {
			return err
		}
		if err := setCall(SettlementEstimated, &held, nil, 0); err != nil {
			return err
		}
		if err := observe(adapters.OutcomeSucceeded, modelProviderTrust); err != nil {
			return err
		}
		if err := settleState(ctx, tx, tenantID, attemptID, a.state, observedState, adapters.OutcomeSucceeded, ""); err != nil {
			return err
		}
	case ModelCallCut:
		if err := rebookHeld(ctx, tx, tenantID, attemptID, "estimated", 0, "model-cut"); err != nil {
			return err
		}
		if err := setCall(SettlementEstimated, &held, nil, 0); err != nil {
			return err
		}
		if a.state != "UNKNOWN" {
			if err := transition(ctx, tx, tenantID, attemptID, a.state, "UNKNOWN", out.Reason); err != nil {
				return err
			}
		}
	case ModelCallNotSent:
		if err := release(ctx, tx, tenantID, attemptID, "model-not-sent"); err != nil {
			return err
		}
		if err := setCall(SettlementReleased, nil, nil, 0); err != nil {
			return err
		}
		if err := observe(adapters.OutcomeFailed, "adapter_refusal"); err != nil {
			return err
		}
		if err := settleState(ctx, tx, tenantID, attemptID, a.state, observedState, adapters.OutcomeFailed, out.Reason); err != nil {
			return err
		}
	}
	if r := out.Replay; r != nil {
		headers, err := json.Marshal(r.Headers)
		if err != nil {
			return err
		}
		if r.Headers == nil {
			headers = []byte(`{}`)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_model_replays
				(tenant_id, attempt_id, status_code, headers, body, body_sha256, body_bytes, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now() + $8 * interval '1 second')
			ON CONFLICT DO NOTHING`,
			tenantID, attemptID, r.StatusCode, headers, r.Body, r.BodySHA256, len(r.Body), int64(r.TTL/time.Second)); err != nil {
			return err
		}
	}
	// Expired responses are cleared as calls settle: the body goes, the row
	// and its digest stay. Bounded, so no settlement pays for a backlog.
	_, err := tx.ExecContext(ctx, `UPDATE authority_model_replays SET body = NULL, purged_at = now()
		WHERE (tenant_id, attempt_id) IN (
			SELECT tenant_id, attempt_id FROM authority_model_replays
			WHERE tenant_id = $1 AND body IS NOT NULL AND expires_at < now() LIMIT 100)`, tenantID)
	return err
}

func nullInt(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// rebookHeld moves every held exposure of the attempt to kind (confirmed,
// estimated or released) in the transaction that settles it.
//
//   - confirmed: a usd_micros sum exposure takes micros, whatever it held, even
//     above it (an overage stays on the counter as reported); any other
//     exposure (a count, another unit's zero quote) is confirmed as held.
//   - estimated: every exposure keeps its held amount and moves from reserved
//     to used.
//   - released: every exposure gives its amount back.
//
// Each move is a reversing held posting and, unless released, a posting of the
// new kind; the counter moves the held amount out of reserved and the new
// amount into used. Rows are taken in (limit_id, bucket_start) order, the
// order admission locks its counters in.
func rebookHeld(ctx context.Context, tx *sql.Tx, tenantID, attemptID, kind string, micros int64, cause string) error {
	rows, err := tx.QueryContext(ctx, `SELECT e.limit_id::text, e.bucket_start, e.amount, l.unit, l.measure
		FROM authority_exposures e
		JOIN authority_limits l ON l.tenant_id = e.tenant_id AND l.limit_id = e.limit_id
		WHERE e.tenant_id = $1 AND e.attempt_id = $2 AND e.kind = 'held'
		ORDER BY e.limit_id, e.bucket_start FOR UPDATE OF e`, tenantID, attemptID)
	if err != nil {
		return err
	}
	type exposure struct {
		limitID       string
		start         time.Time
		amount        int64
		unit, measure string
	}
	var held []exposure
	for rows.Next() {
		var e exposure
		if err := rows.Scan(&e.limitID, &e.start, &e.amount, &e.unit, &e.measure); err != nil {
			_ = rows.Close()
			return err
		}
		held = append(held, e)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, e := range held {
		amount := e.amount
		switch kind {
		case "released":
			amount = 0
		case "confirmed":
			if e.unit == UnitUSDMicros && e.measure == "sum" {
				amount = micros
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authority_counters SET reserved = reserved - $4, used = used + $5
			WHERE tenant_id = $1 AND limit_id = $2 AND bucket_start = $3`, tenantID, e.limitID, e.start, e.amount, amount); err != nil {
			return err
		}
		if e.amount != 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO authority_postings (tenant_id, attempt_id, limit_id, bucket_start, kind, amount, cause)
				VALUES ($1, $2, $3, $4, 'held', $5, $6)`, tenantID, attemptID, e.limitID, e.start, -e.amount, "reverse:"+cause); err != nil {
				return err
			}
		}
		if kind != "released" && amount != 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO authority_postings (tenant_id, attempt_id, limit_id, bucket_start, kind, amount, cause)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`, tenantID, attemptID, e.limitID, e.start, kind, amount, cause); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authority_exposures SET kind = $5, amount = $6
			WHERE tenant_id = $1 AND attempt_id = $2 AND limit_id = $3 AND bucket_start = $4`,
			tenantID, attemptID, e.limitID, e.start, kind, amount); err != nil {
			return err
		}
	}
	return nil
}

// ModelCallReplay returns the response a settled call kept, for the caller's
// tenant and workspace: nil when there is none, when it was too large to keep
// or when it has expired. A caller with an episode claim is held to its own
// episode's calls, like every other read of an attempt.
func (s *Service) ModelCallReplay(ctx context.Context, caller Caller, attemptID string) (*ModelCallReplay, error) {
	if err := checkCaller(caller); err != nil {
		return nil, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return nil, err
	}
	var replay *ModelCallReplay
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var r ModelCallReplay
		var headers []byte
		var live bool
		err := tx.QueryRowContext(ctx, `SELECT r.status_code, r.headers, r.body, r.body_sha256, r.expires_at, r.expires_at > now()
			FROM authority_model_replays r
			JOIN authority_effect_attempts a ON a.tenant_id = r.tenant_id AND a.attempt_id = r.attempt_id
			WHERE r.tenant_id = $1 AND r.attempt_id = $2 AND a.workspace_id = $3 AND r.body IS NOT NULL
				AND ($4 = '' OR (a.episode_id = $4 AND a.requester_principal_id = $5))`,
			caller.TenantID, attemptID, caller.WorkspaceID, episodeScope(caller), caller.PrincipalID).Scan(&r.StatusCode, &headers, &r.Body, &r.BodySHA256, &r.ExpiresAt, &live)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !live) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(headers, &r.Headers); err != nil {
			return fmt.Errorf("stored replay headers: %w", err)
		}
		r.ExpiresAt = r.ExpiresAt.UTC()
		replay = &r
		return nil
	})
	return replay, err
}

// loadModelCall reads the money row of a model call, nil when the attempt has
// none yet (it was never claimed).
func loadModelCall(ctx context.Context, tx *sql.Tx, tenantID, attemptID string) (*ModelCall, error) {
	var m ModelCall
	var estimated, confirmed sql.NullInt64
	var usage []byte
	err := tx.QueryRowContext(ctx, `SELECT route, api, state, currency_code, held_micros, estimated_micros, confirmed_micros, billable_micros, usage
		FROM authority_model_calls WHERE tenant_id = $1 AND attempt_id = $2`, tenantID, attemptID).
		Scan(&m.Route, &m.API, &m.State, &m.CurrencyCode, &m.HeldMicros, &estimated, &confirmed, &m.BillableMicros, &usage)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if estimated.Valid {
		m.EstimatedMicros = &estimated.Int64
	}
	if confirmed.Valid {
		m.ConfirmedMicros = &confirmed.Int64
	}
	m.Usage = usage
	return &m, nil
}
