// Package admission is the effect gateway's admission transaction (HELM-751
// s2, ADR-0001 §1): Propose, and the reads of attempts and their content.
// dispatch.go adds the dispatch claim, Dispatch and Observe (s3).
//
// Propose is one PostgreSQL transaction at READ COMMITTED, bound to the
// token's tenant through app.current_tenant under forced row security:
//
//  1. idempotency first: the attempt is inserted with ON CONFLICT DO NOTHING
//     on (tenant, idempotency key); the same key with the same request digest
//     returns the stored attempt untouched, a different digest is a conflict;
//  2. the mandate is resolved from the token's principal, the effect type and
//     the target (HELM-750 s2b; a mandate_id in the request only selects). The
//     gateway's own authority plans (helm.authority.provision.v1 and narrow.v1)
//     have none: authority for a plan is the approval of its exact bytes;
//  3. authority rows are locked FOR SHARE in the global order: the tenant
//     control row, the principals of the chain (requester, holders,
//     delegators) by id, the mandates root to leaf, the effect-type row, the
//     limits by id;
//  4. stops are read in a statement after those locks;
//  5. counters are created on demand and locked FOR UPDATE in
//     (limit_id, bucket_start) order;
//  6. Decide runs (pure), and the transaction records ADMITTED with a
//     conditional hold and a permit, DENIED, or ESCALATED with approval digest
//     v1.
//
// The package imports no legacy kernel runtime (guardian, proxy, mcp,
// executor); boundary_test.go holds that, so it can move to its own repo.
package admission

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// Code classifies an error the way the wire contract does.
type Code int

const (
	CodeInvalidArgument Code = iota + 1
	CodePermissionDenied
	CodeNotFound
	CodeAlreadyExists
	CodeFailedPrecondition
)

// Error is a refusal the caller can act on. Anything else is a transient
// failure of the gateway.
type Error struct {
	Code    Code
	Reason  contracts.ReasonCode
	Message string
}

func (e *Error) Error() string { return e.Message }

func refuse(code Code, reason contracts.ReasonCode, format string, args ...any) *Error {
	return &Error{Code: code, Reason: reason, Message: fmt.Sprintf(format, args...)}
}

var errNotFound = refuse(CodeNotFound, "", "no such attempt")

// Caller is the identity a verified token carries (R9, ADR-0005). Nothing in
// a request body sets it.
type Caller struct {
	TenantID    string
	WorkspaceID string
	PrincipalID string
	// ActorID is the token's act.sub: the workload that carries a
	// principal's call. Empty for a direct call.
	ActorID string
	// Episode is the token's helm_episode claim, verified: the bounded worker
	// run the token was minted for. Nil for every other token. It is the only
	// source of an attempt's episode: Propose records it, and a caller that has
	// one proposes under its work item and reads only its own episode's
	// attempts.
	Episode *Episode
}

// Episode is a worker token's helm_episode claim (jwks.EpisodeClaim), and what
// an attempt records of it. The work item is the attempt's case_id.
type Episode struct {
	EpisodeID  string
	WorkItemID string
	// OrganizationVersionID is empty when the token names none.
	OrganizationVersionID string
}

// ProposeInput is a ProposeRequest.
type ProposeInput struct {
	IdempotencyKey    string
	MandateID         string
	CommitmentID      string
	CaseID            string
	EffectType        string
	Target            string
	Arguments         []byte
	Quote             []Amount
	Distinct          []DistinctValue
	ApprovalExpiresAt *time.Time
	// Set only by ProposeWorkEffect after validating and canonicalizing the
	// intent. It is not a caller-supplied transport field or read privilege.
	workEffect bool
}

// MaxTransaction is the longest a gateway database transaction may run. Every
// transaction runs under a context this long, so the driver cancels whatever
// it is waiting for and rolls it back. ListAttempts relies on it: an attempt's
// updated_at is the time its transaction began, so a listing is final for the
// times before its settled_before, which lies further back than this.
const MaxTransaction = 2 * time.Minute

// Config tunes admission. Zero values take the defaults.
type Config struct {
	// PermitTTL is how long an issued permit stays claimable. Default 10m.
	PermitTTL time.Duration
	// ApprovalWindow bounds how long an escalation stays pending; a
	// requested approval_expires_at is clamped to it. Default 24h.
	ApprovalWindow time.Duration
	// DispatchTimeout bounds one adapter Dispatch or Observe. The dispatch
	// fence (dispatch_deadline) is the claim time plus this plus a minute.
	// Default 2m.
	DispatchTimeout time.Duration
	// DispatchGrace is added to DispatchTimeout for the fence: a provider can
	// still apply a write shortly after the gateway stopped waiting for it.
	// Default 1m.
	DispatchGrace time.Duration
	// Adapters perform the effect types they declare (§9.1). An effect type
	// no adapter declares is not dispatched.
	Adapters []adapters.Adapter
	// Credentials is the connection custody the adapters take provider
	// credentials from (R8). Nil: every dispatch is NOT_SENT for want of one.
	Credentials Credentials
	// Jobs enqueues the escalation-expiry and reconciliation jobs in the
	// transaction that makes them due (TA §6.2). helm-gateway serve always
	// sets it; nil enqueues nothing, for tests of admission alone.
	Jobs Enqueuer
	// MaxTransaction bounds every database transaction the service runs (a
	// provider call is never inside one). Default the package's MaxTransaction,
	// 2m; a test may set a shorter one.
	MaxTransaction time.Duration
}

// Service runs admission over one database. It holds no tenant data: the
// only state it keeps is compiled mandate conditions, keyed by the digest of
// their text.
type Service struct {
	db            *sql.DB
	cfg           Config
	adapters      map[string]adapters.Adapter
	resultSchemas map[string]*adapters.ResultSchema

	conditions sync.Map // [32]byte -> *authority.Snapshot
}

// New returns a Service over db, whose schema Migrate has created.
func New(db *sql.DB, cfg Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("admission requires a database")
	}
	if cfg.PermitTTL <= 0 {
		cfg.PermitTTL = 10 * time.Minute
	}
	if cfg.ApprovalWindow <= 0 {
		cfg.ApprovalWindow = 24 * time.Hour
	}
	if cfg.DispatchTimeout <= 0 {
		cfg.DispatchTimeout = 2 * time.Minute
	}
	if cfg.DispatchGrace <= 0 {
		cfg.DispatchGrace = time.Minute
	}
	if cfg.MaxTransaction <= 0 {
		cfg.MaxTransaction = MaxTransaction
	}
	byType := map[string]adapters.Adapter{}
	resultSchemas := map[string]*adapters.ResultSchema{}
	for _, a := range cfg.Adapters {
		for _, d := range a.Declarations() {
			if _, dup := byType[d.EffectType]; dup {
				return nil, fmt.Errorf("two adapters declare %s", d.EffectType)
			}
			byType[d.EffectType] = a
			resultSchema, err := adapters.CompileResultSchema(d)
			if err != nil {
				return nil, fmt.Errorf("%s result contract: %w", d.EffectType, err)
			}
			if resultSchema != nil && fixedResultKind(d.EffectType) != "" {
				return nil, fmt.Errorf("%s already has a fixed result contract", d.EffectType)
			}
			resultSchemas[d.EffectType] = resultSchema
		}
	}
	return &Service{db: db, cfg: cfg, adapters: byType, resultSchemas: resultSchemas}, nil
}

// inTenant runs fn in one READ COMMITTED transaction bound to tenantID, and
// aborts it at Config.MaxTransaction.
func (s *Service) inTenant(ctx context.Context, tenantID string, fn func(*sql.Tx) error) error {
	return s.inTenantWith(ctx, tenantID, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, fn)
}

// inTenantWith is inTenant with the transaction's options: a read of several
// statements that must agree runs REPEATABLE READ and READ ONLY, so all of them
// see one snapshot. It is the one place a gateway transaction begins, and the
// context it begins under ends at Config.MaxTransaction: the driver watches it
// for the life of the transaction, cancels the statement in flight and rolls
// back, whichever context fn's own statements were given.
func (s *Service) inTenantWith(ctx context.Context, tenantID string, opts *sql.TxOptions, fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.MaxTransaction)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, opts)
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

// Propose admits one effect. It returns the attempt as created or as stored,
// and whether the idempotency key already named this request.
func (s *Service) Propose(ctx context.Context, caller Caller, in ProposeInput) (Attempt, bool, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, false, err
	}
	if in.EffectType == effectargs.AuthorityLift {
		return Attempt{}, false, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"helm.authority.lift is proposed through Lift, which binds the operator's stop token to the stop")
	}
	in, err := bindEpisode(caller.Episode, in)
	if err != nil {
		return Attempt{}, false, err
	}
	args, err := validateProposal(in)
	if err != nil {
		return Attempt{}, false, err
	}
	var attemptID string
	var existing bool
	err = s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if in.workEffect {
			var activeAgent bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_principals
				WHERE tenant_id = $1 AND principal_id = $2 AND kind = 'agent' AND status = 'active')`,
				caller.TenantID, caller.PrincipalID).Scan(&activeAgent); err != nil {
				return err
			}
			if !activeAgent {
				return refuse(CodePermissionDenied, contracts.ReasonPrincipalInactive, "a work effect requires an active agent principal")
			}
		}
		var err error
		attemptID, existing, err = s.proposeTx(ctx, tx, caller, in, args)
		return err
	})
	if err != nil {
		return Attempt{}, false, err
	}
	if in.workEffect {
		// Only replay of this exact verified work intent may recover a result
		// from an earlier episode. Get/GetContent/List remain episode-scoped.
		var attempt Attempt
		err = s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
			var err error
			attempt, err = loadAttemptScoped(ctx, tx, caller, attemptID, caller.Episode.WorkItemID, workEffectDigest(caller, in))
			return err
		})
		return attempt, existing, err
	}
	attempt, err := s.Get(ctx, caller, attemptID)
	return attempt, existing, err
}

// proposeTx is Propose's transaction body, in tx: the attempt ID, and whether
// the idempotency key already named this request.
func (s *Service) proposeTx(ctx context.Context, tx *sql.Tx, caller Caller, in ProposeInput, args map[string]any) (string, bool, error) {
	digest := requestDigest(caller, in)
	var attemptID string
	var provisioned bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_tenants WHERE tenant_id = $1)`,
		caller.TenantID).Scan(&provisioned); err != nil {
		return "", false, err
	}
	if !provisioned {
		return "", false, refuse(CodePermissionDenied, contracts.ReasonTenantIsolation, "the token's tenant has no authority rows in this gateway")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", false, err
	}
	argumentDigest := sha256.Sum256(in.Arguments)
	targetDigest := sha256.Sum256([]byte(in.Target))
	quote, err := json.Marshal(nonNil(in.Quote))
	if err != nil {
		return "", false, err
	}
	distinct, err := json.Marshal(distinctJSON(in.Distinct))
	if err != nil {
		return "", false, err
	}
	// The episode is the verified claim's and nothing else's: the attempt row
	// records it with itself, and nothing ever changes it.
	var episodeID, organizationVersionID string
	if e := caller.Episode; e != nil {
		episodeID, organizationVersionID = e.EpisodeID, e.OrganizationVersionID
	}
	// 1. Idempotency first. A duplicate never locks or changes anything.
	err = tx.QueryRowContext(ctx, `INSERT INTO authority_effect_attempts
			(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
			 requester_actor_id, commitment_id, case_id, effect_type, target, target_digest, argument_digest, quote,
			 distinct_values, episode_id, organization_version_id, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10, $11, $12, $13, $14, $15,
			NULLIF($16, ''), NULLIF($17, ''), 'PROPOSED')
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
		RETURNING attempt_id`,
		caller.TenantID, id, caller.WorkspaceID, in.IdempotencyKey, digest, caller.PrincipalID, caller.ActorID,
		in.CommitmentID, in.CaseID, in.EffectType, in.Target, targetDigest[:], argumentDigest[:], quote, distinct,
		episodeID, organizationVersionID).Scan(&attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		var stored []byte
		if err := tx.QueryRowContext(ctx, `SELECT attempt_id, request_digest FROM authority_effect_attempts
			WHERE tenant_id = $1 AND idempotency_key = $2`, caller.TenantID, in.IdempotencyKey).Scan(&attemptID, &stored); err != nil {
			return "", false, err
		}
		if string(stored) != string(digest) {
			return "", false, refuse(CodeAlreadyExists, contracts.ReasonIdempotencyConflict,
				"the idempotency key was used with a different request")
		}
		return attemptID, true, nil
	}
	if err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_attempt_contents (tenant_id, attempt_id, arguments) VALUES ($1, $2, $3)`,
		caller.TenantID, attemptID, in.Arguments); err != nil {
		return "", false, err
	}
	if in.EffectType == effectargs.GitHubPullRequestCreateDraft {
		if err := checkBranchAttempt(ctx, tx, caller, in); err != nil {
			return "", false, err
		}
	}
	return attemptID, false, s.admit(ctx, tx, caller, in, args, attemptID, argumentDigest[:], targetDigest[:], nil, "PROPOSED")
}

// lockedAuthority is what step 3 locked, with the versions a permit records.
type lockedAuthority struct {
	versions        []AuthorityVersion
	principalFound  bool
	principalActive bool
	principalKind   string
	chain           []mandates.Mandate
	effectTypeFound bool
	riskClass       mandates.RiskClass
	limits          []limitRow
}

type limitRow struct {
	id, unit, measure, window string
	value                     int64
	span                      int
	current                   time.Time
	buckets                   []time.Time
}

// admit runs steps 2 to 6 for an attempt in state from: one the caller just
// inserted (PROPOSED), or an ESCALATED one Approve re-admits with its
// approval (ADR-0001 §1 "Approval", §5.5).
func (s *Service) admit(ctx context.Context, tx *sql.Tx, caller Caller, in ProposeInput, args map[string]any,
	attemptID string, argumentDigest, targetDigest []byte, approval *ApprovalState, from string) error {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT now()`).Scan(&now); err != nil {
		return err
	}
	now = now.UTC()

	// 2. Resolve the mandate from the principal, the effect type and the
	// target. The read is unlocked; the chain is locked below in the global
	// order. A plan effect has none.
	plan := effectargs.IsAuthorityPlan(in.EffectType)
	var leaf uuid.UUID
	var chain []mandates.Mandate
	if !plan {
		var err error
		if leaf, err = resolveMandate(ctx, tx, caller, in); err != nil {
			return err
		}
		if leaf != uuid.Nil {
			if chain, err = mandates.ChainInTx(ctx, tx, caller.TenantID, leaf, false); err != nil {
				return err
			}
		}
	}

	// 3. Authority rows, FOR SHARE, in the global order.
	auth, err := lockAuthority(ctx, tx, caller, in.EffectType, leaf, chain)
	if err != nil {
		return err
	}
	if auth.principalFound && auth.principalKind == string(mandates.PrincipalHuman) && caller.ActorID == "" {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
			"a human principal proposes through the configured workload actor, not directly")
	}
	if plan {
		// The plan's class is its adapter's declaration, not a tenant row.
		declared, _ := provision.DeclaredRisk(in.EffectType)
		auth.riskClass = mandates.RiskClass(declared)
		if refusal, err := precheckPlan(ctx, tx, caller, in); err != nil {
			return err
		} else if refusal != nil {
			// A plan the applied plan does not admit: refused at Propose, which
			// leaves no attempt for an approver to be asked about, and denied
			// when Approve re-admits an attempt it had already escalated.
			if from == "PROPOSED" {
				code := CodeFailedPrecondition
				if refusal.Reason == contracts.ReasonInsufficientPrivilege {
					code = CodePermissionDenied
				}
				return refuse(code, refusal.Reason, "%s", refusal.Detail)
			}
			return recordDecision(ctx, tx, caller.TenantID, attemptID, from, "DENIED", refusal.Reason, nil, string(auth.riskClass), nil, nil)
		}
	}

	// An approval of an effect whose risk is now high, irreversible or an
	// authority change needs step-up, whatever the risk was at escalation:
	// one whose proof decide already used up passes, and otherwise it uses up
	// the proof the approval carries or is refused (STEP_UP_REQUIRED).
	if approval != nil && approval.Approved && !approval.StepUpVerified && needsStepUp(string(auth.riskClass), in.EffectType) {
		if err := spendStepUp(ctx, tx, caller.TenantID, approval.proof); err != nil {
			return err
		}
		approval.StepUpVerified = true
	}

	// 4. Stops, read in a statement after the locks were granted.
	stops, err := activeStops(ctx, tx, caller.TenantID, in.EffectType, auth)
	if err != nil {
		return err
	}

	// 5. Counters, FOR UPDATE in (limit_id, bucket_start) order.
	// Authority changes spend no resource: no limit counts them, so a Lift,
	// which carries no quote, is never refused by a sum limit (L5).
	limits := auth.limits
	if strings.HasPrefix(in.EffectType, "helm.authority.") {
		limits = nil
	}
	counters, err := lockCounters(ctx, tx, caller.TenantID, limits, now, in)
	if err != nil {
		return err
	}

	decideInput := Input{
		Now: now, PrincipalID: caller.PrincipalID, PrincipalFound: auth.principalFound, PrincipalActive: auth.principalActive,
		EffectType: in.EffectType, EffectTypeFound: auth.effectTypeFound, RiskClass: auth.riskClass,
		Target: in.Target, Args: args, Quote: in.Quote, ActiveStops: stops, Counters: counters.states,
		Approval: approval, LiftsStop: liftedStop(in.EffectType, in.Target),
		MandateFree: plan, PrincipalKind: auth.principalKind,
	}
	for _, m := range auth.chain {
		link := Link{Mandate: m}
		if m.Terms.Condition != "" {
			link.Condition = s.condition(m.Terms.Condition)
		}
		decideInput.Chain = append(decideInput.Chain, link)
	}
	decision := Decide(decideInput)

	// 6. Record the decision.
	var mandate any
	if len(auth.chain) > 0 {
		mandate = leaf
	}
	var risk any
	if auth.effectTypeFound || plan {
		risk = string(auth.riskClass)
	}
	switch decision.Verdict {
	case Allow:
		if err := hold(ctx, tx, caller.TenantID, attemptID, counters.holds, counters.caps); err != nil {
			return err
		}
		for _, d := range counters.distinct {
			if _, err := tx.ExecContext(ctx, `INSERT INTO authority_distinct_values (tenant_id, limit_id, bucket_start, value_digest, attempt_id)
				VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
				caller.TenantID, d.key.limitID, d.key.start, d.digest, attemptID); err != nil {
				return err
			}
		}
		permitID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		versions, err := json.Marshal(auth.versions)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_permits (tenant_id, permit_id, attempt_id, argument_digest, authority_versions, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			caller.TenantID, permitID, attemptID, argumentDigest, versions, now.Add(s.cfg.PermitTTL)); err != nil {
			return err
		}
		return recordDecision(ctx, tx, caller.TenantID, attemptID, from, "ADMITTED", "", mandate, risk, nil, nil)
	case Escalate:
		expires := now.Add(s.cfg.ApprovalWindow)
		if in.ApprovalExpiresAt != nil && in.ApprovalExpiresAt.Before(expires) {
			expires = *in.ApprovalExpiresAt
		}
		expires = expires.UTC().Truncate(time.Second)
		approvalDigest := ApprovalDigestV1(attemptID, targetDigest, argumentDigest, in.Quote, expires)
		if err := recordDecision(ctx, tx, caller.TenantID, attemptID, from, "ESCALATED", decision.Reason, mandate, risk, approvalDigest, expires); err != nil {
			return err
		}
		// The escalation's timer, in the same transaction (TA §6.3).
		return s.enqueue(ctx, tx, Job{Kind: JobExpireEscalation, TenantID: caller.TenantID, WorkspaceID: caller.WorkspaceID,
			AttemptID: attemptID, RunAt: expires})
	default:
		return recordDecision(ctx, tx, caller.TenantID, attemptID, from, "DENIED", decision.Reason, mandate, risk, nil, nil)
	}
}

// recordDecision moves an attempt from state from to the decided state and
// bumps its version. A decision on a new attempt sets approvalDigest and
// expires only for ESCALATED; a re-admission keeps the escalation's, which the
// Approval record refers to.
func recordDecision(ctx context.Context, tx *sql.Tx, tenantID, attemptID, from, state string, reason contracts.ReasonCode,
	mandate, risk, approvalDigest, expires any) error {
	res, err := tx.ExecContext(ctx, `UPDATE authority_effect_attempts
		SET state = $3, reason_code = $4, mandate_id = $5, risk_class = $6,
		    approval_digest = CASE WHEN $9 = 'PROPOSED' THEN $7 ELSE approval_digest END,
		    approval_expires_at = CASE WHEN $9 = 'PROPOSED' THEN $8 ELSE approval_expires_at END,
		    version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND attempt_id = $2 AND state = $9`,
		tenantID, attemptID, state, string(reason), mandate, risk, approvalDigest, expires, from)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("attempt %s: decision update touched %d rows (%v)", attemptID, n, err)
	}
	return nil
}

// resolveMandate returns the leaf mandate: the selector when the principal
// holds it, otherwise the principal's first active mandate that names the
// effect type, preferring one whose targets allow the target (a plan makes
// one mandate per grant group, so a seat can hold several for one effect type),
// then by depth and id. When none allows the target the first that names the
// effect type is returned, and decide denies it as out of scope. uuid.Nil
// means none; decide then denies.
func resolveMandate(ctx context.Context, tx *sql.Tx, caller Caller, in ProposeInput) (uuid.UUID, error) {
	var id uuid.UUID
	var err error
	if in.MandateID != "" {
		err = tx.QueryRowContext(ctx, `SELECT mandate_id FROM authority_mandates
			WHERE tenant_id = $1 AND mandate_id = $2 AND holder_id = $3`,
			caller.TenantID, in.MandateID, caller.PrincipalID).Scan(&id)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT mandate_id FROM authority_mandates
			WHERE tenant_id = $1 AND holder_id = $2 AND status = 'active' AND $3 = ANY (effect_types)
			ORDER BY (targets IS NULL OR $4 = ANY (targets)) DESC, depth, mandate_id LIMIT 1`,
			caller.TenantID, caller.PrincipalID, in.EffectType, in.Target).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// lockAuthority takes FOR SHARE on the authority rows in the global order and
// records their versions.
func lockAuthority(ctx context.Context, tx *sql.Tx, caller Caller, effectType string, leaf uuid.UUID,
	unlocked []mandates.Mandate) (lockedAuthority, error) {
	var a lockedAuthority
	var version int64
	if err := tx.QueryRowContext(ctx, `SELECT version FROM authority_tenants WHERE tenant_id = $1 FOR SHARE`,
		caller.TenantID).Scan(&version); err != nil {
		return a, fmt.Errorf("tenant control row: %w", err)
	}
	a.versions = append(a.versions, AuthorityVersion{Kind: "tenant", Version: version})

	// The requester, the workload that carries its call (the token's act.sub),
	// and every holder and delegator of the chain: a stop on any of them
	// suspends the chain (coordinator decision, HELM-750; TA §4.1 item 6).
	principals := map[string]struct{}{caller.PrincipalID: {}}
	if caller.ActorID != "" {
		principals[caller.ActorID] = struct{}{}
	}
	for _, m := range unlocked {
		principals[m.HolderID] = struct{}{}
		principals[m.CreatedBy] = struct{}{}
	}
	ids := make([]string, 0, len(principals))
	for id := range principals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows, err := tx.QueryContext(ctx, `SELECT principal_id, kind, status, version FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = ANY ($2::text[]) ORDER BY principal_id FOR SHARE`,
		caller.TenantID, pq.Array(ids))
	if err != nil {
		return a, err
	}
	for rows.Next() {
		var id, kind, status string
		if err := rows.Scan(&id, &kind, &status, &version); err != nil {
			_ = rows.Close()
			return a, err
		}
		a.versions = append(a.versions, AuthorityVersion{Kind: "principal", Key: id, Version: version})
		if id == caller.PrincipalID {
			a.principalFound, a.principalKind, a.principalActive = true, kind, status == "active"
		}
	}
	if err := rows.Close(); err != nil {
		return a, err
	}
	if err := rows.Err(); err != nil {
		return a, err
	}

	if leaf != uuid.Nil {
		chain, err := mandates.ChainInTx(ctx, tx, caller.TenantID, leaf, true)
		if err != nil {
			return a, err
		}
		// Parent links and holders are immutable after activation, so the
		// locked chain is the one whose principals were locked above.
		if len(chain) != len(unlocked) {
			return a, errors.New("the mandate chain changed while it was being locked")
		}
		for i, m := range chain {
			if m.ID != unlocked[i].ID || m.HolderID != unlocked[i].HolderID || m.CreatedBy != unlocked[i].CreatedBy {
				return a, errors.New("the mandate chain changed while it was being locked")
			}
			a.versions = append(a.versions, AuthorityVersion{Kind: "mandate", Key: m.ID.String(), Version: m.Version})
		}
		a.chain = chain
	}

	var risk string
	err = tx.QueryRowContext(ctx, `SELECT risk_class, version FROM authority_effect_types
		WHERE tenant_id = $1 AND effect_type = $2 FOR SHARE`, caller.TenantID, effectType).Scan(&risk, &version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return a, err
	default:
		a.effectTypeFound = true
		a.riskClass = mandates.RiskClass(risk)
		for _, m := range a.chain {
			a.riskClass = mandates.HigherRisk(a.riskClass, m.Terms.RiskClasses[effectType])
		}
		a.versions = append(a.versions, AuthorityVersion{Kind: "effect_type", Key: effectType, Version: version})
	}

	chainIDs := make([]string, 0, len(a.chain))
	for _, m := range a.chain {
		chainIDs = append(chainIDs, m.ID.String())
	}
	lrows, err := tx.QueryContext(ctx, `SELECT limit_id, unit, measure, window_kind, limit_value, span, version FROM authority_limits
		WHERE tenant_id = $1 AND (mandate_id = ANY ($2::uuid[]) OR mandate_id IS NULL)
		ORDER BY limit_id FOR SHARE`, caller.TenantID, pq.Array(chainIDs))
	if err != nil {
		return a, err
	}
	defer func() { _ = lrows.Close() }()
	for lrows.Next() {
		var l limitRow
		if err := lrows.Scan(&l.id, &l.unit, &l.measure, &l.window, &l.value, &l.span, &version); err != nil {
			return a, err
		}
		a.limits = append(a.limits, l)
		a.versions = append(a.versions, AuthorityVersion{Kind: "limit", Key: l.id, Version: version})
	}
	return a, lrows.Err()
}

// principalStops locks the principals FOR SHARE, in ID order, and returns the
// active stops on any of them: the dispatcher at the claim, the approver at
// Approve. A narrowing Stop updates the principal row, so a stop either
// commits before this lock or waits for the transaction.
func principalStops(ctx context.Context, tx *sql.Tx, tenantID string, ids ...string) ([]string, error) {
	var keys []string
	set := map[string]bool{}
	for _, id := range ids {
		if id != "" && !set[id] {
			set[id] = true
			keys = append(keys, id)
		}
	}
	sort.Strings(keys)
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM authority_principals WHERE tenant_id = $1 AND principal_id = ANY ($2::text[])
		ORDER BY principal_id FOR SHARE`, tenantID, pq.Array(keys)); err != nil {
		return nil, err
	}
	for i := range keys {
		keys[i] = "principal:" + keys[i]
	}
	return stopsOn(ctx, tx, tenantID, keys)
}

// activeStops returns the stops on the tenant, any locked principal, any
// mandate of the chain, or the effect type that are neither lifted nor
// expired. It must run after lockAuthority.
//
// A tenant-wide stop does not cover helm.authority.narrow.v1: the plan only
// narrows, which is what an operator needs during an incident. A stop on the
// requester, on the workload that dispatches it or on the effect type does.
func activeStops(ctx context.Context, tx *sql.Tx, tenantID, effectType string, a lockedAuthority) ([]string, error) {
	keys := []string{"effect_type:" + effectType}
	if effectType != effectargs.AuthorityNarrow {
		keys = append(keys, "tenant:"+tenantID)
	}
	for _, v := range a.versions {
		switch v.Kind {
		case "principal", "mandate":
			keys = append(keys, v.Kind+":"+v.Key)
		}
	}
	return stopsOn(ctx, tx, tenantID, keys)
}

// stopsOn returns the active stops whose "kind:key" is one of keys.
func stopsOn(ctx context.Context, tx *sql.Tx, tenantID string, keys []string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT stop_id::text FROM authority_stops
		WHERE tenant_id = $1 AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		  AND scope_kind || ':' || scope_key = ANY ($2::text[])
		ORDER BY stop_id`, tenantID, pq.Array(keys))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

type bucketKey struct {
	limitID string
	start   time.Time
}

type holdEntry struct {
	key    bucketKey
	amount int64
}

// counted is what step 5 found: decide's counter states, the holds and
// distinct values an ALLOW writes, and each limit's cap for its current
// bucket.
type counted struct {
	states   []CounterState
	holds    []holdEntry
	caps     map[string]int64
	distinct []distinctEntry
}

type distinctEntry struct {
	key    bucketKey
	digest []byte
}

// lockCounters creates every bucket the limits need and locks them FOR
// UPDATE in key order.
func lockCounters(ctx context.Context, tx *sql.Tx, tenantID string, limits []limitRow, now time.Time, in ProposeInput) (counted, error) {
	var keys []bucketKey
	for i := range limits {
		l := &limits[i]
		l.current = bucketStart(l.window, now, 0)
		l.buckets = l.buckets[:0]
		for back := 0; back < l.span; back++ {
			b := bucketStart(l.window, now, back)
			l.buckets = append(l.buckets, b)
			keys = append(keys, bucketKey{l.id, b})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].limitID != keys[j].limitID {
			return keys[i].limitID < keys[j].limitID
		}
		return keys[i].start.Before(keys[j].start)
	})
	type counterRow struct{ used, reserved int64 }
	locked := map[bucketKey]counterRow{}
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_counters (tenant_id, limit_id, bucket_start) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, tenantID, k.limitID, k.start); err != nil {
			return counted{}, err
		}
		var c counterRow
		if err := tx.QueryRowContext(ctx, `SELECT used, reserved FROM authority_counters
			WHERE tenant_id = $1 AND limit_id = $2 AND bucket_start = $3 FOR UPDATE`, tenantID, k.limitID, k.start).
			Scan(&c.used, &c.reserved); err != nil {
			return counted{}, err
		}
		locked[k] = c
	}
	quote := map[string]int64{}
	for _, q := range in.Quote {
		quote[q.Unit] = q.Amount
	}
	distinct := map[string][]byte{}
	for _, d := range in.Distinct {
		distinct[d.Unit] = d.Digest
	}
	out := counted{caps: map[string]int64{}}
	for _, l := range limits {
		var delta int64
		switch l.measure {
		case "sum":
			// Fail closed (HELM-797's prerequisite): a request that names no
			// amount for a summed unit cannot be held against it.
			amount, ok := quote[l.unit]
			if !ok {
				return counted{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
					"a sum limit counts %q, and the quote carries no amount for it", l.unit)
			}
			delta = amount
		case "count":
			delta = 1
		case "distinct":
			value, ok := distinct[l.unit]
			if !ok {
				return counted{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
					"a distinct-value limit counts %q, and the request carries no value for it", l.unit)
			}
			var seen bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_distinct_values
				WHERE tenant_id = $1 AND limit_id = $2 AND bucket_start = $3 AND value_digest = $4)`,
				tenantID, l.id, l.current, value).Scan(&seen); err != nil {
				return counted{}, err
			}
			if !seen {
				delta = 1
				out.distinct = append(out.distinct, distinctEntry{bucketKey{l.id, l.current}, value})
			}
		}
		var used, reserved int64
		for _, b := range l.buckets {
			c := locked[bucketKey{l.id, b}]
			used, _ = add3(used, c.used, 0)
			reserved, _ = add3(reserved, c.reserved, 0)
		}
		cur := locked[bucketKey{l.id, l.current}]
		out.states = append(out.states, CounterState{LimitID: l.id, Limit: l.value, Used: used, Reserved: reserved, Delta: delta})
		if delta > 0 {
			out.holds = append(out.holds, holdEntry{bucketKey{l.id, l.current}, delta})
			// The hold runs on the current bucket; its cap leaves room for
			// the other buckets of the span, which are locked too.
			out.caps[l.id] = l.value - (used - cur.used) - (reserved - cur.reserved)
		}
	}
	return out, nil
}

// hold writes each held exposure with a conditional update. Decide has
// already allowed, so a refused update means the counter and the decision
// disagree: fail closed, and nothing commits (ADR-0001 §5.6).
func hold(ctx context.Context, tx *sql.Tx, tenantID, attemptID string, entries []holdEntry, caps map[string]int64) error {
	for _, e := range entries {
		res, err := tx.ExecContext(ctx, `UPDATE authority_counters SET reserved = reserved + $4
			WHERE tenant_id = $1 AND limit_id = $2 AND bucket_start = $3 AND used + reserved + $4 <= $5`,
			tenantID, e.key.limitID, e.key.start, e.amount, caps[e.key.limitID])
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.New("admission: the conditional hold was refused by the counter")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_exposures (tenant_id, attempt_id, limit_id, bucket_start, kind, amount)
			VALUES ($1, $2, $3, $4, 'held', $5)`, tenantID, attemptID, e.key.limitID, e.key.start, e.amount); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_postings (tenant_id, attempt_id, limit_id, bucket_start, kind, amount, cause)
			VALUES ($1, $2, $3, $4, 'held', $5, 'admit')`, tenantID, attemptID, e.key.limitID, e.key.start, e.amount); err != nil {
			return err
		}
	}
	return nil
}

// bucketStart truncates in UTC, back buckets ago. A limit without a window
// has one bucket at the epoch.
func bucketStart(window string, now time.Time, back int) time.Time {
	u := now.UTC()
	switch window {
	case "hour":
		return u.Truncate(time.Hour).Add(-time.Duration(back) * time.Hour)
	case "day":
		return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -back)
	case "month":
		return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -back, 0)
	}
	return time.Unix(0, 0).UTC()
}

// condition returns the compiled snapshot of a mandate condition. Activation
// (authorityrows, through mandates) refuses a condition that does not compile, so compiling
// here only fills this process's cache, once per condition text; a failure
// returns nil and decide denies.
func (s *Service) condition(text string) *authority.Snapshot {
	key := sha256.Sum256([]byte(text))
	if cached, ok := s.conditions.Load(key); ok {
		return cached.(*authority.Snapshot)
	}
	snapshot, err := mandates.CompileCondition(text)
	if err != nil {
		return nil
	}
	s.conditions.Store(key, snapshot)
	return snapshot
}

// checkBranchAttempt is the draft pull request's Propose precondition
// (HELM-753): branch_attempt_id names a github.branch.create_from_changes
// attempt of this tenant and target in OBSERVED or RECONCILED with outcome
// SUCCEEDED, whose head
// and base equal the pull request's, and whose read-back commit is head_sha.
// Otherwise no attempt is created.
func checkBranchAttempt(ctx context.Context, tx *sql.Tx, caller Caller, in ProposeInput) error {
	tenantID := caller.TenantID
	var pr effectargs.PullRequestCreateDraft
	if err := json.Unmarshal(in.Arguments, &pr); err != nil {
		return err
	}
	failed := func(why string) error {
		return refuse(CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "branch_attempt_id: %s", why)
	}
	// One refusal for "no such attempt", "another workspace's", "not a branch
	// of this repository" and "not observed to succeed", so the check is no
	// oracle for attempts the caller cannot read. The reason goes to the log.
	unusable := func(why string) error {
		slog.InfoContext(ctx, "draft pull request precondition refused", "branch_attempt_id", *pr.BranchAttemptID, "reason", why)
		return failed("no observed branch attempt of this repository in this workspace")
	}
	var effectType, target, state string
	var outcome sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT effect_type, target, state, outcome FROM authority_effect_attempts
		WHERE tenant_id = $1 AND attempt_id = $2 AND workspace_id = $3 FOR SHARE`,
		tenantID, *pr.BranchAttemptID, caller.WorkspaceID).Scan(&effectType, &target, &state, &outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return unusable("no such attempt in this tenant and workspace")
	}
	if err != nil {
		return err
	}
	if effectType != effectargs.GitHubBranchCreateFromChanges || target != in.Target {
		return unusable("the attempt is not a branch of this repository")
	}
	// OBSERVED(SUCCEEDED) or RECONCILED(SUCCEEDED) (HELM-753, #1058).
	if !(state == "OBSERVED" || state == "RECONCILED") || outcome.String != "SUCCEEDED" {
		return unusable("the branch attempt has not been observed to succeed")
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT arguments FROM authority_attempt_contents WHERE tenant_id = $1 AND attempt_id = $2`,
		tenantID, *pr.BranchAttemptID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return failed("the branch attempt's content is not retained")
	}
	if err != nil {
		return err
	}
	var commit sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT result ->> 'commit_sha' FROM authority_observations
		WHERE tenant_id = $1 AND attempt_id = $2 AND result_kind = 'github_branch' AND outcome = 'SUCCEEDED'
		ORDER BY observation_id DESC LIMIT 1`, tenantID, *pr.BranchAttemptID).Scan(&commit)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Head, base and head_sha against the branch attempt: the adapter's pure
	// form of this precondition (HELM-753).
	err = github.CheckBranchAttempt(github.BranchAttemptView{
		AttemptID: *pr.BranchAttemptID, TenantID: tenantID, EffectType: effectType, Target: target,
		State: state, Outcome: outcome.String, Arguments: raw, CommitSHA: commit.String,
	}, github.PullRequestProposal{TenantID: tenantID, Target: in.Target, Arguments: in.Arguments})
	var refusal *adapters.Refusal
	if errors.As(err, &refusal) {
		return refuse(CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "%s", refusal.Detail)
	}
	return err
}

// checkCaller refuses an identity the token layer should never produce.
func checkCaller(c Caller) error {
	if strings.TrimSpace(c.TenantID) == "" || strings.TrimSpace(c.WorkspaceID) == "" || strings.TrimSpace(c.PrincipalID) == "" {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "the token names no tenant, workspace or principal")
	}
	if e := c.Episode; e != nil && !validEpisode(e) {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "the token's episode claim is not well formed")
	}
	return nil
}

// storedDistinct is a distinct value as the attempt row keeps it.
type storedDistinct struct {
	Unit   string `json:"unit"`
	Digest []byte `json:"digest"`
}

func distinctJSON(values []DistinctValue) []storedDistinct {
	out := make([]storedDistinct, 0, len(values))
	for _, v := range values {
		out = append(out, storedDistinct{Unit: v.Unit, Digest: v.Digest})
	}
	return out
}

func nonNil(q []Amount) []Amount {
	if q == nil {
		return []Amount{}
	}
	return q
}

// precheckPlan runs provision.Precheck for an authority plan effect against the
// organization's applied plan. The read is not locked: Propose only spares an
// approver a plan that cannot apply, and Apply checks again on the locked row.
func precheckPlan(ctx context.Context, tx *sql.Tx, caller Caller, in ProposeInput) (*adapters.Refusal, error) {
	parsed, err := effectargs.ParsePlan(in.EffectType, in.Arguments)
	if err != nil {
		return nil, err
	}
	applied, err := provision.LoadApplied(ctx, tx, caller.TenantID, parsed.OrgRef, false)
	if err != nil {
		return nil, err
	}
	return provision.Precheck(&provision.Compiled{Plan: parsed}, applied, caller.PrincipalID), nil
}
