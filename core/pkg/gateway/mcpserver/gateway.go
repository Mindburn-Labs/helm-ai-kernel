package mcpserver

// quantum_posture: SHA-256 digests the identity of a tool call into its
// idempotency key and shortens an over-long episode id inside it; nothing here
// signs or verifies, and no post-quantum claim is made.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
)

// Ledger is the effect gateway's admission as the tools use it:
// *admission.Service. Every tool call goes through it, so it is bound by the
// same mandates, limits, stops, approvals and idempotency as any other effect.
type Ledger interface {
	PrincipalEffects(ctx context.Context, caller admission.Caller) (admission.PrincipalEffects, error)
	// ModelGrants reads what the caller's mandates allow for one effect type; it
	// is named for its first user and reads any.
	ModelGrants(ctx context.Context, caller admission.Caller, effectType string) (admission.Grants, error)
	Propose(ctx context.Context, caller admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error)
	Dispatch(ctx context.Context, caller admission.Caller, attemptID string) (admission.Attempt, bool, error)
	Observe(ctx context.Context, caller admission.Caller, attemptID string) (admission.Attempt, bool, error)
	Get(ctx context.Context, caller admission.Caller, attemptID string) (admission.Attempt, error)
}

var _ Ledger = (*admission.Service)(nil)

// Gateway is the Backend of one gateway process: the gateway's effect types as
// the tools of a worker's episode.
type Gateway struct {
	ledger   Ledger
	byName   map[string]effectTool
	byEffect map[string]effectTool
}

var _ Backend = (*Gateway)(nil)

// NewGateway offers the effect types the adapters declare, as MCP tools.
func NewGateway(ledger Ledger, all []adapters.Adapter) (*Gateway, error) {
	byName, err := effectTools(all)
	if err != nil {
		return nil, err
	}
	g := &Gateway{ledger: ledger, byName: byName, byEffect: map[string]effectTool{}}
	for _, t := range byName {
		g.byEffect[t.effectType] = t
	}
	return g, nil
}

// Tools lists the tools of the caller's mandates: the effect types of its
// active mandates that the gateway performs, and helm_attempt_get. It reflects
// authority, it never grants it: every call is admitted afresh.
func (g *Gateway) Tools(ctx context.Context, c Caller) ([]Tool, error) {
	if c.Episode == nil {
		return nil, ErrForbidden
	}
	pe, err := g.ledger.PrincipalEffects(ctx, c.Caller)
	if err != nil {
		return nil, refusedOr(err)
	}
	if pe.Kind != "agent" {
		return nil, ErrForbidden
	}
	out := []Tool{attemptGetTool()}
	for _, effectType := range pe.EffectTypes {
		if t, ok := g.byEffect[effectType]; ok {
			out = append(out, t.Tool)
		}
	}
	return out, nil
}

// Call runs one tool. An effect tool is proposed under a key derived from the
// episode and the call's identity (idempotencyKey), and when it is admitted it is dispatched and
// observed in the same call, by the worker's own verified identity. The worker's
// token never carries helm.gateway.execute: the permit is claimed here, inside
// the gateway, by the principal the attempt was proposed through.
func (g *Gateway) Call(ctx context.Context, c Caller, call Call) (Result, error) {
	if c.Episode == nil {
		return Result{}, ErrForbidden
	}
	if call.Name == AttemptGetTool {
		return g.attemptGet(ctx, c, call)
	}
	t, ok := g.byName[call.Name]
	if !ok {
		return Result{}, ErrUnknownTool
	}
	return g.effect(ctx, c, t, call)
}

// effect proposes an effect tool's call and drives it as far as it goes.
func (g *Gateway) effect(ctx context.Context, c Caller, t effectTool, call Call) (Result, error) {
	if c.Scope != server.ScopePropose {
		return failed("denied", contracts.ReasonInsufficientPrivilege, "this token covers reads only, and an effect is proposed with helm.gateway.propose"), nil
	}
	var in struct {
		Target    string          `json:"target"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if strictJSON(call.Arguments, &in) != nil || in.Target == "" || len(in.Arguments) == 0 || in.Arguments[0] != '{' {
		return failed("invalid", contracts.ReasonSchemaViolation, `the arguments must be {"target": ..., "arguments": {...}}`), nil
	}
	grants, err := g.ledger.ModelGrants(ctx, c.Caller, t.effectType)
	if err != nil {
		return Result{}, refusedOr(err)
	}
	if grants.PrincipalKind != "agent" {
		return Result{}, ErrForbidden
	}
	propose := admission.ProposeInput{
		IdempotencyKey: idempotencyKey(c.Episode.EpisodeID, call, t.effectType, in.Target, in.Arguments),
		EffectType:     t.effectType, Target: in.Target, Arguments: []byte(in.Arguments), Quote: quoteFor(grants),
	}
	attempt, _, err := g.ledger.Propose(ctx, c.Caller, propose)
	var refusal *admission.Error
	if errors.As(err, &refusal) && refusal.Code == admission.CodeInvalidArgument && strings.Contains(refusal.Message, "quote carries no amount") {
		// A sum limit was added to the chain since the grants were read: price
		// the call again, once.
		if grants, err = g.ledger.ModelGrants(ctx, c.Caller, t.effectType); err != nil {
			return Result{}, refusedOr(err)
		}
		propose.Quote = quoteFor(grants)
		attempt, _, err = g.ledger.Propose(ctx, c.Caller, propose)
	}
	if err != nil {
		return g.refusal(err, "")
	}
	// An escalation stays on the CP's resume path even after approval. Its
	// retained approval digest distinguishes it from a same-call admission;
	// a worker retry must neither claim its permit nor reconcile its dispatch.
	if len(attempt.ApprovalDigest) != 0 {
		return resultFor(attempt), nil
	}
	// A replayed, directly admitted call finds the same attempt: one admitted
	// and never dispatched is dispatched, one in flight is read back.
	id := attempt.ID
	if attempt.State == "ADMITTED" {
		if attempt, _, err = g.ledger.Dispatch(ctx, c.Caller, id); err != nil {
			return g.refusal(err, id)
		}
	}
	switch attempt.State {
	case "DISPATCHING", "DISPATCHED", "UNKNOWN":
		if attempt, _, err = g.ledger.Observe(ctx, c.Caller, id); err != nil {
			return g.refusal(err, id)
		}
	}
	return resultFor(attempt), nil
}

// attemptGet reads back an attempt of the caller's own episode. Another
// episode's attempt, another tenant's, and one that does not exist are the
// same answer.
func (g *Gateway) attemptGet(ctx context.Context, c Caller, call Call) (Result, error) {
	var in struct {
		AttemptID string `json:"attempt_id"`
	}
	if strictJSON(call.Arguments, &in) != nil || in.AttemptID == "" {
		return failed("invalid", contracts.ReasonSchemaViolation, `the arguments must be {"attempt_id": ...}`), nil
	}
	pe, err := g.ledger.PrincipalEffects(ctx, c.Caller)
	if err != nil {
		return Result{}, refusedOr(err)
	}
	if pe.Kind != "agent" {
		return Result{}, ErrForbidden
	}
	attempt, err := g.ledger.Get(ctx, c.Caller, in.AttemptID)
	if err != nil {
		return g.refusal(err, "")
	}
	return resultFor(attempt), nil
}

// refusal is the result of an error admission returned for a call: a refusal
// is an answer the model can act on, anything else is the gateway's own
// failure.
func (g *Gateway) refusal(err error, attemptID string) (Result, error) {
	var refusal *admission.Error
	if !errors.As(err, &refusal) {
		return Result{}, err
	}
	status := map[admission.Code]string{
		admission.CodeInvalidArgument:    "invalid",
		admission.CodePermissionDenied:   "denied",
		admission.CodeNotFound:           "not_found",
		admission.CodeAlreadyExists:      "conflict",
		admission.CodeFailedPrecondition: "refused",
	}[refusal.Code]
	if status == "" {
		return Result{}, err
	}
	r := failed(status, refusal.Reason, refusal.Message)
	if attemptID != "" {
		r.StructuredContent["attempt_id"] = attemptID
	}
	return r, nil
}

// refusedOr turns a refusal of the caller's own identity into a forbidden
// endpoint, and passes anything else on.
func refusedOr(err error) error {
	var refusal *admission.Error
	if errors.As(err, &refusal) && refusal.Code == admission.CodePermissionDenied {
		return ErrForbidden
	}
	return err
}

// quoteFor is a zero amount for every unit the caller's chains sum: a sum limit
// needs an amount for its unit, and an effect tool costs none of it.
func quoteFor(g admission.Grants) []admission.Amount {
	quote := make([]admission.Amount, 0, len(g.SumUnits))
	for _, unit := range g.SumUnits {
		quote = append(quote, admission.Amount{Unit: unit})
	}
	return quote
}

// idempotencyKey is the key of a tool call: the episode, then a digest of what
// identifies the call inside it.
//
// MCP gives a call no id of its own. The request id is unique only among the
// requests a client has in flight, and a client that opens a new session for
// every call (langchain-mcp-adapters does) sends id 1 each time, so the id alone
// would make unrelated calls one. The call is therefore its session (the id the
// server minted at initialize, for the eras that have one), its request id and
// its content: the effect type, the target and the exact argument bytes. The
// same request sent again, which is what a retry is, is the same call and finds
// the same attempt. A request that differs in any of the four is another call,
// which admission decides on its own, and never another call's attempt. A string
// id and an integer id that print alike stay apart.
func idempotencyKey(episodeID string, call Call, effectType, target string, arguments []byte) string {
	var id string
	if len(call.RequestID) > 0 && call.RequestID[0] == '"' {
		var s string
		_ = json.Unmarshal(call.RequestID, &s) // the transport only passes a valid id
		id = "s:" + s
	} else {
		n, _ := strconv.ParseInt(string(call.RequestID), 10, 64)
		id = "n:" + strconv.FormatInt(n, 10)
	}
	digest := sha256.New()
	for _, part := range []string{call.Session, id, effectType, target, string(arguments)} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		digest.Write(length[:])
		digest.Write([]byte(part))
	}
	scope := episodeID
	if len(scope) > 100 {
		sum := sha256.Sum256([]byte(scope))
		scope = "h" + hex.EncodeToString(sum[:20])
	}
	return "mcp:" + scope + ":" + hex.EncodeToString(digest.Sum(nil))[:48]
}

// failed is a tool error: the call did not happen, or did not succeed, and the
// reason says why.
func failed(status string, reason contracts.ReasonCode, message string) Result {
	out := map[string]any{"status": status, "message": message}
	if reason != "" {
		out["reason_code"] = string(reason)
	}
	return Result{StructuredContent: out, IsError: true}
}

// resultFor is what a call reports of its attempt, whatever state the attempt is
// in:
//
//	OBSERVED, RECONCILED (SUCCEEDED)  succeeded, with the typed result
//	OBSERVED, RECONCILED (FAILED)     an error: failed
//	ESCALATED                         not an error: escalated, a human decides
//	DENIED, REJECTED, EXPIRED,
//	CANCELLED                         an error, with the reason code
//	anything in flight                not an error: reconciling
func resultFor(a admission.Attempt) Result {
	out := map[string]any{"attempt_id": a.ID, "effect_type": a.EffectType, "target": a.Target, "state": a.State}
	if a.ReasonCode != "" {
		out["reason_code"] = a.ReasonCode
	}
	status, isError := "reconciling", false
	switch a.State {
	case "ESCALATED":
		status = "escalated"
	case "DENIED":
		status, isError = "denied", true
	case "REJECTED":
		status, isError = "rejected", true
	case "EXPIRED":
		status, isError = "expired", true
	case "CANCELLED":
		status, isError = "cancelled", true
	case "OBSERVED", "RECONCILED", "SETTLED", "COMPENSATED":
		out["outcome"] = a.Outcome
		if a.Outcome == "SUCCEEDED" {
			status = "succeeded"
			addResult(out, a.LatestObservation)
		} else {
			status, isError = "failed", true
		}
	}
	out["status"] = status
	if message := reasonText(contracts.ReasonCode(a.ReasonCode)); isError && message != "" {
		out["message"] = message
	}
	return Result{StructuredContent: out, IsError: isError}
}

// addResult adds the typed result of an observation, the one its effect type
// defines.
func addResult(out map[string]any, o *admission.Observation) {
	switch {
	case o == nil:
	case o.GitHubPullRequest != nil:
		out["result_kind"], out["result"] = "github_pull_request", o.GitHubPullRequest
	case o.GitHubBranch != nil:
		out["result_kind"], out["result"] = "github_branch", o.GitHubBranch
	case o.GitHubRepository != nil:
		out["result_kind"], out["result"] = "github_repository", o.GitHubRepository
	}
}

// reasonText says what a registry reason code means to a worker that was
// refused, in a sentence it can act on.
func reasonText(reason contracts.ReasonCode) string {
	return map[contracts.ReasonCode]string{
		contracts.ReasonBudgetExceeded:           "a budget of this seat, team or organization does not cover the call",
		contracts.ReasonPerCallLimit:             "the call is above the mandate's per-call limit",
		contracts.ReasonEffectOutOfScope:         "the seat's mandates do not cover this effect type or target",
		contracts.ReasonEmergencyStopFenced:      "a stop is in force",
		contracts.ReasonPrincipalInactive:        "the seat's principal is not active",
		contracts.ReasonMandateInactive:          "the seat has no active mandate for this effect type",
		contracts.ReasonMandateOutsideValidity:   "the mandate is outside its validity window",
		contracts.ReasonDelegationScopeViolation: "the mandate chain no longer narrows",
		contracts.ReasonAuthorityChanged:         "authority changed while the call was being made: call again",
		contracts.ReasonPermitExpired:            "the permit expired before the call was sent: call again",
		contracts.ReasonApprovalRejected:         "an approver rejected the call",
		contracts.ReasonApprovalTimeout:          "no approver decided in time",
		contracts.ReasonPreconditionFailed:       "a precondition of the effect does not hold",
	}[reason]
}
