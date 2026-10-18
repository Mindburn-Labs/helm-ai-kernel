package modelgw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
)

// Ledger is the effect gateway's admission and settlement, as the model
// gateway uses it: *admission.Service. Every call goes through it, so a model
// call is bound by the same mandates, limits, stops and idempotency as any
// other effect.
type Ledger interface {
	ModelGrants(ctx context.Context, caller admission.Caller, effectType string) (admission.Grants, error)
	ModelGrantsWithBudget(ctx context.Context, caller admission.Caller, effectType string) (admission.Grants, error)
	ModelCallAttemptByKey(ctx context.Context, caller admission.Caller, key string) (*admission.Attempt, error)
	ModelCallAttemptsByKeys(ctx context.Context, caller admission.Caller, keys []string) ([]admission.Attempt, error)
	GetContent(ctx context.Context, caller admission.Caller, attemptID string) ([]byte, error)
	Propose(ctx context.Context, caller admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error)
	Cancel(ctx context.Context, caller admission.Caller, token admission.Token, attemptID string) (admission.Attempt, bool, error)
	ClaimModelCall(ctx context.Context, caller admission.Caller, attemptID string, fence time.Duration) (*admission.ModelCallClaim, admission.Attempt, error)
	SettleModelCall(ctx context.Context, claim *admission.ModelCallClaim, out admission.ModelCallOutcome) (admission.Attempt, error)
	ModelCallReplay(ctx context.Context, caller admission.Caller, attemptID string) (*admission.ModelCallReplay, error)
}

// Authenticator verifies a request's bearer token: *server.Authenticator.
type Authenticator interface {
	Authenticate(ctx context.Context, header http.Header, scopes ...string) (server.Identity, error)
}

// Gateway serves the model endpoints of one gateway process. The same Gateway
// serves the main listener and the worker listener, each through its own
// Handler.
type Gateway struct {
	Config *Config
	Ledger Ledger
	Keys   KeyProvider
	// Client sends the provider calls; nil takes the default (newHTTPClient).
	Client *http.Client
	Logger *slog.Logger
}

// Listener says which listener a Handler serves and how it authenticates.
type Listener struct {
	Name string
	Auth Authenticator
	// Worker is the worker listener: the work reference and the idempotency
	// scope come from the token's episode alone, and only agent principals
	// call. On the main listener a workload service (the Control Plane) may name
	// them in headers, and any workload principal may call.
	Worker bool
}

const (
	// maxAdmitAttempts bounds the keys tried for one request: each earlier
	// attempt that left no reusable answer takes one.
	maxAdmitAttempts = 16
	// ledgerTimeout bounds the ledger steps that must finish once begun.
	ledgerTimeout = 30 * time.Second
	// fenceGrace is added to the call timeout for the dispatch fence.
	fenceGrace = 2 * time.Minute
	// maxResponseBytes bounds a non-streamed provider response the gateway
	// buffers.
	maxResponseBytes = 16 << 20
	// maxEventBytes bounds one server-sent event.
	maxEventBytes = 4 << 20
	// The gateway's own headers on a request the caller may set on the main
	// listener.
	headerScope  = "X-Helm-Idempotency-Scope"
	headerCaseID = "X-Helm-Case-Id"
	// defaultCaseID is the work reference of a main-listener call that names none.
	defaultCaseID = "model-call"
)

var refPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type handler struct {
	g *Gateway
	l Listener
}

// Handler returns the model endpoints of listener l:
//
//	POST /v1/responses          OpenAI Responses (Codex, the OpenAI Agents SDK)
//	POST /v1/chat/completions   OpenAI Chat Completions
//	POST /v1/messages           Anthropic Messages (also ?beta=true)
//	POST /v1/messages/count_tokens  answered 404: clients estimate
//	GET  /v1/models             the routes the caller may use
func (g *Gateway) Handler(l Listener) http.Handler {
	h := &handler{g: g, l: l}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/responses", h.call(effectargs.APIOpenAIResponses))
	mux.HandleFunc("/v1/chat/completions", h.call(effectargs.APIOpenAIChat))
	mux.HandleFunc("/v1/messages", h.call(effectargs.APIAnthropicMessages))
	mux.HandleFunc("/v1/models", h.models)
	mux.HandleFunc("/v1/", h.notFound)
	return mux
}

func (h *handler) client() *http.Client {
	if h.g.Client != nil {
		return h.g.Client
	}
	return newHTTPClient(h.g.Config)
}

func (h *handler) log() *slog.Logger {
	if h.g.Logger != nil {
		return h.g.Logger
	}
	return slog.Default()
}

// apiForPath is the error format of a path the gateway does not serve.
func apiForPath(path string) string {
	if strings.HasPrefix(path, "/v1/messages") {
		return effectargs.APIAnthropicMessages
	}
	return effectargs.APIOpenAIChat
}

// notFound answers count_tokens and everything else under /v1/ that the
// gateway does not serve. Claude Code estimates its own tokens when
// count_tokens is 404.
func (h *handler) notFound(w http.ResponseWriter, r *http.Request) {
	writeAPIError(w, apiForPath(r.URL.Path), refuse(http.StatusNotFound, kindNotFound, "not_found",
		"this gateway serves /v1/responses, /v1/chat/completions, /v1/messages and /v1/models"))
}

// authenticate verifies the request's token. The Anthropic SDK sends its key in
// x-api-key when it is given an API key, and as a bearer when it is given an
// auth token: both are the same token here.
func (h *handler) authenticate(r *http.Request, api string, scopes ...string) (server.Identity, *apiError) {
	header := r.Header
	if api == effectargs.APIAnthropicMessages || r.URL.Path == "/v1/models" {
		if key := header.Get("X-Api-Key"); key != "" && header.Get("Authorization") == "" {
			header = header.Clone()
			header.Set("Authorization", "Bearer "+key)
		}
	}
	id, err := h.l.Auth.Authenticate(r.Context(), header, scopes...)
	if err == nil {
		return id, nil
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated:
		return server.Identity{}, refuse(http.StatusUnauthorized, kindAuthentication, "invalid_api_key", "a valid bearer token is required")
	case connect.CodePermissionDenied:
		e := refuse(http.StatusForbidden, kindPermission, "insufficient_scope", "this token does not cover the model gateway on this listener")
		e.Reason = contracts.ReasonInsufficientPrivilege
		return server.Identity{}, e
	case connect.CodeUnavailable:
		return server.Identity{}, refuse(http.StatusServiceUnavailable, kindAPI, "unavailable", "the token signing keys could not be loaded")
	}
	return server.Identity{}, refuse(http.StatusInternalServerError, kindAPI, "internal_error", "the gateway could not check the token")
}

func callerOf(id server.Identity) admission.Caller { return id.Caller }

// workRef returns the idempotency scope and the case a call belongs to. On the
// worker listener both come from the token's episode: the request cannot name
// them. On the main listener the workload may name them, and without a scope
// each token is its own (a retry with a new token is a new call).
func (h *handler) workRef(id server.Identity, r *http.Request) (scope, caseID string, _ *apiError) {
	if h.l.Worker {
		if id.Episode == nil {
			return "", "", refuse(http.StatusForbidden, kindPermission, "no_episode", "the token names no episode")
		}
		return id.Episode.EpisodeID, id.Episode.WorkItemID, nil
	}
	scope, caseID = r.Header.Get(headerScope), r.Header.Get(headerCaseID)
	for name, value := range map[string]string{headerScope: scope, headerCaseID: caseID} {
		if value != "" && !refPattern.MatchString(value) {
			return "", "", refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_header", name+" must be 1 to 128 characters of letters, digits and . _ : -")
		}
	}
	if scope == "" {
		scope = id.TokenID
	}
	if scope == "" {
		return "", "", refuse(http.StatusUnauthorized, kindAuthentication, "invalid_api_key", "the token has no id to scope a call to")
	}
	if id.Episode != nil && caseID == "" {
		caseID = id.Episode.WorkItemID
	}
	if caseID == "" {
		caseID = defaultCaseID
	}
	return scope, caseID, nil
}

// keyScope keeps a stored idempotency key inside its length bound.
func keyScope(scope string) string {
	if len(scope) <= 100 && refPattern.MatchString(scope) {
		return scope
	}
	sum := sha256.Sum256([]byte(scope))
	return "h" + hex.EncodeToString(sum[:20])
}

// readBody reads the request body within the configured bound.
func (h *handler) readBody(w http.ResponseWriter, r *http.Request, rc *http.ResponseController) ([]byte, *apiError) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, refuse(http.StatusUnsupportedMediaType, kindInvalidRequest, "unsupported_media_type", "the request must be application/json")
	}
	_ = rc.SetReadDeadline(time.Now().Add(2 * time.Minute))
	r.Body = http.MaxBytesReader(w, r.Body, h.g.Config.MaxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, refuse(http.StatusRequestEntityTooLarge, kindTooLarge, "request_too_large",
				fmt.Sprintf("the request is more than %d bytes", h.g.Config.MaxRequestBytes))
		}
		return nil, refuse(http.StatusBadRequest, kindInvalidRequest, "invalid_body", "the request body could not be read")
	}
	return body, nil
}

// modelArgs are the arguments a model call proposes (effectargs.ModelInferenceArgs
// v1). The digest and size stand for the request, so an attempt's content never
// holds a prompt.
type modelArgs struct {
	Schema          string `json:"schema"`
	API             string `json:"api"`
	Route           string `json:"route"`
	RequestSHA256   string `json:"request_sha256"`
	InputBytes      int64  `json:"input_bytes"`
	MaxOutputTokens int64  `json:"max_output_tokens"`
	Stream          bool   `json:"stream"`
}

// pending is a call being admitted: everything Propose needs but its key.
type pending struct {
	caller     admission.Caller
	scope      string
	digest     string
	keyDigest  string
	baseBody   []byte
	baseOutput int64
	route      *Route
	call       *call
	args       []byte
	quote      []admission.Amount
	mandate    string
	held       int64
	caseID     string
}

func (p *pending) setForwardedArguments() {
	digest := sha256.Sum256(p.call.Body)
	p.digest = hex.EncodeToString(digest[:])
	p.args, _ = json.Marshal(modelArgs{Schema: "model.inference.v1", API: p.call.API, Route: p.route.ID,
		RequestSHA256: p.digest, InputBytes: int64(len(p.call.Body)), MaxOutputTokens: p.call.MaxOutputTokens, Stream: p.call.Stream})
}

func (p *pending) input(n int) admission.ProposeInput {
	digest := p.keyDigest
	if digest == "" {
		digest = p.digest
	}
	return admission.ProposeInput{
		IdempotencyKey: fmt.Sprintf("mi:%s:%s:%d", keyScope(p.scope), digest, n),
		MandateID:      p.mandate,
		CaseID:         p.caseID,
		EffectType:     effectargs.ModelInference,
		Target:         p.route.ID,
		Arguments:      p.args,
		Quote:          p.quote,
	}
}

// price fixes the call's arguments and its worst-case quote in usd_micros, with
// a zero amount for every other unit the chain sums (a sum limit needs an
// amount for its unit), and the mandate that covers the route.
func (p *pending) price(grants admission.Grants) *apiError {
	held, err := p.route.Quote(int64(len(p.call.Body)), p.call.MaxOutputTokens, p.call.MayWriteCache)
	if err != nil {
		e := refuse(http.StatusBadRequest, kindInvalidRequest, "price_overflow", "the worst-case price of this call does not fit: "+err.Error())
		e.Reason = contracts.ReasonArithmeticOverflow
		return e
	}
	p.held = held
	p.quote = []admission.Amount{{Unit: admission.UnitUSDMicros, Amount: held}}
	for _, unit := range grants.SumUnits {
		if unit != admission.UnitUSDMicros {
			p.quote = append(p.quote, admission.Amount{Unit: unit})
		}
	}
	p.mandate, _ = grants.MandateFor(p.route.ID)
	return nil
}

// call serves one model API endpoint: the per-call algorithm of the contract.
func (h *handler) call(api string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		fail := func(e *apiError) { writeAPIError(w, api, e) }
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			fail(refuse(http.StatusMethodNotAllowed, kindInvalidRequest, "method_not_allowed", "use POST"))
			return
		}
		id, aerr := h.authenticate(r, api, server.ScopePropose)
		if aerr != nil {
			fail(aerr)
			return
		}
		rc := http.NewResponseController(w)
		body, aerr := h.readBody(w, r, rc)
		if aerr != nil {
			fail(aerr)
			return
		}
		c, aerr := inspect(h.g.Config, api, body)
		if aerr != nil {
			fail(aerr)
			return
		}
		scope, caseID, aerr := h.workRef(id, r)
		if aerr != nil {
			fail(aerr)
			return
		}

		// From here on the ledger steps run to their end whether or not the
		// client stays: a permit that is proposed and never claimed would hold
		// its reservation.
		ledger, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), ledgerTimeout)
		defer cancel()
		caller := callerOf(id)
		readGrants := h.g.Ledger.ModelGrants
		if c.DefaultedOutput {
			readGrants = h.g.Ledger.ModelGrantsWithBudget
		}
		grants, err := readGrants(ledger, caller, effectargs.ModelInference)
		if err != nil {
			fail(h.ledgerError(ledger, "grants", err, ""))
			return
		}
		if aerr := h.checkPrincipal(grants); aerr != nil {
			fail(aerr)
			return
		}
		var keyDigest string
		var baseBody []byte
		var baseOutput int64
		if c.DefaultedOutput {
			baseBody, baseOutput = bytes.Clone(c.Body), c.MaxOutputTokens
			intentBytes := make([]byte, 0, len(api)+len(caseID)+len(body)+2)
			intentBytes = append(intentBytes, api...)
			intentBytes = append(intentBytes, 0)
			intentBytes = append(intentBytes, caseID...)
			intentBytes = append(intentBytes, 0)
			intentBytes = append(intentBytes, body...)
			intent := sha256.Sum256(intentBytes)
			keyDigest = hex.EncodeToString(intent[:])
		}
		if remaining, bounded := grants.BudgetRemainingFor(c.Route.ID); bounded {
			c.fitDefaultOutput(remaining)
		}
		p := &pending{caller: caller, scope: scope, caseID: caseID, keyDigest: keyDigest, baseBody: baseBody,
			baseOutput: baseOutput, route: c.Route, call: c}
		p.setForwardedArguments()
		if aerr := p.price(grants); aerr != nil {
			fail(aerr)
			return
		}

		claim, replay, aerr := h.admitAndClaim(ledger, p)
		if aerr != nil {
			fail(aerr)
			return
		}
		if replay != nil {
			h.replay(w, replay, p, api)
			return
		}
		h.dispatch(w, r, rc, api, p, claim, start)
	}
}

// checkPrincipal refuses a caller that may not make model calls on this
// listener. Admission still decides everything else from its own rows.
func (h *handler) checkPrincipal(g admission.Grants) *apiError {
	deny := func(msg string) *apiError {
		e := refuse(http.StatusForbidden, kindPermission, "principal_not_allowed", msg)
		e.Reason = contracts.ReasonInsufficientPrivilege
		return e
	}
	switch {
	case g.PrincipalKind == "human":
		return deny("a human does not call models through the gateway; a workload calls for them")
	case h.l.Worker && g.PrincipalKind != "agent":
		return deny("the worker listener serves agent principals only")
	}
	return nil
}

// replayed is a stored answer to the same request: the response, and the
// attempt that first produced it.
type replayed struct {
	AttemptID string
	*admission.ModelCallReplay
}

// admitAndClaim proposes the call, under the next unused idempotency key, and
// claims its permit. It returns a replay instead when the same request in the
// same scope already has a stored answer.
func (h *handler) admitAndClaim(ctx context.Context, p *pending) (*admission.ModelCallClaim, *replayed, *apiError) {
	if p.call.DefaultedOutput && len(p.baseBody) > 0 {
		replay, aerr := h.priorLegacyDefault(ctx, p)
		if replay != nil || aerr != nil {
			return nil, replay, aerr
		}
	}
	refreshed := false
	claims := 0
	for n := 0; n < maxAdmitAttempts; n++ {
		if p.call.DefaultedOutput {
			replay, aerr, skip := h.priorDefaultAttempt(ctx, p, n)
			if replay != nil || aerr != nil {
				return nil, replay, aerr
			}
			if skip {
				continue
			}
		}
		attempt, existing, err := h.g.Ledger.Propose(ctx, p.caller, p.input(n))
		if err != nil {
			var refusal *admission.Error
			switch {
			case !errors.As(err, &refusal):
				return nil, nil, h.ledgerError(ctx, "propose", err, "")
			case refusal.Code == admission.CodeAlreadyExists:
				if p.call.DefaultedOutput {
					// A concurrent retry may have admitted the same raw call with
					// a different affordable cap after our read.
					replay, aerr, _ := h.priorDefaultAttempt(ctx, p, n)
					if replay != nil || aerr != nil {
						return nil, replay, aerr
					}
				}
				continue // a non-reusable key takes the next slot
			case refusal.Code == admission.CodeInvalidArgument && strings.Contains(refusal.Message, "quote carries no amount") && !refreshed:
				// The chain gained a summed unit since the grants were read.
				refreshed = true
				grants, gerr := h.g.Ledger.ModelGrants(ctx, p.caller, effectargs.ModelInference)
				if gerr != nil {
					return nil, nil, h.ledgerError(ctx, "grants", gerr, "")
				}
				if aerr := p.price(grants); aerr != nil {
					return nil, nil, aerr
				}
				n--
				continue
			}
			return nil, nil, h.refusalError(refusal, "")
		}
		if existing {
			switch attempt.State {
			case "ADMITTED":
				// A request that was proposed and not claimed: claim it now.
			case "DISPATCHING", "DISPATCHED":
				e := refuse(http.StatusConflict, kindConflict, "request_in_flight",
					"the same request is already in flight in this episode; retry once it settles")
				e.AttemptID = attempt.ID
				return nil, nil, e
			case "OBSERVED", "RECONCILED", "SETTLED":
				if attempt.Outcome == "SUCCEEDED" {
					replay, err := h.g.Ledger.ModelCallReplay(ctx, p.caller, attempt.ID)
					if err != nil {
						return nil, nil, h.ledgerError(ctx, "replay", err, attempt.ID)
					}
					if replay != nil {
						return nil, &replayed{AttemptID: attempt.ID, ModelCallReplay: replay}, nil
					}
				}
				continue
			case "ESCALATED":
				if _, _, err := h.g.Ledger.Cancel(ctx, p.caller, admission.Token{Scope: server.ScopePropose}, attempt.ID); err != nil {
					return nil, nil, h.ledgerError(ctx, "cancel", err, attempt.ID)
				}
				continue
			default:
				continue // an earlier attempt that left no reusable answer
			}
		}
		switch attempt.State {
		case "DENIED":
			return nil, nil, denial(attempt)
		case "ESCALATED":
			// A model call has no approver (V5): the escalation is cancelled,
			// and the caller is told what would have to change.
			if _, _, err := h.g.Ledger.Cancel(ctx, p.caller, admission.Token{Scope: server.ScopePropose}, attempt.ID); err != nil {
				return nil, nil, h.ledgerError(ctx, "cancel", err, attempt.ID)
			}
			e := refuse(http.StatusForbidden, kindPermission, "approval_not_supported",
				"the mandate requires an approval for this model call, which the model gateway cannot ask for: change the mandate")
			e.Reason, e.AttemptID = contracts.ReasonApprovalRequired, attempt.ID
			return nil, nil, e
		case "ADMITTED":
		default:
			e := refuse(http.StatusConflict, kindConflict, "request_in_flight", "the request is in state "+attempt.State)
			e.AttemptID = attempt.ID
			return nil, nil, e
		}
		claim, after, err := h.g.Ledger.ClaimModelCall(ctx, p.caller, attempt.ID, h.g.Config.CallTimeout+fenceGrace)
		if err != nil {
			var refusal *admission.Error
			if errors.As(err, &refusal) {
				return nil, nil, h.refusalError(refusal, attempt.ID)
			}
			return nil, nil, h.ledgerError(ctx, "claim", err, attempt.ID)
		}
		if claim != nil {
			return claim, nil, nil
		}
		// The claim was refused or lost to a concurrent request.
		switch {
		case after.State == "CANCELLED" && (after.ReasonCode == string(contracts.ReasonAuthorityChanged) || after.ReasonCode == string(contracts.ReasonPermitExpired)):
			// Authority moved between the proposal and the claim: propose again.
			if claims++; claims <= 2 {
				continue
			}
			e := refuse(http.StatusServiceUnavailable, kindAPI, "authority_changing", "authority changed while the call was admitted; retry")
			e.AttemptID = attempt.ID
			return nil, nil, e
		case after.State == "CANCELLED":
			e := refuse(http.StatusForbidden, kindPermission, "claim_refused", "the call was refused when it was about to be sent: "+denialText(contracts.ReasonCode(after.ReasonCode)))
			e.Reason, e.AttemptID = contracts.ReasonCode(after.ReasonCode), attempt.ID
			return nil, nil, e
		}
		e := refuse(http.StatusConflict, kindConflict, "request_in_flight", "the same request is already being sent; retry once it settles")
		e.AttemptID = attempt.ID
		return nil, nil, e
	}
	return nil, nil, refuse(http.StatusConflict, kindConflict, "too_many_attempts",
		"the same request has failed too many times in this episode; change it")
}

// priorLegacyDefault recognizes the bounded sequence of keys used before
// default-cap repricing. Without this check, an upgrade could send a second
// provider call while the old key is still in flight, or miss its saved reply.
func (h *handler) priorLegacyDefault(ctx context.Context, p *pending) (*replayed, *apiError) {
	sum := sha256.Sum256(p.baseBody)
	legacyDigest := hex.EncodeToString(sum[:])
	keys := make([]string, maxAdmitAttempts)
	for n := range keys {
		keys[n] = fmt.Sprintf("mi:%s:%s:%d", keyScope(p.scope), legacyDigest, n)
	}
	attempts, err := h.g.Ledger.ModelCallAttemptsByKeys(ctx, p.caller, keys)
	if err != nil {
		return nil, h.ledgerError(ctx, "legacy_model_calls", err, "")
	}
	var admitted []admission.Attempt
	for _, a := range attempts {
		if a.CaseID != p.caseID || a.Target != p.route.ID {
			continue
		}
		content, err := h.g.Ledger.GetContent(ctx, p.caller, a.ID)
		if err != nil {
			return nil, h.ledgerError(ctx, "legacy_model_content", err, a.ID)
		}
		var args modelArgs
		if err := json.Unmarshal(content, &args); err != nil {
			return nil, h.ledgerError(ctx, "legacy_model_content", err, a.ID)
		}
		if args.API != p.call.API || args.Route != p.route.ID || args.RequestSHA256 != legacyDigest ||
			args.InputBytes != int64(len(p.baseBody)) || args.MaxOutputTokens != p.baseOutput || args.Stream != p.call.Stream {
			continue
		}
		switch a.State {
		case "DISPATCHING", "DISPATCHED":
			e := refuse(http.StatusConflict, kindConflict, "request_in_flight",
				"the same request is already in flight in this episode; retry once it settles")
			e.AttemptID = a.ID
			return nil, e
		case "OBSERVED", "RECONCILED", "SETTLED":
			if a.Outcome == "SUCCEEDED" {
				r, err := h.g.Ledger.ModelCallReplay(ctx, p.caller, a.ID)
				if err != nil {
					return nil, h.ledgerError(ctx, "legacy_replay", err, a.ID)
				}
				if r != nil {
					return &replayed{AttemptID: a.ID, ModelCallReplay: r}, nil
				}
			}
		case "ADMITTED":
			admitted = append(admitted, a)
		}
	}
	for _, a := range admitted {
		if _, _, err := h.g.Ledger.Cancel(ctx, p.caller, admission.Token{Scope: server.ScopePropose}, a.ID); err != nil {
			var refusal *admission.Error
			if errors.As(err, &refusal) && refusal.Code == admission.CodeFailedPrecondition {
				e := refuse(http.StatusConflict, kindConflict, "request_in_flight", "the earlier call began dispatching; retry once it settles")
				e.AttemptID = a.ID
				return nil, e
			}
			return nil, h.ledgerError(ctx, "cancel_legacy_model_call", err, a.ID)
		}
	}
	if len(admitted) > 0 {
		if aerr := h.repriceDefault(ctx, p); aerr != nil {
			return nil, aerr
		}
	}
	return nil, nil
}

// priorDefaultAttempt keeps a retry tied to its original client request even
// when changing budget headroom would select another forwarded output cap.
// The exact forwarded body still determines the quote and admission digest.
func (h *handler) priorDefaultAttempt(ctx context.Context, p *pending, n int) (*replayed, *apiError, bool) {
	a, err := h.g.Ledger.ModelCallAttemptByKey(ctx, p.caller, p.input(n).IdempotencyKey)
	if err != nil {
		return nil, h.ledgerError(ctx, "prior_model_call", err, ""), false
	}
	if a == nil {
		return nil, nil, false
	}
	switch a.State {
	case "DISPATCHING", "DISPATCHED":
		e := refuse(http.StatusConflict, kindConflict, "request_in_flight",
			"the same request is already in flight in this episode; retry once it settles")
		e.AttemptID = a.ID
		return nil, e, false
	case "OBSERVED", "RECONCILED", "SETTLED":
		if a.Outcome == "SUCCEEDED" {
			r, err := h.g.Ledger.ModelCallReplay(ctx, p.caller, a.ID)
			if err != nil {
				return nil, h.ledgerError(ctx, "replay", err, a.ID), false
			}
			if r != nil {
				return &replayed{AttemptID: a.ID, ModelCallReplay: r}, nil, false
			}
		}
	case "ADMITTED":
		argsDigest := sha256.Sum256(p.args)
		if bytes.Equal(a.ArgumentDigest, argsDigest[:]) && slices.Equal(a.Quote, p.quote) &&
			a.Target == p.route.ID && a.MandateID == p.mandate && a.CaseID == p.caseID {
			return nil, nil, false // Propose recovers and claims the same quote.
		}
		// No provider call was claimed for the old cap. Release its hold
		// before proposing the revised cap under the next key.
		cancelled, _, err := h.g.Ledger.Cancel(ctx, p.caller, admission.Token{Scope: server.ScopePropose}, a.ID)
		if err != nil {
			var refusal *admission.Error
			if errors.As(err, &refusal) && refusal.Code == admission.CodeFailedPrecondition {
				e := refuse(http.StatusConflict, kindConflict, "request_in_flight", "the earlier call began dispatching; retry once it settles")
				e.AttemptID = a.ID
				return nil, e, false
			}
			return nil, h.ledgerError(ctx, "cancel_prior_model_call", err, a.ID), false
		}
		if cancelled.State == "CANCELLED" {
			if aerr := h.repriceDefault(ctx, p); aerr != nil {
				return nil, aerr, false
			}
			return nil, nil, true
		}
	}
	return nil, nil, false
}

func (h *handler) repriceDefault(ctx context.Context, p *pending) *apiError {
	grants, err := h.g.Ledger.ModelGrantsWithBudget(ctx, p.caller, effectargs.ModelInference)
	if err != nil {
		return h.ledgerError(ctx, "reprice", err, "")
	}
	p.call.Body = bytes.Clone(p.baseBody)
	p.call.MaxOutputTokens = p.baseOutput
	if remaining, bounded := grants.BudgetRemainingFor(p.route.ID); bounded {
		p.call.fitDefaultOutput(remaining)
	}
	p.setForwardedArguments()
	return p.price(grants)
}

// denial is the 403 for a DENIED attempt, with its registry reason.
func denial(a admission.Attempt) *apiError {
	reason := contracts.ReasonCode(a.ReasonCode)
	e := refuse(http.StatusForbidden, kindPermission, "denied", "the authority gateway denied this model call: "+denialText(reason))
	e.Reason, e.AttemptID = reason, a.ID
	return e
}

// denialText says what a registry reason means for a model call.
func denialText(reason contracts.ReasonCode) string {
	text := map[contracts.ReasonCode]string{
		contracts.ReasonBudgetExceeded:           "the budget of this seat, team or organization does not cover the worst case of this call",
		contracts.ReasonPerCallLimit:             "the worst case of this call is above the mandate's per-call limit; lower the maximum output tokens or shorten the request",
		contracts.ReasonEffectOutOfScope:         "the mandate does not cover this route",
		contracts.ReasonEmergencyStopFenced:      "a stop is in force",
		contracts.ReasonPrincipalInactive:        "the principal is not active",
		contracts.ReasonMandateInactive:          "there is no active mandate for model calls",
		contracts.ReasonMandateOutsideValidity:   "the mandate is outside its validity window",
		contracts.ReasonArithmeticOverflow:       "the price of the call does not fit",
		contracts.ReasonDelegationScopeViolation: "the mandate chain no longer narrows",
		contracts.ReasonAuthorityChanged:         "authority changed",
		contracts.ReasonPermitExpired:            "the permit expired",
	}[reason]
	if text == "" {
		return string(reason)
	}
	return string(reason) + ": " + text
}

// refusalError maps an admission refusal to the status a client expects.
func (h *handler) refusalError(r *admission.Error, attemptID string) *apiError {
	status, kind := http.StatusInternalServerError, kindAPI
	switch r.Code {
	case admission.CodePermissionDenied:
		status, kind = http.StatusForbidden, kindPermission
	case admission.CodeNotFound:
		status, kind = http.StatusNotFound, kindNotFound
	case admission.CodeFailedPrecondition, admission.CodeAlreadyExists:
		status, kind = http.StatusConflict, kindConflict
	}
	e := refuse(status, kind, "gateway_refused", "the authority gateway refused the call: "+r.Message)
	e.Reason, e.AttemptID = r.Reason, attemptID
	return e
}

// ledgerError logs a ledger failure and answers 503, retryable: the caller can
// repeat the same request, which the idempotency key makes safe.
func (h *handler) ledgerError(ctx context.Context, step string, err error, attemptID string) *apiError {
	h.log().ErrorContext(ctx, "model gateway ledger step failed", "step", step, "attempt_id", attemptID, "error", err)
	e := refuse(http.StatusServiceUnavailable, kindAPI, "ledger_unavailable", "the gateway could not evaluate the call; retry")
	e.AttemptID = attemptID
	return e
}

// replay answers a request from the response its first answer stored, with no
// provider call and no new attempt.
func (h *handler) replay(w http.ResponseWriter, replay *replayed, p *pending, api string) {
	for name, value := range replay.Headers {
		w.Header().Set(name, value)
	}
	w.Header().Set(headerReplayed, "true")
	w.Header().Set(headerAttemptID, replay.AttemptID)
	w.Header().Set("Content-Length", fmt.Sprint(len(replay.Body)))
	w.WriteHeader(replay.StatusCode)
	_, _ = w.Write(replay.Body)
	h.log().Info("model call replayed", "listener", h.l.Name, "api", api, "route", p.route.ID, "attempt_id", replay.AttemptID, "bytes", len(replay.Body))
}
