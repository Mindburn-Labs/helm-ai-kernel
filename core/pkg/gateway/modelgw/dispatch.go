package modelgw

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// dispatch sends a claimed call to its provider and answers the client from
// the response, then settles the call. It settles exactly once, whatever
// happens: a claimed permit is spent, so the ledger must learn what became of
// the call (a settlement that cannot be written leaves the attempt DISPATCHING
// inside its fence, where reconciliation makes it UNKNOWN and the hold stays).
func (h *handler) dispatch(w http.ResponseWriter, r *http.Request, rc *http.ResponseController, api string, p *pending,
	claim *admission.ModelCallClaim, start time.Time) {
	predispatch := time.Since(start)
	cfg := h.g.Config
	_ = rc.SetWriteDeadline(time.Now().Add(cfg.CallTimeout + time.Minute))

	settled := false
	settle := func(out admission.ModelCallOutcome) {
		if settled {
			return
		}
		settled = true
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), ledgerTimeout)
		defer cancel()
		attempt, err := h.g.Ledger.SettleModelCall(ctx, claim, out)
		if err != nil {
			h.log().ErrorContext(ctx, "settling a model call failed; the attempt stays with its hold for reconciliation",
				"attempt_id", claim.AttemptID, "error", err)
			return
		}
		fields := []any{"listener", h.l.Name, "api", api, "route", claim.Route, "attempt_id", claim.AttemptID, "state", attempt.State,
			"held_micros", claim.HeldMicros, "predispatch_ms", predispatch.Milliseconds(), "total_ms", time.Since(start).Milliseconds()}
		if m := attempt.ModelCall; m != nil {
			fields = append(fields, "settlement", m.State, "billable_micros", m.BillableMicros)
			if m.ConfirmedMicros != nil {
				fields = append(fields, "confirmed_micros", *m.ConfirmedMicros)
				if *m.ConfirmedMicros > m.HeldMicros {
					// Recorded as the provider reported it, never clipped and never billed past the hold.
					h.log().WarnContext(ctx, "a model call consumed more than its reservation; the overage is recorded as reported",
						"attempt_id", claim.AttemptID, "route", claim.Route, "held_micros", m.HeldMicros, "confirmed_micros", *m.ConfirmedMicros,
						"overage_micros", *m.ConfirmedMicros-m.HeldMicros)
				}
			}
		}
		h.log().InfoContext(ctx, "model call", fields...)
	}
	// A panic below, or a path that forgets to settle, is a cut call.
	defer func() {
		settle(admission.ModelCallOutcome{Result: admission.ModelCallCut, Reason: contracts.ReasonProviderError})
	}()

	provider := cfg.Provider(p.route.Provider)
	key, err := h.g.Keys.Key(r.Context(), provider.ID)
	if err != nil {
		h.log().ErrorContext(r.Context(), "no provider key for a model call", "provider", provider.ID, "error", err)
		settle(admission.ModelCallOutcome{Result: admission.ModelCallNotSent, Reason: contracts.ReasonProviderCredentialRejected})
		fail := refuse(http.StatusBadGateway, kindAPI, "provider_unavailable", "the gateway holds no usable key for this route's provider")
		fail.AttemptID = claim.AttemptID
		writeAPIError(w, api, fail)
		return
	}

	// The call ends at its timeout, when a stream goes quiet, or when the
	// client leaves.
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	limit := time.AfterFunc(cfg.CallTimeout, func() { cancel(context.DeadlineExceeded) })
	defer limit.Stop()

	req, state, err := newProviderRequest(ctx, provider, p.call, key, r.Header, r.URL.RawQuery)
	if err != nil {
		settle(admission.ModelCallOutcome{Result: admission.ModelCallNotSent, Reason: contracts.ReasonProviderError})
		writeAPIError(w, api, refuse(http.StatusBadGateway, kindAPI, "provider_unavailable", "the gateway could not build the provider request"))
		return
	}
	resp, err := h.client().Do(req)
	if err != nil {
		// Before the whole request left, the provider cannot have acted on it.
		result := admission.ModelCallCut
		if !state.written.Load() {
			result = admission.ModelCallNotSent
		}
		h.log().WarnContext(r.Context(), "provider call failed", "provider", provider.ID, "attempt_id", claim.AttemptID, "sent", state.written.Load(), "error", scrub(err))
		settle(admission.ModelCallOutcome{Result: result, Reason: contracts.ReasonProviderError})
		e := refuse(http.StatusBadGateway, kindAPI, "provider_unavailable", "the provider could not be reached")
		e.AttemptID = claim.AttemptID
		writeAPIError(w, api, e)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	head := func() {
		for _, name := range relayedResponseHeaders {
			if v := resp.Header.Get(name); v != "" {
				w.Header().Set(name, v)
			}
		}
		w.Header().Set(headerAttemptID, claim.AttemptID)
		w.Header().Set("Server-Timing", fmt.Sprintf("helm-predispatch;dur=%.1f", float64(predispatch.Microseconds())/1000))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		h.relayProviderError(w, api, resp, claim, head, settle)
		return
	}

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		rr := h.relayStream(w, rc, resp, ctx, cancel, p, head)
		out, abort := h.outcome(p, rr)
		settle(out)
		if abort {
			// The stream broke after the client was answered part of the way:
			// sever the connection, so the client sees an error and retries
			// instead of taking a truncated stream for a finished one.
			panic(http.ErrAbortHandler)
		}
		return
	}
	rr := h.relayBody(w, resp, ctx, cancel, p, head)
	out, _ := h.outcome(p, rr)
	settle(out)
	if !rr.completed && !rr.clientGone {
		// Nothing has been written yet: say the response did not arrive whole.
		e := refuse(http.StatusBadGateway, kindAPI, "provider_response_failed", "the provider's response did not arrive whole")
		if rr.tooLarge {
			e = refuse(http.StatusBadGateway, kindAPI, "provider_response_too_large", "the provider's response is more than the gateway buffers")
		}
		e.AttemptID = claim.AttemptID
		writeAPIError(w, api, e)
	}
}

// relayProviderError answers a provider's non-2xx response. Nothing was
// generated, so the hold is released. A key the provider rejects is the
// gateway's problem, not the caller's: it is not passed on as a 401 for a
// token that was fine.
func (h *handler) relayProviderError(w http.ResponseWriter, api string, resp *http.Response, claim *admission.ModelCallClaim,
	head func(), settle func(admission.ModelCallOutcome)) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		h.log().Error("a provider rejected the gateway's key", "attempt_id", claim.AttemptID, "status", resp.StatusCode)
		settle(admission.ModelCallOutcome{Result: admission.ModelCallNotSent, Reason: contracts.ReasonProviderCredentialRejected})
		e := refuse(http.StatusBadGateway, kindAPI, "provider_credential_rejected", "the provider rejected the gateway's credential; the operator must rotate it")
		e.Reason, e.AttemptID = contracts.ReasonProviderCredentialRejected, claim.AttemptID
		writeAPIError(w, api, e)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		settle(admission.ModelCallOutcome{Result: admission.ModelCallNotSent, Reason: contracts.ReasonProviderError})
		e := refuse(http.StatusBadGateway, kindAPI, "provider_redirected", "the provider answered with a redirect, which the gateway does not follow")
		e.AttemptID = claim.AttemptID
		writeAPIError(w, api, e)
	default:
		settle(admission.ModelCallOutcome{Result: admission.ModelCallNotSent, Reason: contracts.ReasonProviderError})
		head()
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}
}

// relayResult is what one relayed response came to.
type relayResult struct {
	status int
	// header holds the relayed headers a replay keeps.
	header map[string]string
	// completed: the provider finished the response.
	completed bool
	// providerError: the response is an error the provider reported in-band.
	providerError bool
	usage         *reported
	// cut: the response did not complete; clientGone and idle say why.
	clientGone bool
	// tooLarge: the provider's response was more than the gateway buffers.
	tooLarge bool
	// tee is the response as delivered, nil once it outgrew the replay bound.
	tee      []byte
	teeFull  bool
	evidence hash.Hash
	bytes    int64
}

func newRelayResult(resp *http.Response) *relayResult {
	rr := &relayResult{status: resp.StatusCode, header: map[string]string{}, evidence: sha256.New()}
	for _, name := range relayedResponseHeaders {
		if v := resp.Header.Get(name); v != "" {
			rr.header[name] = v
		}
	}
	return rr
}

// deliver adds delivered bytes to the evidence digest and, while it fits, to
// the copy kept for replay.
func (rr *relayResult) deliver(b []byte, replayBound int64) {
	rr.evidence.Write(b)
	rr.bytes += int64(len(b))
	if rr.teeFull {
		return
	}
	if rr.bytes > replayBound {
		rr.tee, rr.teeFull = nil, true
		return
	}
	rr.tee = append(rr.tee, b...)
}

// idleReader ends a call whose body goes quiet.
type idleReader struct {
	r     io.Reader
	timer *time.Timer
	d     time.Duration
}

func (i *idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	i.timer.Reset(i.d)
	return n, err
}

// relayStream forwards a server-sent event stream event by event, exactly as
// the provider wrote it (pings, comments and unknown events included), keeping
// a copy and reading the usage. The one event it may withhold is the
// usage-only chunk it asked a chat provider for.
func (h *handler) relayStream(w http.ResponseWriter, rc *http.ResponseController, resp *http.Response, ctx context.Context,
	cancel context.CancelCauseFunc, p *pending, head func()) *relayResult {
	cfg := h.g.Config
	rr := newRelayResult(resp)
	head()
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	idle := time.AfterFunc(cfg.IdleTimeout, func() { cancel(errIdle) })
	defer idle.Stop()
	events := newSSEReader(&idleReader{r: resp.Body, timer: idle, d: cfg.IdleTimeout}, maxEventBytes)
	tracker := newStreamTracker(p.call.API)
	for {
		ev, err := events.Next()
		if err != nil {
			rr.completed = tracker.done && errors.Is(err, io.EOF)
			rr.clientGone = context.Cause(ctx) == context.Canceled
			break
		}
		tracker.observe(ev)
		if p.call.DropChatUsage && p.call.API == effectargs.APIOpenAIChat && isChatUsageOnly(ev.Data) {
			continue
		}
		if _, err := w.Write(ev.Raw); err != nil {
			rr.clientGone = true
			cancel(context.Canceled)
			break
		}
		rr.deliver(ev.Raw, cfg.MaxReplayBytes)
		if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			rr.clientGone = true
			cancel(context.Canceled)
			break
		}
		// The terminal event is the last one: a provider that keeps the
		// connection open after it must not keep the call open.
		if tracker.done {
			rr.completed = true
			break
		}
	}
	rr.usage, rr.providerError = tracker.usage(), tracker.providerError
	return rr
}

// relayBody forwards a complete, non-streamed response.
func (h *handler) relayBody(w http.ResponseWriter, resp *http.Response, ctx context.Context, cancel context.CancelCauseFunc,
	p *pending, head func()) *relayResult {
	cfg := h.g.Config
	rr := newRelayResult(resp)
	idle := time.AfterFunc(cfg.IdleTimeout, func() { cancel(errIdle) })
	defer idle.Stop()
	body, err := io.ReadAll(io.LimitReader(&idleReader{r: resp.Body, timer: idle, d: cfg.IdleTimeout}, maxResponseBytes+1))
	switch {
	case err != nil:
		rr.clientGone = context.Cause(ctx) == context.Canceled
		return rr
	case len(body) > maxResponseBytes:
		rr.tooLarge = true
		return rr
	}
	rr.completed = true
	rr.usage = parseBodyUsage(p.call.API, body)
	head()
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
	rr.deliver(body, cfg.MaxReplayBytes)
	return rr
}

// outcome turns what a relay came to into the settlement. abort is true when a
// stream broke part of the way through and the client is still there to be told.
func (h *handler) outcome(p *pending, rr *relayResult) (out admission.ModelCallOutcome, abort bool) {
	digest := rr.evidence.Sum(nil)
	switch {
	case rr.tooLarge:
		return admission.ModelCallOutcome{Result: admission.ModelCallCut, Reason: contracts.ReasonProviderResponseTooLarge}, false
	case !rr.completed:
		return admission.ModelCallOutcome{Result: admission.ModelCallCut, Reason: contracts.ReasonProviderError}, !rr.clientGone
	}
	out = admission.ModelCallOutcome{Result: admission.ModelCallEstimated, EvidenceDigest: digest}
	if rr.usage != nil {
		if cost, err := p.route.Cost(rr.usage.Usage); err == nil {
			out.Result, out.ConfirmedMicros, out.Usage = admission.ModelCallConfirmed, cost, rr.usage.Raw
		} else {
			h.log().Error("a provider's usage could not be priced; the hold stands as an estimate", "route", p.route.ID, "error", err)
		}
	}
	// An error the provider reported in-band is not an answer to replay.
	if rr.tee != nil && !rr.providerError && len(rr.tee) > 0 {
		sum := sha256.Sum256(rr.tee)
		out.Replay = &admission.ModelCallReplay{StatusCode: rr.status, Headers: rr.header, Body: rr.tee, BodySHA256: sum[:], TTL: h.g.Config.ReplayTTL}
	}
	return out, false
}

// scrub keeps a transport error's text out of a log when it could carry a URL
// with credentials. The gateway builds no such URL, but an error from the
// standard library is quoted, so it is reduced to its class here.
func scrub(err error) string {
	var netErr interface{ Timeout() bool }
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	}
	return "transport error"
}
