package spendproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// maxUpstreamResponse caps buffered (non-streaming) upstream response bodies.
const maxUpstreamResponse = 32 << 20

// Upstream forwards OpenAI-compatible requests to a cloud provider base URL
// (e.g. OpenRouter's https://openrouter.ai/api/v1) with bearer-key auth.
// Settlement cost is derived from the SAME snapshot-hashed price book that
// produced the quote — never from provider-console numbers — so baseline and
// substitute captures are priced identically and provably.
type Upstream struct {
	// BaseURL includes the /v1 suffix, mirroring OPENAI_BASE_URL semantics.
	BaseURL string
	APIKey  string
	Client  *http.Client
	Prices  inferencegateway.PriceProvider
}

// NewUpstream validates and returns the upstream dispatcher.
func NewUpstream(baseURL, apiKey string, prices inferencegateway.PriceProvider) (*Upstream, error) {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errors.New("spendproxy: upstream base URL is required")
	}
	if apiKey == "" {
		return nil, errors.New("spendproxy: upstream API key is required (set OPENROUTER_API_KEY or pass --api-key)")
	}
	if prices == nil {
		return nil, errors.New("spendproxy: upstream requires the price book")
	}
	return &Upstream{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 10 * time.Minute},
		Prices:  prices,
	}, nil
}

// upstreamURL maps an inbound /v1/... path onto the upstream base URL.
func (u *Upstream) upstreamURL(inboundPath string) string {
	return u.BaseURL + strings.TrimPrefix(inboundPath, "/v1")
}

// rewriteModel replaces the body's "model" with the quote's selected model when
// the engine substituted the route. Everything else in the body — full message
// arrays included — passes through untouched.
func rewriteModel(body []byte, quote *economic.RouteQuote) ([]byte, error) {
	if quote.SelectedModelID == quote.RequestedModelID {
		return body, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("spendproxy: parse request body for model substitution: %w", err)
	}
	model, err := json.Marshal(quote.SelectedModelID)
	if err != nil {
		return nil, err
	}
	fields["model"] = model
	return json.Marshal(fields)
}

// openAIUsage covers both the chat-completions shape (prompt/completion) and
// the responses-API shape (input/output).
type openAIUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
}

func (o *openAIUsage) tokens() (int64, int64, bool) {
	if o == nil {
		return 0, 0, false
	}
	in := o.PromptTokens
	if in == 0 {
		in = o.InputTokens
	}
	out := o.CompletionTokens
	if out == 0 {
		out = o.OutputTokens
	}
	return in, out, in > 0 || out > 0
}

// CostCents prices actual token usage on the exact snapshot the quote was
// issued from. It fails closed when the book no longer holds that snapshot —
// settlement must never price on different numbers than the quote did.
func (u *Upstream) CostCents(quote *economic.RouteQuote, inputTokens, outputTokens int64) (int64, error) {
	snap, ok := u.Prices.Snapshot(quote.SelectedProviderID, quote.SelectedModelID)
	if !ok {
		return 0, fmt.Errorf("spendproxy: no price snapshot for settled route %s/%s", quote.SelectedProviderID, quote.SelectedModelID)
	}
	if snap.SourceHash != quote.ProviderPriceSnapshotHash {
		return 0, fmt.Errorf("spendproxy: price book source hash changed since quote (%s != %s); refusing to settle", snap.SourceHash, quote.ProviderPriceSnapshotHash)
	}
	return snap.QuoteCents(inputTokens, outputTokens)
}

// notSent marks an error as one before any byte of the request left the
// process: only then may the gateway release the reservation.
func notSent(err error) error { return fmt.Errorf("%w: %w", api.ErrDispatchNotSent, err) }

// Dispatch performs one buffered (non-streaming) upstream call. It satisfies
// api.ProviderDispatch modulo the pre-dispatch persistence wrapper the server
// adds around it.
//
// An error before the transport has a connection to the upstream is wrapped in
// api.ErrDispatchNotSent: no byte of the request can have left. Every later
// failure (a transport error, a timeout, an error status, a body cut after the
// status line) is a dispatch that may have reached the provider, which the
// gateway debits at its hold (helm-tracker#313, audit H8). An answer whose
// usage cannot be read or priced is returned with UsageUnknown set, for the
// same settlement. An answer from another model than the quoted one is priced
// at the dearer of the two, and the mismatch is recorded (audit M18).
func (u *Upstream) Dispatch(ctx context.Context, inboundPath string, quote *economic.RouteQuote, body []byte) (api.DispatchOutcome, error) {
	payload, err := rewriteModel(body, quote)
	if err != nil {
		return api.DispatchOutcome{}, notSent(err)
	}
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.upstreamURL(inboundPath), bytes.NewReader(payload))
	if err != nil {
		return api.DispatchOutcome{}, notSent(fmt.Errorf("spendproxy: build upstream request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+u.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("spendproxy: upstream request failed: %w", err)
		if !connected.Load() {
			return api.DispatchOutcome{}, notSent(err)
		}
		return api.DispatchOutcome{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse))
	if err != nil {
		return api.DispatchOutcome{}, fmt.Errorf("spendproxy: read upstream response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return api.DispatchOutcome{}, fmt.Errorf("spendproxy: upstream status %d: %s", resp.StatusCode, snippet(raw, 512))
	}

	var parsed struct {
		ID    string       `json:"id"`
		Model *string      `json:"model"`
		Usage *openAIUsage `json:"usage"`
	}
	parseErr := json.Unmarshal(raw, &parsed)
	requestID := parsed.ID
	if requestID == "" {
		requestID = "upstream-" + quote.ID
	}
	outcome := api.DispatchOutcome{ResponseBody: raw, ProviderRequestID: requestID}
	in, out, usageSeen := parsed.Usage.tokens()
	if parseErr != nil || !usageSeen || in < 0 || out < 0 {
		// The provider answered, so it may have billed the call, but its usage
		// is not readable: the gateway settles at the hold.
		outcome.UsageUnknown = true
		return outcome, nil
	}
	cost, err := u.CostCents(quote, in, out)
	if err != nil {
		outcome.UsageUnknown = true
		return outcome, nil
	}
	if responded := stringOrEmpty(parsed.Model); !sameModel(responded, quote.SelectedModelID) {
		cost = u.mismatchCost(quote, responded, cost, in, out)
		outcome.Notes = map[string]string{"response_model": responded, "model_mismatch": "true"}
	}
	outcome.ProviderCostCents, outcome.InputTokens, outcome.OutputTokens = cost, in, out
	return outcome, nil
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// datedSnapshot matches the version suffix providers append to a model id in
// their answers: gpt-4o-mini answers as gpt-4o-mini-2024-07-18, and Anthropic
// models carry an 8-digit date.
var datedSnapshot = regexp.MustCompile(`^-(\d{4}-\d{2}-\d{2}|\d{8})$`)

// sameModel reports whether a provider's answer names the quoted model: the
// same id, or the same id with a dated snapshot suffix. An answer that names no
// model does not.
func sameModel(responded, quoted string) bool {
	if responded == quoted {
		return true
	}
	rest, ok := strings.CutPrefix(responded, quoted)
	return ok && datedSnapshot.MatchString(rest)
}

// mismatchCost prices an answer from another model than the quoted one at the
// dearer of the two: the responded model's price when the price book has it
// for the quoted provider, or, for a model it cannot price, at least the hold.
func (u *Upstream) mismatchCost(quote *economic.RouteQuote, responded string, quotedCost, in, out int64) int64 {
	if responded != "" {
		if snap, ok := u.Prices.Snapshot(quote.SelectedProviderID, responded); ok {
			if cost, err := snap.QuoteCents(in, out); err == nil {
				return max(quotedCost, cost)
			}
		}
	}
	return max(quotedCost, quote.MaxAmountCents)
}

// StreamOutcome is what a completed (or interrupted) SSE stream yields for
// settlement.
type StreamOutcome struct {
	ProviderRequestID string
	InputTokens       int64
	OutputTokens      int64
	UsageSeen         bool
}

// DispatchStream performs a streaming chat-completions call, piping the SSE
// bytes to the client verbatim while tee-parsing the chunks for the provider
// request id and the final usage block. The caller must have set governance
// headers before this writes the 200 status line.
//
// A nil error with UsageSeen=false means the stream ended without a usage
// chunk; the caller settles on quote estimates. A non-nil error alongside a
// non-nil outcome means the stream broke mid-flight — money may have been
// spent, so the caller MUST still settle.
func (u *Upstream) DispatchStream(w http.ResponseWriter, r *http.Request, quote *economic.RouteQuote, body []byte) (*StreamOutcome, error) {
	payload, err := rewriteModel(body, quote)
	if err != nil {
		return nil, err
	}
	payload, err = ensureIncludeUsage(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u.upstreamURL(r.URL.Path), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("spendproxy: build upstream request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+u.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("spendproxy: upstream request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("spendproxy: upstream status %d: %s", resp.StatusCode, snippet(raw, 512))
	}

	// Stream begins: from here on the dispatch has happened and the caller
	// must settle regardless of how the copy ends.
	outcome := &StreamOutcome{ProviderRequestID: "upstream-" + quote.ID}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/event-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			if _, writeErr := w.Write(line); writeErr == nil && flusher != nil {
				flusher.Flush()
			}
			parseSSELine(line, outcome)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return outcome, nil
			}
			return outcome, fmt.Errorf("spendproxy: upstream stream interrupted: %w", readErr)
		}
	}
}

// ensureIncludeUsage asks the upstream for the final usage chunk so settlement
// can use actual token counts. Existing stream_options fields are preserved.
func ensureIncludeUsage(body []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("spendproxy: parse streaming request body: %w", err)
	}
	var opts map[string]json.RawMessage
	if raw, ok := fields["stream_options"]; ok {
		if err := json.Unmarshal(raw, &opts); err != nil {
			return nil, fmt.Errorf("spendproxy: parse stream_options: %w", err)
		}
	}
	if opts == nil {
		opts = make(map[string]json.RawMessage, 1)
	}
	opts["include_usage"] = json.RawMessage("true")
	encoded, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	fields["stream_options"] = encoded
	return json.Marshal(fields)
}

// parseSSELine extracts the provider request id and usage from an SSE data
// line. Non-data lines and [DONE] are ignored.
func parseSSELine(line []byte, outcome *StreamOutcome) {
	trimmed := bytes.TrimSpace(line)
	if !bytes.HasPrefix(trimmed, []byte("data:")) {
		return
	}
	data := bytes.TrimSpace(trimmed[len("data:"):])
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}
	var chunk struct {
		ID    string       `json:"id"`
		Usage *openAIUsage `json:"usage"`
	}
	if err := json.Unmarshal(data, &chunk); err != nil {
		return
	}
	if chunk.ID != "" {
		outcome.ProviderRequestID = chunk.ID
	}
	if in, out, ok := chunk.Usage.tokens(); ok {
		outcome.InputTokens = in
		outcome.OutputTokens = out
		outcome.UsageSeen = true
	}
}

func snippet(raw []byte, limit int) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
