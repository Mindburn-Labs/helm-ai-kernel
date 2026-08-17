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
	"strings"
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

// Dispatch performs one buffered (non-streaming) upstream call. It satisfies
// api.ProviderDispatch modulo the pre-dispatch persistence wrapper the server
// adds around it.
func (u *Upstream) Dispatch(ctx context.Context, inboundPath string, quote *economic.RouteQuote, body []byte) (api.DispatchOutcome, error) {
	payload, err := rewriteModel(body, quote)
	if err != nil {
		return api.DispatchOutcome{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.upstreamURL(inboundPath), bytes.NewReader(payload))
	if err != nil {
		return api.DispatchOutcome{}, fmt.Errorf("spendproxy: build upstream request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+u.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.Client.Do(req)
	if err != nil {
		return api.DispatchOutcome{}, fmt.Errorf("spendproxy: upstream request failed: %w", err)
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
		Usage *openAIUsage `json:"usage"`
	}
	// Tolerate non-JSON success bodies: settlement then uses quote estimates.
	_ = json.Unmarshal(raw, &parsed)

	in, out, usageSeen := parsed.Usage.tokens()
	if !usageSeen {
		// Conservative: settle at the quoted estimate rather than under-charge.
		in, out = quote.InputTokens, quote.OutputTokens
	}
	cost, err := u.CostCents(quote, in, out)
	if err != nil {
		return api.DispatchOutcome{}, err
	}
	requestID := parsed.ID
	if requestID == "" {
		requestID = "upstream-" + quote.ID
	}
	return api.DispatchOutcome{
		ResponseBody:      raw,
		ProviderRequestID: requestID,
		ProviderCostCents: cost,
		InputTokens:       in,
		OutputTokens:      out,
	}, nil
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
