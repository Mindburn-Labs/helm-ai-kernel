package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// proxySessionHeader names the caller session that --max-iterations and
// --max-wallclock are counted against. It must be a canonical UUID; without a
// valid one the request's correlation ID is its session.
const proxySessionHeader = "X-Helm-Session-ID"

// proxyLocalCredential is the transport identity of an unauthenticated
// loopback sidecar, the proxy's analogue of `mcp serve --auth none`.
const proxyLocalCredential = "helm-proxy-local"

func proxyRequestDirector(upstreamURL *url.URL, upstream, apiKey string) func(*http.Request) {
	return func(req *http.Request) {
		// helm correlation_id — also used as gen_ai.tool.call.id so OTel traces
		// and helm-ai-kernel receipts cross-reference 1:1.
		// Adopt-or-mint (telemetry contract §2.2): a valid inbound
		// X-Helm-Correlation-ID is honoured so a caller can thread one
		// product identity through the whole request path; anything
		// else is replaced with a freshly minted ID.
		corr, _ := tracing.AdoptOrMintFromHeaders(req.Header)
		ctx := tracing.WithCorrelationID(req.Context(), corr)
		ctx = context.WithValue(ctx, ctxKeyCorrelationID, string(corr))
		sessionID := strings.TrimSpace(req.Header.Get(proxySessionHeader))
		if !correlation.IsValid(sessionID) {
			sessionID = string(corr)
		}
		ctx = context.WithValue(ctx, ctxKeySessionID, sessionID)

		// Stamp the product identity onto the edge server span so OTel
		// traces and receipts join 1:1 (HELM-333); same attribute the
		// governance tracer uses.
		oteltrace.SpanFromContext(ctx).SetAttributes(
			attribute.String(observability.HelmCorrelationID, string(corr)))

		// Inject W3C traceparent so the upstream provider's traces (if any)
		// link back into our governance trace tree. InjectHTTPHeaders also
		// sets the advisory X-Helm-Correlation-ID for upstreams that echo it.
		helmotel.InjectTraceparent(ctx, req.Header)
		tracing.InjectHTTPHeaders(ctx, req.Header)
		ctx = context.WithValue(ctx, ctxKeyTraceparent, req.Header.Get("traceparent"))

		*req = *req.WithContext(ctx)

		req.URL.Scheme = upstreamURL.Scheme
		req.URL.Host = upstreamURL.Host
		origPath := req.URL.Path
		if strings.HasPrefix(origPath, "/v1") && strings.HasSuffix(upstream, "/v1") {
			req.URL.Path = upstreamURL.Path + strings.TrimPrefix(origPath, "/v1")
		} else {
			req.URL.Path = upstreamURL.Path + origPath
		}
		req.Host = upstreamURL.Host

		// Let the transport negotiate compression itself so it decodes the
		// response before governance reads it. A client-chosen encoding would
		// reach ModifyResponse compressed, where no tool call can be parsed.
		req.Header.Del("Accept-Encoding")

		// Forward API key
		if apiKey != "" && req.Header.Get("Authorization") == "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
}

// writeStreamingToolsRefusal answers a request that asks for a streamed
// response while offering tools. The proxy cannot parse a stream, so it cannot
// hold a streamed tool call for a decision; the request never reaches the
// upstream (audit 03-02).
func writeStreamingToolsRefusal(w http.ResponseWriter) {
	const reason = "PROXY_STREAMING_TOOLS_REFUSED"
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": `HELM proxy cannot govern tool calls in a streamed response; send requests that declare tools with "stream": false`,
			"type":    "helm_governance_denied",
			"code":    reason,
		},
		"helm": map[string]any{"status": "STREAMING_TOOLS_REFUSED", "reason_code": reason},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Helm-Status", "STREAMING_TOOLS_REFUSED")
	w.Header().Set("X-Helm-Reason-Code", reason)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(body)
}
