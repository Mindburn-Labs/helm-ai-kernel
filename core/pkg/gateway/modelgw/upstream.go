package modelgw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// KeyProvider is the connection custody the gateway takes a provider's API key
// from, for one request at a time (custody.ProviderKeys, R8). Nothing else
// holds a provider credential.
type KeyProvider interface {
	Key(ctx context.Context, providerID string) (string, error)
}

// The headers the gateway forwards from the client to the provider. Anything
// else the client sent, its own credential included, stops here.
var forwardedRequestHeaders = []string{"Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

// The headers the gateway relays back from the provider. The provider's own
// Content-Encoding is not one: the transport decompresses, and the client gets
// the plain body.
var relayedResponseHeaders = []string{
	"Content-Type", "Cache-Control", "Retry-After", "Request-Id", "X-Request-Id", "X-Should-Retry",
	"Openai-Processing-Ms", "Openai-Version", "Anthropic-Organization-Id",
}

// The default Anthropic API version, sent when the client sent none.
const defaultAnthropicVersion = "2023-06-01"

// newHTTPClient is the client for provider calls. It ignores the environment's
// proxy settings, follows no redirect (a redirect would carry the key to
// another host), and puts no deadline of its own on a body: the call's context
// and the stream's idle timer end a call.
func newHTTPClient(cfg *Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          256,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: cfg.CallTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// providerURL is where a provider serves api. An Anthropic base URL is the API
// root, so the path carries the version; an OpenAI base URL includes it. Only
// Anthropic's own beta=true query is passed on.
func providerURL(p *Provider, api, rawQuery string) string {
	url := p.BaseURL
	switch api {
	case effectargs.APIOpenAIChat:
		url += "/chat/completions"
	case effectargs.APIOpenAIResponses:
		url += "/responses"
	default:
		if p.Kind == KindAnthropic {
			url += "/v1/messages"
		} else {
			url += "/messages"
		}
		if rawQuery == "beta=true" {
			url += "?beta=true"
		}
	}
	return url
}

// sent records how far a provider request got: whether the whole request,
// body included, left the gateway. Before that the provider cannot have acted
// on it, so a failure is a definite "not sent"; after it, it may have.
type sent struct{ written atomic.Bool }

// newProviderRequest builds the request for one call: the client's body, the
// allowlisted headers, and the provider's key in the header the provider takes
// it in. The key exists only in this request.
func newProviderRequest(ctx context.Context, p *Provider, c *call, key string, in http.Header, rawQuery string) (*http.Request, *sent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, providerURL(p, c.API, rawQuery), bytes.NewReader(c.Body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "helm-model-gateway")
	for _, name := range forwardedRequestHeaders {
		if v := in.Get(name); v != "" {
			req.Header.Set(name, v)
		}
	}
	if c.API == effectargs.APIAnthropicMessages && req.Header.Get("Anthropic-Version") == "" {
		req.Header.Set("Anthropic-Version", defaultAnthropicVersion)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if p.Auth == AuthXAPIKey {
		req.Header.Set("X-Api-Key", key)
	} else {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	state := &sent{}
	trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			state.written.Store(true)
		}
	}}
	return req.WithContext(httptrace.WithClientTrace(ctx, trace)), state, nil
}

var errIdle = errors.New("the provider's stream was idle too long")
