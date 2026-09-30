// Package modelgw is the model gateway (HELM-752, target architecture §8,
// ADR-0003): one gateway for every model call, in Zone C beside the effect
// gateway it is built on. Unmodified clients (the OpenAI and Anthropic SDKs,
// Claude Code and the Claude Agent SDK, the OpenAI Agents SDK, Codex) point
// their base URL at it and speak their own API: the gateway passes each API's
// native request and response through unchanged, except the maximum output
// tokens it clamps or injects, and puts every call through the effect
// gateway's admission.
//
// Every call is one model.inference attempt. The gateway prices the worst
// case, proposes it as the caller (the tenant, workspace and principal come
// from the token alone, R9), claims the permit, injects the provider key that
// only the gateway holds (R8), streams the response back while keeping a copy,
// and settles the provider-reported usage against the reservation. The same
// request in the same episode is answered from the stored response and never
// reaches the provider twice (R6).
package modelgw

// quantum_posture: SHA-256 request digests and content addresses; no signature
// is made or verified here, and no post-quantum claim is made.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// EnvRoutesFile names the routes file: providers, routes and prices
// (HELM_GATEWAY_MODEL_ROUTES_FILE). Without it the gateway serves no model
// endpoints.
const EnvRoutesFile = "HELM_GATEWAY_MODEL_ROUTES_FILE"

// The provider kinds. anthropic and openai are the vendors' own APIs;
// openai-compatible is any upstream that speaks OpenAI's wire format, such as
// OpenRouter, so any model can be a route.
const (
	KindAnthropic        = "anthropic"
	KindOpenAI           = "openai"
	KindOpenAICompatible = "openai-compatible"
)

// The provider auth styles: how the gateway presents a key upstream.
const (
	AuthXAPIKey = "x-api-key"
	AuthBearer  = "bearer"
)

// PriceUnit is the only unit prices are written in: integer usd_micros per
// million tokens, so a tariff such as USD 0.042 per million tokens is exactly
// 42000 and no price is rounded.
const PriceUnit = "usd_micros_per_million_tokens"

// The maximum-output-token field a chat route injects when the request names
// none.
const (
	ChatMaxCompletionTokens = "max_completion_tokens"
	ChatMaxTokens           = "max_tokens"
)

// Limits' defaults and bounds.
const (
	defaultMaxRequestBytes = 8 << 20
	defaultMaxReplayBytes  = 8 << 20
	maxReplayBytesCeiling  = 64 << 20
	defaultReplayTTL       = 2 * time.Hour
	defaultCallTimeout     = 20 * time.Minute
	defaultIdleTimeout     = 10 * time.Minute
	maxConfigBytes         = 1 << 20
	maxPriceMicros         = 1_000_000_000_000
	maxOutputTokensCeiling = 1 << 20
)

var (
	providerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	// A route id is the mandate target: exact strings, no spaces or controls.
	routeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)
	modelPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
)

// File is the routes file. It is closed: an unknown field is a refusal.
type File struct {
	Version   int        `json:"version"`
	Providers []Provider `json:"providers"`
	Routes    []Route    `json:"routes"`
	Limits    *Limits    `json:"limits,omitempty"`
}

// Provider is an upstream and where its key is. The key file is a path, never
// the key: the chart mounts it into the gateway Pod only.
type Provider struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// BaseURL is https (http on a loopback address, for development only).
	// For anthropic it is the API root without a version, for the OpenAI kinds
	// it includes the version prefix, such as https://api.openai.com/v1.
	BaseURL string `json:"base_url"`
	KeyFile string `json:"key_file"`
	// Auth overrides how the key is presented: x-api-key (the default for
	// anthropic) or bearer (the default for the OpenAI kinds).
	Auth string `json:"auth,omitempty"`
}

// Route is a priced model on a provider. Its ID is what a mandate's targets
// name; a request's model may be the ID or the provider's model id.
type Route struct {
	ID       string   `json:"id"`
	Provider string   `json:"provider"`
	Model    string   `json:"model"`
	APIs     []string `json:"apis"`
	Price    Price    `json:"price"`
	// DefaultMaxOutputTokens is injected when a request names none;
	// MaxOutputTokens is the clamp.
	DefaultMaxOutputTokens int64 `json:"default_max_output_tokens"`
	MaxOutputTokens        int64 `json:"max_output_tokens"`
	// ChatMaxTokensField is the field an openai-chat request gets when it
	// names no maximum: max_completion_tokens (the default for openai) or
	// max_tokens (the default for openai-compatible).
	ChatMaxTokensField string `json:"chat_max_tokens_field,omitempty"`
}

// Price is a tariff in PriceUnit. Input and Output are required (an unpriced
// route is refused, ADR-0003); the cache prices default to Input, which claims
// no discount and no surcharge.
type Price struct {
	Unit         string `json:"unit"`
	Input        *int64 `json:"input"`
	Output       *int64 `json:"output"`
	CacheRead    *int64 `json:"cache_read,omitempty"`
	CacheWrite5m *int64 `json:"cache_write_5m,omitempty"`
	CacheWrite1h *int64 `json:"cache_write_1h,omitempty"`
}

// Limits bounds what the gateway buffers and how long a call runs. Durations
// are Go durations.
type Limits struct {
	MaxRequestBytes int64  `json:"max_request_bytes,omitempty"`
	MaxReplayBytes  int64  `json:"max_replay_bytes,omitempty"`
	ReplayTTL       string `json:"replay_ttl,omitempty"`
	CallTimeout     string `json:"call_timeout,omitempty"`
	IdleTimeout     string `json:"idle_timeout,omitempty"`
}

// Config is a validated routes file.
type Config struct {
	providers map[string]*Provider
	routes    []*Route
	byName    map[string]map[string]*Route // api -> request model name -> route

	MaxRequestBytes int64
	MaxReplayBytes  int64
	ReplayTTL       time.Duration
	CallTimeout     time.Duration
	IdleTimeout     time.Duration
}

// LoadConfig reads and validates the routes file at path.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured routes file path
	if err != nil {
		return nil, fmt.Errorf("model routes: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("model routes: %w", err)
	}
	if len(raw) > maxConfigBytes {
		return nil, fmt.Errorf("model routes: the file is more than %d bytes", maxConfigBytes)
	}
	return ParseConfig(raw)
}

// ParseConfig validates a routes file. It reads no key file: the custody does,
// and refuses a missing one when the gateway starts.
func ParseConfig(raw []byte) (*Config, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("model routes: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("model routes: trailing data after the routes object")
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("model routes: version must be 1, got %d", f.Version)
	}
	c := &Config{providers: map[string]*Provider{}, byName: map[string]map[string]*Route{}}
	for i := range f.Providers {
		p := f.Providers[i]
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("model routes: provider %d (%q): %w", i, p.ID, err)
		}
		if _, dup := c.providers[p.ID]; dup {
			return nil, fmt.Errorf("model routes: provider %q is defined twice", p.ID)
		}
		c.providers[p.ID] = &p
	}
	if len(c.providers) == 0 {
		return nil, errors.New("model routes: no providers")
	}
	ids := map[string]bool{}
	for i := range f.Routes {
		r := f.Routes[i]
		p := c.providers[r.Provider]
		if p == nil {
			return nil, fmt.Errorf("model routes: route %q names unknown provider %q", r.ID, r.Provider)
		}
		if err := r.validate(p); err != nil {
			return nil, fmt.Errorf("model routes: route %d (%q): %w", i, r.ID, err)
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("model routes: route %q is defined twice", r.ID)
		}
		ids[r.ID] = true
		c.routes = append(c.routes, &r)
	}
	if len(c.routes) == 0 {
		return nil, errors.New("model routes: no routes")
	}
	// A request names a model by the route id or the provider's model id. On
	// one API a name must mean one route, or the gateway would guess which
	// budget a call belongs to.
	for _, r := range c.routes {
		for _, api := range r.APIs {
			if c.byName[api] == nil {
				c.byName[api] = map[string]*Route{}
			}
			for _, name := range slices.Compact([]string{r.ID, r.Model}) {
				if other, dup := c.byName[api][name]; dup && other != r {
					return nil, fmt.Errorf("model routes: %q names both route %q and route %q on %s", name, other.ID, r.ID, api)
				}
				c.byName[api][name] = r
			}
		}
	}
	sort.Slice(c.routes, func(i, j int) bool { return c.routes[i].ID < c.routes[j].ID })
	return c, c.applyLimits(f.Limits)
}

func (c *Config) applyLimits(l *Limits) error {
	c.MaxRequestBytes, c.MaxReplayBytes = defaultMaxRequestBytes, defaultMaxReplayBytes
	c.ReplayTTL, c.CallTimeout, c.IdleTimeout = defaultReplayTTL, defaultCallTimeout, defaultIdleTimeout
	if l == nil {
		return nil
	}
	if l.MaxRequestBytes != 0 {
		if l.MaxRequestBytes < 1<<10 || l.MaxRequestBytes > 256<<20 {
			return errors.New("model routes: limits.max_request_bytes must be 1 KiB to 256 MiB")
		}
		c.MaxRequestBytes = l.MaxRequestBytes
	}
	if l.MaxReplayBytes != 0 {
		if l.MaxReplayBytes < 1<<10 || l.MaxReplayBytes > maxReplayBytesCeiling {
			return errors.New("model routes: limits.max_replay_bytes must be 1 KiB to 64 MiB")
		}
		c.MaxReplayBytes = l.MaxReplayBytes
	}
	for name, spec := range map[string]struct {
		text   string
		lo, hi time.Duration
		into   *time.Duration
	}{
		"replay_ttl":   {l.ReplayTTL, time.Minute, 168 * time.Hour, &c.ReplayTTL},
		"call_timeout": {l.CallTimeout, time.Second, 2 * time.Hour, &c.CallTimeout},
		"idle_timeout": {l.IdleTimeout, time.Second, time.Hour, &c.IdleTimeout},
	} {
		if spec.text == "" {
			continue
		}
		d, err := time.ParseDuration(spec.text)
		if err != nil || d < spec.lo || d > spec.hi {
			return fmt.Errorf("model routes: limits.%s must be a duration from %s to %s", name, spec.lo, spec.hi)
		}
		*spec.into = d
	}
	return nil
}

func (p *Provider) validate() error {
	if !providerIDPattern.MatchString(p.ID) {
		return errors.New("id must be lowercase letters, digits and hyphens, starting with a letter")
	}
	switch p.Kind {
	case KindAnthropic, KindOpenAI, KindOpenAICompatible:
	default:
		return fmt.Errorf("kind must be %s, %s or %s", KindAnthropic, KindOpenAI, KindOpenAICompatible)
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base_url must be an absolute URL without credentials, query or fragment")
	}
	if !(u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return errors.New("base_url must be https (http only on a loopback address)")
	}
	p.BaseURL = strings.TrimRight(p.BaseURL, "/")
	if !filepath.IsAbs(p.KeyFile) || len(p.KeyFile) > 1024 || strings.ContainsRune(p.KeyFile, 0) {
		return errors.New("key_file must be an absolute path")
	}
	switch p.Auth {
	case "":
		p.Auth = AuthBearer
		if p.Kind == KindAnthropic {
			p.Auth = AuthXAPIKey
		}
	case AuthXAPIKey, AuthBearer:
	default:
		return fmt.Errorf("auth must be %s or %s", AuthXAPIKey, AuthBearer)
	}
	return nil
}

func (r *Route) validate(p *Provider) error {
	if !routeIDPattern.MatchString(r.ID) {
		return errors.New("id must be 1 to 128 characters of letters, digits and . _ : / @ + -")
	}
	if !modelPattern.MatchString(r.Model) {
		return errors.New("model must be the provider's model id: 1 to 256 characters of letters, digits and . _ : / @ + -")
	}
	if len(r.APIs) == 0 {
		return errors.New("apis is required")
	}
	seen := map[string]bool{}
	for _, api := range r.APIs {
		if seen[api] {
			return fmt.Errorf("api %q is listed twice", api)
		}
		seen[api] = true
		if !slices.Contains(APIs(), api) {
			return fmt.Errorf("api %q is not one of %s", api, strings.Join(APIs(), ", "))
		}
		if !providerServes(p.Kind, api) {
			return fmt.Errorf("provider %q (%s) does not serve %s", p.ID, p.Kind, api)
		}
	}
	if err := r.Price.validate(); err != nil {
		return err
	}
	if r.DefaultMaxOutputTokens < 1 || r.MaxOutputTokens < r.DefaultMaxOutputTokens || r.MaxOutputTokens > maxOutputTokensCeiling {
		return fmt.Errorf("default_max_output_tokens and max_output_tokens must satisfy 1 <= default <= max <= %d", maxOutputTokensCeiling)
	}
	switch r.ChatMaxTokensField {
	case "":
		r.ChatMaxTokensField = ChatMaxCompletionTokens
		if p.Kind == KindOpenAICompatible {
			r.ChatMaxTokensField = ChatMaxTokens
		}
	case ChatMaxCompletionTokens, ChatMaxTokens:
		if !seen[effectargs.APIOpenAIChat] {
			return errors.New("chat_max_tokens_field needs the openai-chat api")
		}
	default:
		return fmt.Errorf("chat_max_tokens_field must be %s or %s", ChatMaxCompletionTokens, ChatMaxTokens)
	}
	return nil
}

func (pr *Price) validate() error {
	if pr.Unit != PriceUnit {
		return fmt.Errorf("price.unit must be %q", PriceUnit)
	}
	if pr.Input == nil || pr.Output == nil {
		return errors.New("price.input and price.output are required: an unpriced route is refused")
	}
	for name, v := range map[string]*int64{"input": pr.Input, "output": pr.Output, "cache_read": pr.CacheRead,
		"cache_write_5m": pr.CacheWrite5m, "cache_write_1h": pr.CacheWrite1h} {
		if v != nil && (*v < 0 || *v > maxPriceMicros) {
			return fmt.Errorf("price.%s must be from 0 to %d", name, maxPriceMicros)
		}
	}
	return nil
}

// APIs are the model APIs the gateway passes through natively.
func APIs() []string {
	return []string{effectargs.APIOpenAIResponses, effectargs.APIOpenAIChat, effectargs.APIAnthropicMessages}
}

// providerServes reports whether a provider kind can serve an API: the vendors
// serve their own, and an OpenAI-compatible upstream may serve any.
func providerServes(kind, api string) bool {
	switch kind {
	case KindAnthropic:
		return api == effectargs.APIAnthropicMessages
	case KindOpenAI:
		return api == effectargs.APIOpenAIResponses || api == effectargs.APIOpenAIChat
	}
	return true
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Resolve returns the route a request's model names on api.
func (c *Config) Resolve(api, model string) (*Route, bool) {
	r, ok := c.byName[api][model]
	return r, ok
}

// Routes returns every route by id.
func (c *Config) Routes() []*Route { return slices.Clone(c.routes) }

// Provider returns a provider by id.
func (c *Config) Provider(id string) *Provider { return c.providers[id] }

// KeyFiles maps each provider to its key file, for the custody.
func (c *Config) KeyFiles() map[string]string {
	out := make(map[string]string, len(c.providers))
	for id, p := range c.providers {
		out[id] = p.KeyFile
	}
	return out
}

// Serves reports whether the route serves api.
func (r *Route) Serves(api string) bool { return slices.Contains(r.APIs, api) }
