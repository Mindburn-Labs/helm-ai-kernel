// Package spendproxy composes the SPEND3 RouteQuote engine
// (core/pkg/inferencegateway), the governed OpenAI-compatible gateway routes
// (core/pkg/api.GovernedGateway), a real cloud provider dispatch, in-process
// signed BudgetVerdict issuance, and durable JSONL receipt persistence into a
// locally runnable governed inference proxy: `helm-ai-kernel spend-proxy`.
//
// Fail-closed posture: there is no unreceipted dispatch path. Every upstream
// dispatch requires an ALLOW RouteQuote persisted to the durable store BEFORE
// the provider is called, and settlement receipts are appended as soon as the
// engine commits the debit. A receipt-store write failure refuses dispatch.
package spendproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// Config is the checked-in, snapshot-hashed configuration for the spend proxy.
// The sha256 of the raw config file bytes becomes the price-source hash bound
// into every ProviderPriceSnapshot (and therefore into every quote and
// receipt), so the exact price numbers used for a capture window are provable
// from the file alone.
type Config struct {
	// TenantID scopes every envelope, quote, and receipt the proxy emits.
	TenantID string `json:"tenant_id"`
	// TreasuryID is the settlement credit account for the double-entry ledger.
	TreasuryID string `json:"treasury_id"`
	// RoutePolicyID names the route policy; the engine hashes it together with
	// the TTL/stale/cap knobs into the RoutePolicyHash on every quote.
	RoutePolicyID string `json:"route_policy_id"`
	Currency      string `json:"currency"`
	// PlatformFeeBps is the platform fee in basis points of provider cost.
	PlatformFeeBps int64 `json:"platform_fee_bps"`
	// QuoteTTLSeconds must cover the full dispatch INCLUDING streaming time:
	// the engine refuses to settle an expired quote, so a stream that outlives
	// the TTL would leave an authorized-but-unsettled trail.
	QuoteTTLSeconds int64 `json:"quote_ttl_seconds"`
	// PriceTTLHours is how long the loaded price snapshots stay fresh. After
	// expiry the engine fails closed (ERR_PROVIDER_PRICE_STALE) until the proxy
	// is restarted against a re-captured price config.
	PriceTTLHours int64 `json:"price_ttl_hours"`

	Balance   BalanceConfig   `json:"balance"`
	Defaults  RequestDefaults `json:"request_defaults"`
	Providers []ProviderCfg   `json:"providers"`
	Prices    []PriceCfg      `json:"prices"`
	Envelopes []EnvelopeCfg   `json:"envelopes"`
}

// BalanceConfig funds the governed balance account backing settlements.
type BalanceConfig struct {
	AccountID    string `json:"account_id"`
	OpeningCents int64  `json:"opening_cents"`
}

// RequestDefaults are applied to inbound requests that carry no X-HELM-*
// governance headers (a stock OpenAI client repointed via OPENAI_BASE_URL).
// Defaulting is attribution only — the full quote/verdict/settle path still
// runs against the default envelope. Leave EnvelopeID empty to disable
// defaulting, in which case header-less requests fail closed with 400.
type RequestDefaults struct {
	WorkspaceID string `json:"workspace_id,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	PrincipalID string `json:"principal_id,omitempty"`
	EnvelopeID  string `json:"envelope_id,omitempty"`
}

// ProviderCfg declares a provider terms profile (legal/commercial boundary).
type ProviderCfg struct {
	ID string `json:"id"`
	// AccountMode is BYOK, DIRECT, or MANAGED_ORG_ACCOUNT.
	AccountMode    string `json:"account_mode"`
	TermsVersion   string `json:"terms_version"`
	LegalReviewRef string `json:"legal_review_ref"`
	ContractRef    string `json:"contract_ref,omitempty"`
}

// PriceCfg is one provider/model price entry. Token prices are micro-cents
// (1e-6 cents) per token: $2.50 per 1M tokens = 250 micro-cents per token.
type PriceCfg struct {
	ProviderID            string `json:"provider_id"`
	ModelID               string `json:"model_id"`
	InputTokenMicroCents  int64  `json:"input_token_micro_cents"`
	OutputTokenMicroCents int64  `json:"output_token_micro_cents"`
	RequestCents          int64  `json:"request_cents,omitempty"`
	SourceURI             string `json:"source_uri,omitempty"`
}

// RouteRef names a provider/model route inside an envelope fallback chain.
type RouteRef struct {
	ProviderID string `json:"provider_id"`
	ModelID    string `json:"model_id"`
}

// EnvelopeCfg declares one agent spend envelope. To capture a paired
// baseline-vs-substitute run, declare two envelopes: one that allows the
// baseline model directly, and one that allows only the substitute with
// AllowModelSubstitution=true so a request for the baseline is truthfully
// recorded as ModelSubstituted on its RouteQuote.
type EnvelopeCfg struct {
	ID                         string   `json:"id"`
	AgentID                    string   `json:"agent_id"`
	PrincipalID                string   `json:"principal_id"`
	BudgetID                   string   `json:"budget_id"`
	MaxAmountCents             int64    `json:"max_amount_cents"`
	PerRequestMaxCents         int64    `json:"per_request_max_cents"`
	ApprovalRequiredAboveCents int64    `json:"approval_required_above_cents,omitempty"`
	AllowedProviders           []string `json:"allowed_providers"`
	AllowedModels              []string `json:"allowed_models"`
	// FallbackRoutes doubles as the route-resolution table: the engine selects
	// routes from this chain, so every allowed model must appear here.
	FallbackRoutes         []RouteRef `json:"fallback_routes"`
	AllowModelSubstitution bool       `json:"allow_model_substitution"`
}

// LoadConfig reads and validates the config file, returning the parsed config
// and the sha256 source hash of the raw file bytes ("sha256:<hex>").
func LoadConfig(path string) (*Config, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("spendproxy: read config: %w", err)
	}
	sum := sha256.Sum256(raw)
	sourceHash := "sha256:" + hex.EncodeToString(sum[:])

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, "", fmt.Errorf("spendproxy: parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("spendproxy: config %s: %w", path, err)
	}
	return &cfg, sourceHash, nil
}

// Validate applies defaults and rejects configurations that could only fail
// later at runtime with a less useful error.
func (c *Config) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if c.TreasuryID == "" {
		return errors.New("treasury_id is required")
	}
	if c.RoutePolicyID == "" {
		return errors.New("route_policy_id is required")
	}
	if c.Currency == "" {
		return errors.New("currency is required")
	}
	if c.PlatformFeeBps < 0 {
		return errors.New("platform_fee_bps cannot be negative")
	}
	if c.QuoteTTLSeconds <= 0 {
		c.QuoteTTLSeconds = 300
	}
	if c.PriceTTLHours <= 0 {
		c.PriceTTLHours = 24
	}
	if c.Balance.AccountID == "" {
		return errors.New("balance.account_id is required")
	}
	if c.Balance.OpeningCents <= 0 {
		return errors.New("balance.opening_cents must be positive")
	}
	if len(c.Providers) == 0 {
		return errors.New("at least one provider is required")
	}
	providerIDs := make(map[string]struct{}, len(c.Providers))
	for i, p := range c.Providers {
		if p.ID == "" || p.AccountMode == "" || p.TermsVersion == "" || p.LegalReviewRef == "" {
			return fmt.Errorf("providers[%d]: id, account_mode, terms_version, legal_review_ref are required", i)
		}
		providerIDs[p.ID] = struct{}{}
	}
	if len(c.Prices) == 0 {
		return errors.New("at least one price entry is required")
	}
	priceKeys := make(map[string]struct{}, len(c.Prices))
	for i, p := range c.Prices {
		if p.ProviderID == "" || p.ModelID == "" {
			return fmt.Errorf("prices[%d]: provider_id and model_id are required", i)
		}
		if _, ok := providerIDs[p.ProviderID]; !ok {
			return fmt.Errorf("prices[%d]: provider %q has no terms profile", i, p.ProviderID)
		}
		if p.InputTokenMicroCents == 0 && p.OutputTokenMicroCents == 0 && p.RequestCents == 0 {
			return fmt.Errorf("prices[%d]: at least one price field must be set", i)
		}
		priceKeys[p.ProviderID+"\x00"+p.ModelID] = struct{}{}
	}
	if len(c.Envelopes) == 0 {
		return errors.New("at least one envelope is required")
	}
	envIDs := make(map[string]struct{}, len(c.Envelopes))
	for i, e := range c.Envelopes {
		if e.ID == "" || e.AgentID == "" || e.PrincipalID == "" || e.BudgetID == "" {
			return fmt.Errorf("envelopes[%d]: id, agent_id, principal_id, budget_id are required", i)
		}
		if e.MaxAmountCents <= 0 || e.PerRequestMaxCents <= 0 {
			return fmt.Errorf("envelopes[%d]: max_amount_cents and per_request_max_cents must be positive", i)
		}
		if len(e.AllowedProviders) == 0 || len(e.AllowedModels) == 0 {
			return fmt.Errorf("envelopes[%d]: allowed_providers and allowed_models are required", i)
		}
		for _, pid := range e.AllowedProviders {
			if _, ok := providerIDs[pid]; !ok {
				return fmt.Errorf("envelopes[%d]: allowed provider %q has no terms profile", i, pid)
			}
		}
		// Route resolution happens through the fallback chain, so every allowed
		// model must be reachable through it with a priced route.
		routed := make(map[string]struct{}, len(e.FallbackRoutes))
		for j, r := range e.FallbackRoutes {
			if r.ProviderID == "" || r.ModelID == "" {
				return fmt.Errorf("envelopes[%d].fallback_routes[%d]: provider_id and model_id are required", i, j)
			}
			if _, ok := priceKeys[r.ProviderID+"\x00"+r.ModelID]; !ok {
				return fmt.Errorf("envelopes[%d].fallback_routes[%d]: no price entry for %s/%s", i, j, r.ProviderID, r.ModelID)
			}
			routed[r.ModelID] = struct{}{}
		}
		for _, m := range e.AllowedModels {
			if _, ok := routed[m]; !ok {
				return fmt.Errorf("envelopes[%d]: allowed model %q is not in fallback_routes (route resolution would fail closed)", i, m)
			}
		}
		envIDs[e.ID] = struct{}{}
	}
	if c.Defaults.EnvelopeID != "" {
		if _, ok := envIDs[c.Defaults.EnvelopeID]; !ok {
			return fmt.Errorf("request_defaults.envelope_id %q is not a declared envelope", c.Defaults.EnvelopeID)
		}
		if c.Defaults.AgentID == "" {
			return errors.New("request_defaults.agent_id is required when request_defaults.envelope_id is set")
		}
	}
	return nil
}

// BuildBooks materializes the price and terms books from the config. Snapshots
// are stamped effective at load time and expire after PriceTTLHours; the
// config-file source hash is bound into every snapshot.
func (c *Config) BuildBooks(now time.Time, sourceHash string) (*inferencegateway.MemoryPriceBook, *inferencegateway.MemoryTermsBook, error) {
	terms := inferencegateway.NewMemoryTermsBook()
	for _, p := range c.Providers {
		profile := economic.NewProviderTermsProfile(
			termsProfileID(p.ID), p.ID, economic.ProviderAccountMode(p.AccountMode),
			p.TermsVersion, p.LegalReviewRef,
		)
		profile.TenantID = c.TenantID
		profile.ContractRef = p.ContractRef
		if err := terms.Put(profile); err != nil {
			return nil, nil, fmt.Errorf("spendproxy: terms profile %s: %w", p.ID, err)
		}
	}
	prices := inferencegateway.NewMemoryPriceBook()
	expiry := now.Add(time.Duration(c.PriceTTLHours) * time.Hour)
	for _, p := range c.Prices {
		snap := economic.NewProviderPriceSnapshot(
			priceSnapshotID(p.ProviderID, p.ModelID), p.ProviderID, p.ModelID,
			c.Currency, termsProfileID(p.ProviderID), sourceHash,
			now.Add(-time.Minute), expiry,
		)
		snap.InputTokenMicroCents = p.InputTokenMicroCents
		snap.OutputTokenMicroCents = p.OutputTokenMicroCents
		snap.RequestCents = p.RequestCents
		snap.SourceURI = p.SourceURI
		if err := prices.Put(snap); err != nil {
			return nil, nil, fmt.Errorf("spendproxy: price snapshot %s/%s: %w", p.ProviderID, p.ModelID, err)
		}
	}
	return prices, terms, nil
}

// BuildEnvelopes materializes the agent spend envelopes. The config source hash
// doubles as the envelope policy hash: envelope policy is exactly what the
// config file says it is.
func (c *Config) BuildEnvelopes(sourceHash string) (map[string]*economic.AgentSpendEnvelope, error) {
	out := make(map[string]*economic.AgentSpendEnvelope, len(c.Envelopes))
	for _, e := range c.Envelopes {
		env := economic.NewAgentSpendEnvelope(
			e.ID, c.TenantID, e.AgentID, e.PrincipalID, e.BudgetID,
			c.Currency, economic.SpendPeriodDaily,
			e.MaxAmountCents, e.PerRequestMaxCents, sourceHash,
		)
		env.AllowedProviders = append([]string(nil), e.AllowedProviders...)
		env.AllowedModels = append([]string(nil), e.AllowedModels...)
		env.ApprovalRequiredAboveCents = e.ApprovalRequiredAboveCents
		env.AllowModelSubstitution = e.AllowModelSubstitution
		routes := make([]economic.ModelRoute, 0, len(e.FallbackRoutes))
		for _, r := range e.FallbackRoutes {
			routes = append(routes, economic.ModelRoute{
				ProviderID: r.ProviderID,
				ModelID:    r.ModelID,
				// The engine copies this into the quote's
				// provider_price_snapshot_hash; binding the config source hash
				// here makes every quote provably priced from this config file.
				PriceSnapshotHash: sourceHash,
			})
		}
		env.FallbackModels = routes
		if err := env.Validate(); err != nil {
			return nil, fmt.Errorf("spendproxy: envelope %s: %w", e.ID, err)
		}
		out[e.ID] = env
	}
	return out, nil
}

func termsProfileID(providerID string) string { return "terms-" + providerID }

func priceSnapshotID(providerID, modelID string) string {
	return "price-" + providerID + "-" + sanitizeModelID(modelID)
}

func sanitizeModelID(modelID string) string {
	out := make([]rune, 0, len(modelID))
	for _, r := range modelID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
