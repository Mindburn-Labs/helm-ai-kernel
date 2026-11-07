// quantum_posture: LIG spend-receipt verification uses classical Ed25519;
// privacy filtering adds no post-quantum cryptographic control or assurance.
// Package gateway provides the Local Inference Gateway (LIG).
package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
)

// GatewayRouter normalizes capability requests across providers.
type GatewayRouter struct {
	activeProfile           *Profile
	client                  *http.Client
	budgetVerdictReceiptKey map[string]ed25519.PublicKey
}

type EnginePinMismatchError struct {
	Field string
	Got   string
	Want  string
}

type SpendVerdictError struct {
	Decision *economic.SpendAuthorityDecision
	Reason   string
}

// NewGatewayRouter creates a new Local Inference Gateway router.
func NewGatewayRouter() *GatewayRouter {
	return &GatewayRouter{client: &http.Client{Timeout: 30 * time.Second}}
}

type RouteConfig struct {
	Provider            ProviderType
	BaseURL             string
	ModelName           string
	ModelHash           string
	ProfileID           string
	RuntimeVersion      string
	VerifierProfileID   string
	AttestedMeasurement string
	AlternateProfileID  string
	EnginePin           *EnginePin
}

// RouteWithConfig binds a concrete local provider endpoint and model identity.
func (r *GatewayRouter) RouteWithConfig(_ context.Context, cfg RouteConfig) error {
	if cfg.Provider == "" {
		return errors.New("lig: provider is required")
	}
	if !isKnownProvider(cfg.Provider) {
		return fmt.Errorf("lig: unsupported provider %q", cfg.Provider)
	}
	if cfg.ModelName == "" {
		return errors.New("lig: model is required")
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL(cfg.Provider)
	}
	normalized, err := normalizeBaseURL(baseURL)
	if err != nil {
		return err
	}

	profile := Profile{
		ID:                  cfg.ProfileID,
		Provider:            cfg.Provider,
		BaseURL:             normalized,
		ModelName:           cfg.ModelName,
		ModelHash:           cfg.ModelHash,
		RuntimeVersion:      cfg.RuntimeVersion,
		VerifierProfileID:   cfg.VerifierProfileID,
		AttestedMeasurement: cfg.AttestedMeasurement,
		AlternateProfileID:  cfg.AlternateProfileID,
		EnginePin:           cfg.EnginePin,
		Capabilities: Capabilities{
			SupportsStreaming: true,
			SupportsJSONMode:  true,
			SupportsTools:     cfg.Provider != ProviderLlamaCPP,
			MaxContextWindow:  8192,
		},
	}
	if profile.ID == "" {
		profile.ID = "local/" + string(cfg.Provider)
	}
	r.activeProfile = &profile
	return nil
}

// ActiveProfile returns the currently bound profile.
func (r *GatewayRouter) ActiveProfile() *Profile {
	return r.activeProfile
}

// HealthCheck verifies that the bound provider endpoint is reachable.
func (r *GatewayRouter) HealthCheck(ctx context.Context) error {
	if r.activeProfile == nil {
		return errors.New("lig: no active profile routed; must call Route() first")
	}
	_, err := r.runtimeVersion(ctx, *r.activeProfile)
	return err
}

// ExecContext represents normalized LLM execution parameters within HELM.
type ExecContext struct {
	Prompt        string
	Temperature   float32
	System        string
	JSONMode      bool
	Tools         []string
	SpendDecision *economic.SpendAuthorityDecision
	SpendReceipt  *economic.BudgetVerdictReceipt
}

// ExecResult encapsulates normalized output and telemetry for receipts.
type ExecResult struct {
	Content           string
	GatewayID         string
	RuntimeType       ProviderType
	RuntimeVersion    string
	ModelHash         string
	BudgetVerdict     economic.BudgetVerdict
	SpendReasonCode   economic.SpendReasonCode
	SpendDecisionHash string
	SpendReceiptHash  string
	Duration          time.Duration
}

type budgetVerdictDispatchPermit struct {
	decisionHash string
	receiptHash  string
}

func isKnownProvider(provider ProviderType) bool {
	switch provider {
	case ProviderOllama, ProviderLlamaCPP, ProviderVLLM, ProviderLMStudio:
		return true
	default:
		return false
	}
}

func defaultBaseURL(provider ProviderType) string {
	switch provider {
	case ProviderOllama:
		return "http://localhost:11434"
	case ProviderLlamaCPP:
		return "http://localhost:8080"
	case ProviderVLLM:
		return "http://localhost:8000"
	case ProviderLMStudio:
		return "http://localhost:1234"
	default:
		return ""
	}
}

func normalizeBaseURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("lig: base URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("lig: invalid base URL %q", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (r *GatewayRouter) runtimeVersion(ctx context.Context, profile Profile) (string, error) {
	switch profile.Provider {
	case ProviderOllama:
		var out struct {
			Version string `json:"version"`
		}
		if err := r.getJSON(ctx, profile.BaseURL+"/api/version", &out); err != nil {
			return "", err
		}
		if out.Version == "" {
			return "", errors.New("lig: Ollama did not report a runtime version")
		}
		return out.Version, nil
	case ProviderVLLM:
		var out struct {
			Version string `json:"version"`
		}
		if err := r.getJSON(ctx, profile.BaseURL+"/version", &out); err == nil && out.Version != "" {
			return out.Version, nil
		}
		return r.openAICompatibleHealth(ctx, profile)
	case ProviderLlamaCPP, ProviderLMStudio:
		return r.openAICompatibleHealth(ctx, profile)
	default:
		return "", fmt.Errorf("lig: unsupported provider %q", profile.Provider)
	}
}

func (r *GatewayRouter) openAICompatibleHealth(ctx context.Context, profile Profile) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profile.BaseURL+"/v1/models", nil)
	if err != nil {
		return "", err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("lig: provider health failed: HTTP %d", resp.StatusCode)
	}
	version := strings.TrimSpace(resp.Header.Get("Server"))
	if version == "" {
		version = "openai-compatible"
	}
	return version, nil
}

func (r *GatewayRouter) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("lig: provider GET failed: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, privacy.MaxPayloadBytes+1))
	if err != nil {
		return errors.New("lig: provider response read failed")
	}
	protected, _, err := privacy.ProtectModelResponseJSON(ctx, json.RawMessage(data))
	if err != nil {
		return privacy.ErrDataEgressBlocked
	}
	return json.Unmarshal(protected, out)
}
