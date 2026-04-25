// Package gateway provides the Local Inference Gateway (LIG).
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GatewayRouter normalizes capability requests across providers.
type GatewayRouter struct {
	activeProfile *Profile
	client        *http.Client
}

// NewGatewayRouter creates a new Local Inference Gateway router.
func NewGatewayRouter() *GatewayRouter {
	return &GatewayRouter{client: &http.Client{Timeout: 30 * time.Second}}
}

type RouteConfig struct {
	Provider  ProviderType
	BaseURL   string
	ModelName string
	ModelHash string
	ProfileID string
}

// Route binds one of the built-in provider profiles.
func (r *GatewayRouter) Route(ctx context.Context, profileID string) error {
	_ = ctx
	profiles := GetBlessedProfiles()
	var selected *Profile
	for _, p := range profiles {
		if p.ID == profileID {
			pcopy := p
			selected = &pcopy
			break
		}
	}

	if selected == nil {
		return fmt.Errorf("lig: access denied, unknown profile %q", profileID)
	}

	r.activeProfile = selected
	return nil
}

// RouteWithConfig binds a concrete local provider endpoint and model identity.
func (r *GatewayRouter) RouteWithConfig(_ context.Context, cfg RouteConfig) error {
	if cfg.Provider == "" {
		return errors.New("lig: provider is required")
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
		ID:        cfg.ProfileID,
		Provider:  cfg.Provider,
		BaseURL:   normalized,
		ModelName: cfg.ModelName,
		ModelHash: cfg.ModelHash,
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
	Prompt      string
	Temperature float32
	System      string
	JSONMode    bool
	Tools       []string
}

// ExecResult encapsulates normalized output and telemetry for receipts.
type ExecResult struct {
	Content        string
	GatewayID      string
	RuntimeType    ProviderType
	RuntimeVersion string
	ModelHash      string
	Duration       time.Duration
}

// Execute performs an inference request, enforcing LIG constraints.
func (r *GatewayRouter) Execute(ctx context.Context, req ExecContext) (*ExecResult, error) {
	if r.activeProfile == nil {
		return nil, errors.New("lig: no active profile routed; must call Route() first")
	}

	if req.JSONMode && !r.activeProfile.Capabilities.SupportsJSONMode {
		return nil, fmt.Errorf("lig: capability constraint violation; model %s does not support JSON mode", r.activeProfile.ID)
	}
	if len(req.Tools) > 0 && !r.activeProfile.Capabilities.SupportsTools {
		return nil, fmt.Errorf("lig: capability constraint violation; model %s does not support tools", r.activeProfile.ID)
	}

	modelHash := r.activeProfile.ModelHash
	if modelHash == "" {
		discovered, err := r.discoverModelHash(ctx, *r.activeProfile)
		if err != nil {
			return nil, err
		}
		modelHash = discovered
	}
	if modelHash == "" {
		return nil, errors.New("lig: model hash is required and could not be discovered")
	}

	start := time.Now()
	version, err := r.runtimeVersion(ctx, *r.activeProfile)
	if err != nil {
		return nil, err
	}
	content, err := r.executeProvider(ctx, *r.activeProfile, req)
	if err != nil {
		return nil, err
	}

	return &ExecResult{
		Content:        content,
		GatewayID:      r.activeProfile.ID,
		RuntimeType:    r.activeProfile.Provider,
		RuntimeVersion: version,
		ModelHash:      modelHash,
		Duration:       time.Since(start),
	}, nil
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

func (r *GatewayRouter) discoverModelHash(ctx context.Context, profile Profile) (string, error) {
	if profile.Provider != ProviderOllama {
		return "", nil
	}
	var tags struct {
		Models []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"models"`
	}
	if err := r.getJSON(ctx, profile.BaseURL+"/api/tags", &tags); err != nil {
		return "", err
	}
	for _, model := range tags.Models {
		if model.Name == profile.ModelName && model.Digest != "" {
			return model.Digest, nil
		}
	}
	return "", nil
}

func (r *GatewayRouter) executeProvider(ctx context.Context, profile Profile, req ExecContext) (string, error) {
	if profile.Provider == ProviderOllama {
		return r.executeOllama(ctx, profile, req)
	}
	return r.executeOpenAICompatible(ctx, profile, req)
}

func (r *GatewayRouter) executeOllama(ctx context.Context, profile Profile, req ExecContext) (string, error) {
	payload := map[string]any{
		"model":  profile.ModelName,
		"stream": false,
		"messages": []map[string]string{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.Prompt},
		},
		"options": map[string]any{"temperature": req.Temperature},
	}
	if req.JSONMode {
		payload["format"] = "json"
	}
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := r.postJSON(ctx, profile.BaseURL+"/api/chat", payload, &out); err != nil {
		return "", err
	}
	if out.Message.Content == "" {
		return "", errors.New("lig: Ollama returned empty content")
	}
	return out.Message.Content, nil
}

func (r *GatewayRouter) executeOpenAICompatible(ctx context.Context, profile Profile, req ExecContext) (string, error) {
	messages := []map[string]string{}
	if req.System != "" {
		messages = append(messages, map[string]string{"role": "system", "content": req.System})
	}
	messages = append(messages, map[string]string{"role": "user", "content": req.Prompt})

	payload := map[string]any{
		"model":       profile.ModelName,
		"messages":    messages,
		"temperature": req.Temperature,
		"stream":      false,
	}
	if req.JSONMode {
		payload["response_format"] = map[string]string{"type": "json_object"}
	}
	if len(req.Tools) > 0 {
		payload["tools"] = req.Tools
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := r.postJSON(ctx, profile.BaseURL+"/v1/chat/completions", payload, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 || out.Choices[0].Message.Content == "" {
		return "", errors.New("lig: provider returned empty content")
	}
	return out.Choices[0].Message.Content, nil
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("lig: GET %s failed: HTTP %d %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (r *GatewayRouter) postJSON(ctx context.Context, endpoint string, payload any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("lig: POST %s failed: HTTP %d %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
