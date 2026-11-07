package gateway

// ProviderType represents a known local LLM provider.
type ProviderType string

const (
	ProviderOllama   ProviderType = "ollama"
	ProviderLlamaCPP ProviderType = "llamacpp"
	ProviderVLLM     ProviderType = "vllm"
	ProviderLMStudio ProviderType = "lmstudio"
)

// Capabilities defines the normalized, explicitly verified feature set of a local provider.
type Capabilities struct {
	SupportsStreaming bool `json:"supports_streaming"`
	SupportsJSONMode  bool `json:"supports_json_mode"`
	SupportsTools     bool `json:"supports_tools"`
	SupportsVision    bool `json:"supports_vision"`
	MaxContextWindow  int  `json:"max_context_window"`
}

// Profile represents a deterministic provider binding.
type Profile struct {
	ID                  string       `json:"id"`
	Provider            ProviderType `json:"provider"`
	BaseURL             string       `json:"base_url"`
	ModelName           string       `json:"model_name"`
	ModelHash           string       `json:"model_hash,omitempty"`
	RuntimeVersion      string       `json:"runtime_version,omitempty"`
	VerifierProfileID   string       `json:"verifier_profile_id,omitempty"`
	AttestedMeasurement string       `json:"attested_measurement,omitempty"`
	AlternateProfileID  string       `json:"alternate_profile_id,omitempty"`
	EnginePin           *EnginePin   `json:"engine_pin,omitempty"`
	Capabilities        Capabilities `json:"capabilities"`
}

// EnginePin is the deterministic provider identity allowed for execution.
type EnginePin struct {
	Provider                   ProviderType `json:"provider"`
	BaseURL                    string       `json:"base_url,omitempty"`
	ModelName                  string       `json:"model_name,omitempty"`
	ModelHash                  string       `json:"model_hash,omitempty"`
	RuntimeVersion             string       `json:"runtime_version,omitempty"`
	VerifierProfileID          string       `json:"verifier_profile_id,omitempty"`
	AttestedMeasurement        string       `json:"attested_measurement,omitempty"`
	ApprovedAlternateProfileID string       `json:"approved_alternate_profile_id,omitempty"`
}
