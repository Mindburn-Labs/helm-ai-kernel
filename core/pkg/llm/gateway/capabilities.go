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
	ID           string       `json:"id"`
	Provider     ProviderType `json:"provider"`
	BaseURL      string       `json:"base_url"`
	ModelName    string       `json:"model_name"`
	ModelHash    string       `json:"model_hash,omitempty"`
	Capabilities Capabilities `json:"capabilities"`
}

// GetBlessedProfiles returns provider profiles. Callers must bind a concrete
// model name and model hash before executing inference.
func GetBlessedProfiles() []Profile {
	return []Profile{
		{
			ID:        "local/ollama",
			Provider:  ProviderOllama,
			BaseURL:   "http://localhost:11434",
			ModelName: "local-model",
			Capabilities: Capabilities{
				SupportsStreaming: true,
				SupportsJSONMode:  true,
				SupportsTools:     true,
				MaxContextWindow:  32768,
			},
		},
		{
			ID:        "local/llamacpp",
			Provider:  ProviderLlamaCPP,
			BaseURL:   "http://localhost:8080",
			ModelName: "local-model",
			Capabilities: Capabilities{
				SupportsStreaming: true,
				SupportsJSONMode:  true,
				MaxContextWindow:  8192,
			},
		},
		{
			ID:        "local/vllm",
			Provider:  ProviderVLLM,
			BaseURL:   "http://localhost:8000",
			ModelName: "local-model",
			Capabilities: Capabilities{
				SupportsStreaming: true,
				SupportsJSONMode:  true,
				SupportsTools:     true,
				MaxContextWindow:  32768,
			},
		},
		{
			ID:        "local/lmstudio",
			Provider:  ProviderLMStudio,
			BaseURL:   "http://localhost:1234",
			ModelName: "local-model",
			Capabilities: Capabilities{
				SupportsStreaming: true,
				SupportsJSONMode:  true,
				SupportsTools:     true,
				MaxContextWindow:  32768,
			},
		},
	}
}
