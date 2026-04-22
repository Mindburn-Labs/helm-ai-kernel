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
// This prevents wild deviations in capabilities from polluting HELM logic.
type Capabilities struct {
	SupportsStreaming bool `json:"supports_streaming"`
	SupportsJSONMode  bool `json:"supports_json_mode"`
	SupportsTools     bool `json:"supports_tools"`
	SupportsVision    bool `json:"supports_vision"`
	MaxContextWindow  int  `json:"max_context_window"`
}

// Profile represents a deterministic blessed profile bound to a provider.
type Profile struct {
	ID           string       `json:"id"`
	Provider     ProviderType `json:"provider"`
	ModelName    string       `json:"model_name"`
	Capabilities Capabilities `json:"capabilities"`
}

// GetBlessedProfiles returns the canonical list of permitted local models.
// Restricting local execution to deterministic Blessed Profiles prevents 
// non-canonical "hype" models from polluting receipt truth.
func GetBlessedProfiles() []Profile {
	return []Profile{
		{
			ID:        "local/qwen-3.5-27b-reasoning-q4",
			Provider:  ProviderOllama,
			ModelName: "qwen:27b-v3.5-q4_K_M",
			Capabilities: Capabilities{
				SupportsStreaming: true,
				SupportsJSONMode:  true,
				SupportsTools:     true,
				MaxContextWindow:  32768,
			},
		},
		{
			ID:        "local/llama-3-70b-instruct-q4",
			Provider:  ProviderLlamaCPP,
			ModelName: "Meta-Llama-3-70B-Instruct.Q4_K_M.gguf",
			Capabilities: Capabilities{
				SupportsStreaming: true,
				SupportsJSONMode:  true,
				SupportsTools:     true,
				MaxContextWindow:  8192,
			},
		},
		{
			ID:        "local/embedding/bge-m3",
			Provider:  ProviderOllama,
			ModelName: "bge-m3:latest",
			Capabilities: Capabilities{
				SupportsStreaming: false,
				SupportsTools:     false,
				MaxContextWindow:  8192,
			},
		},
		{
			ID:        "local/mixtral-8x7b-vLLM",
			Provider:  ProviderVLLM,
			ModelName: "mistralai/Mixtral-8x7B-Instruct-v0.1",
			Capabilities: Capabilities{
				SupportsStreaming: true,
				SupportsJSONMode:  true,
				SupportsTools:     true,
				MaxContextWindow:  32768,
			},
		},
	}
}
