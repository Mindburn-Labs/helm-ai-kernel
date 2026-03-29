package agents

import "context"

// LLMClient abstracts LLM completions for use by all agents.
type LLMClient interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}
