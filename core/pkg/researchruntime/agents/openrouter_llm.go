package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const openRouterChatURL = "https://openrouter.ai/api/v1/chat/completions"

// OpenRouterLLM implements LLMClient via OpenRouter's chat completions API.
type OpenRouterLLM struct {
	apiKey     string
	model      string
	baseURL    string // defaults to openRouterChatURL
	httpClient *http.Client
}

func NewOpenRouterLLM(apiKey, model string) *OpenRouterLLM {
	return &OpenRouterLLM{
		apiKey:     apiKey,
		model:      model,
		baseURL:    openRouterChatURL,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *OpenRouterLLM) Complete(ctx context.Context, system, user string) (string, error) {
	messages := []map[string]string{
		{"role": "system", "content": system},
		{"role": "user", "content": user},
	}
	body, _ := json.Marshal(map[string]any{
		"model":    c.model,
		"messages": messages,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openrouter: status %d", resp.StatusCode)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openrouter: empty response")
	}
	return result.Choices[0].Message.Content, nil
}
