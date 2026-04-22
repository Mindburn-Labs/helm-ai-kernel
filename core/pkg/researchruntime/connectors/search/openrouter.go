package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const openRouterBase = "https://openrouter.ai/api/v1"

// OpenRouterClient calls an OpenRouter-hosted LLM to perform web search.
// Models with built-in search (e.g. perplexity/llama-3.1-sonar-large-128k-online)
// return grounded results; the response is parsed from a JSON array embedded in
// the model's text output.
type OpenRouterClient struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewOpenRouterClient creates a ready-to-use OpenRouterClient.
func NewOpenRouterClient(apiKey, model string) *OpenRouterClient {
	return &OpenRouterClient{
		apiKey:     apiKey,
		model:      model,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// Search implements Client by prompting the configured model on OpenRouter and
// parsing its JSON array response into []Result.
func (c *OpenRouterClient) Search(ctx context.Context, req Request) ([]Result, error) {
	prompt := fmt.Sprintf(
		"Search the web and return up to %d results for: %s\n\n"+
			"Return ONLY a JSON array with objects containing \"url\", \"title\", and \"snippet\" fields. No other text.",
		req.MaxResults, req.Query,
	)

	body, _ := json.Marshal(map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, openRouterBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openrouter search: status %d", resp.StatusCode)
	}

	var orResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&orResp); err != nil {
		return nil, err
	}
	if len(orResp.Choices) == 0 {
		return nil, fmt.Errorf("openrouter: empty response")
	}

	return parseSearchResults(orResp.Choices[0].Message.Content, c.model)
}

// parseSearchResults extracts a JSON array from the model's text output and
// converts it to []Result. The model may prepend prose before the array, so we
// locate the first '[' and last ']' delimiters.
func parseSearchResults(content, model string) ([]Result, error) {
	start := strings.Index(content, "[")
	if start < 0 {
		return nil, fmt.Errorf("openrouter: no JSON array in response")
	}
	end := strings.LastIndex(content, "]")
	if end < start {
		return nil, fmt.Errorf("openrouter: malformed JSON array")
	}

	var raw []struct {
		URL     string `json:"url"`
		Title   string `json:"title"`
		Snippet string `json:"snippet"`
	}
	if err := json.Unmarshal([]byte(content[start:end+1]), &raw); err != nil {
		return nil, fmt.Errorf("openrouter: parse results: %w", err)
	}

	now := time.Now()
	results := make([]Result, 0, len(raw))
	for _, r := range raw {
		if r.URL == "" {
			continue
		}
		results = append(results, Result{
			URL:       r.URL,
			Title:     r.Title,
			Snippet:   r.Snippet,
			Source:    model,
			FetchedAt: now,
		})
	}
	return results, nil
}
