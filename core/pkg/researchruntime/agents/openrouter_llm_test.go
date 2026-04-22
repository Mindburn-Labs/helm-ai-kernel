package agents

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenRouterLLM_Complete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer test-key")

		var req map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "test-model", req["model"])

		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "Hello from LLM"}},
			},
		}))
	}))
	defer srv.Close()

	llm := &OpenRouterLLM{
		apiKey:     "test-key",
		model:      "test-model",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	result, err := llm.Complete(context.Background(), "be helpful", "say hello")
	require.NoError(t, err)
	assert.Equal(t, "Hello from LLM", result)
}

func TestOpenRouterLLM_Complete_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	llm := &OpenRouterLLM{
		apiKey:     "bad-key",
		model:      "test-model",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := llm.Complete(context.Background(), "sys", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
}

func TestOpenRouterLLM_Complete_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{},
		}))
	}))
	defer srv.Close()

	llm := &OpenRouterLLM{
		apiKey:     "test-key",
		model:      "test-model",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := llm.Complete(context.Background(), "sys", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty response")
}

func TestNewOpenRouterLLM_Defaults(t *testing.T) {
	llm := NewOpenRouterLLM("my-key", "some-model")
	assert.Equal(t, "my-key", llm.apiKey)
	assert.Equal(t, "some-model", llm.model)
	assert.Equal(t, openRouterChatURL, llm.baseURL)
	assert.NotNil(t, llm.httpClient)
}
