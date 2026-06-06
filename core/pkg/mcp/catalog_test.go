package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryCatalog(t *testing.T) {
	catalog := NewInMemoryCatalog()
	ctx := context.Background()

	tool1 := ToolRef{
		Name:        "calculator",
		Description: "Performs basic math",
		ServerID:    "math-server",
	}
	tool2 := ToolRef{
		Name:        "weather",
		Description: "Get weather reports",
		ServerID:    "weather-server",
	}

	require.NoError(t, catalog.Register(ctx, tool1))
	require.NoError(t, catalog.Register(ctx, tool2))

	t.Run("Search Exact Name", func(t *testing.T) {
		results, err := catalog.Search(ctx, "calculator")
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "calculator", results[0].Name)
	})

	t.Run("Search Partial Description", func(t *testing.T) {
		results, err := catalog.Search(ctx, "basic math")
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "calculator", results[0].Name)
	})

	t.Run("Search Case Insensitive", func(t *testing.T) {
		results, err := catalog.Search(ctx, "WEATHER")
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "weather", results[0].Name)
	})

	t.Run("No Results", func(t *testing.T) {
		results, err := catalog.Search(ctx, "stock-market")
		assert.NoError(t, err)
		assert.Empty(t, results)
	})
}

func TestToolCatalog_Register_Validation(t *testing.T) {
	catalog := NewInMemoryCatalog()
	ctx := context.Background()

	t.Run("Empty name is rejected", func(t *testing.T) {
		err := catalog.Register(ctx, ToolRef{Description: "no name"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("Valid ref is accepted", func(t *testing.T) {
		err := catalog.Register(ctx, ToolRef{Name: "valid-tool"})
		assert.NoError(t, err)
	})
}

func TestToolCatalog_AuditToolCall(t *testing.T) {
	catalog := NewInMemoryCatalog()

	t.Run("Successful audit", func(t *testing.T) {
		receipt, err := catalog.AuditToolCall("test-tool", map[string]any{"path": "/tmp/input.txt"}, "ok")
		require.NoError(t, err)
		assert.Equal(t, "test-tool", receipt.ToolName)
		assert.Contains(t, receipt.Inputs, "path")
		assert.Contains(t, receipt.Outputs, "ok")
	})

	t.Run("Sensitive inputs and outputs are redacted", func(t *testing.T) {
		receipt, err := catalog.AuditToolCall("test-tool", map[string]any{
			"api_key": "sk-live-secret",
			"nested":  map[string]any{"password": "p@ssw0rd", "path": "/tmp/input.txt"},
		}, map[string]any{"seed": "mnemonic", "status": "ok"})
		require.NoError(t, err)
		assert.NotContains(t, receipt.Inputs, "sk-live-secret")
		assert.NotContains(t, receipt.Inputs, "p@ssw0rd")
		assert.NotContains(t, receipt.Outputs, "mnemonic")
		assert.Contains(t, receipt.Inputs, "[REDACTED]")
		assert.Contains(t, receipt.Outputs, "[REDACTED]")
		assert.Contains(t, receipt.Inputs, "/tmp/input.txt")
		assert.Contains(t, receipt.Outputs, "ok")
	})

	t.Run("Token-like values and customer payload fields are redacted", func(t *testing.T) {
		receipt, err := catalog.AuditToolCall("test-tool", map[string]any{
			"note": "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJhZ2VudCJ9.c2lnbmF0dXJl",
			"safe": "ok",
			"items": []any{
				map[string]any{"description": "public"},
				map[string]any{"description": "github_pat_1234567890abcdef"},
			},
		}, map[string]any{
			"content": "customer secret text",
			"status":  "ok",
			"message": "sk-live-output-token",
		})
		require.NoError(t, err)
		assert.NotContains(t, receipt.Inputs, "Bearer")
		assert.NotContains(t, receipt.Inputs, "github_pat_")
		assert.NotContains(t, receipt.Outputs, "customer secret text")
		assert.NotContains(t, receipt.Outputs, "sk-live-output-token")
		assert.Contains(t, receipt.Inputs, "public")
		assert.Contains(t, receipt.Inputs, "ok")
		assert.Contains(t, receipt.Outputs, "ok")
		assert.Contains(t, receipt.Inputs, "[REDACTED]")
		assert.Contains(t, receipt.Outputs, "[REDACTED]")
	})

	t.Run("Unmarshalable input returns error", func(t *testing.T) {
		// Channels cannot be marshaled to JSON
		_, err := catalog.AuditToolCall("bad", map[string]any{"ch": make(chan int)}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "marshal tool call inputs")
	})
}
