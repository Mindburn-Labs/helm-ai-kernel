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
		receipt, err := catalog.AuditToolCall("test-tool", map[string]any{"key": "val"}, "ok")
		require.NoError(t, err)
		assert.Equal(t, "test-tool", receipt.ToolName)
		assert.Contains(t, receipt.Inputs, "key")
		assert.Contains(t, receipt.Outputs, "ok")
	})

	t.Run("Unmarshalable input returns error", func(t *testing.T) {
		// Channels cannot be marshaled to JSON
		_, err := catalog.AuditToolCall("bad", map[string]any{"ch": make(chan int)}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "marshal tool call inputs")
	})
}
