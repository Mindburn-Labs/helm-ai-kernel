package wasm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntime_LoadModule(t *testing.T) {
	rt := NewRuntime()
	mod, err := rt.LoadModule("deny-all", "1.0.0", []byte{0x00, 0x61, 0x73, 0x6D}, "evaluate")
	require.NoError(t, err)
	assert.Equal(t, "deny-all", mod.Name)
	assert.Equal(t, "1.0.0", mod.Version)
	assert.NotEmpty(t, mod.Hash)
	assert.NotEmpty(t, mod.ID)
}

func TestRuntime_LoadModule_Empty(t *testing.T) {
	rt := NewRuntime()
	_, err := rt.LoadModule("empty", "1.0", []byte{}, "evaluate")
	assert.Error(t, err)
}

func TestRuntime_Evaluate_FailClosed(t *testing.T) {
	rt := NewRuntime()
	rt.LoadModule("test-policy", "1.0", []byte{0x00, 0x61}, "evaluate")

	ctx := context.Background()
	result, err := rt.Evaluate(ctx, "test-policy", EvalRequest{
		Principal: "agent-1", Action: "write", Resource: "secrets",
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", result.Decision) // Fail-closed default
	assert.NotEmpty(t, result.PolicyID)
}

func TestRuntime_Evaluate_UnknownModule(t *testing.T) {
	rt := NewRuntime()
	ctx := context.Background()
	_, err := rt.Evaluate(ctx, "nonexistent", EvalRequest{})
	assert.Error(t, err)
}

func TestRuntime_ListModules(t *testing.T) {
	rt := NewRuntime()
	rt.LoadModule("a", "1.0", []byte{0x01}, "eval")
	rt.LoadModule("b", "2.0", []byte{0x02}, "eval")
	assert.Len(t, rt.ListModules(), 2)
}
