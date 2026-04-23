package governance

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/capabilities"
)

func TestFirewall_BlocksUnauthorizedTool(t *testing.T) {
	// 1. Setup Engine (Loads Default Policy)
	engine, err := NewDecisionEngine(capabilities.NewToolCatalog())
	require.NoError(t, err)

	// 2. Attempt "rm" (Unauthorized)
	payload := []byte(`{"action": "rm"}`)
	_, err = engine.Evaluate(context.Background(), "intent-malicious", payload)

	// 3. Verify Deny
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "policy violation")
	assert.Contains(t, err.Error(), "E3 action 'rm' not explicitly allowed")
}

func TestFirewall_AllowsAuthorizedTool(t *testing.T) {
	// 1. Setup Engine
	engine, err := NewDecisionEngine(capabilities.NewToolCatalog())
	require.NoError(t, err)

	// 2. Attempt "deploy" (Authorized)
	payload := []byte(`{"action": "deploy"}`)
	intent, err := engine.Evaluate(context.Background(), "intent-safe", payload)

	// 3. Verify Success
	assert.NoError(t, err)
	assert.NotNil(t, intent)
	assert.NotEmpty(t, intent.DecisionID, "Should have DecisionID")
	assert.NotEmpty(t, intent.Signature, "Should be signed")
	assert.Equal(t, "deploy", intent.TargetCapability) // Ensure Binding
}

func TestFirewall_BlocksMalformedPayload(t *testing.T) {
	engine, err := NewDecisionEngine(capabilities.NewToolCatalog())
	require.NoError(t, err)

	// Invalid JSON
	payload := []byte(`{not-json}`)
	_, err = engine.Evaluate(context.Background(), "intent-bad", payload)

	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "malformed payload"))
}
