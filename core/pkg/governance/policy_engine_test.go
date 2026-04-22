package governance

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyEngine_Evaluation(t *testing.T) {
	pe, err := NewPolicyEngine()
	require.NoError(t, err)

	// 1. Load Policy
	src := `action == "read" && resource.startsWith("doc-")`
	err = pe.LoadPolicy("policy-1", src)
	require.NoError(t, err)

	// 2. Evaluate Allow
	reqAllowed := contracts.AccessRequest{
		PrincipalID: "user1",
		Action:      "read",
		ResourceID:  "doc-123",
	}
	dec, err := pe.Evaluate(context.Background(), "policy-1", reqAllowed)
	require.NoError(t, err)
	assert.Equal(t, "ALLOW", dec.Verdict)
	assert.Contains(t, dec.Reason, "Allowed by policy")

	// 3. Evaluate Deny
	reqDenied := contracts.AccessRequest{
		PrincipalID: "user1",
		Action:      "write",
		ResourceID:  "doc-123",
	}
	dec, err = pe.Evaluate(context.Background(), "policy-1", reqDenied)
	require.NoError(t, err)
	assert.Equal(t, "DENY", dec.Verdict)
	assert.Contains(t, dec.Reason, "Denied by policy")

	// 4. Missing Policy
	dec, err = pe.Evaluate(context.Background(), "missing-policy", reqAllowed)
	require.NoError(t, err)
	assert.Equal(t, "DENY", dec.Verdict)
	assert.Contains(t, dec.Reason, "not found")

	// 5. Global Eval (Default Deny for now)
	dec, err = pe.Evaluate(context.Background(), "", reqAllowed)
	require.NoError(t, err)
	assert.Equal(t, "DENY", dec.Verdict)
	assert.Contains(t, dec.Reason, "No specific policy")

	// 6. List Definitions
	defs := pe.ListDefinitions()
	assert.Equal(t, src, defs["policy-1"])
}

func TestPolicyEngine_CompilationError(t *testing.T) {
	pe, err := NewPolicyEngine()
	require.NoError(t, err)

	err = pe.LoadPolicy("bad", "invalid syntax ((")
	assert.Error(t, err)
}
