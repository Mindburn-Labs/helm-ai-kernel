package guardian

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/stretchr/testify/require"
)

type tokenTestRig struct {
	registry      *capability.Registry
	rollbackPlans capability.RollbackPlanStore
	authority     *capability.TokenAuthority
	verifier      *capability.TokenVerifier
}

func tokenAsMap(t *testing.T, token *capability.Token) map[string]interface{} {
	t.Helper()
	buf, err := json.Marshal(token)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(buf, &out))
	return out
}
