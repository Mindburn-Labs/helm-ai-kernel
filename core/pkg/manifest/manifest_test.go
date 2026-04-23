package manifest_test

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModule_Marshaling verifies that the Module struct matches
// the expected JSON schema for extensions.
// Invariant: Manifest schema must remain backward compatible.
func TestModule_Marshaling(t *testing.T) {
	mod := manifest.Module{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "A test module",
		Dependencies: []string{
			"dep-1",
		},
		Capabilities: []manifest.CapabilityConfig{
			{
				Name:        "cap-1",
				Description: "does something",
				ArgsSchema:  "{}",
			},
		},
		Policies: []manifest.PolicyConfig{
			{
				Name:        "policy-1",
				RegoContent: "package test",
				EnforcedOn:  "BeforeExecution",
			},
		},
	}

	data, err := json.Marshal(mod)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.Contains(t, jsonStr, "test-module")
	assert.Contains(t, jsonStr, "capabilities")
	assert.Contains(t, jsonStr, "rego_content")

	// Round trip
	var decoded manifest.Module
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, mod, decoded)
}
