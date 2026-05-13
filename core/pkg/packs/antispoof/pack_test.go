package antispoof_test

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/packs/antispoof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultScenarios_Count verifies that exactly 8 scenarios are returned.
func TestDefaultScenarios_Count(t *testing.T) {
	scenarios := antispoof.DefaultScenarios()
	assert.Len(t, scenarios, 8, "DefaultScenarios must return exactly 8 built-in scenarios")
}

// TestDefaultScenarios_RequiredFields verifies each scenario has non-empty fields.
func TestDefaultScenarios_RequiredFields(t *testing.T) {
	for _, s := range antispoof.DefaultScenarios() {
		t.Run(s.Name, func(t *testing.T) {
			assert.NotEmpty(t, s.Name, "Name must be non-empty")
			assert.NotEmpty(t, s.Channel, "Channel must be non-empty")
			assert.NotEmpty(t, s.Attack, "Attack must be non-empty")
			assert.NotEmpty(t, s.Description, "Description must be non-empty")
		})
	}
}

// TestDefaultScenarios_UniqueNames verifies there are no duplicate scenario names.
func TestDefaultScenarios_UniqueNames(t *testing.T) {
	seen := make(map[string]struct{})
	for _, s := range antispoof.DefaultScenarios() {
		_, duplicate := seen[s.Name]
		assert.False(t, duplicate, "duplicate scenario name: %q", s.Name)
		seen[s.Name] = struct{}{}
	}
}

// TestAntiSpoofPack_AllScenariosBlocked verifies that DefaultAntiSpoofValidator
// blocks every built-in spoofing scenario.
func TestAntiSpoofPack_AllScenariosBlocked(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 8, result.TotalScenarios)
	assert.Equal(t, 8, result.Blocked, "all 8 scenarios must be blocked by DefaultAntiSpoofValidator")
	assert.Equal(t, 0, result.Bypassed, "no scenarios must bypass the validator")
}

// TestAntiSpoofPack_EachScenarioResultPresent verifies one result per scenario.
func TestAntiSpoofPack_EachScenarioResultPresent(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	assert.Len(t, result.Results, 8)
	scenarioNames := make(map[string]struct{})
	for _, s := range antispoof.DefaultScenarios() {
		scenarioNames[s.Name] = struct{}{}
	}
	for _, r := range result.Results {
		_, found := scenarioNames[r.ScenarioName]
		assert.True(t, found, "unexpected scenario name in results: %q", r.ScenarioName)
	}
}

// TestAntiSpoofPack_BlockedResultsHaveSuspiciousTrust verifies that each blocked
// scenario is detected with SenderTrustSuspicious.
func TestAntiSpoofPack_BlockedResultsHaveSuspiciousTrust(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	for _, r := range result.Results {
		if r.Blocked {
			assert.Equal(t, string(channels.SenderTrustSuspicious), r.DetectedAs,
				"blocked scenario %q must be detected as suspicious", r.ScenarioName)
		}
	}
}

// TestAntiSpoofPack_ContentHashNonEmpty verifies a content hash is produced.
func TestAntiSpoofPack_ContentHashNonEmpty(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	assert.NotEmpty(t, result.ContentHash)
	assert.Len(t, result.ContentHash, 64, "SHA-256 hex must be 64 characters")
}

// TestAntiSpoofPack_ContentHashIsDeterministic verifies that two identical runs
// produce the same content hash.
func TestAntiSpoofPack_ContentHashIsDeterministic(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result1, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	result2, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	assert.Equal(t, result1.ContentHash, result2.ContentHash,
		"content hash must be identical across runs with the same scenarios and validator")
}

// TestAntiSpoofPack_PackIDIsSet verifies the PackID field is populated.
func TestAntiSpoofPack_PackIDIsSet(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	assert.NotEmpty(t, result.PackID)
}

// TestAntiSpoofPack_EmptyScenarios_ReturnsEmptyResult verifies graceful handling
// of a pack with no scenarios configured.
func TestAntiSpoofPack_EmptyScenarios_ReturnsEmptyResult(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: []antispoof.Scenario{}}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, result.TotalScenarios)
	assert.Equal(t, 0, result.Blocked)
	assert.Equal(t, 0, result.Bypassed)
}

// TestAntiSpoofPack_ResponseMsIsNonNegative verifies timing fields are sane.
func TestAntiSpoofPack_ResponseMsIsNonNegative(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	for _, r := range result.Results {
		assert.GreaterOrEqual(t, r.ResponseMs, int64(0),
			"ResponseMs must be non-negative for scenario %q", r.ScenarioName)
	}
}
