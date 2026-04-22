package governance_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/governance"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/provenance"
	"github.com/stretchr/testify/assert"
)

func TestClassifier(t *testing.T) {
	c := governance.NewClassifier()

	assert.Equal(t, governance.DataClassInternal, c.Classify("Hello World"))
	assert.Equal(t, governance.DataClassConfidential, c.Classify("Contact: ivan@example.com"))
	assert.Equal(t, governance.DataClassConfidential, c.Classify("Key: sk-12345678901234567890"))
	assert.Equal(t, governance.DataClassRestricted, c.Classify("System Panic! root_password leaked"))
}

func TestConnectorManifest(t *testing.T) {
	m := governance.NewConnectorManifest()

	// Slack (Internal)
	allowed, err := m.CanEgress("slack", governance.DataClassPublic)
	assert.True(t, allowed)
	assert.NoError(t, err)

	allowed, _ = m.CanEgress("slack", governance.DataClassInternal)
	assert.True(t, allowed)

	allowed, _ = m.CanEgress("slack", governance.DataClassConfidential)
	assert.False(t, allowed, "Confidential should NOT go to slack")

	// Email (Confidential)
	allowed, _ = m.CanEgress("email", governance.DataClassConfidential)
	assert.True(t, allowed)

	// Logger (Restricted)
	allowed, _ = m.CanEgress("logger", governance.DataClassRestricted)
	assert.True(t, allowed)
}

func TestEnvelopeIntegration(t *testing.T) {
	b := provenance.NewBuilder()

	// 1. Public segment
	b.AddSystemPrompt("Hello")
	env := b.Build()
	// Default/Empty usually treats as Public or Lowest?
	// Our `isHigherSensitivity` logic starts with empty=0 (Public).
	// So "Hello" (Internal default from Classifier) should bump it to Internal?
	// Wait, SystemPrompt is Classify("Hello") -> Internal (default).
	// So Envelope should be Internal.

	// Let's verify Internal.
	assert.Equal(t, governance.DataClassInternal, env.DataClassification)

	// 2. Add Confidential
	b.AddUserInput("My email is user@example.com", "u1")
	env = b.Build()
	assert.Equal(t, governance.DataClassConfidential, env.DataClassification)

	// 3. Add Restricted
	b.AddToolOutput("FATAL: root_password = 123", "t1")
	env = b.Build()
	assert.Equal(t, governance.DataClassRestricted, env.DataClassification)
}
