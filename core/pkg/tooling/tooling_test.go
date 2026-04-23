package tooling

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToolDescriptor_Fingerprint(t *testing.T) {
	t.Run("Same descriptor produces same fingerprint", func(t *testing.T) {
		desc1 := &ToolDescriptor{
			ToolID:             "email-send",
			Version:            "1.0.0",
			Endpoint:           "https://api.email.example.com/send",
			AuthMethodClass:    "oauth2",
			DeterministicFlags: []string{"idempotent", "auditable"},
			InputSchemaHash:    "abc123",
			OutputSchemaHash:   "def456",
		}

		desc2 := &ToolDescriptor{
			ToolID:             "email-send",
			Version:            "1.0.0",
			Endpoint:           "https://api.email.example.com/send",
			AuthMethodClass:    "oauth2",
			DeterministicFlags: []string{"idempotent", "auditable"},
			InputSchemaHash:    "abc123",
			OutputSchemaHash:   "def456",
		}

		assert.Equal(t, desc1.Fingerprint(), desc2.Fingerprint())
	})

	t.Run("Flag order does not affect fingerprint", func(t *testing.T) {
		desc1 := &ToolDescriptor{
			ToolID:             "tool-1",
			Version:            "1.0.0",
			Endpoint:           "http://localhost",
			DeterministicFlags: []string{"b", "a", "c"},
			InputSchemaHash:    "hash1",
			OutputSchemaHash:   "hash2",
		}

		desc2 := &ToolDescriptor{
			ToolID:             "tool-1",
			Version:            "1.0.0",
			Endpoint:           "http://localhost",
			DeterministicFlags: []string{"c", "a", "b"},
			InputSchemaHash:    "hash1",
			OutputSchemaHash:   "hash2",
		}

		assert.Equal(t, desc1.Fingerprint(), desc2.Fingerprint(),
			"Fingerprint should be stable regardless of flag order")
	})

	t.Run("Different version produces different fingerprint", func(t *testing.T) {
		desc1 := &ToolDescriptor{
			ToolID:           "tool-1",
			Version:          "1.0.0",
			Endpoint:         "http://localhost",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		desc2 := &ToolDescriptor{
			ToolID:           "tool-1",
			Version:          "2.0.0", // Changed
			Endpoint:         "http://localhost",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		assert.NotEqual(t, desc1.Fingerprint(), desc2.Fingerprint())
	})

	t.Run("Fingerprint is 64 character hex string", func(t *testing.T) {
		desc := &ToolDescriptor{
			ToolID:           "tool-1",
			Version:          "1.0.0",
			Endpoint:         "http://localhost",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		fp := desc.Fingerprint()
		assert.Len(t, fp, 64, "SHA-256 hex should be 64 characters")
	})
}

func TestToolDescriptor_Validate(t *testing.T) {
	t.Run("Valid descriptor passes", func(t *testing.T) {
		desc := &ToolDescriptor{
			ToolID:           "tool-1",
			Version:          "1.0.0",
			Endpoint:         "http://localhost",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		assert.NoError(t, desc.Validate())
	})

	t.Run("Missing tool_id fails", func(t *testing.T) {
		desc := &ToolDescriptor{
			Version:          "1.0.0",
			Endpoint:         "http://localhost",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		err := desc.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tool_id")
	})

	t.Run("Missing version fails", func(t *testing.T) {
		desc := &ToolDescriptor{
			ToolID:           "tool-1",
			Endpoint:         "http://localhost",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		err := desc.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "version")
	})
}

func TestToolDescriptor_HasChanged(t *testing.T) {
	desc1 := &ToolDescriptor{
		ToolID:           "tool-1",
		Version:          "1.0.0",
		Endpoint:         "http://localhost",
		InputSchemaHash:  "hash1",
		OutputSchemaHash: "hash2",
	}

	desc2 := &ToolDescriptor{
		ToolID:           "tool-1",
		Version:          "1.0.0",
		Endpoint:         "http://localhost",
		InputSchemaHash:  "hash1",
		OutputSchemaHash: "hash2",
	}

	desc3 := &ToolDescriptor{
		ToolID:           "tool-1",
		Version:          "1.0.1", // Changed
		Endpoint:         "http://localhost",
		InputSchemaHash:  "hash1",
		OutputSchemaHash: "hash2",
	}

	assert.False(t, desc1.HasChanged(desc2))
	assert.True(t, desc1.HasChanged(desc3))
}

func TestToolRegistry(t *testing.T) {
	t.Run("Register and get tool", func(t *testing.T) {
		registry := NewToolRegistry()

		tool := &ToolDescriptor{
			ToolID:           "tool-1",
			Version:          "1.0.0",
			Endpoint:         "http://localhost",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		err := registry.Register(tool)
		require.NoError(t, err)

		retrieved, ok := registry.Get("tool-1")
		assert.True(t, ok)
		assert.Equal(t, tool.ToolID, retrieved.ToolID)
	})

	t.Run("Register invalid tool fails", func(t *testing.T) {
		registry := NewToolRegistry()

		tool := &ToolDescriptor{
			Version: "1.0.0", // Missing ToolID
		}

		err := registry.Register(tool)
		assert.Error(t, err)
	})

	t.Run("List returns sorted IDs", func(t *testing.T) {
		registry := NewToolRegistry()

		for _, id := range []string{"zebra", "alpha", "beta"} {
			err := registry.Register(&ToolDescriptor{
				ToolID:           id,
				Version:          "1.0.0",
				Endpoint:         "http://localhost",
				InputSchemaHash:  "h1",
				OutputSchemaHash: "h2",
			})
			require.NoError(t, err)
		}

		list := registry.List()
		assert.Equal(t, []string{"alpha", "beta", "zebra"}, list)
	})
}

func TestCanonicalJSON(t *testing.T) {
	t.Run("Keys are sorted", func(t *testing.T) {
		input := map[string]interface{}{
			"zebra": 1,
			"alpha": 2,
			"beta":  3,
		}

		result, err := CanonicalJSON(input)
		require.NoError(t, err)

		expected := `{"alpha":2,"beta":3,"zebra":1}`
		assert.Equal(t, expected, string(result))
	})

	t.Run("Nested objects are sorted", func(t *testing.T) {
		input := map[string]interface{}{
			"outer": map[string]interface{}{
				"z": 1,
				"a": 2,
			},
		}

		result, err := CanonicalJSON(input)
		require.NoError(t, err)

		expected := `{"outer":{"a":2,"z":1}}`
		assert.Equal(t, expected, string(result))
	})

	t.Run("Integers normalized", func(t *testing.T) {
		input := map[string]interface{}{
			"int":   float64(42),
			"float": 3.14,
		}

		result, err := CanonicalJSON(input)
		require.NoError(t, err)

		// 42 should be rendered as int, 3.14 as float
		assert.Contains(t, string(result), `"int":42`)
		assert.Contains(t, string(result), `"float":3.14`)
	})
}

func TestNormalizeBundle(t *testing.T) {
	t.Run("Same bundle produces same output", func(t *testing.T) {
		bundle := &PolicyInputBundle{
			RequestID:  "req-123",
			EffectType: "DATA_WRITE",
			Principal:  "user@example.com",
			Target:     "/data/users",
			Payload: map[string]interface{}{
				"name": "test",
			},
		}

		norm1, err := NormalizeBundle(bundle)
		require.NoError(t, err)

		norm2, err := NormalizeBundle(bundle)
		require.NoError(t, err)

		assert.Equal(t, norm1, norm2)
	})

	t.Run("Nil bundle returns error", func(t *testing.T) {
		_, err := NormalizeBundle(nil)
		assert.Error(t, err)
	})
}

func TestNormalizationEquivalent(t *testing.T) {
	bundleA := &PolicyInputBundle{
		RequestID:  "req-1",
		EffectType: "TEST",
		Principal:  "user",
		Target:     "/target",
		Payload:    map[string]interface{}{"key": "value"},
	}

	bundleB := &PolicyInputBundle{
		RequestID:  "req-1",
		EffectType: "TEST",
		Principal:  "user",
		Target:     "/target",
		Payload:    map[string]interface{}{"key": "value"},
	}

	bundleC := &PolicyInputBundle{
		RequestID:  "req-2", // Different
		EffectType: "TEST",
		Principal:  "user",
		Target:     "/target",
		Payload:    map[string]interface{}{"key": "value"},
	}

	eq1, err := NormalizationEquivalent(bundleA, bundleB)
	require.NoError(t, err)
	assert.True(t, eq1)

	eq2, err := NormalizationEquivalent(bundleA, bundleC)
	require.NoError(t, err)
	assert.False(t, eq2)
}

func TestToolChangeDetector(t *testing.T) {
	tool := &ToolDescriptor{
		ToolID:           "payment-api",
		Version:          "1.0.0",
		Endpoint:         "https://api.stripe.com",
		InputSchemaHash:  "hash1",
		OutputSchemaHash: "hash2",
	}

	t.Run("First registration becomes baseline", func(t *testing.T) {
		detector := NewToolChangeDetector()
		changed, _ := detector.CheckForChange(tool)
		assert.False(t, changed, "First check should not show change")
		assert.False(t, detector.RequiresReevaluation(tool.ToolID))
	})

	t.Run("Same tool shows no change", func(t *testing.T) {
		detector := NewToolChangeDetector()
		detector.CheckForChange(tool)
		changed, _ := detector.CheckForChange(tool)
		assert.False(t, changed)
	})

	t.Run("Changed tool triggers reevaluation", func(t *testing.T) {
		detector := NewToolChangeDetector()
		detector.CheckForChange(tool)

		updated := &ToolDescriptor{
			ToolID:           "payment-api",
			Version:          "2.0.0", // Changed
			Endpoint:         "https://api.stripe.com",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}

		changed, msg := detector.CheckForChange(updated)
		assert.True(t, changed)
		assert.Contains(t, msg, "payment-api")
		assert.True(t, detector.RequiresReevaluation("payment-api"))
	})

	t.Run("GateExecution blocks when reevaluation needed", func(t *testing.T) {
		detector := NewToolChangeDetector()
		detector.CheckForChange(tool)

		updated := &ToolDescriptor{
			ToolID:           "payment-api",
			Version:          "2.0.0",
			Endpoint:         "https://api.stripe.com",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}
		detector.CheckForChange(updated)

		err := detector.GateExecution(updated)
		require.Error(t, err, "Should block execution")
		assert.Contains(t, err.Error(), "tool_change_blocked")

		// Cast to ToolChangeError
		var changeErr *ToolChangeError
		require.True(t, errors.As(err, &changeErr))
		assert.Equal(t, "payment-api", changeErr.ToolID)
	})

	t.Run("MarkReevaluated clears block", func(t *testing.T) {
		detector := NewToolChangeDetector()
		detector.CheckForChange(tool)

		updated := &ToolDescriptor{
			ToolID:           "payment-api",
			Version:          "2.0.0",
			Endpoint:         "https://api.stripe.com",
			InputSchemaHash:  "hash1",
			OutputSchemaHash: "hash2",
		}
		detector.CheckForChange(updated)
		assert.True(t, detector.RequiresReevaluation("payment-api"))

		detector.MarkReevaluated(updated)
		assert.False(t, detector.RequiresReevaluation("payment-api"))

		err := detector.GateExecution(updated)
		assert.NoError(t, err, "Should allow execution after reevaluation")
	})
}
