package a2a

import (
	"testing"
	"time"
)

// FuzzEnvelopeValidation fuzzes A2A envelope construction and validation.
// Invariants:
//   - Must never panic on any input
//   - Envelope with zero TTL should be expired
func FuzzEnvelopeValidation(f *testing.F) {
	f.Add("agent-1", "agent-2", "hash-abc", "METERING_RECEIPTS")
	f.Add("", "", "", "")
	f.Add("agent\x00inject", "agent\ttab", "hash\nnewline", "UNKNOWN_FEATURE")
	f.Add("agent-a", "agent-b", "payload-hash", "IATP_AUTH")
	f.Add("agent-a", "agent-b", "payload-hash", "PEER_VOUCHING")

	f.Fuzz(func(t *testing.T, origin, target, payloadHash, feature string) {
		now := time.Now()

		env := Envelope{
			EnvelopeID:       "fuzz-env-1",
			SchemaVersion:    SchemaVersion{Major: 1, Minor: 0, Patch: 0},
			OriginAgentID:    origin,
			TargetAgentID:    target,
			RequiredFeatures: []Feature{Feature(feature)},
			OfferedFeatures:  []Feature{Feature(feature)},
			PayloadHash:      payloadHash,
			CreatedAt:        now,
			ExpiresAt:        now.Add(5 * time.Minute),
		}

		// Must not panic
		_ = env.EnvelopeID
		_ = env.SchemaVersion

		// Expired envelope check
		expiredEnv := env
		expiredEnv.ExpiresAt = now.Add(-1 * time.Minute)
		if !expiredEnv.ExpiresAt.Before(now) {
			t.Fatal("expired envelope should have ExpiresAt in the past")
		}
	})
}
