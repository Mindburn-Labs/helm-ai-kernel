package proofgraph

import (
	"encoding/json"
	"testing"
)

// FuzzNodeComputeHash fuzzes ProofGraph node hash computation.
// Invariants:
//   - Must never panic
//   - Deterministic: same node produces identical hash
//   - Non-empty hash for valid nodes
func FuzzNodeComputeHash(f *testing.F) {
	f.Add("INTENT", "principal-1", `{"action":"test"}`, "parent-abc")
	f.Add("ATTESTATION", "agent-2", `{"verdict":"ALLOW"}`, "")
	f.Add("EFFECT", "", `{}`, "parent-1")
	f.Add("TRUST_SCORE", "agent-x", `{"score":500,"tier":"NEUTRAL"}`, "parent-2")
	f.Add("AGENT_KILL", "admin", `{"reason":"rogue behavior"}`, "parent-3")
	f.Add("VOUCH", "voucher-1", `{"vouchee":"agent-5","stake":100}`, "")

	f.Fuzz(func(t *testing.T, kind, principal, payloadStr, parentHash string) {
		// Build a node with fuzzed fields
		var payload json.RawMessage
		if json.Valid([]byte(payloadStr)) {
			payload = json.RawMessage(payloadStr)
		} else {
			payload = json.RawMessage(`{}`)
		}

		var parents []string
		if parentHash != "" {
			parents = []string{parentHash}
		}

		node := &Node{
			Kind:      NodeType(kind),
			Parents:   parents,
			Lamport:   1,
			Principal: principal,
			Payload:   payload,
			Sig:       "test-sig",
		}

		// Must not panic
		hash, err := node.ComputeNodeHashE()
		if err != nil {
			return // canonicalization failure is acceptable for arbitrary input
		}

		// Hash must be non-empty
		if hash == "" {
			t.Fatal("ComputeNodeHashE returned empty hash without error")
		}

		// Determinism: same node must produce same hash
		hash2, err2 := node.ComputeNodeHashE()
		if err2 != nil {
			t.Fatal("second hash computation failed but first succeeded")
		}
		if hash != hash2 {
			t.Fatalf("non-deterministic hash: %s != %s", hash, hash2)
		}
	})
}
