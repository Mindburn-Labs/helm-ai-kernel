package contracts

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// TestCanonicalReceiptHash_Parity provides reference test vectors
// for cross-runtime receipt hash parity verification.
// Any other runtime (Rust, TypeScript, etc.) that implements JCS (RFC 8785)
// canonicalization should produce identical hashes for these inputs.
func TestCanonicalReceiptHash_Parity(t *testing.T) {
	// Test vector 1: Minimal receipt
	tv1 := map[string]interface{}{
		"receipt_id":  "rcpt-tv1",
		"decision_id": "dec-tv1",
		"effect_id":   "eff-tv1",
		"status":      "SUCCESS",
		"timestamp":   "2026-01-01T00:00:00Z",
	}

	hash1, err := canonicalize.CanonicalHash(tv1)
	if err != nil {
		t.Fatalf("tv1: %v", err)
	}
	// Verify determinism: hash same data again
	hash1b, err := canonicalize.CanonicalHash(tv1)
	if err != nil {
		t.Fatalf("tv1 repeat: %v", err)
	}
	if hash1 != hash1b {
		t.Fatalf("tv1: hash not deterministic: %s vs %s", hash1, hash1b)
	}
	t.Logf("TV1 hash: %s", hash1)

	// Test vector 2: Receipt with metadata
	tv2 := map[string]interface{}{
		"receipt_id":  "rcpt-tv2",
		"decision_id": "dec-tv2",
		"effect_id":   "eff-tv2",
		"status":      "FAILURE",
		"timestamp":   "2026-06-15T12:30:00Z",
		"executor_id": "helm-agent-v1",
		"blob_hash":   "sha256:deadbeef",
		"metadata": map[string]interface{}{
			"tool":   "provision_tenant",
			"region": "eu-west-1",
		},
	}

	hash2, err := canonicalize.CanonicalHash(tv2)
	if err != nil {
		t.Fatalf("tv2: %v", err)
	}
	t.Logf("TV2 hash: %s", hash2)

	// Test vector 3: Different field insertion order should produce same hash
	tv3a := map[string]interface{}{
		"status":      "SUCCESS",
		"receipt_id":  "rcpt-tv3",
		"timestamp":   "2026-03-01T08:00:00Z",
		"effect_id":   "eff-tv3",
		"decision_id": "dec-tv3",
	}
	tv3b := map[string]interface{}{
		"decision_id": "dec-tv3",
		"effect_id":   "eff-tv3",
		"receipt_id":  "rcpt-tv3",
		"status":      "SUCCESS",
		"timestamp":   "2026-03-01T08:00:00Z",
	}

	hash3a, err := canonicalize.CanonicalHash(tv3a)
	if err != nil {
		t.Fatalf("tv3a: %v", err)
	}
	hash3b, err := canonicalize.CanonicalHash(tv3b)
	if err != nil {
		t.Fatalf("tv3b: %v", err)
	}
	if hash3a != hash3b {
		t.Fatalf("tv3: insertion order affected hash: %s vs %s", hash3a, hash3b)
	}
	t.Logf("TV3 hash (order-independent): %s", hash3a)

	// Test vector 4: Receipt with nested metadata
	tv4 := map[string]interface{}{
		"receipt_id":  "rcpt-tv4",
		"decision_id": "dec-tv4",
		"effect_id":   "eff-tv4",
		"status":      "SUCCESS",
		"timestamp":   "2026-12-31T23:59:59Z",
		"metadata": map[string]interface{}{
			"tool":     "builder_generate",
			"industry": "fintech",
			"nested": map[string]interface{}{
				"inner_key": "inner_value",
				"count":     float64(42),
			},
		},
	}

	hash4, err := canonicalize.CanonicalHash(tv4)
	if err != nil {
		t.Fatalf("tv4: %v", err)
	}
	t.Logf("TV4 hash (nested metadata): %s", hash4)

	// Test vector 5: Empty metadata fields
	tv5 := map[string]interface{}{
		"receipt_id":  "rcpt-tv5",
		"decision_id": "dec-tv5",
		"effect_id":   "eff-tv5",
		"status":      "PARTIAL",
		"timestamp":   "2026-07-04T00:00:00Z",
		"blob_hash":   "",
		"executor_id": "",
	}

	hash5, err := canonicalize.CanonicalHash(tv5)
	if err != nil {
		t.Fatalf("tv5: %v", err)
	}
	t.Logf("TV5 hash (empty strings): %s", hash5)

	// Cross-check: all hashes are distinct
	hashes := map[string]string{
		"TV1": hash1,
		"TV2": hash2,
		"TV3": hash3a,
		"TV4": hash4,
		"TV5": hash5,
	}
	seen := make(map[string]string)
	for name, h := range hashes {
		if prev, ok := seen[h]; ok {
			t.Fatalf("hash collision between %s and %s: %s", prev, name, h)
		}
		seen[h] = name
	}

	// Print reference table for cross-runtime implementers
	t.Log("\n=== Cross-Runtime Hash Parity Reference Vectors ===")
	t.Logf("TV1 (minimal):           %s", hash1)
	t.Logf("TV2 (with metadata):     %s", hash2)
	t.Logf("TV3 (order-independent): %s", hash3a)
	t.Logf("TV4 (nested metadata):   %s", hash4)
	t.Logf("TV5 (empty strings):     %s", hash5)
}
