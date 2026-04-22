package receipts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestReceiptTamperResistance(t *testing.T) {
	// 1. Create a valid receipt
	original := contracts.Receipt{
		ReceiptID:  "rcpt_test_001",
		DecisionID: "dec_test_001",
		Status:     "SUCCESS",
		Timestamp:  time.Now().UTC(),
		Metadata: map[string]any{
			"agent": "test-agent",
		},
	}

	// 2. Canonicalize and Sign (Simulated)
	asMap := toMap(t, original)
	delete(asMap, "signature") // Ensure clean state

	cb, _ := canonicalize.JCS(asMap)
	hash := sha256.Sum256(cb)
	sig := hex.EncodeToString(hash[:]) // Simulating signature = hash of payload for this test

	original.Signature = sig

	// 3. Tamper with Metadata
	tampered := original
	tampered.Metadata = map[string]any{
		"agent": "MALICIOUS-agent",
	}

	// 4. Verify Failure
	tamperedMap := toMap(t, tampered)
	delete(tamperedMap, "signature") // Remove sig for hashing check

	cbTamper, _ := canonicalize.JCS(tamperedMap)
	hashTamper := sha256.Sum256(cbTamper)
	sigTamper := hex.EncodeToString(hashTamper[:])

	if sigTamper == original.Signature {
		t.Fatal("Tampering was NOT detected! Hash remained identical.")
	}
	t.Log("PASS: Tampering changed the underlying hash.")
}

func toMap(t *testing.T, v interface{}) map[string]interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	return m
}
