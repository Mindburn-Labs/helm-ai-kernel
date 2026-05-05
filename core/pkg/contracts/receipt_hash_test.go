package contracts

import (
	"strings"
	"testing"
	"time"
)

func TestReceiptChainHashIsDeterministicAndSignatureBound(t *testing.T) {
	receipt := &Receipt{
		ReceiptID:    "rcpt-1",
		DecisionID:   "dec-1",
		EffectID:     "EXECUTE_TOOL",
		Status:       "ALLOW",
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Metadata:     map[string]any{"resource": "tool-a", "action": "EXECUTE_TOOL"},
		Signature:    "sig-1",
		LamportClock: 1,
		ArgsHash:     "sha256:args",
	}

	first, err := ReceiptChainHash(receipt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReceiptChainHash(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("hash not deterministic: %s vs %s", first, second)
	}
	if len(first) != 64 || strings.HasPrefix(first, "sha256:") {
		t.Fatalf("unexpected chain hash format: %q", first)
	}

	receipt.Signature = "sig-2"
	tampered, err := ReceiptChainHash(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if tampered == first {
		t.Fatal("receipt chain hash did not change when signature changed")
	}
}
