package verifier

// F-03 regression: the offline verifier's chain-of-custody checks must detect
// truncation, reordering and forking of a receipt chain.
//
// Before this change checkChainIntegrity passed on "proofgraph.json parses as
// JSON" and checkLamportMonotonicity passed on "N receipt files present", so
// every scenario below reported PASS.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// buildReceiptChain returns n receipts correctly linked genesis-to-head.
func buildReceiptChain(t *testing.T, session string, n int) []*contracts.Receipt {
	t.Helper()
	var chain []*contracts.Receipt
	prevHash := ""
	for i := 1; i <= n; i++ {
		r := &contracts.Receipt{
			ReceiptID:    string(rune('a'+i-1)) + "-receipt",
			DecisionID:   "decision-" + string(rune('a'+i-1)),
			EffectID:     "effect-" + string(rune('a'+i-1)),
			Status:       "APPLIED",
			OutputHash:   "sha256:out",
			ExecutorID:   session,
			LamportClock: uint64(i),
			PrevHash:     prevHash,
		}
		h, err := contracts.ReceiptChainHash(r)
		if err != nil {
			t.Fatalf("ReceiptChainHash: %v", err)
		}
		prevHash = h
		chain = append(chain, r)
	}
	return chain
}

// writeChain materialises receipts into a pack layout and returns the pack dir.
func writeChain(t *testing.T, receipts []*contracts.Receipt) string {
	t.Helper()
	dir := t.TempDir()
	receiptsDir := filepath.Join(dir, "receipts")
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A parseable proof graph must be present, otherwise checkChainIntegrity
	// returns early on "missing proof graph" and every negative case below would
	// pass for the wrong reason.
	if err := os.WriteFile(filepath.Join(dir, "proofgraph.json"), []byte(`{"nodes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, r := range receipts {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(receiptsDir, string(rune('0'+i))+"-"+r.ReceiptID+".json")
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestChainIntegrity_AcceptsWellFormedChain(t *testing.T) {
	dir := writeChain(t, buildReceiptChain(t, "session-1", 4))

	if got := checkChainIntegrity(dir); !got.Pass {
		t.Fatalf("a correctly linked chain must verify, got: %s", got.Reason)
	}
	if got := checkLamportMonotonicity(dir); !got.Pass {
		t.Fatalf("a correctly ordered chain must verify, got: %s", got.Reason)
	}
}

// Deleting a receipt from the middle leaves the tail unreachable from genesis.
func TestChainIntegrity_DetectsTruncation(t *testing.T) {
	chain := buildReceiptChain(t, "session-1", 5)
	truncated := append([]*contracts.Receipt{}, chain[:2]...)
	truncated = append(truncated, chain[3:]...) // drop index 2
	dir := writeChain(t, truncated)

	got := checkChainIntegrity(dir)
	if got.Pass {
		t.Fatal("a chain with a receipt removed from the middle reported PASS — " +
			"deleting evidence would be undetectable")
	}
	t.Logf("truncation detected: %s", got.Reason)
}

// Two receipts sharing a parent is a forked history.
func TestChainIntegrity_DetectsFork(t *testing.T) {
	chain := buildReceiptChain(t, "session-1", 3)

	// A second child of receipt 1, carrying a different effect.
	fork := &contracts.Receipt{
		ReceiptID:    "forged-receipt",
		DecisionID:   "decision-forged",
		EffectID:     "effect-forged",
		Status:       "APPLIED",
		OutputHash:   "sha256:forged",
		ExecutorID:   "session-1",
		LamportClock: 2,
		PrevHash:     chain[1].PrevHash, // same parent as chain[1]
	}
	dir := writeChain(t, append(chain, fork))

	got := checkChainIntegrity(dir)
	if got.Pass {
		t.Fatal("a forked chain reported PASS — two conflicting histories would both verify")
	}
	t.Logf("fork detected: %s", got.Reason)
}

// Removing the genesis receipt should be detected, not silently accepted.
func TestChainIntegrity_DetectsMissingGenesis(t *testing.T) {
	chain := buildReceiptChain(t, "session-1", 4)
	dir := writeChain(t, chain[1:])

	got := checkChainIntegrity(dir)
	if got.Pass {
		t.Fatal("a chain with no genesis receipt reported PASS — the start of history could be dropped")
	}
	t.Logf("missing genesis detected: %s", got.Reason)
}

// Lamport clocks must be strictly sequential along the linked chain.
func TestLamportMonotonicity_DetectsNonMonotonicClock(t *testing.T) {
	chain := buildReceiptChain(t, "session-1", 3)
	// Rewrite the head's clock and re-link so only the ordering claim is wrong.
	chain[2].LamportClock = 99
	h, err := contracts.ReceiptChainHash(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	chain[2].PrevHash = h
	dir := writeChain(t, chain)

	got := checkLamportMonotonicity(dir)
	if got.Pass {
		t.Fatal("a chain with a non-sequential lamport clock reported PASS — " +
			"ordering claims are not actually checked")
	}
	t.Logf("non-monotonic clock detected: %s", got.Reason)
}

// A receipt whose body was edited no longer hashes to what its child references.
func TestChainIntegrity_DetectsTamperedReceiptBody(t *testing.T) {
	chain := buildReceiptChain(t, "session-1", 3)
	// Flip the verdict-bearing field on the middle receipt without re-linking.
	chain[1].Status = "DENIED"
	dir := writeChain(t, chain)

	got := checkChainIntegrity(dir)
	if got.Pass {
		t.Fatal("editing a receipt body left the chain verifying — " +
			"prev_hash linkage is not being recomputed")
	}
	t.Logf("tampered body detected: %s", got.Reason)
}
