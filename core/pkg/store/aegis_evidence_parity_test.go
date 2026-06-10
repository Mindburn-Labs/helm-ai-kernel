package store_test

// AEGIS evidence-integrity parity proofs (MIN-493).
//
// AEGIS (arXiv 2603.12621) emits Ed25519-signed, SHA-256 hash-chained
// tamper-evident records per intercepted call. These tests bind HELM's
// parity claim to code: every audit record is SHA-256 hash-chained in an
// append-only store, tampering is detected, exported bundles re-verify,
// and chain heads are Ed25519-signable/verifiable with HELM's key
// management. Narrative: docs/AEGIS_COMPARISON.md.

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func appendParityEntries(t *testing.T, s *store.AuditStore, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := s.Append(store.EntryTypeAudit, "agent:worker", "tool.call", map[string]string{"tool": "crm.read"}, nil); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestAegisParityHashChainPerInterceptedCall(t *testing.T) {
	s := store.NewAuditStore()
	appendParityEntries(t, s, 5)

	if err := s.VerifyChain(); err != nil {
		t.Fatalf("intact chain must verify: %v", err)
	}

	entries := s.Query(store.QueryFilter{EntryType: store.EntryTypeAudit})
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	for i, entry := range entries {
		if entry.EntryHash == "" || entry.PayloadHash == "" || entry.PreviousHash == "" {
			t.Fatalf("entry %d missing chain fields: %+v", i, entry)
		}
		if i > 0 && entry.PreviousHash != entries[i-1].EntryHash {
			t.Fatalf("entry %d not chained to predecessor", i)
		}
	}
}

func TestAegisParityTamperDetection(t *testing.T) {
	s := store.NewAuditStore()
	appendParityEntries(t, s, 3)

	entries := s.Query(store.QueryFilter{EntryType: store.EntryTypeAudit})
	// Mutate a stored record in place (the store returns pointers; this
	// simulates post-hoc tampering with persisted evidence).
	entries[1].Action = "tool.exfiltrate"
	if err := s.VerifyChain(); err == nil {
		t.Fatal("tampered record must break chain verification")
	}
}

func TestAegisParityExportedBundleReverifies(t *testing.T) {
	s := store.NewAuditStore()
	appendParityEntries(t, s, 4)

	bundle, err := s.ExportBundle(store.QueryFilter{EntryType: store.EntryTypeAudit})
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	if err := store.VerifyBundle(bundle); err != nil {
		t.Fatalf("exported bundle must verify: %v", err)
	}
	if bundle.ChainHead != s.GetChainHead() {
		t.Fatalf("bundle chain head %s != store chain head %s", bundle.ChainHead, s.GetChainHead())
	}

	bundle.Entries[0].Action = "tool.exfiltrate"
	if err := store.VerifyBundle(bundle); err == nil {
		t.Fatal("tampered bundle must fail verification")
	}
}

func TestAegisParityEd25519SignedChainHead(t *testing.T) {
	s := store.NewAuditStore()
	appendParityEntries(t, s, 3)

	hsm, err := crypto.NewSoftHSM(t.TempDir())
	if err != nil {
		t.Fatalf("NewSoftHSM: %v", err)
	}
	signer, err := hsm.GetSigner("audit-attestation")
	if err != nil {
		t.Fatalf("GetSigner: %v", err)
	}

	head := []byte(s.GetChainHead())
	sigHex, err := signer.Sign(head)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := crypto.Verify(signer.PublicKey(), sigHex, head)
	if err != nil || !ok {
		t.Fatalf("Ed25519 signature over chain head must verify: ok=%v err=%v", ok, err)
	}
	ok, err = crypto.Verify(signer.PublicKey(), sigHex, []byte("forged-chain-head"))
	if err != nil {
		t.Fatalf("verify forged head: %v", err)
	}
	if ok {
		t.Fatal("signature must not verify over a forged chain head")
	}
}
