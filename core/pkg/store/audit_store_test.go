package store

import (
	"errors"
	"testing"
	"time"
)

func TestAuditStore_Append(t *testing.T) {
	store := NewAuditStore()

	entry, err := store.Append(EntryTypeAttestation, "module-1", "created", map[string]string{"version": "1.0"}, nil)
	if err != nil {
		t.Fatalf("failed to append: %v", err)
	}

	if store.GetSequence() != 1 {
		t.Errorf("expected store sequence 1, got %d", store.GetSequence())
	}
	if store.GetChainHead() != entry.EntryHash {
		t.Errorf("expected chain head %q, got %q", entry.EntryHash, store.GetChainHead())
	}

	if entry.Sequence != 1 {
		t.Errorf("expected sequence 1, got %d", entry.Sequence)
	}
	if entry.EntryType != EntryTypeAttestation {
		t.Errorf("expected attestation type, got %s", entry.EntryType)
	}
	if entry.PreviousHash != "genesis" {
		t.Errorf("expected genesis as first previous hash, got %s", entry.PreviousHash)
	}
}

func TestAuditStore_HashChaining(t *testing.T) {
	store := NewAuditStore()

	entry1, _ := store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)
	entry2, _ := store.Append(EntryTypeAdmission, "mod-1", "admitted", nil, nil)
	entry3, _ := store.Append(EntryTypeDeploy, "mod-1", "deployed", nil, nil)

	// Verify chaining
	if entry2.PreviousHash != entry1.EntryHash {
		t.Error("entry2 should link to entry1")
	}
	if entry3.PreviousHash != entry2.EntryHash {
		t.Error("entry3 should link to entry2")
	}

	// Verify sequence
	if entry1.Sequence != 1 || entry2.Sequence != 2 || entry3.Sequence != 3 {
		t.Error("sequence numbers incorrect")
	}
}

func TestAuditStore_VerifyChain(t *testing.T) {
	store := NewAuditStore()

	_, _ = store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)
	_, _ = store.Append(EntryTypeAdmission, "mod-1", "admitted", nil, nil)
	_, _ = store.Append(EntryTypeDeploy, "mod-1", "deployed", nil, nil)

	err := store.VerifyChain()
	if err != nil {
		t.Errorf("expected valid chain, got error: %v", err)
	}
}

func TestAuditStore_Get(t *testing.T) {
	store := NewAuditStore()

	entry, _ := store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)

	// Get by ID
	found, err := store.Get(entry.EntryID)
	if err != nil {
		t.Errorf("failed to get by ID: %v", err)
	}
	if found.EntryID != entry.EntryID {
		t.Error("got wrong entry")
	}

	// Get by hash
	foundByHash, err := store.GetByHash(entry.EntryHash)
	if err != nil {
		t.Errorf("failed to get by hash: %v", err)
	}
	if foundByHash.EntryID != entry.EntryID {
		t.Error("got wrong entry by hash")
	}

	// Get non-existent
	_, err = store.Get("non-existent")
	if !errors.Is(err, ErrEntryNotFound) {
		t.Error("expected ErrEntryNotFound")
	}
}

func TestAuditStore_Query(t *testing.T) {
	store := NewAuditStore()

	_, _ = store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)
	_, _ = store.Append(EntryTypeAdmission, "mod-1", "admitted", nil, nil)
	_, _ = store.Append(EntryTypeAttestation, "mod-2", "created", nil, nil)

	// Query by type
	results := store.Query(QueryFilter{EntryType: EntryTypeAttestation})
	if len(results) != 2 {
		t.Errorf("expected 2 attestation entries, got %d", len(results))
	}

	// Query by subject
	results = store.Query(QueryFilter{Subject: "mod-1"})
	if len(results) != 2 {
		t.Errorf("expected 2 mod-1 entries, got %d", len(results))
	}

	// Query by sequence range
	results = store.Query(QueryFilter{StartSeq: 2, EndSeq: 3})
	if len(results) != 2 {
		t.Errorf("expected 2 entries in range, got %d", len(results))
	}
}

func TestAuditStore_ExportBundle(t *testing.T) {
	store := NewAuditStore()

	_, _ = store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)
	_, _ = store.Append(EntryTypeAdmission, "mod-1", "admitted", nil, nil)
	_, _ = store.Append(EntryTypeDeploy, "mod-1", "deployed", nil, nil)

	bundle, err := store.ExportBundle(QueryFilter{Subject: "mod-1"})
	if err != nil {
		t.Fatalf("failed to export bundle: %v", err)
	}

	if bundle.EntryCount != 3 {
		t.Errorf("expected 3 entries, got %d", bundle.EntryCount)
	}
	if bundle.BundleHash == "" {
		t.Error("bundle should have hash")
	}

	// Verify bundle
	err = VerifyBundle(bundle)
	if err != nil {
		t.Errorf("bundle verification failed: %v", err)
	}
}

func TestAuditStore_Handler(t *testing.T) {
	store := NewAuditStore()

	var captured *AuditEntry
	store.AddHandler(func(entry *AuditEntry) {
		captured = entry
	})

	entry, _ := store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)

	if captured == nil {
		t.Error("handler not called")
	}
	if captured.EntryID != entry.EntryID {
		t.Error("handler received wrong entry")
	}
}

func TestAuditStore_TimeFilter(t *testing.T) {
	store := NewAuditStore()

	_, _ = store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)
	time.Sleep(10 * time.Millisecond)
	mid := time.Now()
	time.Sleep(10 * time.Millisecond)
	_, _ = store.Append(EntryTypeAdmission, "mod-1", "admitted", nil, nil)

	// Query entries before mid
	results := store.Query(QueryFilter{EndTime: &mid})
	if len(results) != 1 {
		t.Errorf("expected 1 entry before mid, got %d", len(results))
	}

	// Query entries after mid
	results = store.Query(QueryFilter{StartTime: &mid})
	if len(results) != 1 {
		t.Errorf("expected 1 entry after mid, got %d", len(results))
	}
}

func TestAuditStore_Size(t *testing.T) {
	store := NewAuditStore()

	if store.Size() != 0 {
		t.Error("expected size 0 initially")
	}

	_, _ = store.Append(EntryTypeAttestation, "mod-1", "created", nil, nil)
	_, _ = store.Append(EntryTypeAdmission, "mod-1", "admitted", nil, nil)

	if store.Size() != 2 {
		t.Errorf("expected size 2, got %d", store.Size())
	}
}

func TestVerifyBundle_BrokenChain(t *testing.T) {
	bundle := &AuditEvidenceBundle{
		BundleID: "test",
		Entries: []*AuditEntry{
			{EntryID: "1", EntryHash: "hash1", PreviousHash: "genesis"},
			{EntryID: "2", EntryHash: "hash2", PreviousHash: "wrong-hash"}, // Wrong link
		},
	}

	// Set bundle hash to match entries
	bundle.BundleHash = computeHash([]byte(`[{"entry_id":"1"},{"entry_id":"2"}]`))

	err := VerifyBundle(bundle)
	if err == nil {
		t.Error("expected error for broken chain")
	}
}
