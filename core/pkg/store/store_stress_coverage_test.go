package store

import (
	"fmt"
	"sync"
	"testing"
)

// --- Audit Store 500 Entries ---

func TestStress_AuditStore_500Entries(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 500; i++ {
		_, err := s.Append(EntryTypeAudit, fmt.Sprintf("subj-%d", i), "action", map[string]string{"i": fmt.Sprintf("%d", i)}, nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if s.Size() != 500 {
		t.Fatalf("expected 500 entries, got %d", s.Size())
	}
}

func TestStress_AuditStore_SequenceMonotonic(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 100; i++ {
		s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	}
	if s.GetSequence() != 100 {
		t.Fatalf("expected sequence 100, got %d", s.GetSequence())
	}
}

func TestStress_AuditStore_EntryIDsUnique(t *testing.T) {
	s := NewAuditStore()
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		e, _ := s.Append(EntryTypeAudit, "subj", "action", nil, nil)
		if seen[e.EntryID] {
			t.Fatalf("duplicate entry ID: %s", e.EntryID)
		}
		seen[e.EntryID] = true
	}
}

func TestStress_AuditStore_GetByID(t *testing.T) {
	s := NewAuditStore()
	entry, _ := s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	got, err := s.Get(entry.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntryID != entry.EntryID {
		t.Fatal("entry ID mismatch")
	}
}

func TestStress_AuditStore_GetNotFound(t *testing.T) {
	s := NewAuditStore()
	_, err := s.Get("ghost")
	if err != ErrEntryNotFound {
		t.Fatalf("expected ErrEntryNotFound, got %v", err)
	}
}

func TestStress_AuditStore_GetByHash(t *testing.T) {
	s := NewAuditStore()
	entry, _ := s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	got, err := s.GetByHash(entry.EntryHash)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntryHash != entry.EntryHash {
		t.Fatal("hash mismatch")
	}
}

// --- Hash Chain Verification ---

func TestStress_AuditStore_HashChain_500Entries(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 500; i++ {
		s.Append(EntryTypeAudit, "subj", "action", map[string]string{"i": fmt.Sprintf("%d", i)}, nil)
	}
	if err := s.VerifyChain(); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestStress_AuditStore_GenesisHead(t *testing.T) {
	s := NewAuditStore()
	if s.GetChainHead() != "genesis" {
		t.Fatal("expected genesis head on empty store")
	}
}

func TestStress_AuditStore_HeadAdvances(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	head1 := s.GetChainHead()
	s.Append(EntryTypeAudit, "subj", "action2", nil, nil)
	head2 := s.GetChainHead()
	if head1 == head2 {
		t.Fatal("head should advance after append")
	}
}

func TestStress_AuditStore_VerifyEmptyChain(t *testing.T) {
	s := NewAuditStore()
	if err := s.VerifyChain(); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

// --- Query 100 Results ---

func TestStress_AuditStore_Query100Results(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 200; i++ {
		s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	}
	results := s.Query(QueryFilter{MaxResults: 100})
	if len(results) != 100 {
		t.Fatalf("expected 100 results, got %d", len(results))
	}
}

func TestStress_AuditStore_QueryByType(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 50; i++ {
		s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	}
	for i := 0; i < 50; i++ {
		s.Append(EntryTypeDeploy, "subj", "deploy", nil, nil)
	}
	results := s.Query(QueryFilter{EntryType: EntryTypeDeploy})
	if len(results) != 50 {
		t.Fatalf("expected 50 deploy entries, got %d", len(results))
	}
}

func TestStress_AuditStore_QueryBySubject(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 100; i++ {
		subj := "a"
		if i%2 == 0 {
			subj = "b"
		}
		s.Append(EntryTypeAudit, subj, "action", nil, nil)
	}
	results := s.Query(QueryFilter{Subject: "b"})
	if len(results) != 50 {
		t.Fatalf("expected 50 subject-b entries, got %d", len(results))
	}
}

func TestStress_AuditStore_QueryBySequenceRange(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 100; i++ {
		s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	}
	results := s.Query(QueryFilter{StartSeq: 50, EndSeq: 60})
	if len(results) != 11 {
		t.Fatalf("expected 11 entries in range [50,60], got %d", len(results))
	}
}

func TestStress_AuditStore_ExportBundle(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 50; i++ {
		s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	}
	bundle, err := s.ExportBundle(QueryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.EntryCount != 50 {
		t.Fatalf("expected 50 entries in bundle, got %d", bundle.EntryCount)
	}
	if err := VerifyBundle(bundle); err != nil {
		t.Fatalf("bundle verification failed: %v", err)
	}
}

func TestStress_AuditStore_ExportBundleEmpty(t *testing.T) {
	s := NewAuditStore()
	_, err := s.ExportBundle(QueryFilter{})
	if err == nil {
		t.Fatal("expected error exporting empty store")
	}
}

// --- Concurrent Append 50 Goroutines ---

func TestStress_Concurrent_Append50Goroutines(t *testing.T) {
	s := NewAuditStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				s.Append(EntryTypeAudit, fmt.Sprintf("subj-%d", id), "action", nil, nil)
			}
		}(i)
	}
	wg.Wait()
	if s.Size() != 500 {
		t.Fatalf("expected 500 entries, got %d", s.Size())
	}
	if err := s.VerifyChain(); err != nil {
		t.Fatalf("chain broken after concurrent appends: %v", err)
	}
}

func TestStress_AuditStore_Handler(t *testing.T) {
	s := NewAuditStore()
	count := 0
	s.AddHandler(func(entry *AuditEntry) { count++ })
	for i := 0; i < 10; i++ {
		s.Append(EntryTypeAudit, "subj", "action", nil, nil)
	}
	if count != 10 {
		t.Fatalf("expected 10 handler calls, got %d", count)
	}
}

func TestStress_AuditStore_PayloadHash(t *testing.T) {
	s := NewAuditStore()
	e, _ := s.Append(EntryTypeAudit, "subj", "action", map[string]string{"key": "val"}, nil)
	if e.PayloadHash == "" {
		t.Fatal("expected payload hash to be set")
	}
}

func TestStress_AuditStore_Metadata(t *testing.T) {
	s := NewAuditStore()
	meta := map[string]string{"env": "prod", "region": "us-east-1"}
	e, _ := s.Append(EntryTypeAudit, "subj", "action", nil, meta)
	if e.Metadata["env"] != "prod" {
		t.Fatal("metadata not preserved")
	}
}

func TestStress_AuditStore_EntryTypes(t *testing.T) {
	s := NewAuditStore()
	types := []EntryType{EntryTypeAttestation, EntryTypeAdmission, EntryTypeAudit, EntryTypeDeploy, EntryTypePolicyChange}
	for _, et := range types {
		e, err := s.Append(et, "subj", "action", nil, nil)
		if err != nil {
			t.Fatalf("type %s: %v", et, err)
		}
		if e.EntryType != et {
			t.Fatalf("expected type %s, got %s", et, e.EntryType)
		}
	}
}

func TestStress_AuditStore_PreviousHash(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "subj", "action1", nil, nil)
	e2, _ := s.Append(EntryTypeAudit, "subj", "action2", nil, nil)
	if e2.PreviousHash == "genesis" {
		t.Fatal("second entry should not have genesis as previous hash")
	}
}

func TestStress_AuditStore_GetByHashNotFound(t *testing.T) {
	s := NewAuditStore()
	_, err := s.GetByHash("sha256:nonexistent")
	if err != ErrEntryNotFound {
		t.Fatalf("expected ErrEntryNotFound, got %v", err)
	}
}

func TestStress_AuditStore_QueryEmpty(t *testing.T) {
	s := NewAuditStore()
	results := s.Query(QueryFilter{EntryType: EntryTypeAudit})
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestStress_AuditStore_ConcurrentQueryAndAppend(t *testing.T) {
	s := NewAuditStore()
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Append(EntryTypeAudit, "subj", "action", nil, nil)
		}()
	}
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Query(QueryFilter{})
		}()
	}
	wg.Wait()
}
