package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinal_EntryTypeConstants(t *testing.T) {
	types := []EntryType{EntryTypeAttestation, EntryTypeAdmission, EntryTypeAudit, EntryTypeDeploy, EntryTypePolicyChange, EntryTypeViolation, EntryTypeEvidence, EntryTypeSecurityEvent}
	if len(types) != 8 {
		t.Fatal("expected 8 entry types")
	}
}

func TestFinal_AuditEntryJSONRoundTrip(t *testing.T) {
	e := AuditEntry{EntryID: "e1", Sequence: 1, EntryType: EntryTypeAudit, Subject: "agent-1"}
	data, _ := json.Marshal(e)
	var got AuditEntry
	json.Unmarshal(data, &got)
	if got.EntryID != "e1" || got.EntryType != EntryTypeAudit {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_NewAuditStore(t *testing.T) {
	s := NewAuditStore()
	if s == nil || s.Size() != 0 {
		t.Fatal("new store should be empty")
	}
}

func TestFinal_AuditStoreAppend(t *testing.T) {
	s := NewAuditStore()
	e, err := s.Append(EntryTypeAudit, "agent-1", "check", map[string]string{"key": "val"}, nil)
	if err != nil || e == nil {
		t.Fatal("append failed")
	}
	if s.Size() != 1 {
		t.Fatal("size should be 1")
	}
}

func TestFinal_AuditStoreGet(t *testing.T) {
	s := NewAuditStore()
	e, _ := s.Append(EntryTypeAudit, "agent-1", "check", nil, nil)
	got, err := s.Get(e.EntryID)
	if err != nil || got.EntryID != e.EntryID {
		t.Fatal("get failed")
	}
}

func TestFinal_AuditStoreGetNotFound(t *testing.T) {
	s := NewAuditStore()
	_, err := s.Get("nope")
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_AuditStoreGetByHash(t *testing.T) {
	s := NewAuditStore()
	e, _ := s.Append(EntryTypeAudit, "a", "b", nil, nil)
	got, err := s.GetByHash(e.EntryHash)
	if err != nil || got.EntryID != e.EntryID {
		t.Fatal("get by hash failed")
	}
}

func TestFinal_AuditStoreChainHead(t *testing.T) {
	s := NewAuditStore()
	if s.GetChainHead() != "genesis" {
		t.Fatal("initial head should be genesis")
	}
	s.Append(EntryTypeAudit, "a", "b", nil, nil)
	if s.GetChainHead() == "genesis" {
		t.Fatal("head should change after append")
	}
}

func TestFinal_AuditStoreVerifyChainEmpty(t *testing.T) {
	s := NewAuditStore()
	if err := s.VerifyChain(); err != nil {
		t.Fatal("empty chain should verify")
	}
}

func TestFinal_AuditStoreVerifyChainValid(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "a", "b", nil, nil)
	s.Append(EntryTypeDeploy, "a", "c", nil, nil)
	if err := s.VerifyChain(); err != nil {
		t.Fatal(err)
	}
}

func TestFinal_AuditStoreSequenceIncrement(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "a", "b", nil, nil)
	s.Append(EntryTypeAudit, "a", "c", nil, nil)
	if s.GetSequence() != 2 {
		t.Fatalf("expected seq 2, got %d", s.GetSequence())
	}
}

func TestFinal_AuditStoreQuery(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "agent-1", "check", nil, nil)
	s.Append(EntryTypeDeploy, "agent-2", "deploy", nil, nil)
	results := s.Query(QueryFilter{EntryType: EntryTypeAudit})
	if len(results) != 1 {
		t.Fatal("query should return 1")
	}
}

func TestFinal_AuditStoreQuerySubject(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "agent-1", "a", nil, nil)
	s.Append(EntryTypeAudit, "agent-2", "b", nil, nil)
	results := s.Query(QueryFilter{Subject: "agent-1"})
	if len(results) != 1 {
		t.Fatal("query by subject")
	}
}

func TestFinal_AuditStoreQueryMaxResults(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 10; i++ {
		s.Append(EntryTypeAudit, "a", "b", nil, nil)
	}
	results := s.Query(QueryFilter{MaxResults: 3})
	if len(results) != 3 {
		t.Fatal("max results not respected")
	}
}

func TestFinal_AuditStoreAddHandler(t *testing.T) {
	s := NewAuditStore()
	called := false
	s.AddHandler(func(entry *AuditEntry) { called = true })
	s.Append(EntryTypeAudit, "a", "b", nil, nil)
	if !called {
		t.Fatal("handler not called")
	}
}

func TestFinal_ExportBundleSuccess(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "a", "b", nil, nil)
	bundle, err := s.ExportBundle(QueryFilter{})
	if err != nil || bundle == nil {
		t.Fatal("export failed")
	}
	if bundle.EntryCount != 1 {
		t.Fatal("bundle count mismatch")
	}
}

func TestFinal_ExportBundleEmpty(t *testing.T) {
	s := NewAuditStore()
	_, err := s.ExportBundle(QueryFilter{EntryType: EntryTypeAudit})
	if err == nil {
		t.Fatal("should error on empty")
	}
}

func TestFinal_VerifyBundleSuccess(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "a", "b", nil, nil)
	s.Append(EntryTypeAudit, "a", "c", nil, nil)
	bundle, _ := s.ExportBundle(QueryFilter{})
	if err := VerifyBundle(bundle); err != nil {
		t.Fatal(err)
	}
}

func TestFinal_VerifyBundleEmptyFails(t *testing.T) {
	err := VerifyBundle(&AuditEvidenceBundle{})
	if err == nil {
		t.Fatal("should fail on empty")
	}
}

func TestFinal_AuditEvidenceBundleJSONRoundTrip(t *testing.T) {
	b := AuditEvidenceBundle{BundleID: "b1", Version: "1.0.0", EntryCount: 5}
	data, _ := json.Marshal(b)
	var got AuditEvidenceBundle
	json.Unmarshal(data, &got)
	if got.BundleID != "b1" || got.EntryCount != 5 {
		t.Fatal("bundle round-trip")
	}
}

func TestFinal_ErrorSentinels(t *testing.T) {
	if ErrEntryNotFound.Error() == "" || ErrChainBroken.Error() == "" {
		t.Fatal("error sentinels should have messages")
	}
}

func TestFinal_ComputeHashPrefix(t *testing.T) {
	h := computeHash([]byte("test"))
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatal("missing prefix")
	}
}

func TestFinal_ComputeHashDeterministic(t *testing.T) {
	h1 := computeHash([]byte("data"))
	h2 := computeHash([]byte("data"))
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_AirgapStoreCreateAndGet(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "helm-test-airgap")
	defer os.RemoveAll(dir)
	s, err := NewAirgapStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s.Put(ctx, "key1", []byte("value1"))
	got, err := s.Get(ctx, "key1")
	if err != nil || string(got) != "value1" {
		t.Fatal("get failed")
	}
}

func TestFinal_AirgapStoreGetMissing(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "helm-test-airgap2")
	defer os.RemoveAll(dir)
	s, _ := NewAirgapStore(dir)
	_, err := s.Get(context.Background(), "nope")
	if err == nil {
		t.Fatal("should error on missing key")
	}
}

func TestFinal_SearchResultFields(t *testing.T) {
	sr := SearchResult{ID: "s1", Text: "test", Score: 0.95}
	if sr.ID != "s1" || sr.Score != 0.95 {
		t.Fatal("search result fields")
	}
}

func TestFinal_MemoryEmbedderEmbed(t *testing.T) {
	e := &MemoryEmbedder{}
	emb, err := e.Embed(context.Background(), "hello")
	if err != nil || len(emb) != 1536 {
		t.Fatal("memory embedder failed")
	}
}

func TestFinal_NewOpenAIEmbedder(t *testing.T) {
	e := NewOpenAIEmbedder("test-key")
	if e == nil {
		t.Fatal("nil embedder")
	}
}

func TestFinal_OpenAIEmbedderNoKey(t *testing.T) {
	e := NewOpenAIEmbedder("")
	_, err := e.Embed(context.Background(), "test")
	if err == nil {
		t.Fatal("should error without key")
	}
}

func TestFinal_QueryFilterMatchesAll(t *testing.T) {
	f := QueryFilter{}
	e := &AuditEntry{EntryType: EntryTypeAudit, Subject: "a", Sequence: 1}
	if !f.matches(e) {
		t.Fatal("empty filter should match all")
	}
}

func TestFinal_QueryFilterSequenceRange(t *testing.T) {
	f := QueryFilter{StartSeq: 2, EndSeq: 5}
	if f.matches(&AuditEntry{Sequence: 1}) {
		t.Fatal("seq 1 should not match")
	}
	if !f.matches(&AuditEntry{Sequence: 3}) {
		t.Fatal("seq 3 should match")
	}
}

func TestFinal_PayloadHashConsistent(t *testing.T) {
	s := NewAuditStore()
	e, _ := s.Append(EntryTypeAudit, "a", "b", map[string]string{"k": "v"}, nil)
	if e.PayloadHash == "" {
		t.Fatal("payload hash should be set")
	}
}
