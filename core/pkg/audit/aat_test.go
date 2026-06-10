package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func fixedAATEntries() []*store.AuditEntry {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return []*store.AuditEntry{
		{
			EntryID:     "00000000-0000-0000-0000-000000000001",
			Sequence:    1,
			Timestamp:   base,
			EntryType:   store.EntryTypeAudit,
			Subject:     "tenant:acme",
			Action:      "tool.call",
			PayloadHash: "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11",
			Metadata:    map[string]string{"connector": "github"},
		},
		{
			EntryID:     "00000000-0000-0000-0000-000000000002",
			Sequence:    2,
			Timestamp:   base.Add(time.Second),
			EntryType:   store.EntryTypeAudit,
			Subject:     "tenant:acme",
			Action:      "verdict.allow",
			PayloadHash: "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22",
		},
		{
			EntryID:     "00000000-0000-0000-0000-000000000003",
			Sequence:    3,
			Timestamp:   base.Add(2 * time.Second),
			EntryType:   store.EntryTypeAudit,
			Subject:     "tenant:acme",
			Action:      "effect.commit",
			PayloadHash: "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33",
			Metadata:    map[string]string{"connector": "slack", "scope": "chat.write"},
		},
	}
}

func fixedAATSigner(t *testing.T) AATSigner {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	signer, err := NewEd25519AATSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("NewEd25519AATSigner: %v", err)
	}
	return signer
}

func TestConvertEntriesToAATChainAndVerify(t *testing.T) {
	records, err := ConvertEntriesToAAT(fixedAATEntries(), "agent-1", nil)
	if err != nil {
		t.Fatalf("ConvertEntriesToAAT: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
	if records[0].PreviousRecordHash != AATGenesisHash {
		t.Fatalf("first record not rooted at genesis: %s", records[0].PreviousRecordHash)
	}
	for i := 1; i < len(records); i++ {
		if records[i].PreviousRecordHash != records[i-1].RecordHash {
			t.Fatalf("chain broken at record %d", i)
		}
	}
	for i, r := range records {
		if r.AATVersion != AATVersion {
			t.Fatalf("record %d wrong aat_version: %s", i, r.AATVersion)
		}
		if r.AgentID != "agent-1" || r.RecordID == "" || r.Timestamp == "" || r.PayloadHash == "" {
			t.Fatalf("record %d missing mandatory fields: %+v", i, r)
		}
	}
	if err := VerifyAATChain(records); err != nil {
		t.Fatalf("VerifyAATChain: %v", err)
	}
}

func TestConvertEntriesToAATDeterministic(t *testing.T) {
	first, err := ConvertEntriesToAAT(fixedAATEntries(), "agent-1", fixedAATSigner(t))
	if err != nil {
		t.Fatalf("first conversion: %v", err)
	}
	second, err := ConvertEntriesToAAT(fixedAATEntries(), "agent-1", fixedAATSigner(t))
	if err != nil {
		t.Fatalf("second conversion: %v", err)
	}
	a, err := MarshalAATJSONL(first)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	b, err := MarshalAATJSONL(second)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("AAT export is not byte-deterministic")
	}
}

func TestAATSignedChainVerifies(t *testing.T) {
	records, err := ConvertEntriesToAAT(fixedAATEntries(), "agent-1", fixedAATSigner(t))
	if err != nil {
		t.Fatalf("ConvertEntriesToAAT: %v", err)
	}
	for i, r := range records {
		if r.Signature == nil || r.Signature.Algorithm != "Ed25519" {
			t.Fatalf("record %d missing Ed25519 signature", i)
		}
	}
	if err := VerifyAATChain(records); err != nil {
		t.Fatalf("VerifyAATChain signed: %v", err)
	}
}

func TestAATTamperDetection(t *testing.T) {
	records, err := ConvertEntriesToAAT(fixedAATEntries(), "agent-1", fixedAATSigner(t))
	if err != nil {
		t.Fatalf("ConvertEntriesToAAT: %v", err)
	}

	tampered := make([]AATRecord, len(records))
	copy(tampered, records)
	tampered[1].Action = "verdict.deny"
	if err := VerifyAATChain(tampered); !errors.Is(err, ErrAATChainBroken) {
		t.Fatalf("expected ErrAATChainBroken for mutated record, got %v", err)
	}

	reordered := []AATRecord{records[1], records[0], records[2]}
	if err := VerifyAATChain(reordered); !errors.Is(err, ErrAATChainBroken) {
		t.Fatalf("expected ErrAATChainBroken for reordered chain, got %v", err)
	}

	badSig := make([]AATRecord, len(records))
	copy(badSig, records)
	sig := *records[0].Signature
	sig.Value = records[1].Signature.Value
	badSig[0].Signature = &sig
	if err := VerifyAATChain(badSig); !errors.Is(err, ErrAATBadSignature) {
		t.Fatalf("expected ErrAATBadSignature, got %v", err)
	}
}

func TestConvertEntriesToAATRejectsEmptyAgentID(t *testing.T) {
	if _, err := ConvertEntriesToAAT(fixedAATEntries(), "", nil); !errors.Is(err, ErrAATEmptyAgentID) {
		t.Fatalf("expected ErrAATEmptyAgentID, got %v", err)
	}
}

func TestAATGoldenFixture(t *testing.T) {
	records, err := ConvertEntriesToAAT(fixedAATEntries(), "agent-1", fixedAATSigner(t))
	if err != nil {
		t.Fatalf("ConvertEntriesToAAT: %v", err)
	}
	got, err := MarshalAATJSONL(records)
	if err != nil {
		t.Fatalf("MarshalAATJSONL: %v", err)
	}

	goldenPath := filepath.Join("testdata", "aat_export_golden.jsonl")
	if os.Getenv("UPDATE_AAT_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0750); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with UPDATE_AAT_GOLDEN=1 to regenerate): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AAT export drifted from golden fixture\n got: %s\nwant: %s", got, want)
	}

	var parsed []AATRecord
	for _, line := range bytes.Split(bytes.TrimSpace(want), []byte("\n")) {
		var r AATRecord
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("golden line unmarshal: %v", err)
		}
		parsed = append(parsed, r)
	}
	if err := VerifyAATChain(parsed); err != nil {
		t.Fatalf("golden fixture chain does not verify: %v", err)
	}
}

func TestExporterGenerateAAT(t *testing.T) {
	s := store.NewAuditStore()
	for _, action := range []string{"tool.call", "verdict.allow"} {
		if _, err := s.Append(store.EntryTypeAudit, "tenant:acme", action, map[string]string{"k": "v"}, nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	exporter := NewExporter(s)
	jsonl, err := exporter.GenerateAAT(context.Background(), ExportRequest{TenantID: "acme"}, "kernel-1", nil)
	if err != nil {
		t.Fatalf("GenerateAAT: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(jsonl), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 AAT records, got %d", len(lines))
	}
	var records []AATRecord
	for _, line := range lines {
		var r AATRecord
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		records = append(records, r)
	}
	if err := VerifyAATChain(records); err != nil {
		t.Fatalf("VerifyAATChain: %v", err)
	}

	if _, err := exporter.GenerateAAT(context.Background(), ExportRequest{}, "kernel-1", nil); !errors.Is(err, ErrEmptyTenantID) {
		t.Fatalf("expected ErrEmptyTenantID, got %v", err)
	}
	empty := NewExporter(nil)
	if _, err := empty.GenerateAAT(context.Background(), ExportRequest{TenantID: "acme"}, "kernel-1", nil); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("expected ErrStoreNotConfigured, got %v", err)
	}
}
