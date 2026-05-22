package evidencepack

import (
	"testing"
	"time"
)

func TestBuilder_AddHostEvidence(t *testing.T) {
	builder := NewBuilder("pack-host", "did:agent:test", "intent-1", "sha256:policy").
		WithCreatedAt(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC))
	if err := builder.AddReceipt("r1", map[string]any{"receipt_id": "r1"}); err != nil {
		t.Fatal(err)
	}
	if err := builder.AddHostEvidence("residual/delta", "chain.json", []byte(`{"receipts":[]}`)); err != nil {
		t.Fatal(err)
	}
	manifest, contents, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	if contents["host_evidence/residual_delta/chain.json"] == nil {
		t.Fatal("host evidence entry missing from pack contents")
	}
	found := false
	for _, entry := range manifest.Entries {
		if entry.Path == "host_evidence/residual_delta/chain.json" && entry.ContentType == "application/json" {
			found = true
		}
	}
	if !found {
		t.Fatalf("host evidence entry missing from manifest: %+v", manifest.Entries)
	}
	first, err := Archive(contents)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Archive(contents)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("host evidence archive output should be deterministic")
	}
}
