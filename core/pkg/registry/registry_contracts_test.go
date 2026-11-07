// quantum_posture: classical Ed25519/SHA-256 only; adds no post-quantum assurance.
package registry

import (
	"encoding/json"
	"testing"
)

func TestFinal_ErrModuleNotFound(t *testing.T) {
	if ErrModuleNotFound.Error() == "" {
		t.Fatal("error should have message")
	}
}

func TestFinal_PackStateConstants(t *testing.T) {
	states := []PackState{PackStatePublished, PackStateVerified, PackStateSigned, PackStateActive, PackStateDeprecated}
	if len(states) != 5 {
		t.Fatal("expected 5 pack states")
	}
}

func TestFinal_PackEntryJSONRoundTrip(t *testing.T) {
	pe := PackEntry{PackID: "p1", Name: "pack1", Version: "1.0", State: PackStatePublished}
	data, _ := json.Marshal(pe)
	var got PackEntry
	json.Unmarshal(data, &got)
	if got.PackID != "p1" || got.State != PackStatePublished {
		t.Fatal("round-trip")
	}
}

func TestFinal_PackSignatureJSONRoundTrip(t *testing.T) {
	ps := PackSignature{SignerID: "s1", Algorithm: "ed25519", Signature: "sig"}
	data, _ := json.Marshal(ps)
	var got PackSignature
	json.Unmarshal(data, &got)
	if got.SignerID != "s1" {
		t.Fatal("sig round-trip")
	}
}

func TestFinal_PackSearchQueryJSONRoundTrip(t *testing.T) {
	q := PackSearchQuery{Name: "test", Limit: 10}
	data, _ := json.Marshal(q)
	var got PackSearchQuery
	json.Unmarshal(data, &got)
	if got.Name != "test" || got.Limit != 10 {
		t.Fatal("query round-trip")
	}
}

func TestFinal_PackSearchResultJSONRoundTrip(t *testing.T) {
	r := PackSearchResult{TotalCount: 5, Entries: []*PackEntry{}}
	data, _ := json.Marshal(r)
	var got PackSearchResult
	json.Unmarshal(data, &got)
	if got.TotalCount != 5 {
		t.Fatal("result round-trip")
	}
}
