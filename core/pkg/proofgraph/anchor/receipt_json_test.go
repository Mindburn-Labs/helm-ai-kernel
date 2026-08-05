package anchor

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// Anchor receipts are embedded in EvidencePack seals and canonicalized with
// JCS, so every receipt any backend returns must marshal to valid JSON. The
// RFC 3161 and eIDAS backends receive binary DER responses; storing them in
// the json.RawMessage archival field produced invalid JSON and broke seal
// canonicalization during release asset staging (v0.8.0 run 31047952314).
func TestBinaryBackendReceiptsMarshalToValidJSON(t *testing.T) {
	der := []byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x01}
	for _, receipt := range []AnchorReceipt{
		{
			Backend:        "rfc3161",
			Request:        AnchorRequest{MerkleRoot: "ab", Timestamp: time.Unix(0, 0).UTC()},
			LogID:          "https://tsa.example/tsr",
			IntegratedTime: time.Unix(0, 0).UTC(),
			Signature:      "MIIBAAIBAQ==",
		},
		{
			Backend:        "eidas",
			Request:        AnchorRequest{MerkleRoot: "cd", Timestamp: time.Unix(0, 0).UTC()},
			LogID:          "https://qtsp.example",
			IntegratedTime: time.Unix(0, 0).UTC(),
			Signature:      "MIIBAAIBAQ==",
		},
	} {
		if len(receipt.RawResponse) != 0 {
			t.Fatalf("%s receipt must not carry raw archival bytes", receipt.Backend)
		}
		data, err := json.Marshal(receipt)
		if err != nil {
			t.Fatalf("marshal %s receipt: %v", receipt.Backend, err)
		}
		if !json.Valid(data) {
			t.Fatalf("%s receipt is not valid JSON", receipt.Backend)
		}
		var round AnchorReceipt
		if err := json.Unmarshal(data, &round); err != nil {
			t.Fatalf("round-trip %s receipt: %v", receipt.Backend, err)
		}
	}
	if json.Valid(der) {
		t.Fatal("test DER fixture unexpectedly valid JSON")
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(json.RawMessage(der)); err == nil {
		t.Fatal("encoding raw DER as json.RawMessage should fail; the guard above depends on it")
	}
}
