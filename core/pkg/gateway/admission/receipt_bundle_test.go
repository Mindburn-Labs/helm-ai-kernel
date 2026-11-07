package admission

// quantum_posture: encodes and verifies fixed-seed classical Ed25519 test
// receipts; no post-quantum claim.

import (
	"bytes"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// encodeReceiptBundle writes the document receipt_verify reads, keeping each
// envelope's exact bytes, and refuses a bundle it cannot vouch for.
func TestEncodeReceiptBundleRoundTrips(t *testing.T) {
	_, stored := frozenGatewayChain(t)
	doc, err := encodeReceiptBundle(stored)
	must(t, err)
	for _, s := range stored {
		if !bytes.Contains(doc, s.Envelope) {
			t.Fatalf("the bundle does not hold receipt %s's exact bytes", s.Ref.ReceiptID)
		}
	}
	parsed, err := receiptverify.ParseBundle(doc)
	must(t, err)
	signer := frozenGatewaySigner(t)
	if parsed.KeyID != signer.GetKeyID() || parsed.PublicKeyHex != "" {
		t.Fatalf("bundle key_id %q, public_key_hex %q", parsed.KeyID, parsed.PublicKeyHex)
	}
	trust := receiptverify.TrustRoot{Keys: map[string]string{signer.GetKeyID(): signer.PublicKey()}}
	if res := receiptverify.VerifyBundleWith(parsed, trust, receiptverify.Options{RequireGatewayBindings: true}); !res.Valid || res.BindingsChecked != 3 {
		t.Fatalf("encoded bundle does not verify: %+v", res)
	}

	two := bytes.Join([][]byte{[]byte("["), stored[0].Envelope, []byte(","), stored[1].Envelope, []byte("]")}, nil)
	for name, bad := range map[string][]SignedReceipt{
		"empty":        nil,
		"no binding":   {{Ref: stored[0].Ref, Envelope: stored[0].Envelope}},
		"wrong id":     {{Ref: stored[1].Ref, Envelope: stored[0].Envelope, Binding: stored[0].Binding}},
		"duplicate":    {stored[0], stored[0]},
		"not receipt":  {{Ref: ReceiptRef{ReceiptID: "x"}, Envelope: []byte(`{"a":1`), Binding: []byte("{}")}},
		"two receipts": {{Ref: stored[0].Ref, Envelope: two, Binding: stored[0].Binding}},
	} {
		if _, err := encodeReceiptBundle(bad); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}
