package admission

// quantum_posture: writes stored classical Ed25519 receipt.v5 envelopes and
// their binding bytes into an export document unchanged; it signs nothing and
// makes no post-quantum claim.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// receiptBundle is the export document: the bundle shape
// receiptverify.ParseBundle reads.
type receiptBundle struct {
	Receipts        []json.RawMessage `json:"receipts"`
	GatewayBindings map[string][]byte `json:"gateway_bindings"`
	KeyID           string            `json:"key_id,omitempty"`
}

// encodeReceiptBundle writes stored receipts, in the order given, as the
// document receipt_verify --receipt reads: a receipts array holding each
// envelope's exact bytes, gateway_bindings mapping each receipt id to its
// binding bytes (base64), and key_id, the signing key the receipts name, when
// they all name one. Every envelope must parse as one receipt with its stored
// receipt id. Nothing about trust travels in it: the verifier supplies the
// key.
func encodeReceiptBundle(receipts []SignedReceipt) ([]byte, error) {
	if len(receipts) == 0 {
		return nil, errors.New("a receipt bundle needs at least one receipt")
	}
	out := receiptBundle{Receipts: make([]json.RawMessage, 0, len(receipts)), GatewayBindings: make(map[string][]byte, len(receipts))}
	keys := map[string]bool{}
	for i, r := range receipts {
		id := r.Ref.ReceiptID
		if len(r.Binding) == 0 {
			return nil, fmt.Errorf("receipt[%d] %q has no binding", i, id)
		}
		parsed, err := receiptverify.ParseBundle(r.Envelope)
		if err != nil || len(parsed.Receipts) != 1 || parsed.Receipts[0] == nil {
			return nil, fmt.Errorf("receipt[%d] %q does not parse as one receipt: %v", i, id, err)
		}
		if parsed.Receipts[0].ReceiptID != id {
			return nil, fmt.Errorf("receipt[%d] carries receipt_id %q, not %q", i, parsed.Receipts[0].ReceiptID, id)
		}
		if _, dup := out.GatewayBindings[id]; dup {
			return nil, fmt.Errorf("receipt %q appears twice", id)
		}
		keys[parsed.Receipts[0].KeyID] = true
		out.Receipts = append(out.Receipts, json.RawMessage(bytes.TrimSpace(r.Envelope)))
		out.GatewayBindings[id] = r.Binding
	}
	if len(keys) == 1 {
		for id := range keys {
			out.KeyID = id
		}
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
