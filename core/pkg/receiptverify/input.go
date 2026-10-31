// quantum_posture: receipt parsing adds no signature scheme or trusted root.
package receiptverify

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type rawReceiptInput struct {
	receipts     []json.RawMessage
	permits      []*PermitRecord
	publicKeyHex string
	keyID        string
	single       bool
}

// ParseBundle accepts the three shapes a receipt reaches a counterparty in.
// Shape selection happens once and retains each receipt's raw object until the
// receipt.v5 signed-member contract has been checked.
func ParseBundle(raw []byte) (Bundle, error) {
	input, err := normalizeReceiptInput(raw)
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{
		Receipts:     make([]*contracts.Receipt, 0, len(input.receipts)),
		Permits:      input.permits,
		PublicKeyHex: input.publicKeyHex,
		KeyID:        input.keyID,
	}
	for i, rawReceipt := range input.receipts {
		if _, err := ParseReceiptDocument(rawReceipt); err != nil {
			return Bundle{}, fmt.Errorf("receipt[%d]: %w", i, err)
		}
		var receipt *contracts.Receipt
		if err := json.Unmarshal(rawReceipt, &receipt); err != nil {
			return Bundle{}, fmt.Errorf("parse receipt[%d]: %w", i, err)
		}
		b.Receipts = append(b.Receipts, receipt)
	}
	if input.single && len(b.Receipts) == 1 && b.Receipts[0] != nil &&
		b.Receipts[0].ReceiptID == "" && b.Receipts[0].Signature == "" {
		return Bundle{}, fmt.Errorf("input parsed as JSON but holds no receipt: expected a receipt object, an array of receipts, or an object with a \"receipts\" array")
	}
	return b, nil
}

func normalizeReceiptInput(raw []byte) (rawReceiptInput, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return rawReceiptInput{}, fmt.Errorf("input is empty")
	}
	if err := ValidateJSONStructure(trimmed); err != nil {
		return rawReceiptInput{}, err
	}
	var input rawReceiptInput
	switch trimmed[0] {
	case '[':
		if err := json.Unmarshal(trimmed, &input.receipts); err != nil {
			return rawReceiptInput{}, fmt.Errorf("parse receipt array: %w", err)
		}
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return rawReceiptInput{}, fmt.Errorf("parse receipt object: %w", err)
		}
		receipts, isBundle := object["receipts"]
		if !isBundle {
			input.receipts = []json.RawMessage{append(json.RawMessage(nil), trimmed...)}
			input.single = true
			return input, nil
		}
		if err := json.Unmarshal(receipts, &input.receipts); err != nil {
			return rawReceiptInput{}, fmt.Errorf("parse receipts bundle: receipts: %w", err)
		}
		for key, target := range map[string]any{
			"permits":        &input.permits,
			"public_key_hex": &input.publicKeyHex,
			"key_id":         &input.keyID,
		} {
			value, ok := object[key]
			if ok {
				if err := json.Unmarshal(value, target); err != nil {
					return rawReceiptInput{}, fmt.Errorf("parse receipts bundle: %s: %w", key, err)
				}
			}
		}
	default:
		return rawReceiptInput{}, fmt.Errorf("input must be a receipt object, an array of receipts, or an object with a \"receipts\" array")
	}
	return input, nil
}
