// quantum_posture: receipt parsing adds no signature scheme or trusted root.
package receiptverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type rawReceiptInput struct {
	receipts     []json.RawMessage
	permits      []*PermitRecord
	publicKeyHex string
	keyID        string
	bindings     map[string][]byte
	single       bool
}

// ParseBundle accepts the three shapes a receipt reaches a counterparty in.
// Shape selection happens once and retains each receipt's raw object until the
// receipt.v5 signed-member contract has been checked.
//
// Member names are matched exactly. A member that is a receipt, bundle or
// permit member in another letter case is refused: encoding/json would bind it
// to the struct field, and the parsed receipt would differ from what a reader
// matching names exactly takes from the same bytes. Keys of maps and free-form
// values (metadata, public_key_set, subject) are data and are compared
// exactly. In the bundle shape, a receipt member beside "receipts" is refused
// too (bundleDecoyMember). A document nested deeper than MaxJSONDepth is
// refused before it is walked.
func ParseBundle(raw []byte) (Bundle, error) {
	input, err := normalizeReceiptInput(raw)
	if err != nil {
		return Bundle{}, err
	}
	return input.bundle(false)
}

// bundle decodes the receipts shape selection kept raw, each under the
// receipt.v5 signed-member contract. anyProfile is AnySignatureProfile.
func (input rawReceiptInput) bundle(anyProfile bool) (Bundle, error) {
	b := Bundle{
		Receipts:        make([]*contracts.Receipt, 0, len(input.receipts)),
		Permits:         input.permits,
		PublicKeyHex:    input.publicKeyHex,
		KeyID:           input.keyID,
		GatewayBindings: input.bindings,
	}
	for i, rawReceipt := range input.receipts {
		if _, err := parseReceiptDocument(rawReceipt, anyProfile); err != nil {
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

// ParseReceipt parses a document that must be exactly one receipt object,
// under the rules ParseBundle applies to each receipt. It is the parser for a
// caller that holds one receipt per document (a file of an evidence bundle, a
// request body, verify receipt) and decodes it into contracts.Receipt: one
// rule then decides what a receipt document is, whichever verifier reads it.
//
// An array, a bundle (an object with a "receipts" member) and an object with
// neither a receipt_id nor a signature are refused: the caller asked for one
// receipt and would otherwise check something else than it was handed.
func ParseReceipt(raw []byte, opts ...ParseOption) (*contracts.Receipt, error) {
	input, err := normalizeReceiptInput(raw)
	if err != nil {
		return nil, err
	}
	if !input.single {
		return nil, fmt.Errorf("input must be one receipt object, not an array of receipts or a receipts bundle")
	}
	anyProfile := false
	for _, opt := range opts {
		anyProfile = anyProfile || opt == AnySignatureProfile
	}
	bundle, err := input.bundle(anyProfile)
	if err != nil {
		return nil, err
	}
	return bundle.Receipts[0], nil
}

// ParseOption is a caller's statement about the verifier it hands the parsed
// receipt to.
type ParseOption int

// AnySignatureProfile leaves signature_profile and signature_algorithm to the
// caller's verifier. This package verifies Ed25519 only, so its parsers refuse
// a receipt that declares any other pair before a check could misread it. A
// caller that verifies with core/pkg/crypto, which knows the hybrid and
// ML-DSA profiles and checks the declared pair itself, passes this option.
// Every other rule of ParseReceipt applies unchanged.
const AnySignatureProfile ParseOption = 1

// bundleDecoyMember returns the first member of a bundle's top level, in name
// order, that is a receipt member in any letter case and not a member of the
// bundle itself, with the receipt member it is.
//
// The bundle shape holds its receipts inside "receipts", and those are what
// the verifier checks. A "verdict" or "tool_name" beside them is checked by
// nothing, yet it is what jq .verdict and JSON.parse(text).verdict return: a
// genuine DENY receipt wrapped in {"verdict":"ALLOW","receipts":[...]} read
// ALLOW to its reader while the verifier answered VERIFIED. The names come
// from contracts.Receipt, so a new receipt member is covered without a second
// list; any other name (a comment, the paging members of the receipts API) is
// not a receipt's and stays accepted.
func bundleDecoyMember(object map[string]json.RawMessage) (member, receiptMember string, found bool) {
	own := membersOf(reflect.TypeFor[Bundle]()).exact
	receipt := membersOf(reflect.TypeFor[contracts.Receipt]()).folded
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, isOwn := own[name]; isOwn {
			continue
		}
		if known, isReceiptMember := receipt[foldName(name)]; isReceiptMember {
			return name, known, true
		}
	}
	return "", "", false
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
		if err := validateJSON(trimmed, reflect.TypeFor[[]*contracts.Receipt]()); err != nil {
			return rawReceiptInput{}, err
		}
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
			if err := validateJSON(trimmed, reflect.TypeFor[contracts.Receipt]()); err != nil {
				return rawReceiptInput{}, err
			}
			input.receipts = []json.RawMessage{append(json.RawMessage(nil), trimmed...)}
			input.single = true
			return input, nil
		}
		if err := validateJSON(trimmed, reflect.TypeFor[Bundle]()); err != nil {
			return rawReceiptInput{}, err
		}
		if member, receiptMember, found := bundleDecoyMember(object); found {
			what := "a receipt member"
			if member != receiptMember {
				what = fmt.Sprintf("the receipt member %q in another letter case", receiptMember)
			}
			return rawReceiptInput{}, fmt.Errorf("member %q at $ is %s at the top level of a receipts bundle: "+
				"a bundle holds its receipts in \"receipts\" and this verifier checks only those, "+
				"so a receipt member beside them would be read as a checked receipt's and is checked by nothing", member, what)
		}
		if err := json.Unmarshal(receipts, &input.receipts); err != nil {
			return rawReceiptInput{}, fmt.Errorf("parse receipts bundle: receipts: %w", err)
		}
		for key, target := range map[string]any{
			"permits":          &input.permits,
			"public_key_hex":   &input.publicKeyHex,
			"key_id":           &input.keyID,
			"gateway_bindings": &input.bindings,
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
