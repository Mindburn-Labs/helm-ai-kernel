package client

// quantum_posture: VerifyReceipt verifies classical Ed25519 receipt.v5
// signatures only; it provides and claims no hybrid or post-quantum
// protection.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ReceiptSignatureV5 is the only receipt signature version VerifyReceipt
// accepts.
const ReceiptSignatureV5 = "receipt.v5"

const maxSafeInteger = 9007199254740991

// signedMembers are the receipt.v5 signed members in RFC 8785 order (all
// ASCII, so UTF-16 and byte order agree).
var signedMembers = []string{
	"args_hash", "decision_id", "effect_id", "lamport_clock", "output_hash", "policy_hash",
	"prev_hash", "reason_code", "receipt_id", "session_id", "signature_version", "status", "verdict",
}

var (
	hex64     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	hex128    = regexp.MustCompile(`^[0-9a-fA-F]{128}$`)
	uintegral = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

// ReceiptVerification is VerifyReceipt's verdict. Valid is true only when
// every check passed; Error names the first check that did not.
type ReceiptVerification struct {
	Valid      bool           `json:"valid"`
	Error      string         `json:"error,omitempty"`
	Detail     string         `json:"detail"`
	ReceiptID  string         `json:"receipt_id,omitempty"`
	Verdict    string         `json:"verdict,omitempty"`
	ReasonCode string         `json:"reason_code,omitempty"`
	KeyID      string         `json:"key_id,omitempty"`
	Signed     map[string]any `json:"signed,omitempty"`
}

type refusal struct{ code, detail string }

func (r *refusal) Error() string { return r.detail }

func refuse(code, format string, args ...any) error {
	return &refusal{code: code, detail: fmt.Sprintf(format, args...)}
}

// VerifyReceipt verifies one receipt.v5 offline: did the holder of a key you
// trust sign this receipt, and do its signed members say what the receipt
// says? It reads no network, clock or environment.
//
// It checks the receipt.v5 signed envelope: one JSON object with
// no duplicate member, no letter-case variant of a typed receipt member,
// and at most 64 nested containers;
// signature_version "receipt.v5" (an unversioned legacy receipt is refused);
// the thirteen signed members with their wire types; lamport_clock an integer
// in [0, 2^53-1]; signature_profile and signature_algorithm both empty or
// exactly classical/ed25519; and the Ed25519 signature over the RFC 8785
// canonical JSON of the signed members under one of trustedKeys (hex, with or
// without an "ed25519:" prefix). key_id is a hint, never a filter, and the
// receipt's own public_key_set is never trusted. Chain linkage, permits and
// gateway bindings and the schema of unsigned metadata are receipt_verify's.
// Invalid UTF-8 is refused. Only Signed contains authenticated fields; KeyID
// is an unsigned claim and does not identify which trusted key verified.
//
// A key served by the HELM that signed the receipt is HELM vouching for
// itself: pin it once, out of band. The shared vectors in
// core/pkg/receiptverify/testdata/offline-verifier-vectors.json hold this
// function, the Python and TypeScript SDKs and receipt_verify to the same
// verdicts.
func VerifyReceipt(receiptJSON []byte, trustedKeys ...string) ReceiptVerification {
	signed, keyID, signature, err := parseReceiptV5(receiptJSON)
	if err == nil {
		err = verifySigned(signed, signature, trustedKeys)
	}
	if err != nil {
		var r *refusal
		if errors.As(err, &r) {
			return ReceiptVerification{Error: r.code, Detail: r.detail}
		}
		return ReceiptVerification{Error: "malformed", Detail: err.Error()}
	}
	return ReceiptVerification{
		Valid:      true,
		Detail:     "the receipt.v5 signature verifies under a trusted key",
		ReceiptID:  signed["receipt_id"].(string),
		Verdict:    signed["verdict"].(string),
		ReasonCode: signed["reason_code"].(string),
		KeyID:      keyID,
		Signed:     signed,
	}
}

func parseReceiptV5(raw []byte) (map[string]any, string, []byte, error) {
	if !utf8.Valid(raw) {
		return nil, "", nil, refuse("malformed", "receipt document must be UTF-8")
	}
	if err := checkJSONStructure(raw); err != nil {
		return nil, "", nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, "", nil, refuse("malformed", "receipt is not JSON: %v", err)
	}
	document, ok := value.(map[string]any)
	if !ok {
		return nil, "", nil, refuse("malformed", "receipt must be a JSON object")
	}
	if _, bundle := document["receipts"]; bundle {
		return nil, "", nil, refuse("malformed", "input must be one receipt object, not a bundle")
	}
	if err := checkReceiptMemberNames(document, receiptMemberShape); err != nil {
		return nil, "", nil, err
	}
	version, present := document["signature_version"]
	if !present {
		return nil, "", nil, refuse("unsupported_version", "receipt has no signature_version; legacy receipts are not verified here")
	}
	if text, ok := version.(string); !ok || text != ReceiptSignatureV5 {
		return nil, "", nil, refuse("unsupported_version", "unsupported receipt signature version %v", version)
	}
	signed := make(map[string]any, len(signedMembers))
	for _, member := range signedMembers {
		value, exists := document[member]
		if !exists {
			return nil, "", nil, refuse("missing_member", "receipt.v5 missing signed member %q", member)
		}
		if member == "lamport_clock" {
			number, ok := value.(json.Number)
			if !ok {
				return nil, "", nil, refuse("missing_member", "receipt.v5 signed member %q must be an unsigned integer", member)
			}
			literal := number.String()
			if !uintegral.MatchString(literal) {
				return nil, "", nil, refuse("non_interoperable_number", "lamport_clock %s is not an integer in [0, 2^53-1]", literal)
			}
			clock, err := strconv.ParseUint(literal, 10, 64)
			if err != nil || clock > maxSafeInteger {
				return nil, "", nil, refuse("non_interoperable_number", "lamport_clock %s is outside [0, 2^53-1]", literal)
			}
			signed[member] = clock
			continue
		}
		text, ok := value.(string)
		if !ok {
			return nil, "", nil, refuse("missing_member", "receipt.v5 signed member %q must be a string", member)
		}
		signed[member] = text
	}
	profile, profileOK := optionalString(document, "signature_profile")
	algorithm, algorithmOK := optionalString(document, "signature_algorithm")
	if !profileOK || !algorithmOK || !((profile == "" && algorithm == "") || (profile == "classical" && algorithm == "ed25519")) {
		return nil, "", nil, refuse("signature_metadata", "signature metadata must be both empty or exactly classical/ed25519")
	}
	signatureText, _ := document["signature"].(string)
	if signatureText == "" {
		return nil, "", nil, refuse("unsigned", "receipt carries no signature")
	}
	if !hex128.MatchString(signatureText) {
		return nil, "", nil, refuse("signature_rejected", "signature is not 64 bytes of hex")
	}
	signature, _ := hex.DecodeString(signatureText)
	keyID, _ := document["key_id"].(string)
	return signed, keyID, signature, nil
}

func optionalString(document map[string]any, member string) (string, bool) {
	value, exists := document[member]
	if !exists {
		return "", true
	}
	text, ok := value.(string)
	return text, ok
}

func verifySigned(signed map[string]any, signature []byte, trustedKeys []string) error {
	if len(trustedKeys) == 0 {
		return refuse("no_trusted_key", "no trusted public key supplied")
	}
	keys := make([]ed25519.PublicKey, 0, len(trustedKeys))
	for _, key := range trustedKeys {
		text := strings.TrimPrefix(strings.TrimSpace(key), "ed25519:")
		if !hex64.MatchString(text) {
			return refuse("bad_key", "a trusted key must be a 32-byte Ed25519 public key in hex")
		}
		decoded, _ := hex.DecodeString(text)
		keys = append(keys, ed25519.PublicKey(decoded))
	}
	payload := receiptSigningPayload(signed)
	for _, key := range keys {
		if ed25519.Verify(key, payload, signature) {
			return nil
		}
	}
	return refuse("signature_rejected", "signature does not verify under any trusted key")
}

// receiptSigningPayload is the RFC 8785 canonical JSON a receipt.v5 signature
// covers, for signed members as parsed by VerifyReceipt.
func receiptSigningPayload(signed map[string]any) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, member := range signedMembers {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`"` + member + `":`)
		switch value := signed[member].(type) {
		case uint64:
			buf.WriteString(strconv.FormatUint(value, 10))
		case string:
			writeJCSString(&buf, value)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// writeJCSString writes the RFC 8785 string escape set, as
// core/pkg/canonicalize does: only '"', '\\' and U+0000..U+001F are escaped.
func writeJCSString(buf *bytes.Buffer, value string) {
	buf.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// checkJSONStructure refuses duplicate object members anywhere and any value
// after the first, which encoding/json would otherwise collapse or ignore.
func checkJSONStructure(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return refuse("malformed", "receipt has a value after the first")
	}
	return nil
}

func scanValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return refuse("malformed", "receipt is not JSON: %v", err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= 64 {
		return refuse("malformed", "JSON exceeds the 64-level nesting limit")
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return refuse("malformed", "receipt is not JSON: %v", err)
			}
			name, _ := key.(string)
			if seen[name] {
				return refuse("duplicate_member", "duplicate object member %q", name)
			}
			seen[name] = true
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return refuse("malformed", "receipt is not JSON: %v", err)
	}
	return nil
}
