// quantum_posture: this command verifies classical Ed25519 signatures only; it
// provides and claims no hybrid or post-quantum protection.
//
// Command receipt_verify verifies a HELM receipt chain — and the effect
// permits that authorized it — with no HELM service in the trust path.
//
// It reads a receipt file and public key material, and prints a verdict. It
// opens no sockets, reads no environment for endpoints, and fetches no keys —
// not by policy but by construction: the binary's transitive import graph
// contains no transport package, and core/pkg/receiptverify's
// TestNoTransportPackageIsReachable fails the build if one appears. Run it on
// a machine with no network and it behaves identically.
//
// Usage:
//
//	receipt_verify --receipt chain.json --key <hex>
//	receipt_verify --receipt bundle.json --key <hex> --key issuer=<hex>
//	receipt_verify --receipt chain.json --key-file pub.hex
//	receipt_verify --receipt chain.json --allow-self-attested
//
// The receipt file is either a single receipt object, a JSON array of receipts
// in causal order, or an object with a "receipts" array (an EvidencePack-shaped
// bundle). A bundle may also carry "permits" — the signed EffectPermits that
// authorized the recorded effects — which are then verified over the
// effect_permit.v1 envelope, evidence obligations included. --key and
// --key-file repeat: receipts and permits are often signed by different keys,
// and every supplied key is trusted. A bundle may also carry "public_key_hex"
// and "key_id" about itself; those are only used when --allow-self-attested is
// set, because a key that travels with the thing it verifies is not a trust
// root.
//
// Exit codes: 0 verified, 1 verification failed, 2 usage error.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// repeatable collects a flag's values across repeated uses.
type repeatable []string

func (r *repeatable) String() string { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("receipt_verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var keyValues, keyFiles repeatable
	var (
		receiptPath = fs.String("receipt", "", "path to a receipt, receipt array, or receipts bundle (JSON); \"-\" for stdin")
		selfAttest  = fs.Bool("allow-self-attested", false,
			"verify against the key carried inside the receipt. This proves internal consistency only: "+
				"whoever wrote the receipt also wrote the key. Never sufficient to trust a counterparty's receipt.")
		asJSON = fs.Bool("json", false, "emit the verdict as JSON")
	)
	fs.Var(&keyValues, "key", "hex-encoded Ed25519 public key to trust, optionally as <key-id>=<hex>; repeatable")
	fs.Var(&keyFiles, "key-file", "file holding a hex-encoded Ed25519 public key, optionally as <key-id>=<path>; repeatable")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "receipt_verify — verify a HELM receipt chain offline.\n\n"+
			"Usage:\n  receipt_verify --receipt <file> --key <hex>\n\n"+
			"No network access is performed. Supply the signing key out of band;\n"+
			"a key that arrives with the receipt is not a trust root.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *receiptPath == "" {
		fs.Usage()
		return 2
	}

	raw, err := readInput(*receiptPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	b, err := parseReceipts(raw)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	trust := receiptverify.TrustRoot{Keys: map[string]string{}, AllowSelfAttested: *selfAttest}

	defaultID := ""
	if len(b.Receipts) > 0 && b.Receipts[0] != nil {
		defaultID = b.Receipts[0].KeyID
	}
	addKey := func(id, hexKey string) {
		if id == "" {
			if _, taken := trust.Keys[defaultID]; !taken {
				id = defaultID
			} else {
				id = fmt.Sprintf("cli-key-%d", len(trust.Keys)+1)
			}
		}
		trust.Keys[id] = hexKey
	}
	for _, v := range keyValues {
		id, hexKey := splitKeySpec(v)
		addKey(id, strings.TrimSpace(hexKey))
	}
	for _, v := range keyFiles {
		id, path := splitKeySpec(v)
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			fmt.Fprintf(stderr, "error: read key file: %v\n", rerr)
			return 2
		}
		addKey(id, strings.TrimSpace(string(data)))
	}

	if len(trust.Keys) == 0 && !*selfAttest {
		fmt.Fprintf(stderr,
			"error: no verification key supplied.\n\n"+
				"Pass --key/--key-file with the signer's public key, obtained from the signer\n"+
				"through a channel other than this file. To inspect the receipt against the key\n"+
				"it carries about itself — which proves only that it is internally consistent —\n"+
				"pass --allow-self-attested.\n")
		return 2
	}

	res := receiptverify.VerifyBundle(b, trust)

	if *asJSON {
		out, merr := json.MarshalIndent(res, "", "  ")
		if merr != nil {
			fmt.Fprintf(stderr, "error: %v\n", merr)
			return 2
		}
		fmt.Fprintln(stdout, string(out))
	} else {
		writeHuman(stdout, res)
	}

	if !res.Valid {
		return 1
	}
	return 0
}

// splitKeySpec splits an optional "<id>=<value>" flag form. Hex never contains
// '=', so a bare value is unambiguous.
func splitKeySpec(v string) (id, value string) {
	if i := strings.IndexByte(v, '='); i >= 0 {
		return v[:i], v[i+1:]
	}
	return "", v
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		var buf []byte
		tmp := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		return buf, nil
	}
	return os.ReadFile(path)
}

type rawReceiptInput struct {
	receipts     []json.RawMessage
	permits      []*receiptverify.PermitRecord
	publicKeyHex string
	keyID        string
	single       bool
}

// parseReceipts accepts the three shapes a receipt reaches a counterparty in.
// Shape selection happens once and retains each receipt's raw object until the
// receipt.v5 signed-member contract has been checked.
func parseReceipts(raw []byte) (receiptverify.Bundle, error) {
	input, err := normalizeReceiptInput(raw)
	if err != nil {
		return receiptverify.Bundle{}, err
	}
	b := receiptverify.Bundle{
		Receipts:     make([]*contracts.Receipt, 0, len(input.receipts)),
		Permits:      input.permits,
		PublicKeyHex: input.publicKeyHex,
		KeyID:        input.keyID,
	}
	for i, rawReceipt := range input.receipts {
		if err := validateRawReceiptV5(rawReceipt); err != nil {
			return receiptverify.Bundle{}, fmt.Errorf("receipt[%d]: %w", i, err)
		}
		var receipt *contracts.Receipt
		if err := json.Unmarshal(rawReceipt, &receipt); err != nil {
			return receiptverify.Bundle{}, fmt.Errorf("parse receipt[%d]: %w", i, err)
		}
		b.Receipts = append(b.Receipts, receipt)
	}
	if input.single && len(b.Receipts) == 1 && b.Receipts[0] != nil &&
		b.Receipts[0].ReceiptID == "" && b.Receipts[0].Signature == "" {
		return receiptverify.Bundle{}, fmt.Errorf("input parsed as JSON but holds no receipt: expected a receipt object, an array of receipts, or an object with a \"receipts\" array")
	}
	return b, nil
}

func normalizeReceiptInput(raw []byte) (rawReceiptInput, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return rawReceiptInput{}, fmt.Errorf("input is empty")
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

func validateRawReceiptV5(raw json.RawMessage) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("receipt must be a JSON object: %w", err)
	}
	versionValue, ok := document["signature_version"]
	if !ok {
		return nil // retained unversioned receipt compatibility
	}
	var version string
	if err := json.Unmarshal(versionValue, &version); err != nil {
		return fmt.Errorf("signed member %q must be a string", "signature_version")
	}
	if version != contracts.ReceiptSignatureV5 {
		return nil
	}
	for _, field := range []string{
		"signature_version", "receipt_id", "decision_id", "effect_id", "status", "output_hash", "prev_hash",
		"args_hash", "verdict", "reason_code", "policy_hash", "session_id",
	} {
		value, exists := document[field]
		if !exists {
			return fmt.Errorf("receipt.v5 missing signed member %q", field)
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return fmt.Errorf("receipt.v5 signed member %q must be a string", field)
		}
	}
	lamport, exists := document["lamport_clock"]
	if !exists {
		return fmt.Errorf("receipt.v5 missing signed member %q", "lamport_clock")
	}
	var clock uint64
	if err := json.Unmarshal(lamport, &clock); err != nil {
		return fmt.Errorf("receipt.v5 signed member %q must be an unsigned integer", "lamport_clock")
	}
	return nil
}

func writeHuman(w *os.File, res receiptverify.Result) {
	verdict := "NOT VERIFIED"
	if res.Valid {
		verdict = "VERIFIED"
	}
	fmt.Fprintf(w, "%s — %d receipt(s)", verdict, res.Receipts)
	if res.Permits > 0 {
		fmt.Fprintf(w, ", %d permit(s)", res.Permits)
	}
	if res.PreimageVersion != "" {
		fmt.Fprintf(w, ", preimage %s", res.PreimageVersion)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	for _, c := range res.Checks {
		mark := "x"
		switch c.Status {
		case receiptverify.StatusPass:
			mark = "+"
		case receiptverify.StatusNotApplicable:
			mark = "-"
		}
		fmt.Fprintf(w, "  [%s] %-22s %s\n", mark, c.Name, c.Detail)
	}
	for _, e := range res.Errors {
		fmt.Fprintf(w, "  [x] %-22s %s\n", "input", e)
	}

	fmt.Fprintln(w)
	if res.Valid {
		fmt.Fprintln(w, "These receipts were signed by the key you supplied and are internally consistent.")
		fmt.Fprintln(w, "That the key belongs to any particular party is not established here.")
	}
}
