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
//	receipt_verify --receipt export.json --key "<key_id>=<hex>" --require-bindings --json
//	receipt_verify --receipt r.json --key "<key_id>=<hex>" --binding <receipt_id>=binding.json --require-bindings
//	receipt_verify --receipt old.json --key <hex> --allow-legacy-v4
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
// A gateway receipt signs, as output_hash, the SHA-256 of a binding document
// (helm.gateway.receipt-binding.v1) that names its tenant, workspace, attempt,
// version and state. A bundle exported by the gateway carries those documents
// as "gateway_bindings" (receipt id to the base64 of the exact bytes);
// --binding <receipt_id>=<file> supplies one from a file and repeats. Each
// supplied binding is checked against the receipt that signs it (the binding
// check); with none supplied that check is not_applicable, so a gateway
// receipt's own facts go unchecked and the exit code is still 0.
// --require-bindings fails verification instead when any receipt whose
// session_id names a gateway chain has no binding; use it for gateway
// exports. The JSON verdict counts gateway_receipts and bindings_checked.
//
// Member names are matched exactly. A file in which a receipt, bundle, permit
// or binding member is spelled in another letter case, or in which two members
// of one object differ only in letter case, does not parse: a reader that
// matches names exactly (jq, JavaScript) would take other values from it than
// this verifier.
//
// A receipt with no signature_version is a legacy v4 receipt. Its signature
// covers eight colon-joined fields with no escaping, not verdict, tool_name or
// timestamp, and the signature of a receipt.v5 receipt can be replayed as one.
// Such a file is not checked (exit 2) unless --allow-legacy-v4 is given; the
// output then says how many receipts are legacy and what their signature does
// not cover.
//
// Exit codes: 0 verified, 1 verification failed, 2 no verdict reported (bad or
// missing flags, no key, an unreadable receipt or key file, a receipt file that
// does not parse, a legacy receipt without --allow-legacy-v4, or a JSON verdict
// that cannot be encoded).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

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
	var keyValues, keyFiles, bindingFiles repeatable
	var (
		receiptPath = fs.String("receipt", "", "path to a receipt, receipt array, or receipts bundle (JSON); \"-\" for stdin")
		selfAttest  = fs.Bool("allow-self-attested", false,
			"verify against the key carried inside the receipt. This proves internal consistency only: "+
				"whoever wrote the receipt also wrote the key. Never sufficient to trust a counterparty's receipt.")
		asJSON  = fs.Bool("json", false, "emit the verdict as JSON")
		require = fs.Bool("require-bindings", false,
			"fail when a receipt whose session_id names a gateway chain has no binding document, so a pass covers every gateway receipt's own facts")
		allowLegacy = fs.Bool("allow-legacy-v4", false,
			"check receipts with no signature_version as legacy v4 receipts instead of refusing the file (exit 2). "+
				"A legacy signature does not cover verdict, tool_name or timestamp, and a receipt.v5 signature can be replayed as one.")
	)
	fs.Var(&keyValues, "key", "hex-encoded Ed25519 public key to trust, optionally as <key-id>=<hex>; repeatable")
	fs.Var(&keyFiles, "key-file", "file holding a hex-encoded Ed25519 public key, optionally as <key-id>=<path>; repeatable")
	fs.Var(&bindingFiles, "binding", "gateway binding document as <receipt-id>=<path>, the exact bytes the receipt's output_hash covers; repeatable")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "receipt_verify — verify a HELM receipt chain offline.\n\n"+
			"Usage:\n  receipt_verify --receipt <file> --key <hex>\n\n"+
			"No network access is performed. Supply the signing key out of band;\n"+
			"a key that arrives with the receipt is not a trust root.\n\n"+
			"Member names are matched exactly: a file with a member spelled in another\n"+
			"letter case does not parse. A receipt with no signature_version is a legacy\n"+
			"receipt and is not checked unless --allow-legacy-v4 is given.\n\n"+
			"Exit codes: 0 verified, 1 verification failed, 2 no verdict reported.\n\nFlags:\n")
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

	if err := addBindings(&b, bindingFiles); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	// A legacy receipt without the opt-in is not checked, which is no verdict
	// (exit 2), not a failed one (exit 1).
	if legacy := receiptverify.LegacyV4Refusal(b.Receipts); legacy != nil && !*allowLegacy {
		fmt.Fprintf(stderr, "error: %v\n", legacy)
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

	res := receiptverify.VerifyBundleWith(b, trust, receiptverify.Options{
		RequireGatewayBindings: *require,
		AllowLegacyV4:          *allowLegacy,
	})

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

// addBindings reads each --binding <receipt_id>=<path> into the bundle's
// gateway bindings. A receipt id given twice, or one the bundle already binds,
// is refused rather than silently replaced.
func addBindings(b *receiptverify.Bundle, specs []string) error {
	for _, spec := range specs {
		id, path := splitKeySpec(spec)
		if id == "" || path == "" {
			return fmt.Errorf("--binding %q must be <receipt-id>=<path>", spec)
		}
		if _, taken := b.GatewayBindings[id]; taken {
			return fmt.Errorf("--binding: receipt %q already has a binding", id)
		}
		data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied binding file
		if err != nil {
			return fmt.Errorf("read binding file: %w", err)
		}
		if b.GatewayBindings == nil {
			b.GatewayBindings = map[string][]byte{}
		}
		b.GatewayBindings[id] = data
	}
	return nil
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

func parseReceipts(raw []byte) (receiptverify.Bundle, error) {
	return receiptverify.ParseBundle(raw)
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
	if res.GatewayReceipts > 0 {
		fmt.Fprintf(w, ", %d gateway receipt(s) with %d binding(s) checked", res.GatewayReceipts, res.BindingsChecked)
	}
	if res.PreimageVersion != "" {
		fmt.Fprintf(w, ", preimage %s", res.PreimageVersion)
	}
	if res.LegacyReceipts > 0 {
		fmt.Fprintf(w, ", %d LEGACY receipt(s)", res.LegacyReceipts)
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
		fmt.Fprintln(w, "Every receipt's signature verifies under a key you supplied, and no check failed.")
		fmt.Fprintln(w, "A signature covers the members of its signed envelope, not the whole receipt:")
		fmt.Fprintln(w, "each check above says what it covers. That the key belongs to any particular")
		fmt.Fprintln(w, "party is not established here.")
	}
	if res.LegacyReceipts > 0 {
		fmt.Fprintf(w, "%d receipt(s) have no signature_version and were checked as legacy v4 receipts (--allow-legacy-v4).\n", res.LegacyReceipts)
		fmt.Fprintln(w, "A legacy signature does not cover verdict, tool_name or timestamp: nothing above")
		fmt.Fprintln(w, "establishes those members of a legacy receipt, and a receipt.v5 signature can be replayed as one.")
	}
}
