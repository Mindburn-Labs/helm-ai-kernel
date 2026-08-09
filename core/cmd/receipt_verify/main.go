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

// parseReceipts accepts the three shapes a receipt reaches a counterparty in.
func parseReceipts(raw []byte) (receiptverify.Bundle, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return receiptverify.Bundle{}, fmt.Errorf("input is empty")
	}

	if strings.HasPrefix(trimmed, "[") {
		var rs []*contracts.Receipt
		if err := json.Unmarshal(raw, &rs); err != nil {
			return receiptverify.Bundle{}, fmt.Errorf("parse receipt array: %w", err)
		}
		return receiptverify.Bundle{Receipts: rs}, nil
	}

	var b receiptverify.Bundle
	if err := json.Unmarshal(raw, &b); err == nil && (len(b.Receipts) > 0 || len(b.Permits) > 0) {
		return b, nil
	}

	var single contracts.Receipt
	if err := json.Unmarshal(raw, &single); err != nil {
		return receiptverify.Bundle{}, fmt.Errorf("parse receipt: %w", err)
	}
	if single.ReceiptID == "" && single.Signature == "" {
		return receiptverify.Bundle{}, fmt.Errorf("input parsed as JSON but holds no receipt: expected a receipt object, an array of receipts, or an object with a \"receipts\" array")
	}
	return receiptverify.Bundle{Receipts: []*contracts.Receipt{&single}}, nil
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
