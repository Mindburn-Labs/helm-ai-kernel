// quantum_posture: this command verifies classical Ed25519 signatures only; it
// provides and claims no hybrid or post-quantum protection.
//
// Command receipt_verify verifies a HELM receipt chain with no HELM service in
// the trust path.
//
// It reads a receipt file and a public key, and prints a verdict. It opens no
// sockets, reads no environment for endpoints, and fetches no keys — not by
// policy but by construction: the binary's transitive import graph contains no
// transport package, and core/pkg/receiptverify's TestNoTransportPackageIsReachable
// fails the build if one appears. Run it on a machine with no network and it
// behaves identically.
//
// Usage:
//
//	receipt_verify --receipt chain.json --key <hex>
//	receipt_verify --receipt chain.json --key-file pub.hex
//	receipt_verify --receipt chain.json --allow-self-attested
//
// The receipt file is either a single receipt object, a JSON array of receipts
// in causal order, or an object with a "receipts" array (an EvidencePack-shaped
// bundle). A bundle may also carry "public_key_hex" and "key_id"; those are only
// used when --allow-self-attested is set, because a key that travels with the
// thing it verifies is not a trust root.
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

// bundle is the permissive input shape: a receipt array plus optional key
// material that the receipt supplied about itself.
type bundle struct {
	Receipts     []*contracts.Receipt `json:"receipts"`
	PublicKeyHex string               `json:"public_key_hex,omitempty"`
	KeyID        string               `json:"key_id,omitempty"`
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("receipt_verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		receiptPath = fs.String("receipt", "", "path to a receipt, receipt array, or receipts bundle (JSON); \"-\" for stdin")
		keyHex      = fs.String("key", "", "hex-encoded Ed25519 public key to verify against")
		keyFile     = fs.String("key-file", "", "file holding a hex-encoded Ed25519 public key")
		keyID       = fs.String("key-id", "", "key id the supplied key is bound to (defaults to the receipt's declared key_id)")
		selfAttest  = fs.Bool("allow-self-attested", false,
			"verify against the key carried inside the receipt. This proves internal consistency only: "+
				"whoever wrote the receipt also wrote the key. Never sufficient to trust a counterparty's receipt.")
		asJSON = fs.Bool("json", false, "emit the verdict as JSON")
	)
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

	resolved := strings.TrimSpace(*keyHex)
	if *keyFile != "" {
		data, rerr := os.ReadFile(*keyFile)
		if rerr != nil {
			fmt.Fprintf(stderr, "error: read key file: %v\n", rerr)
			return 2
		}
		resolved = strings.TrimSpace(string(data))
	}
	if resolved != "" {
		id := *keyID
		if id == "" && len(b.Receipts) > 0 {
			id = b.Receipts[0].KeyID
		}
		trust.Keys[id] = resolved
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

	res := receiptverify.Verify(b.Receipts, trust)

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
func parseReceipts(raw []byte) (bundle, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return bundle{}, fmt.Errorf("input is empty")
	}

	if strings.HasPrefix(trimmed, "[") {
		var rs []*contracts.Receipt
		if err := json.Unmarshal(raw, &rs); err != nil {
			return bundle{}, fmt.Errorf("parse receipt array: %w", err)
		}
		return bundle{Receipts: rs}, nil
	}

	var b bundle
	if err := json.Unmarshal(raw, &b); err == nil && len(b.Receipts) > 0 {
		return b, nil
	}

	var single contracts.Receipt
	if err := json.Unmarshal(raw, &single); err != nil {
		return bundle{}, fmt.Errorf("parse receipt: %w", err)
	}
	if single.ReceiptID == "" && single.Signature == "" {
		return bundle{}, fmt.Errorf("input parsed as JSON but holds no receipt: expected a receipt object, an array of receipts, or an object with a \"receipts\" array")
	}
	return bundle{Receipts: []*contracts.Receipt{&single}}, nil
}

func writeHuman(w *os.File, res receiptverify.Result) {
	verdict := "NOT VERIFIED"
	if res.Valid {
		verdict = "VERIFIED"
	}
	fmt.Fprintf(w, "%s — %d receipt(s)", verdict, res.Receipts)
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
