// quantum_posture: verify receipt checks classical Ed25519 receipt.v5
// signatures only; it adds no post-quantum assurance.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// runVerifyReceiptCmd verifies one Kernel receipt.v5 JSON file offline.
//
// Exit 0 only when the receipt.v5 signature matches the signed members under
// the key the file carries AND verifies under the caller-supplied Ed25519
// public key. A key carried inside the file is not a trust root.
//
// The signature covers 13 members, not the file. The report echoes only
// members inside that envelope, lists them as signed_members, and lists the
// file's other members as unsigned_members: rewriting those leaves
// integrity_valid true, so the report must not read as if they were checked.
// The file is read by the parser receipt_verify uses (receiptverify.ParseReceipt).
//
// Usage: helm-ai-kernel verify receipt --receipt <file> --trusted-public-key-file <expected-ed25519.pub>
func runVerifyReceiptCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("verify receipt", flag.ContinueOnError)
	var (
		receiptPath          string
		trustedPublicKeyFile string
		jsonOutput           bool
	)
	cmd.StringVar(&receiptPath, "receipt", "", "Kernel receipt.v5 JSON file")
	cmd.StringVar(&trustedPublicKeyFile, "trusted-public-key-file", "", "Caller-owned Ed25519 public key file")
	cmd.BoolVar(&jsonOutput, "json", false, "Print JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)
	if code, ok := cliui.ParseFlags(cmd, reorderFlagsFirst(args, cliui.ValueFlagNames(cmd)), stderr, "verify receipt", cliui.FormatText); !ok {
		return code
	}
	jsonOutput = jsonOutput || formatFlag.IsJSON()
	errFormat := cliui.FormatText
	if jsonOutput {
		errFormat = cliui.FormatJSON
	}
	if receiptPath == "" && cmd.NArg() == 1 {
		receiptPath = cmd.Arg(0)
	}
	if strings.TrimSpace(receiptPath) == "" || strings.TrimSpace(trustedPublicKeyFile) == "" {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("verify receipt", "--receipt and --trusted-public-key-file are required").
			WithHint("this is Foundation/offline receipt.v5 verify, not EvidencePack and not workstation verify-decision"), errFormat)
	}

	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "verify receipt", "read %s", receiptPath), errFormat)
	}
	// One parser decides what a receipt document is. ParseReceiptDocument
	// alone looks members up by exact name while encoding/json folds letter
	// case, so a file whose only version member was "Signature_Version"
	// skipped the receipt.v5 member checks and was still decoded as receipt.v5.
	parsed, err := receiptverify.ParseReceipt(raw)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "verify receipt", "parse receipt"), errFormat)
	}
	receipt := *parsed
	if receipt.SignatureVersion != contracts.ReceiptSignatureV5 {
		return cliui.WriteErrorFormat(stderr, cliui.Failf("verify receipt", "signature_version %q is not receipt.v5", receipt.SignatureVersion), errFormat)
	}
	signedMembers := receiptverify.ReceiptV5SignedMembers()
	unsignedMembers, err := unsignedReceiptMembers(raw, signedMembers)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "verify receipt", "parse receipt"), errFormat)
	}

	trustedKey, err := loadTrustedPublicKeyFile(trustedPublicKeyFile)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "verify receipt", "load trusted public key"), errFormat)
	}
	trustedHex := hex.EncodeToString(trustedKey)

	integrityValid := receiptEmbeddedIntegrityValid(&receipt)
	report := receiptverify.Verify([]*contracts.Receipt{&receipt}, receiptverify.TrustRoot{
		Keys: map[string]string{
			receipt.KeyID: trustedHex,
			"caller":      trustedHex,
		},
	})
	signerTrusted := report.Valid

	result := map[string]any{
		"receipt":           receiptPath,
		"receipt_id":        receipt.ReceiptID,
		"decision_id":       receipt.DecisionID,
		"verdict":           receipt.Verdict,
		"reason_code":       receipt.ReasonCode,
		"signature_version": receipt.SignatureVersion,
		"integrity_valid":   integrityValid,
		"integrity_scope":   verifyReceiptIntegrityScope,
		"signed_members":    signedMembers,
		"unsigned_members":  unsignedMembers,
		"signer_trusted":    signerTrusted,
		"trust_anchor":      trustedPublicKeyFile,
	}
	if jsonOutput {
		if err := cliui.WriteJSON(stdout, result); err != nil {
			return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "verify receipt", "encode report"), errFormat)
		}
	} else {
		admissible := integrityValid && signerTrusted
		switch {
		case !integrityValid:
			_, _ = fmt.Fprintf(stdout, "%sTAMPERED — this receipt.v5 file does not match its own signature%s\n", ColorRed, ColorReset)
			_, _ = fmt.Fprintf(stdout, "  A signed member was altered after signing, or the signature was. Do not act on anything below.\n")
		case !signerTrusted:
			_, _ = fmt.Fprintf(stdout, "%sUNVERIFIED — signature is intact but the signer is not the supplied trust anchor%s\n", ColorRed, ColorReset)
			_, _ = fmt.Fprintf(stdout, "  A key that arrives inside the receipt is not a trust root. Pass --trusted-public-key-file.\n")
		default:
			_, _ = fmt.Fprintf(stdout, "%sADMISSIBLE — receipt.v5 signature verifies under the caller-supplied key%s\n", ColorGreen, ColorReset)
		}
		_, _ = fmt.Fprintf(stdout, "%sKernel receipt.v5 offline verification%s\n", ColorBold, ColorReset)
		_, _ = fmt.Fprintf(stdout, "  receipt:   %s\n", receiptPath)
		_, _ = fmt.Fprintf(stdout, "  id:        %s\n", receipt.ReceiptID)
		if admissible {
			_, _ = fmt.Fprintf(stdout, "  verdict:   %s\n", receipt.Verdict)
		} else {
			_, _ = fmt.Fprintf(stdout, "  verdict:   %s (unverified — claimed by the receipt, not established)\n", receipt.Verdict)
		}
		_, _ = fmt.Fprintf(stdout, "  reason:    %s\n", receipt.ReasonCode)
		_, _ = fmt.Fprintf(stdout, "  version:   %s\n", receipt.SignatureVersion)
		_, _ = fmt.Fprintf(stdout, "  integrity: %v (the signature over the %d signed members, under the key the file carries)\n", integrityValid, len(signedMembers))
		_, _ = fmt.Fprintf(stdout, "  trusted:   %v\n", signerTrusted)
		_, _ = fmt.Fprintf(stdout, "  anchor:    %s\n", trustedPublicKeyFile)
		_, _ = fmt.Fprintf(stdout, "  signed:    %s\n", strings.Join(signedMembers, ", "))
		if len(unsignedMembers) > 0 {
			_, _ = fmt.Fprintf(stdout, "  unsigned:  %s\n", strings.Join(unsignedMembers, ", "))
			_, _ = fmt.Fprintf(stdout, "             no signature covers these members of the file; they are its writer's claims, not checked here\n")
		}
	}
	if !integrityValid || !signerTrusted {
		return 1
	}
	return 0
}

// verifyReceiptIntegrityScope travels with integrity_valid in the JSON report,
// because "integrity" alone reads as "the file is as it was signed".
const verifyReceiptIntegrityScope = "integrity_valid is the receipt.v5 signature checked over signed_members under the key the file carries; " +
	"signer_trusted is the same signature under the caller's key. Neither covers unsigned_members, which can be rewritten without changing either"

// unsignedReceiptMembers returns, in name order, the members of the receipt
// file that are outside the signed envelope. The signature member is left
// out: it is what covers the others, not a claim.
func unsignedReceiptMembers(raw []byte, signed []string) ([]string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, err
	}
	covered := map[string]bool{"signature": true}
	for _, name := range signed {
		covered[name] = true
	}
	unsigned := make([]string, 0, len(members))
	for name := range members {
		if !covered[name] {
			unsigned = append(unsigned, name)
		}
	}
	sort.Strings(unsigned)
	return unsigned, nil
}

// receiptEmbeddedIntegrityValid reports whether the receipt's signature
// matches its signed members under the Ed25519 key the receipt carries. It
// says nothing about who signed, and nothing about members outside the signed
// envelope.
func receiptEmbeddedIntegrityValid(receipt *contracts.Receipt) bool {
	if receipt == nil || receipt.PublicKeySet == nil {
		return false
	}
	pub := strings.TrimSpace(receipt.PublicKeySet[helmcrypto.SigPrefixEd25519])
	if pub == "" {
		return false
	}
	ok, _, err := helmcrypto.VerifyReceiptSignature(pub, receipt)
	return err == nil && ok
}
