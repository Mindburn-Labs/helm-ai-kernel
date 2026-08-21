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
	"strings"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// runVerifyReceiptCmd verifies one Kernel receipt.v5 JSON file offline.
//
// Exit 0 only when the file is internally consistent AND the signature
// verifies under the caller-supplied Ed25519 public key. A key carried
// inside the file is not a trust root.
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
	if _, err := receiptverify.ParseReceiptDocument(raw); err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "verify receipt", "parse receipt"), errFormat)
	}
	var receipt contracts.Receipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "verify receipt", "decode receipt"), errFormat)
	}
	if receipt.SignatureVersion != contracts.ReceiptSignatureV5 {
		return cliui.WriteErrorFormat(stderr, cliui.Failf("verify receipt", "signature_version %q is not receipt.v5", receipt.SignatureVersion), errFormat)
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
			_, _ = fmt.Fprintf(stdout, "  Its contents were altered after signing. Do not act on anything below.\n")
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
		_, _ = fmt.Fprintf(stdout, "  integrity: %v\n", integrityValid)
		_, _ = fmt.Fprintf(stdout, "  trusted:   %v\n", signerTrusted)
		_, _ = fmt.Fprintf(stdout, "  anchor:    %s\n", trustedPublicKeyFile)
	}
	if !integrityValid || !signerTrusted {
		return 1
	}
	return 0
}

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
