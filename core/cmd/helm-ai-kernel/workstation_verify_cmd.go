package main

// quantum_posture: Workstation verification checks classical Ed25519 signatures.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func runWorkstationVerifyDecisionCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation verify-decision", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var receiptPath, dataDir, trustedPublicKeyFile string
	var jsonOut bool
	cmd.StringVar(&receiptPath, "receipt", "", "Workstation policy decision receipt JSON")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	cmd.StringVar(&dataDir, "data-dir", defaultSetupDataDir(), "Directory for HELM local signing state")
	cmd.StringVar(&trustedPublicKeyFile, "trusted-public-key-file", "", "Path to caller-owned Ed25519 public key file")
	if err := cmd.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if receiptPath == "" && cmd.NArg() == 1 {
		receiptPath = cmd.Arg(0)
	}
	if receiptPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --receipt is required")
		return 2
	}
	receipt, err := workstation.LoadDecisionReceipt(receiptPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot load decision receipt: %v\n", err)
		return 1
	}
	integrityValid, err := workstation.VerifyDecisionReceiptSignature(receipt)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: decision receipt integrity check failed: %v\n", err)
		return 1
	}
	trustedKey, trustAnchor, trustAnchorAvailable, err := resolveTrustedWorkstationPublicKey(dataDir, trustedPublicKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: load trusted public key: %v\n", err)
		return 1
	}
	signerTrusted := false
	if trustAnchorAvailable {
		signerTrusted, err = workstation.VerifyDecisionReceiptWithTrustedKey(receipt, trustedKey)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: trusted decision receipt verification failed: %v\n", err)
			return 1
		}
	}
	result := map[string]any{
		"receipt":         receiptPath,
		"decision_id":     receipt.DecisionID,
		"verdict":         receipt.Verdict,
		"reason_code":     receipt.ReasonCode,
		"effect_type":     receipt.Request.EffectType,
		"target":          receipt.Request.Target,
		"receipt_hash":    receipt.ReceiptHash,
		"integrity_valid": integrityValid,
		"signer_trusted":  signerTrusted,
		"trust_anchor":    trustAnchor,
	}
	if jsonOut {
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		// Lead with the admissibility verdict, not the receipt's own claim. A
		// tampered receipt still carries a verdict field, and printing it at the
		// same weight as everything else made the forgery the loudest thing on
		// screen while the one line that mattered — integrity:false — sat two
		// rows below in plain text. The receipt's verdict is only meaningful
		// once the receipt verifies against a trusted signer; until then it is
		// an unverified claim and is labelled as one.
		admissible := integrityValid && signerTrusted
		switch {
		case !integrityValid:
			_, _ = fmt.Fprintf(stdout, "%sTAMPERED — this receipt does not match its own signature%s\n", ColorRed, ColorReset)
			_, _ = fmt.Fprintf(stdout, "  Its contents were altered after signing. Do not act on anything below.\n")
		case !signerTrusted:
			_, _ = fmt.Fprintf(stdout, "%sUNVERIFIED — signature is intact but the signer is not a trusted anchor%s\n", ColorRed, ColorReset)
			if !trustAnchorAvailable {
				_, _ = fmt.Fprintf(stdout, "  No trust anchor was available. Pass --trusted-public-key-file to name the key you trust.\n")
			} else {
				_, _ = fmt.Fprintf(stdout, "  The receipt was signed by a key you have not anchored. A key that arrives with the receipt is not a trust root.\n")
			}
		default:
			_, _ = fmt.Fprintf(stdout, "%sADMISSIBLE — signature verifies under a trusted anchor%s\n", ColorGreen, ColorReset)
		}
		_, _ = fmt.Fprintf(stdout, "%sWorkstation Policy Decision Verification%s\n", ColorBold, ColorReset)
		_, _ = fmt.Fprintf(stdout, "  receipt:   %s\n", receiptPath)
		_, _ = fmt.Fprintf(stdout, "  decision:  %s\n", receipt.DecisionID)
		if admissible {
			_, _ = fmt.Fprintf(stdout, "  verdict:   %s\n", receipt.Verdict)
		} else {
			// Never present the verdict of an inadmissible receipt as a bare
			// fact; the reader must not be able to quote it as the finding.
			_, _ = fmt.Fprintf(stdout, "  verdict:   %s (unverified — claimed by the receipt, not established)\n", receipt.Verdict)
		}
		_, _ = fmt.Fprintf(stdout, "  reason:    %s\n", receipt.ReasonCode)
		_, _ = fmt.Fprintf(stdout, "  effect:    %s\n", receipt.Request.EffectType)
		_, _ = fmt.Fprintf(stdout, "  target:    %s\n", receipt.Request.Target)
		_, _ = fmt.Fprintf(stdout, "  hash:      %s\n", receipt.ReceiptHash)
		_, _ = fmt.Fprintf(stdout, "  integrity: %v\n", integrityValid)
		_, _ = fmt.Fprintf(stdout, "  trusted:   %v\n", signerTrusted)
		_, _ = fmt.Fprintf(stdout, "  anchor:    %s\n", trustAnchor)
	}
	if !integrityValid || !signerTrusted {
		return 1
	}
	return 0
}

// printReceiptVerification says, ahead of any figure taken from receipts,
// which signature checks those receipts went through.
func printReceiptVerification(stdout io.Writer, verification *workstation.ReceiptVerification) {
	if verification == nil {
		return
	}
	_, _ = fmt.Fprintf(stdout, "Signatures: %d input files match the key they name, %d do not and are not counted\n", verification.Counted(), len(verification.NotCounted))
	for _, input := range verification.NotCounted {
		_, _ = fmt.Fprintf(stdout, "  not counted: %s (%s)\n", input.SourcePath, input.SignatureStatus)
	}
	for _, input := range verification.DuplicateInputs {
		_, _ = fmt.Fprintf(stdout, "  duplicate, counted once: %s (copy of %s)\n", input.SourcePath, input.DuplicateOf)
	}
	if verification.TrustAnchor == "" {
		_, _ = fmt.Fprintln(stdout, "Signer trust: not checked (no trusted workstation public key; pass --trusted-public-key-file)")
		return
	}
	_, _ = fmt.Fprintf(stdout, "Signer trust: checked against %s: %d by that key, %d by another key, %d by the retired built-in key\n",
		verification.TrustAnchor,
		verification.Statuses[workstation.SignatureTrustedKey],
		verification.Statuses[workstation.SignatureUntrustedKey],
		verification.Statuses[workstation.SignatureRetiredKey])
}
