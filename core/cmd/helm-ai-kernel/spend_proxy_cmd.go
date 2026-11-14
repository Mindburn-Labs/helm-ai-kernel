// Offline receipt compatibility and the historical spend-proxy command.
// Live spending uses helm-gateway; this command never authorizes effects.
// quantum_posture: offline exports verify classical Ed25519 signatures and
// SHA-256 content addresses; no post-quantum claim is made here.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/spendproxy"
)

// runSpendProxyCmd retains offline evidence compatibility only. Live model
// effects and reconciliation belong to helm-gateway's Postgres ledger.
func runSpendProxyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "export":
			return runSpendProxyExport(args[1:], stdout, stderr)
		case "savings-export":
			return runSpendProxySavingsExport(args[1:], stdout, stderr)
		case "savings-verify":
			return runSpendProxySavingsVerify(args[1:], stdout, stderr)
		}
	}
	_, _ = fmt.Fprintln(stderr, "Live spend-proxy and local reconciliation are retired. Use helm-gateway for model calls and its Postgres effect ledger for reconciliation. Offline export, savings-export and savings-verify remain available. See docs/architecture/model-gateway.md.")
	return 2
}

// runSpendProxyExport renders captured receipts into offline-verifiable spend
// EvidencePacks under --out. With --public-key it verifies every signature of
// each exported intent against the key its key id names; the flag repeats for
// a log signed by more than one key (a reconcile after the seed changed). The
// receipts directory's own key registry is never the trust root.
func runSpendProxyExport(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("spend-proxy export", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		receiptsDir string
		outDir      string
		intent      string
		publicKeys  multiFlag
		jsonOut     bool
	)
	cmd.StringVar(&receiptsDir, "receipts-dir", "./helm-spend-receipts", "Directory holding the receipt log")
	cmd.StringVar(&outDir, "out", "./helm-spend-evidence", "Output directory for spend EvidencePacks")
	cmd.StringVar(&intent, "intent", "", "Export only this spend intent id (default: all)")
	cmd.Var(&publicKeys, "public-key", "The issuer's Ed25519 public key (ed25519:<hex>), obtained out of band; repeat it for a log signed by more than one key. Every signature is verified against the key its key id names; without it no signature is verified")
	cmd.BoolVar(&jsonOut, "json", false, "Print the export summary as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	opts := spendproxy.ExportOptions{ReceiptsDir: receiptsDir, OutDir: outDir, IntentFilter: intent}
	for i, text := range publicKeys {
		pub, err := spendproxy.ParsePublicKey(text)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: --public-key: %v\n", err)
			return 2
		}
		if i == 0 {
			opts.PublicKey = pub
		} else {
			opts.PublicKeys = append(opts.PublicKeys, pub)
		}
	}

	results, err := spendproxy.ExportEvidencePacks(opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}
	for _, res := range results {
		status := "offline-verified"
		if !res.OfflineVerified {
			status = "VERIFICATION FAILED"
		}
		sig := "signatures not checked (no --public-key)"
		if res.SignatureVerified {
			sig = "signatures verified against " + strings.Join(res.SignatureKeyIDs, ", ") + ": " + strings.Join(res.SignaturesChecked, ", ")
		}
		_, _ = fmt.Fprintf(stdout, "%s: %s, %s -> %s\n", res.SpendIntentID, status, sig, res.OutputDir)
	}
	_, _ = fmt.Fprintf(stdout, "%d spend EvidencePack(s) exported to %s\n", len(results), outDir)
	return 0
}

// runSpendProxySavingsExport builds the HELM-614 savings EvidencePack from a
// paired capture: receipts + task-split manifest + task results + parity
// pre-run + the exact price-book config. The pack is offline-verified before
// it is written.
func runSpendProxySavingsExport(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("spend-proxy savings-export", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		receiptsDir string
		captureDir  string
		configPath  string
		outDir      string
		signSecret  string
		jsonOut     bool
	)
	cmd.StringVar(&receiptsDir, "receipts-dir", "./helm-spend-receipts", "Directory holding the receipt log and trusted-key registry")
	cmd.StringVar(&captureDir, "capture", "", "Directory holding task_split_manifest.json, task_results.json, parity_prerun.json (required)")
	cmd.StringVar(&configPath, "config", "", "The exact spend-proxy config the capture ran with (required; embedded as the price-book snapshot)")
	cmd.StringVar(&outDir, "out", "./helm-spend-evidence", "Output directory for the savings EvidencePack")
	cmd.StringVar(&signSecret, "sign", "", "Signing seed for the pack manifest signature (or set HELM_SPEND_PROXY_SIGNING_SEED; must be the capture's signing key)")
	cmd.BoolVar(&jsonOut, "json", false, "Print the export summary as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if captureDir == "" || configPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --capture and --config are required")
		return 2
	}
	if signSecret == "" {
		signSecret = os.Getenv("HELM_SPEND_PROXY_SIGNING_SEED")
	}

	res, err := spendproxy.ExportSavingsEvidencePack(spendproxy.SavingsExportOptions{
		ReceiptsDir:   receiptsDir,
		CaptureDir:    captureDir,
		ConfigPath:    configPath,
		OutDir:        outDir,
		SigningSecret: signSecret,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}
	printSavingsSummary(stdout, res)
	return 0
}

func printSavingsSummary(stdout io.Writer, res *spendproxy.SavingsExportResult) {
	view := res.View
	_, _ = fmt.Fprintf(stdout, "savings pack:   %s (run %s)\n", res.PackID, res.RunID)
	_, _ = fmt.Fprintf(stdout, "manifest hash:  %s\n", res.ManifestHash)
	_, _ = fmt.Fprintf(stdout, "output:         %s\n", res.OutputDir)
	_, _ = fmt.Fprintf(stdout, "offline verify: ok=%v checks=%d receipts=%d\n", res.OfflineVerified, len(res.ChecksPassed), res.ReceiptsVerified)
	_, _ = fmt.Fprintf(stdout, "baseline:       %s -> %s, settled %d cents, token-priced %d micro-cents, %d/%d passed, CPST %d micro-cents (token-priced)\n",
		view.Baseline.RequestedModelID, view.Baseline.DispatchedModelID, view.Baseline.SpendCents, view.Baseline.TokenPricedMicroCents, view.Baseline.TasksPassed, view.Baseline.TasksTotal, view.Baseline.CPSTTokenPricedMicroCents)
	_, _ = fmt.Fprintf(stdout, "substitute:     %s -> %s, settled %d cents, token-priced %d micro-cents, %d/%d passed, CPST %d micro-cents (token-priced)\n",
		view.Substitute.RequestedModelID, view.Substitute.DispatchedModelID, view.Substitute.SpendCents, view.Substitute.TokenPricedMicroCents, view.Substitute.TasksPassed, view.Substitute.TasksTotal, view.Substitute.CPSTTokenPricedMicroCents)
	if view.SavingsClaimValid {
		_, _ = fmt.Fprintf(stdout, "parity bar:     MET; savings %d micro-cents per successful task (%d bps, token-priced basis)\n", view.SavingsPerTaskMicroCents, view.SavingsPercentBps)
	} else {
		_, _ = fmt.Fprintf(stdout, "parity bar:     NOT MET — no savings claim; the pack records the negative result\n")
	}
}

// runSpendProxySavingsVerify is the skeptic's offline entrypoint: verify a
// written savings pack directory with no receipts dir, ledger, or network.
func runSpendProxySavingsVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("spend-proxy savings-verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		packDir         string
		jsonOut         bool
		issuerKeyID     string
		issuerPublicKey string
	)
	cmd.StringVar(&packDir, "pack", "", "Savings pack directory to verify offline (required)")
	cmd.BoolVar(&jsonOut, "json", false, "Print the verification result as JSON")
	cmd.StringVar(&issuerKeyID, "issuer-key-id", "", "Expected issuer key id, pinned out of band")
	cmd.StringVar(&issuerPublicKey, "issuer-public-key", "", "Expected issuer Ed25519 public key hex, pinned out of band. Without the pin the pack's own key registry is the only trust root and the result is UNVERIFIABLE (exit 1)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if packDir == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --pack is required")
		return 2
	}
	if (issuerKeyID == "") != (issuerPublicKey == "") {
		_, _ = fmt.Fprintln(stderr, "Error: --issuer-key-id and --issuer-public-key must be given together")
		return 2
	}
	var issuerKeys map[string]string
	if issuerKeyID != "" {
		issuerKeys = map[string]string{issuerKeyID: issuerPublicKey}
	}
	res, err := spendproxy.VerifySavingsPackDirWithIssuer(packDir, issuerKeys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "VERIFICATION FAILED: %v\n", err)
		return 1
	}
	// Audit 13-04: without a pinned issuer key the signatures prove only that
	// the pack is consistent with the key registry it carries itself.
	exit := 0
	if res.SelfAttested {
		exit = 1
	}
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return exit
	}
	if res.SelfAttested {
		_, _ = fmt.Fprintf(stdout, "pack %s: UNVERIFIABLE (self-attested): internally consistent under the pack's own key registry (%d receipts), but no issuer key was pinned; pass --issuer-key-id and --issuer-public-key\n", res.PackID, res.ReceiptsVerified)
	} else {
		_, _ = fmt.Fprintf(stdout, "pack %s: offline-verified ok=%v issuer=%s (%d receipts)\n", res.PackID, res.OK, issuerKeyID, res.ReceiptsVerified)
	}
	_, _ = fmt.Fprintf(stdout, "manifest hash: %s\n", res.ManifestHash)
	for _, check := range res.ChecksPassed {
		_, _ = fmt.Fprintf(stdout, "  check passed: %s\n", check)
	}
	if !res.SavingsClaimValid {
		_, _ = fmt.Fprintln(stdout, "note: parity bar not met — this pack records a negative result, no savings claim")
	}
	return exit
}

func init() {
	Register(Subcommand{
		Name:    "spend-proxy",
		Aliases: []string{},
		Usage:   "Offline historical receipt export and verification (live spending uses helm-gateway)",
		RunFn:   runSpendProxyCmd,
	})
}
