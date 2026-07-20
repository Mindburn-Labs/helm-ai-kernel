package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/profile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/profile/updatebundle"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// boundary profile <compile|attest|verify|bundle-verify> — the Boundary
// Enforcement Profile CLI. Nested under the existing `boundary` command
// because top-level `boundary verify` (record verification) and `bundle`
// (policy bundles) are taken. HELM compiles and attests; the OS enforces.
func runBoundaryProfileCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		boundaryProfileUsage(stderr)
		return 2
	}
	switch args[0] {
	case "compile":
		return runBoundaryProfileCompile(args[1:], stdout, stderr)
	case "attest":
		return runBoundaryProfileAttest(args[1:], stdout, stderr)
	case "verify":
		return runBoundaryProfileVerify(args[1:], stdout, stderr)
	case "bundle-verify":
		return runBoundaryProfileBundleVerify(args[1:], stdout, stderr)
	case "--help", "-h", "help":
		boundaryProfileUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown boundary profile subcommand: %s\n", args[0])
		boundaryProfileUsage(stderr)
		return 2
	}
}

func boundaryProfileUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel boundary profile <subcommand> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Boundary Enforcement Profile: HELM compiles OS enforcement artifacts from")
	fmt.Fprintln(w, "policy and attests the live posture matches; the OS enforces. Fail closed.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  compile        Compile systemd/nftables/cgroup artifacts + signed compile receipt")
	fmt.Fprintln(w, "                 --input profile.json --out DIR [--kernel-version V] [--compiled-at RFC3339] [--receipt-id ID] [--json]")
	fmt.Fprintln(w, "  attest         Read live OS posture, compare against the compile receipt")
	fmt.Fprintln(w, "                 --receipt PATH --artifacts DIR [--enforce] [--out PATH] [--observed-at RFC3339] [--json]")
	fmt.Fprintln(w, "  verify         Offline-verify a compile receipt (and optional attestation / artifact dir)")
	fmt.Fprintln(w, "                 --receipt PATH --public-key HEX [--attestation PATH] [--artifacts DIR] [--json]")
	fmt.Fprintln(w, "  bundle-verify  Offline-verify a signed update bundle against its manifest")
	fmt.Fprintln(w, "                 --bundle PATH.tar.gz --manifest PATH --public-key HEX [--json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Signing key: HELM_SIGNING_KEY_HEX (32-byte seed or 64-byte private key, hex).")
	fmt.Fprintln(w, "compile requires it — compile receipts are never emitted unsigned.")
}

func runBoundaryProfileCompile(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary profile compile", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	inputPath := cmd.String("input", "", "Path to the profile input JSON document")
	outDir := cmd.String("out", "", "Directory to write the compiled artifacts into")
	kernelVersion := cmd.String("kernel-version", displayVersion(), "Kernel version recorded in the compile receipt")
	compiledAt := cmd.String("compiled-at", "", "Compile timestamp (RFC3339; defaults to now, pin for reproducible output)")
	receiptID := cmd.String("receipt-id", "", "Receipt id override (defaults to bp-<input-hash-prefix>)")
	keyID := cmd.String("key-id", "", "Signer key id recorded in the receipt (defaults to the hex public key)")
	jsonOut := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *inputPath == "" || *outDir == "" {
		fmt.Fprintln(stderr, "Error: --input and --out are required")
		return 2
	}
	input, err := loadBoundaryProfileInput(*inputPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	signer, err := boundarySigningKey(*keyID)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		fmt.Fprintln(stderr, "Compile receipts are never emitted unsigned.")
		return 2
	}
	when := time.Now().UTC()
	if *compiledAt != "" {
		when, err = time.Parse(time.RFC3339Nano, *compiledAt)
		if err != nil {
			fmt.Fprintf(stderr, "Error: invalid --compiled-at: %v\n", err)
			return 2
		}
	}
	compiled, err := profile.Compile(input, signer, profile.CompileOptions{
		KernelVersion: *kernelVersion,
		CompiledAt:    when,
		ReceiptID:     *receiptID,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	for path, content := range compiled.Files {
		target := filepath.Join(*outDir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
	}
	receiptBytes, err := canonicalize.JCS(compiled.Receipt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	receiptPath := filepath.Join(*outDir, "compile_receipt.json")
	if err := os.WriteFile(receiptPath, append(receiptBytes, '\n'), 0o644); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(stdout, stderr, map[string]any{
			"receipt_id":        compiled.Receipt.ReceiptID,
			"profile_id":        compiled.Receipt.ProfileID,
			"mode_tier":         compiled.Receipt.ModeTier,
			"policy_input_hash": compiled.Receipt.PolicyInputHash,
			"artifact_set_hash": compiled.Receipt.ArtifactSetHash,
			"receipt_path":      receiptPath,
			"artifacts":         compiled.Receipt.Artifacts,
		})
	}
	fmt.Fprintf(stdout, "Compiled Boundary Enforcement Profile %s (tier %s)\n", compiled.Receipt.ProfileID, compiled.Receipt.ModeTier)
	fmt.Fprintf(stdout, "  Receipt:      %s (%s)\n", compiled.Receipt.ReceiptID, receiptPath)
	fmt.Fprintf(stdout, "  Input hash:   %s\n", compiled.Receipt.PolicyInputHash)
	fmt.Fprintf(stdout, "  Artifact set: %s (%d files)\n", compiled.Receipt.ArtifactSetHash, len(compiled.Receipt.Artifacts))
	for _, ref := range compiled.Receipt.Artifacts {
		fmt.Fprintf(stdout, "    %s\n", ref.Path)
	}
	fmt.Fprintln(stdout, "Apply with systemd/nft on the appliance; then `boundary profile attest`.")
	return 0
}

func runBoundaryProfileAttest(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary profile attest", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	receiptPath := cmd.String("receipt", "", "Path to compile_receipt.json")
	artifactsDir := cmd.String("artifacts", "", "Directory holding the compiled artifacts")
	enforce := cmd.Bool("enforce", false, "Exit non-zero unless the verdict is MATCH (for systemd gating)")
	outPath := cmd.String("out", "", "Attestation receipt output path (default <data>/receipts/boundary-profile/<id>.json)")
	observedAt := cmd.String("observed-at", "", "Observation timestamp (RFC3339; defaults to now)")
	jsonOut := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *receiptPath == "" || *artifactsDir == "" {
		fmt.Fprintln(stderr, "Error: --receipt and --artifacts are required")
		return 2
	}
	receipt, err := loadCompileReceipt(*receiptPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	files, err := readArtifactDir(*artifactsDir)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	when := time.Now().UTC()
	if *observedAt != "" {
		when, err = time.Parse(time.RFC3339Nano, *observedAt)
		if err != nil {
			fmt.Fprintf(stderr, "Error: invalid --observed-at: %v\n", err)
			return 2
		}
	}
	// Signing is optional for attestations: hash-sealed always, signed when
	// a key is configured.
	var signer crypto.Signer
	if strings.TrimSpace(os.Getenv("HELM_SIGNING_KEY_HEX")) != "" {
		signer, err = boundarySigningKey("")
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
	}
	attestation, attErr := profile.Attest(receipt, files, profile.LiveProber(), signer, profile.AttestOptions{ObservedAt: when})
	if attErr != nil && attestation.RecordHash == "" {
		// Hard failure before an attestation could be sealed (artifact
		// tamper, unreadable receipt): fail closed with no receipt to write.
		fmt.Fprintf(stderr, "Error: %v\n", attErr)
		return 1
	}
	target := *outPath
	if target == "" {
		target = filepath.Join(normalizedDataDir(""), "receipts", "boundary-profile", attestation.AttestationID+".json")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	attestationBytes, err := canonicalize.JCS(attestation)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := os.WriteFile(target, append(attestationBytes, '\n'), 0o644); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOut {
		_ = printJSON(stdout, stderr, map[string]any{
			"attestation_id":   attestation.AttestationID,
			"verdict":          attestation.Verdict,
			"receipt_id":       attestation.ReceiptID,
			"attestation_path": target,
			"gate_dispatch":    profile.GateDispatch(attestation),
		})
	} else {
		fmt.Fprintf(stdout, "Posture attestation %s: %s (receipt %s)\n", attestation.AttestationID, attestation.Verdict, attestation.ReceiptID)
		for _, check := range attestation.Checks {
			if check.Result != profile.CheckPass {
				fmt.Fprintf(stdout, "  DRIFT %s %s: expected %q observed %q\n", check.Target, check.Property, check.Expected, check.Observed)
			}
		}
		fmt.Fprintf(stdout, "  Attestation receipt: %s\n", target)
	}
	if attErr != nil {
		fmt.Fprintf(stderr, "Error: %v\n", attErr)
		return 1
	}
	if *enforce && !profile.GateDispatch(attestation) {
		fmt.Fprintln(stderr, "Posture DRIFT: refusing (fail closed). The OS should not start the gateway.")
		return 1
	}
	return 0
}

func runBoundaryProfileVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary profile verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	receiptPath := cmd.String("receipt", "", "Path to compile_receipt.json")
	publicKeyHex := cmd.String("public-key", "", "Trust-root Ed25519 public key (hex)")
	attestationPath := cmd.String("attestation", "", "Optional posture attestation to verify against the receipt")
	artifactsDir := cmd.String("artifacts", "", "Optional artifact directory to re-derive the artifact set hash from")
	jsonOut := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *receiptPath == "" || *publicKeyHex == "" {
		fmt.Fprintln(stderr, "Error: --receipt and --public-key are required")
		return 2
	}
	publicKey, err := parseEd25519PublicKey(*publicKeyHex)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	receipt, err := loadCompileReceipt(*receiptPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	checks := map[string]string{}
	fail := func(name string, err error) { checks[name] = "FAIL: " + err.Error() }
	if err := profile.VerifyCompileReceipt(receipt, publicKey); err != nil {
		fail("receipt_signature", err)
	} else {
		checks["receipt_signature"] = "PASS"
	}
	if *artifactsDir != "" {
		files, err := readArtifactDir(*artifactsDir)
		if err != nil {
			fail("artifact_set", err)
		} else if _, setHash, err := profile.ArtifactSetHash(files); err != nil {
			fail("artifact_set", err)
		} else if setHash != receipt.ArtifactSetHash {
			fail("artifact_set", fmt.Errorf("artifact set %s does not match receipt %s", setHash, receipt.ArtifactSetHash))
		} else {
			checks["artifact_set"] = "PASS"
		}
	}
	if *attestationPath != "" {
		attestation, err := loadPostureAttestation(*attestationPath)
		switch {
		case err != nil:
			fail("attestation", err)
		case attestation.ReceiptHash != receipt.RecordHash || attestation.ReceiptID != receipt.ReceiptID:
			fail("attestation", fmt.Errorf("attestation is bound to a different receipt"))
		default:
			if err := profile.VerifyPostureAttestation(attestation, publicKey); err != nil {
				fail("attestation", err)
			} else {
				checks["attestation"] = "PASS (verdict " + attestation.Verdict + ")"
			}
		}
	}
	failed := false
	for _, result := range checks {
		if strings.HasPrefix(result, "FAIL") {
			failed = true
		}
	}
	if *jsonOut {
		_ = printJSON(stdout, stderr, map[string]any{"receipt_id": receipt.ReceiptID, "checks": checks, "verified": !failed})
	} else {
		fmt.Fprintf(stdout, "Compile receipt %s (profile %s, tier %s)\n", receipt.ReceiptID, receipt.ProfileID, receipt.ModeTier)
		for name, result := range checks {
			fmt.Fprintf(stdout, "  %-18s %s\n", name+":", result)
		}
	}
	if failed {
		return 1
	}
	return 0
}

func runBoundaryProfileBundleVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary profile bundle-verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	bundlePath := cmd.String("bundle", "", "Path to the update bundle (.tar.gz)")
	manifestPath := cmd.String("manifest", "", "Path to the signed update bundle manifest JSON")
	publicKeyHex := cmd.String("public-key", "", "Publisher Ed25519 public key (hex)")
	jsonOut := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" || *manifestPath == "" || *publicKeyHex == "" {
		fmt.Fprintln(stderr, "Error: --bundle, --manifest and --public-key are required")
		return 2
	}
	publicKey, err := parseEd25519PublicKey(*publicKeyHex)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	manifest, err := loadUpdateBundleManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	bundle, err := os.Open(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	defer bundle.Close()
	if err := updatebundle.VerifyBundle(bundle, manifest, publicKey); err != nil {
		fmt.Fprintf(stderr, "Update bundle verification FAILED: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(stdout, stderr, map[string]any{"bundle_id": manifest.BundleID, "kernel_version": manifest.KernelVersion, "entries": len(manifest.Entries), "verified": true})
	}
	fmt.Fprintf(stdout, "Update bundle %s verified: %d entries, kernel %s, signer %s\n", manifest.BundleID, len(manifest.Entries), manifest.KernelVersion, manifest.SignerKeyID)
	return 0
}

// boundarySigningKey mirrors the conform flow's HELM_SIGNING_KEY_HEX
// semantics (32-byte seed or 64-byte private key, hex). The default key id is
// the hex public key so offline verification is self-contained.
func boundarySigningKey(keyID string) (*crypto.Ed25519Signer, error) {
	keyHex := strings.TrimSpace(os.Getenv("HELM_SIGNING_KEY_HEX"))
	if keyHex == "" {
		return nil, fmt.Errorf("HELM_SIGNING_KEY_HEX is required")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid HELM_SIGNING_KEY_HEX: %w", err)
	}
	var privateKey ed25519.PrivateKey
	switch len(keyBytes) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(keyBytes)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(keyBytes)
	default:
		return nil, fmt.Errorf("HELM_SIGNING_KEY_HEX must be a 32-byte seed or 64-byte private key")
	}
	if keyID == "" {
		keyID = hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	}
	return crypto.NewEd25519SignerFromKey(privateKey, keyID), nil
}

func parseEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func loadBoundaryProfileInput(path string) (profile.ProfileInput, error) {
	var input profile.ProfileInput
	if err := loadStrictJSON(path, &input); err != nil {
		return profile.ProfileInput{}, err
	}
	return input, nil
}

func loadCompileReceipt(path string) (profile.CompileReceipt, error) {
	var receipt profile.CompileReceipt
	if err := loadStrictJSON(path, &receipt); err != nil {
		return profile.CompileReceipt{}, err
	}
	return receipt, nil
}

func loadPostureAttestation(path string) (profile.PostureAttestation, error) {
	var attestation profile.PostureAttestation
	if err := loadStrictJSON(path, &attestation); err != nil {
		return profile.PostureAttestation{}, err
	}
	return attestation, nil
}

func loadUpdateBundleManifest(path string) (updatebundle.UpdateBundleManifest, error) {
	var manifest updatebundle.UpdateBundleManifest
	if err := loadStrictJSON(path, &manifest); err != nil {
		return updatebundle.UpdateBundleManifest{}, err
	}
	return manifest, nil
}

// loadStrictJSON rejects unknown fields: operator-authored and trust-bearing
// documents never get silently reinterpreted.
func loadStrictJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func readArtifactDir(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "compile_receipt.json" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = content
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read artifact dir %s: %w", dir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("artifact dir %s holds no artifacts", dir)
	}
	return files, nil
}

func printJSON(stdout, stderr io.Writer, v any) int {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	return 0
}
