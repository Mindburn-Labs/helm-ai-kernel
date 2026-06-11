package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// runVerifyEntryCmd implements the privacy-preserving single-entry verification
// surface (MIN-512):
//
//	helm-ai-kernel verify --entry <path> --proof <file> [--json]
//
// It verifies, fully offline and without the rest of the pack, that one manifest
// entry (e.g. a single receipt) belongs to the pack identified by the proof's
// binding (manifest_hash + entries_merkle_root). The proof is an InclusionProof
// artifact (see protocols/spec/evidence-pack-v1.md §14). When the proof carries
// an SD-JWT selective-disclosure presentation, the entry's redacted receipt
// claims travel with it; this command checks Merkle membership and reports the
// disclosed/public claim names. Cryptographic SD-JWT signature verification is
// the verifier's responsibility once it holds the issuer key.
//
// Exit codes: 0 = entry verified · 1 = verification failed · 2 = runtime error.
func runVerifyEntryCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("verify-entry", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		entryPath  string
		proofPath  string
		jsonOutput bool
	)
	cmd.StringVar(&entryPath, "entry", "", "Manifest entry path to verify (e.g. receipts/decision-001.json)")
	cmd.StringVar(&proofPath, "proof", "", "Path to the inclusion-proof JSON artifact")
	cmd.BoolVar(&jsonOutput, "json", false, "Output result as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if proofPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --proof <file> is required for single-entry verification")
		return 2
	}

	data, err := os.ReadFile(proofPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read proof: %v\n", err)
		return 2
	}
	var proof evidencepack.InclusionProof
	if err := json.Unmarshal(data, &proof); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid proof JSON: %v\n", err)
		return 2
	}

	// If --entry is supplied, it MUST match the proof's bound entry. This stops a
	// caller from being handed a valid proof for a different entry than asked.
	if entryPath != "" && entryPath != proof.Entry.Path {
		result := entryVerifyResult{
			Verified: false,
			Entry:    proof.Entry.Path,
			Reason:   fmt.Sprintf("requested entry %q does not match proof entry %q", entryPath, proof.Entry.Path),
		}
		return emitEntryResult(stdout, result, jsonOutput)
	}

	result := entryVerifyResult{
		Entry:        proof.Entry.Path,
		PackID:       proof.Binding.PackID,
		ManifestHash: proof.Binding.ManifestHash,
		PolicyHash:   proof.Binding.PolicyHash,
		MerkleRoot:   proof.Binding.EntriesMerkleRoot,
		CreatedAt:    proof.Binding.CreatedAt,
	}

	if err := evidencepack.VerifyInclusionProof(&proof); err != nil {
		result.Verified = false
		result.Reason = err.Error()
		return emitEntryResult(stdout, result, jsonOutput)
	}

	result.Verified = true
	if proof.Disclosure != nil {
		result.PublicClaims = proof.Disclosure.PublicClaims
		result.HasPresentation = strings.TrimSpace(proof.Disclosure.Presentation) != ""
	}
	return emitEntryResult(stdout, result, jsonOutput)
}

type entryVerifyResult struct {
	Verified        bool     `json:"verified"`
	Entry           string   `json:"entry"`
	PackID          string   `json:"pack_id,omitempty"`
	ManifestHash    string   `json:"manifest_hash,omitempty"`
	PolicyHash      string   `json:"policy_hash,omitempty"`
	MerkleRoot      string   `json:"entries_merkle_root,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	PublicClaims    []string `json:"public_claims,omitempty"`
	HasPresentation bool     `json:"has_presentation,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

func emitEntryResult(stdout io.Writer, result entryVerifyResult, asJSON bool) int {
	if asJSON {
		out, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(out))
	} else if result.Verified {
		_, _ = fmt.Fprintf(stdout, "VERIFIED · entry %s · pack %s\n", result.Entry, result.PackID)
		_, _ = fmt.Fprintf(stdout, "manifest %s · policy %s\n", result.ManifestHash, result.PolicyHash)
		if result.HasPresentation {
			_, _ = fmt.Fprintf(stdout, "selective-disclosure present · public claims: %s\n", strings.Join(result.PublicClaims, ", "))
		}
	} else {
		_, _ = fmt.Fprintf(stdout, "FAILED · entry %s\n  - %s\n", result.Entry, result.Reason)
	}
	if !result.Verified {
		return 1
	}
	return 0
}

// hasFlag reports whether args contains the given flag in any of its forms
// (-name, --name, -name=..., --name=...).
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		trimmed := strings.TrimLeft(a, "-")
		if trimmed == name || strings.HasPrefix(trimmed, name+"=") {
			return true
		}
	}
	return false
}
