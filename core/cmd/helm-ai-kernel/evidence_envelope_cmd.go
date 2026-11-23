package main

import (
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

func runEvidenceEnvelope(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel evidence envelope <list|create|get|verify> [flags]")
		return 2
	}
	if answeredSurfaceHelp("Usage: helm-ai-kernel evidence envelope [flags]", args, stdout) {
		return 0
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "list":
		cmd := flag.NewFlagSet("evidence envelope list", flag.ContinueOnError)
		cmd.SetOutput(stderr)
		jsonOutput := cmd.Bool("json", false, "Output as JSON")
		if err := cmd.Parse(args[1:]); err != nil {
			return 2
		}
		if *jsonOutput {
			return writeSurfaceJSON(stdout, registry.ListEnvelopes())
		}
		fmt.Fprintln(stdout, "No envelope manifests recorded in this local CLI registry.")
		return 0
	case "create":
		return runEvidenceEnvelopeCreate(args[1:], stdout, stderr)
	case "get":
		return runEvidenceEnvelopeGet(args[1:], stdout, stderr)
	case "payload":
		return runEvidenceEnvelopePayload(args[1:], stdout, stderr)
	case "verify":
		return runEvidenceEnvelopeVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown evidence envelope subcommand: %s\n", args[0])
		return 2
	}
}

func runEvidenceEnvelopeCreate(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope create", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	envelope := cmd.String("envelope", "", "Envelope type")
	nativeHash := cmd.String("native-hash", "", "Native EvidencePack root hash")
	manifestID := cmd.String("manifest-id", "evidence-export", "Envelope manifest id")
	subject := cmd.String("subject", "", "Evidence subject")
	experimental := cmd.Bool("experimental", false, "Allow experimental envelope types")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *envelope == "" || *nativeHash == "" {
		fmt.Fprintln(stderr, "Error: --envelope and --native-hash are required")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	manifest, payload, err := buildEvidenceEnvelope(*manifestID, *envelope, *nativeHash, *subject, *experimental)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := registry.PutEnvelope(manifest); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := registry.PutEnvelopePayload(payload); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, map[string]any{"manifest": manifest, "payload": payload})
	}
	fmt.Fprintf(stdout, "Created evidence envelope %s payload=%s\n", manifest.ManifestID, payload.PayloadHash)
	return 0
}

func runEvidenceEnvelopeGet(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	manifestID := cmd.String("manifest-id", "", "Envelope manifest id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *manifestID == "" && cmd.NArg() > 0 {
		*manifestID = cmd.Arg(0)
	}
	if *manifestID == "" {
		fmt.Fprintln(stderr, "Error: --manifest-id is required")
		return 2
	}
	result := map[string]any{"manifest_id": *manifestID, "state": "not_found", "verified": false}
	if manifest, ok := newLocalSurfaceRegistry().GetEnvelope(*manifestID); ok {
		if *jsonOutput {
			return writeSurfaceJSON(stdout, manifest)
		}
		fmt.Fprintf(stdout, "Envelope manifest %s hash=%s payload=%s\n", manifest.ManifestID, manifest.ManifestHash, manifest.PayloadHash)
		return 0
	}
	if *jsonOutput {
		return writeSurfaceJSONResult(stdout, result, false)
	}
	fmt.Fprintf(stdout, "Envelope manifest %s is not recorded in this local CLI registry\n", *manifestID)
	return 1
}

func runEvidenceEnvelopePayload(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope payload", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	manifestID := cmd.String("manifest-id", "", "Envelope manifest id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *manifestID == "" && cmd.NArg() > 0 {
		*manifestID = cmd.Arg(0)
	}
	if *manifestID == "" {
		fmt.Fprintln(stderr, "Error: --manifest-id is required")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	payload, ok := registry.GetEnvelopePayload(*manifestID)
	if !ok {
		manifest, manifestOK := registry.GetEnvelope(*manifestID)
		if !manifestOK {
			fmt.Fprintf(stderr, "Error: envelope manifest %q not found\n", *manifestID)
			return 1
		}
		var err error
		payload, err = evidencepkg.BuildEnvelopePayload(manifest)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, payload)
	}
	fmt.Fprintf(stdout, "Envelope payload %s type=%s hash=%s\n", payload.ManifestID, payload.PayloadType, payload.PayloadHash)
	return 0
}

func runEvidenceEnvelopeVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	manifestID := cmd.String("manifest-id", "", "Envelope manifest id recorded in the local registry (required)")
	manifestHash := cmd.String("manifest-hash", "", "Expected manifest hash, compared with the recorded manifest")
	nativeRoot := cmd.String("native-root", "", "Expected native EvidencePack root hash, compared with the recorded manifest")
	envelope := cmd.String("envelope", "dsse", "Envelope type")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	// Nothing is verified until the supplied values have been compared with a
	// manifest this command loaded; the supplied values alone prove nothing.
	result := contracts.EvidenceEnvelopeVerification{
		ManifestID:   *manifestID,
		ManifestHash: *manifestHash,
		Envelope:     *envelope,
		NativeRoot:   *nativeRoot,
		Checks: map[string]string{
			"native_authority": evidencepkg.EnvelopeCheckSkipped,
			"manifest_hash":    evidencepkg.EnvelopeCheckSkipped,
			"payload_hash":     evidencepkg.EnvelopeCheckSkipped,
			"envelope_role":    evidencepkg.EnvelopeCheckSkipped,
		},
		Errors:     []string{"no manifest id was given, so there is no recorded manifest to compare with: nothing was checked"},
		VerifiedAt: time.Now().UTC(),
	}
	if *nativeRoot != "" {
		result.Checks["native_root"] = evidencepkg.EnvelopeCheckSkipped
	}
	if *manifestID != "" {
		registry := newLocalSurfaceRegistry()
		manifest, ok := registry.GetEnvelope(*manifestID)
		if !ok {
			result.Errors = []string{fmt.Sprintf("envelope manifest %q is not recorded in this local CLI registry: nothing was checked", *manifestID)}
		} else {
			// A payload that was not recorded is not rebuilt from the manifest:
			// it would only match itself, and payload_hash would pass unchecked.
			if payload, recorded := registry.GetEnvelopePayload(*manifestID); recorded {
				result = evidencepkg.VerifyEnvelopePayload(manifest, payload)
			} else {
				result = evidencepkg.VerifyEnvelopeManifest(manifest)
			}
			if *manifestHash != "" && *manifestHash != manifest.ManifestHash {
				result.Checks["manifest_hash"] = evidencepkg.EnvelopeCheckFail
				result.Errors = append(result.Errors, "supplied manifest hash does not match the recorded manifest")
			}
			if *nativeRoot != "" {
				result.Checks["native_root"] = evidencepkg.EnvelopeCheckPass
				if *nativeRoot != manifest.NativeEvidenceHash {
					result.Checks["native_root"] = evidencepkg.EnvelopeCheckFail
					result.Errors = append(result.Errors, "supplied native root does not match the recorded manifest")
				}
			}
			// Verified takes every check having run and passed; a skipped
			// check is not a pass.
			result.Verified = len(result.Errors) == 0
			for _, status := range result.Checks {
				if status != evidencepkg.EnvelopeCheckPass {
					result.Verified = false
				}
			}
		}
	}
	if *jsonOutput {
		return writeSurfaceJSONResult(stdout, result, result.Verified)
	}
	fmt.Fprintf(stdout, "Evidence envelope verify manifest=%s verified=%t\n", result.ManifestID, result.Verified)
	for _, check := range slices.Sorted(maps.Keys(result.Checks)) {
		fmt.Fprintf(stdout, "  %-17s %s\n", check, result.Checks[check])
	}
	if !result.Verified {
		for _, reason := range result.Errors {
			fmt.Fprintf(stderr, "Error: %s\n", reason)
		}
		return 1
	}
	return 0
}
