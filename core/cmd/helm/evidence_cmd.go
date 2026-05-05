package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-oss/core/pkg/evidence"
)

func runEvidenceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm evidence <export|envelope> [flags]")
		return 2
	}
	switch args[0] {
	case "export":
		return runEvidenceExport(args[1:], stdout, stderr)
	case "envelope":
		return runEvidenceEnvelope(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm evidence <export|envelope> [flags]")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown evidence subcommand: %s\n", args[0])
		return 2
	}
}

func runEvidenceExport(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence export", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		envelope     string
		nativeHash   string
		manifestID   string
		subject      string
		experimental bool
		jsonOutput   bool
	)
	cmd.StringVar(&envelope, "envelope", "", "Envelope type: dsse, jws, in-toto, slsa, sigstore, scitt, cose (REQUIRED)")
	cmd.StringVar(&nativeHash, "native-hash", "", "Verified native EvidencePack root hash (REQUIRED)")
	cmd.StringVar(&manifestID, "manifest-id", "evidence-export", "Envelope manifest id")
	cmd.StringVar(&subject, "subject", "", "Evidence subject identifier")
	cmd.BoolVar(&experimental, "experimental", false, "Allow experimental envelope formats such as SCITT or COSE")
	cmd.BoolVar(&jsonOutput, "json", false, "Output manifest as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if envelope == "" || nativeHash == "" {
		fmt.Fprintln(stderr, "Error: --envelope and --native-hash are required")
		return 2
	}

	manifest, err := evidencepkg.BuildEnvelopeManifest(evidencepkg.EnvelopeExportRequest{
		ManifestID:         manifestID,
		Envelope:           evidencepkg.EnvelopeExportType(envelope),
		NativeEvidenceHash: nativeHash,
		Subject:            subject,
		CreatedAt:          time.Now().UTC(),
		AllowExperimental:  experimental,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(manifest)
		return 0
	}
	fmt.Fprintf(stdout, "Evidence envelope manifest\n")
	fmt.Fprintf(stdout, "  Envelope: %s\n", manifest.Envelope)
	fmt.Fprintf(stdout, "  Native:   %s\n", manifest.NativeEvidenceHash)
	fmt.Fprintf(stdout, "  Hash:     %s\n", manifest.ManifestHash)
	fmt.Fprintf(stdout, "  Payload:  %s\n", manifest.PayloadHash)
	return 0
}

func buildEvidenceEnvelope(manifestID, envelope, nativeHash, subject string, experimental bool) (contracts.EvidenceEnvelopeManifest, contracts.EvidenceEnvelopePayload, error) {
	manifest, err := evidencepkg.BuildEnvelopeManifest(evidencepkg.EnvelopeExportRequest{
		ManifestID:         manifestID,
		Envelope:           evidencepkg.EnvelopeExportType(envelope),
		NativeEvidenceHash: nativeHash,
		Subject:            subject,
		CreatedAt:          time.Now().UTC(),
		AllowExperimental:  experimental,
	})
	if err != nil {
		return contracts.EvidenceEnvelopeManifest{}, contracts.EvidenceEnvelopePayload{}, err
	}
	payload, err := evidencepkg.BuildEnvelopePayload(manifest)
	if err != nil {
		return contracts.EvidenceEnvelopeManifest{}, contracts.EvidenceEnvelopePayload{}, err
	}
	return manifest, payload, nil
}

func init() {
	Register(Subcommand{Name: "evidence", Aliases: []string{}, Usage: "Export evidence envelopes over native EvidencePacks", RunFn: runEvidenceCmd})
}
