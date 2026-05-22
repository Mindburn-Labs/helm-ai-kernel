package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func runEvidenceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel evidence <export|verify|envelope|scopes|inspect|diff|attach-host-chain|correlate-host> [flags]")
		return 2
	}
	switch args[0] {
	case "export":
		return runEvidenceExport(args[1:], stdout, stderr)
	case "verify":
		return runEvidenceVerify(args[1:], stdout, stderr)
	case "envelope":
		return runEvidenceEnvelope(args[1:], stdout, stderr)
	case "scopes":
		return runEvidenceScopes(args[1:], stdout, stderr)
	case "inspect":
		return runEvidenceInspect(args[1:], stdout, stderr)
	case "diff":
		return runEvidenceDiff(args[1:], stdout, stderr)
	case "attach-host-chain":
		return runEvidenceAttachHostChain(args[1:], stdout, stderr)
	case "correlate-host":
		return runEvidenceCorrelateHost(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel evidence <export|verify|envelope|scopes|inspect|diff|attach-host-chain|correlate-host> [flags]")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown evidence subcommand: %s\n", args[0])
		return 2
	}
}

type evidenceInspectReport struct {
	Bundle             string                 `json:"bundle"`
	Verified           bool                   `json:"verified"`
	Summary            string                 `json:"summary"`
	IssueCount         int                    `json:"issue_count"`
	MerkleRoot         string                 `json:"merkle_root,omitempty"`
	ManifestLaunchID   string                 `json:"manifest_launch_id,omitempty"`
	IndexEntryCount    int                    `json:"index_entry_count"`
	EvidenceGraphRef   string                 `json:"evidence_graph_ref,omitempty"`
	EvidenceGraphRoot  string                 `json:"evidence_graph_root,omitempty"`
	EvidenceGraphNodes int                    `json:"evidence_graph_nodes,omitempty"`
	FileHashes         map[string]string      `json:"file_hashes,omitempty"`
	Checks             []verifier.CheckResult `json:"checks"`
}

func runEvidenceInspect(args []string, stdout, stderr io.Writer) int {
	jsonOutput, positionals, err := parseEvidenceJSONArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel evidence inspect <bundle> [--json]")
		return 2
	}
	report, err := inspectEvidenceBundle(positionals[0])
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return 0
	}
	fmt.Fprintf(stdout, "EvidencePack %s\n", report.Bundle)
	fmt.Fprintf(stdout, "  Verified: %t\n", report.Verified)
	fmt.Fprintf(stdout, "  Summary:  %s\n", report.Summary)
	if report.MerkleRoot != "" {
		fmt.Fprintf(stdout, "  Merkle:   %s\n", report.MerkleRoot)
	}
	if report.EvidenceGraphRoot != "" {
		fmt.Fprintf(stdout, "  Graph:    %s (%d nodes)\n", report.EvidenceGraphRoot, report.EvidenceGraphNodes)
	}
	return boolExit(report.Verified)
}

type evidenceDiffReport struct {
	BundleA   string   `json:"bundle_a"`
	BundleB   string   `json:"bundle_b"`
	Identical bool     `json:"identical"`
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
	Changed   []string `json:"changed"`
	Unchanged int      `json:"unchanged"`
}

func runEvidenceDiff(args []string, stdout, stderr io.Writer) int {
	jsonOutput, positionals, err := parseEvidenceJSONArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if len(positionals) != 2 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel evidence diff <bundle-a> <bundle-b> [--json]")
		return 2
	}
	report, err := diffEvidenceBundles(positionals[0], positionals[1])
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return 0
	}
	fmt.Fprintf(stdout, "EvidencePack diff\n")
	fmt.Fprintf(stdout, "  Identical: %t\n", report.Identical)
	fmt.Fprintf(stdout, "  Added:     %d\n", len(report.Added))
	fmt.Fprintf(stdout, "  Removed:   %d\n", len(report.Removed))
	fmt.Fprintf(stdout, "  Changed:   %d\n", len(report.Changed))
	fmt.Fprintf(stdout, "  Unchanged: %d\n", report.Unchanged)
	return 0
}

func parseEvidenceJSONArgs(args []string) (bool, []string, error) {
	jsonOutput := false
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json", "-json":
			jsonOutput = true
		case "--":
			positionals = append(positionals, args[i+1:]...)
			return jsonOutput, positionals, nil
		default:
			if strings.HasPrefix(arg, "-") {
				return false, nil, fmt.Errorf("unknown flag: %s", arg)
			}
			positionals = append(positionals, arg)
		}
	}
	return jsonOutput, positionals, nil
}

func inspectEvidenceBundle(bundle string) (evidenceInspectReport, error) {
	var out evidenceInspectReport
	err := withEvidenceBundleDir(bundle, func(dir string) error {
		report, err := verifier.VerifyBundle(dir)
		if err != nil {
			return err
		}
		out = evidenceInspectReport{
			Bundle:          bundle,
			Verified:        report.Verified,
			Summary:         report.Summary,
			IssueCount:      report.IssueCount,
			MerkleRoot:      report.MerkleRoot,
			IndexEntryCount: report.Roots.EntryCount,
			Checks:          report.Checks,
		}
		if manifest, err := readLaunchpadManifest(dir); err == nil {
			out.ManifestLaunchID = manifest.LaunchID
			out.FileHashes = manifest.FileHashes
			if hash, ok := manifest.Artifacts["04_EXPORTS/launchpad_evidence_graph.json"]; ok {
				out.EvidenceGraphRef = hash
			}
		}
		if graph, err := readEvidenceGraph(dir); err == nil {
			out.EvidenceGraphRoot = graph.RootHash
			out.EvidenceGraphNodes = len(graph.Nodes)
		}
		return nil
	})
	return out, err
}

func diffEvidenceBundles(a, b string) (evidenceDiffReport, error) {
	out := evidenceDiffReport{BundleA: a, BundleB: b}
	err := withEvidenceBundleDir(a, func(dirA string) error {
		return withEvidenceBundleDir(b, func(dirB string) error {
			indexA, err := readEvidenceIndex(dirA)
			if err != nil {
				return err
			}
			indexB, err := readEvidenceIndex(dirB)
			if err != nil {
				return err
			}
			for path, hashA := range indexA {
				hashB, ok := indexB[path]
				if !ok {
					out.Removed = append(out.Removed, path)
					continue
				}
				if hashA != hashB {
					out.Changed = append(out.Changed, path)
					continue
				}
				out.Unchanged++
			}
			for path := range indexB {
				if _, ok := indexA[path]; !ok {
					out.Added = append(out.Added, path)
				}
			}
			sort.Strings(out.Added)
			sort.Strings(out.Removed)
			sort.Strings(out.Changed)
			out.Identical = len(out.Added) == 0 && len(out.Removed) == 0 && len(out.Changed) == 0
			return nil
		})
	})
	return out, err
}

func withEvidenceBundleDir(bundle string, fn func(string) error) error {
	info, err := os.Stat(bundle)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fn(bundle)
	}
	tempDir, err := os.MkdirTemp("", "helm-evidence-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	if err := extractEvidenceArchive(bundle, tempDir); err != nil {
		return err
	}
	return fn(tempDir)
}

func readLaunchpadManifest(dir string) (lpreceipts.EvidencePackManifest, error) {
	var manifest lpreceipts.EvidencePackManifest
	data, err := os.ReadFile(filepath.Join(dir, "04_EXPORTS", "launchpad_manifest.json"))
	if err != nil {
		return manifest, err
	}
	return manifest, json.Unmarshal(data, &manifest)
}

func readEvidenceGraph(dir string) (lpreceipts.EvidenceGraph, error) {
	var graph lpreceipts.EvidenceGraph
	data, err := os.ReadFile(filepath.Join(dir, "04_EXPORTS", "launchpad_evidence_graph.json"))
	if err != nil {
		return graph, err
	}
	return graph, json.Unmarshal(data, &graph)
}

func readEvidenceIndex(dir string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "00_INDEX.json"))
	if err != nil {
		return nil, err
	}
	var index struct {
		Entries []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, entry := range index.Entries {
		if entry.Path == "" {
			continue
		}
		out[entry.Path] = strings.TrimPrefix(entry.SHA256, "sha256:")
	}
	return out, nil
}

func boolExit(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

func runEvidenceExport(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return runLaunchEvidence(append([]string{args[0], "--export", "--json"}, args[1:]...), stdout, stderr)
	}
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

func runEvidenceVerify(args []string, stdout, stderr io.Writer) int {
	normalized := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--offline" {
			continue
		}
		normalized = append(normalized, arg)
	}
	return runVerifyCmd(normalized, stdout, stderr)
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
	Register(Subcommand{Name: "evidence", Aliases: []string{}, Usage: "Inspect, diff, and export native EvidencePacks", RunFn: runEvidenceCmd})
}
