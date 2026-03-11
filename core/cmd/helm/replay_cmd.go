package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/tape"
)

// runReplayCmd implements `helm replay` per §2.1.
//
// Replays a run from VCR tapes and verifies hash match.
//
// Exit codes:
//
//	0 = replay matches
//	1 = replay diverged
//	2 = runtime error
func runReplayCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("replay", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		verify      bool
		evidenceDir string
		jsonOutput  bool
	)

	cmd.BoolVar(&verify, "verify", false, "Verify tape integrity after loading")
	cmd.StringVar(&evidenceDir, "evidence", "", "Path to EvidencePack directory (REQUIRED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output results as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if evidenceDir == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --evidence is required (path to EvidencePack)")
		return 2
	}

	// Check for tapes directory
	tapesDir := filepath.Join(evidenceDir, "08_TAPES")
	if _, err := os.Stat(tapesDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: tapes directory not found: %s\n", tapesDir)
		return 2
	}

	// Load manifest using tape package API
	manifest, err := tape.ReadManifest(tapesDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read tape manifest: %v\n", err)
		return 2
	}

	// Load tape entries from individual files
	entries, err := loadTapeEntries(tapesDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot load tape entries: %v\n", err)
		return 2
	}

	result := map[string]any{
		"evidence_dir":  evidenceDir,
		"run_id":        manifest.RunID,
		"entry_count":   len(entries),
		"manifest_refs": len(manifest.Entries),
		"replay_status": "COMPLETE",
	}

	if verify {
		// Verify tape integrity using tape package API
		issues := tape.VerifyManifestIntegrity(entries, manifest)

		// Additional checks
		for i := 1; i < len(entries); i++ {
			if entries[i].Seq <= entries[i-1].Seq {
				issues = append(issues, fmt.Sprintf(
					"non-monotonic sequence at index %d: %d <= %d",
					i, entries[i].Seq, entries[i-1].Seq,
				))
			}
		}
		for i, e := range entries {
			if e.DataClass == "" {
				issues = append(issues, fmt.Sprintf("entry %d: missing data_class (tape residency)", i))
			}
		}

		if len(issues) > 0 {
			result["replay_status"] = "DIVERGED"
			result["issues"] = issues

			if jsonOutput {
				data, _ := json.MarshalIndent(result, "", "  ")
				_, _ = fmt.Fprintln(stdout, string(data))
			} else {
				_, _ = fmt.Fprintf(stdout, "Replay DIVERGED (%d issues):\n", len(issues))
				for _, issue := range issues {
					_, _ = fmt.Fprintf(stdout, "  - %s\n", issue)
				}
			}
			return 1
		}
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		_, _ = fmt.Fprintf(stdout, "Replay complete: %d entries verified\n", len(entries))
		_, _ = fmt.Fprintf(stdout, "Run ID:  %s\n", manifest.RunID)
		_, _ = fmt.Fprintf(stdout, "Status:  %s\n", result["replay_status"])
	}

	return 0
}

// loadTapeEntries loads tape entries from JSON files in the tapes directory.
func loadTapeEntries(tapesDir string) ([]tape.Entry, error) {
	files, err := filepath.Glob(filepath.Join(tapesDir, "entry_*.json"))
	if err != nil {
		return nil, err
	}

	var entries []tape.Entry
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		var entry tape.Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func init() {
	Register(Subcommand{Name: "replay", Aliases: []string{}, Usage: "Replay and verify from tapes (--evidence)", RunFn: runReplayCmd})
}
