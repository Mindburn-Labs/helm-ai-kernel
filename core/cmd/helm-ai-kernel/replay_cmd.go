package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
)

// Replay statuses.
const (
	// replayStatusComplete: every tape entry was served back in sequence and
	// matched its recorded hash and the manifest.
	replayStatusComplete = "COMPLETE"
	// replayStatusDiverged: the replayer missed an entry, or a served value
	// does not match what was recorded.
	replayStatusDiverged = "DIVERGED"
	// replayStatusNotRun: the tape holds no entries, so nothing was replayed.
	replayStatusNotRun = "NOT_RUN"
)

// runReplayCmd implements `helm-ai-kernel replay` per §2.1.
//
// It serves the recorded tape of a run back through tape.Replayer and reports
// what the replayer returned: every entry must be served in sequence from 1
// with no tape miss, each served value must match the hash recorded on its
// entry, and the tape and tape_manifest.json must name the same entries with
// the same hashes.
//
// It replays recorded inputs only. It does not re-execute the run or compare
// decisions: this command has the tape, not the code and policy that consumed
// it.
//
// Exit codes:
//
//	0 = every tape entry was replayed and matched
//	1 = the replay diverged, or the tape holds nothing to replay
//	2 = runtime or usage error; nothing was replayed
func runReplayCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("replay", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		verify      bool
		evidenceDir string
		jsonOutput  bool
	)

	cmd.BoolVar(&verify, "verify", false, "Also require tape residency metadata (data_class) on every entry")
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

	replayed, issues := replayTape(entries, manifest)
	if verify {
		for i, e := range entries {
			if e.DataClass == "" {
				issues = append(issues, fmt.Sprintf("entry %d: missing data_class (tape residency)", i))
			}
		}
	}

	status := replayStatusComplete
	switch {
	case len(issues) > 0:
		status = replayStatusDiverged
	case replayed == 0:
		// Nothing was served, so there is no replay to call complete.
		status = replayStatusNotRun
	}
	result := map[string]any{
		"evidence_dir":     evidenceDir,
		"run_id":           manifest.RunID,
		"entry_count":      len(entries),
		"manifest_refs":    len(manifest.Entries),
		"entries_replayed": replayed,
		"replay_status":    status,
	}
	if len(issues) > 0 {
		result["issues"] = issues
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		switch status {
		case replayStatusDiverged:
			_, _ = fmt.Fprintf(stdout, "Replay DIVERGED: %d of %d tape entries replayed, %d issues:\n", replayed, len(entries), len(issues))
			for _, issue := range issues {
				_, _ = fmt.Fprintf(stdout, "  - %s\n", issue)
			}
		case replayStatusNotRun:
			_, _ = fmt.Fprintf(stdout, "Nothing replayed: the tape holds no entries (tape_manifest.json lists %d).\n", len(manifest.Entries))
		default:
			_, _ = fmt.Fprintf(stdout, "Replayed %d of %d tape entries through the tape replayer: each was served in sequence and matches its recorded hash and tape_manifest.json.\n", replayed, len(entries))
			_, _ = fmt.Fprintln(stdout, "This replays recorded inputs only; it does not re-execute the run or compare decisions.")
		}
		_, _ = fmt.Fprintf(stdout, "Run ID:  %s\n", manifest.RunID)
		_, _ = fmt.Fprintf(stdout, "Status:  %s\n", status)
	}

	if status != replayStatusComplete {
		return 1
	}
	return 0
}

// replayTape serves the tape back through tape.Replayer the way a replayed run
// consumes it, front to back, and returns how many entries were served with
// their recorded value intact, plus everything that did not hold.
func replayTape(entries []tape.Entry, manifest *tape.Manifest) (int, []string) {
	var issues []string
	replayer := tape.NewReplayer(entries)
	if replayer.Count() != len(entries) {
		// The replayer keys entries by seq, so a repeated seq leaves one entry
		// that can never be served.
		issues = append(issues, fmt.Sprintf("%d entry files hold %d distinct sequence numbers: entries share a sequence number", len(entries), replayer.Count()))
	}

	replayed := 0
	served := make(map[uint64]bool, replayer.Count())
	for range replayer.Count() {
		entry, err := replayer.Next()
		if err != nil {
			issues = append(issues, err.Error())
			continue
		}
		served[entry.Seq] = true
		sum := sha256.Sum256(entry.Value)
		if computed := hex.EncodeToString(sum[:]); computed != entry.ValueHash {
			issues = append(issues, fmt.Sprintf("seq=%d served value does not match its recorded value_hash: recorded %s, got %s", entry.Seq, entry.ValueHash, computed))
			continue
		}
		replayed++
	}

	// A hole stops the walk short of the entries behind it.
	listed := make(map[uint64]bool, len(manifest.Entries))
	for _, item := range manifest.Entries {
		listed[item.Seq] = true
	}
	var unreached, unlisted []uint64
	seen := make(map[uint64]bool, len(entries))
	for _, entry := range entries {
		if seen[entry.Seq] {
			continue
		}
		seen[entry.Seq] = true
		if !served[entry.Seq] {
			unreached = append(unreached, entry.Seq)
		}
		if !listed[entry.Seq] {
			unlisted = append(unlisted, entry.Seq)
		}
	}
	sort.Slice(unreached, func(i, j int) bool { return unreached[i] < unreached[j] })
	sort.Slice(unlisted, func(i, j int) bool { return unlisted[i] < unlisted[j] })
	for _, seq := range unreached {
		issues = append(issues, fmt.Sprintf("seq=%d is on the tape but was never served: the sequence is not contiguous from 1", seq))
	}
	for _, seq := range unlisted {
		issues = append(issues, fmt.Sprintf("seq=%d is on the tape but not listed in tape_manifest.json", seq))
	}

	// The manifest is what the run says it recorded; the tape must hold each
	// of those entries with the same hash.
	issues = append(issues, tape.VerifyManifestIntegrity(entries, manifest)...)
	return replayed, issues
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
	Register(Subcommand{Name: "replay", Aliases: []string{}, Usage: "Serve an EvidencePack's recorded tape back through the tape replayer and report misses and hash mismatches (--evidence); replays recorded inputs, does not re-execute the run", RunFn: runReplayCmd})
}
