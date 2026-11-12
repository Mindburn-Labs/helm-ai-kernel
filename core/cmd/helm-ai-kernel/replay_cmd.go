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
	// replayStatusComplete: the entry files are in sequence order, every tape
	// entry was served back in sequence and matched the value_hash recorded on
	// it, and tape_manifest.json agrees with the tape. It says nothing about
	// who wrote the tape: see replaySealNotice.
	replayStatusComplete = "COMPLETE"
	// replayStatusDiverged: the replayer missed an entry, a served value does
	// not match what was recorded, the entry files are out of order, or the
	// manifest and the tape disagree.
	replayStatusDiverged = "DIVERGED"
	// replayStatusNotRun: the tape holds no entries, so nothing was replayed.
	replayStatusNotRun = "NOT_RUN"
)

// replaySealNotice is printed with every COMPLETE result. The command reads
// 08_TAPES only and never the pack seal, so it cannot tell the recorded tape
// from one that was rewritten with its manifest.
const replaySealNotice = "The pack seal is not checked: a tape and tape_manifest.json rewritten together replay as COMPLETE. " +
	"Run `helm-ai-kernel verify` on the pack to check its seal and the hashes of the tape files it indexes."

// runReplayCmd implements `helm-ai-kernel replay` per §2.1.
//
// It serves the recorded tape of a run back through tape.Replayer and reports
// what the replayer returned. COMPLETE means all of this held:
//
//   - 08_TAPES, tape_manifest.json and every entry_*.json are real files and
//     directories, not symbolic links;
//   - the entry files, in name order, carry strictly increasing sequence
//     numbers;
//   - every entry was served in sequence from 1 with no tape miss, and each
//     served value matches the value_hash recorded on its entry;
//   - tape_manifest.json lists every entry exactly once, and every field it
//     carries for an entry equals that entry.
//
// It replays recorded inputs only. It does not re-execute the run or compare
// decisions: this command has the tape, not the code and policy that consumed
// it. It does not check the pack seal either, so a tape and manifest that were
// rewritten together replay as COMPLETE.
//
// Exit codes:
//
//	0 = every tape entry was replayed and matched
//	1 = the replay diverged, or the tape holds nothing to replay
//	2 = runtime or usage error, or a symbolic link where the tape should be;
//	    nothing was replayed
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

	// Everything under the tape directory is named by the pack. A symbolic
	// link there points at bytes the pack does not hold, so it is refused
	// instead of followed.
	tapesDir := filepath.Join(evidenceDir, "08_TAPES")
	if err := requireNoSymlink(tapesDir, true); err != nil {
		writeText(stderr, "Error: %s\n", err)
		return 2
	}
	if err := requireNoSymlink(filepath.Join(tapesDir, "tape_manifest.json"), false); err != nil {
		writeText(stderr, "Error: cannot read tape manifest: %s\n", err)
		return 2
	}

	// Load manifest using tape package API
	manifest, err := tape.ReadManifest(tapesDir)
	if err != nil {
		writeText(stderr, "Error: cannot read tape manifest: %s\n", err)
		return 2
	}

	// Load tape entries from individual files
	entries, files, err := loadTapeEntries(tapesDir)
	if err != nil {
		writeText(stderr, "Error: cannot load tape entries: %s\n", err)
		return 2
	}

	replayed, issues := replayTape(entries, files, manifest)
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
		// Always false: this command never reads the pack seal.
		"seal_checked": false,
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
			writeText(stdout, "Replay DIVERGED: %d of %d tape entries replayed, %d issues:\n", replayed, len(entries), len(issues))
			for _, issue := range issues {
				writeText(stdout, "  - %s\n", issue)
			}
		case replayStatusNotRun:
			writeText(stdout, "Nothing replayed: the tape holds no entries (tape_manifest.json lists %d).\n", len(manifest.Entries))
		default:
			writeText(stdout, "Replayed %d of %d tape entries through the tape replayer.\n", replayed, len(entries))
			writeText(stdout, "COMPLETE means: the entry files are in sequence order; every entry was served in sequence from 1 with no tape miss; "+
				"each served value matches the value_hash recorded on its entry; tape_manifest.json lists every entry exactly once; "+
				"and every field tape_manifest.json carries for an entry equals that entry.\n")
			writeText(stdout, "%s\n", replaySealNotice)
			writeText(stdout, "This replays recorded inputs only; it does not re-execute the run or compare decisions.\n")
		}
		writeText(stdout, "Run ID:  %s\n", manifest.RunID)
		writeText(stdout, "Status:  %s\n", status)
	}

	if status != replayStatusComplete {
		return 1
	}
	return 0
}

// replayTape serves the tape back through tape.Replayer the way a replayed run
// consumes it, front to back, and returns how many entries were served with
// their recorded value intact, plus everything that did not hold. files names
// the entry file each entry was read from, in the order they were read.
func replayTape(entries []tape.Entry, files []string, manifest *tape.Manifest) (int, []string) {
	var issues []string

	// The replayer keys entries by seq, so the order of the files does not
	// change what it serves. A tape whose files are out of sequence order was
	// still not written by a recorder, which numbers entries as it appends.
	for i := 1; i < len(entries); i++ {
		if entries[i].Seq <= entries[i-1].Seq {
			issues = append(issues, fmt.Sprintf("entry files are not in sequence order: %s holds seq=%d after seq=%d in %s",
				files[i], entries[i].Seq, entries[i-1].Seq, files[i-1]))
		}
	}

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
	// of those entries, and every field a manifest row carries must equal the
	// entry it names.
	issues = append(issues, tape.VerifyManifestIntegrity(entries, manifest)...)
	return replayed, issues
}

// loadTapeEntries loads tape entries from the entry_*.json files in the tapes
// directory, in file-name order, and returns the base name of the file each
// entry came from.
func loadTapeEntries(tapesDir string) ([]tape.Entry, []string, error) {
	paths, err := filepath.Glob(filepath.Join(tapesDir, "entry_*.json"))
	if err != nil {
		return nil, nil, err
	}
	// Glob returns names sorted; sort again so the sequence-order check does
	// not depend on that.
	sort.Strings(paths)

	var entries []tape.Entry
	var files []string
	for _, f := range paths {
		name := filepath.Base(f)
		if err := requireNoSymlink(f, false); err != nil {
			return nil, nil, err
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", name, err)
		}
		var entry tape.Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", name, err)
		}
		entries = append(entries, entry)
		files = append(files, name)
	}

	return entries, files, nil
}

// requireNoSymlink refuses a path that is a symbolic link, or that is not the
// kind of file the tape layout puts there: a directory when wantDir is set, a
// regular file otherwise. It looks at the path itself and does not follow it.
func requireNoSymlink(path string, wantDir bool) error {
	name := filepath.Base(path)
	info, err := os.Lstat(path)
	if err != nil {
		if wantDir {
			return fmt.Errorf("tapes directory not found: %s", path)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("refusing to read %s: it is a symbolic link, and a tape is replayed only from files the pack holds", name)
	case wantDir && !info.IsDir():
		return fmt.Errorf("refusing to read %s: it is not a directory", name)
	case !wantDir && !info.Mode().IsRegular():
		return fmt.Errorf("refusing to read %s: it is not a regular file", name)
	}
	return nil
}

func init() {
	Register(Subcommand{Name: "replay", Aliases: []string{}, Usage: "Serve an EvidencePack's recorded tape back through the tape replayer and report misses and hash mismatches (--evidence); replays recorded inputs, does not re-execute the run", RunFn: runReplayCmd})
}
