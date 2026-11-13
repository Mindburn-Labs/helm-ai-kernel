package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

// Replay statuses.
const (
	// replayStatusComplete: the entry files are in sequence order, every tape
	// entry was served back in sequence and matched the value_hash recorded on
	// it, and tape_manifest.json agrees with the tape. It says nothing about
	// who wrote the tape: see replaySealNotice.
	replayStatusComplete = "COMPLETE"
	// replayStatusDiverged: the replayer missed an entry, a served value does
	// not match what was recorded, the entry files are out of order, an entry
	// has a type the recorder never writes, or the manifest and the tape
	// disagree.
	replayStatusDiverged = "DIVERGED"
	// replayStatusNotRun: the tape holds no entries, or could not be read, so
	// nothing was replayed.
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
// what the replayer returned. The tape is read through one os.Root on the
// pack (package packfs) and judged by tape.Tape.Replay, the same code the
// verifier's replay_determinism check runs. COMPLETE means all of this held:
//
//   - 08_TAPES, tape_manifest.json and every entry_*.json are real files and
//     directories, not symbolic links;
//   - the entry files, in the order of the number in their name, carry
//     strictly increasing sequence numbers;
//   - every entry was served in sequence from 1 with no tape miss, each
//     served value matches the value_hash recorded on its entry, and each
//     entry has a type the recorder writes;
//   - tape_manifest.json lists every entry exactly once, every row carries
//     seq, type, key, sha256 and size_bytes, and every field it carries for an
//     entry equals that entry.
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
//	    nothing was replayed. Under --json the result is still printed, with
//	    replay_status NOT_RUN and the error.
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

	// fail reports a tape that could not be read. Nothing was replayed.
	fail := func(err error) int {
		writeText(stderr, "Error: %s\n", err)
		if jsonOutput {
			data, _ := json.MarshalIndent(map[string]any{
				"evidence_dir":     evidenceDir,
				"entries_replayed": 0,
				"replay_status":    replayStatusNotRun,
				"seal_checked":     false,
				"error":            err.Error(),
			}, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		}
		return 2
	}

	pack, err := packfs.Open(evidenceDir)
	if err != nil {
		return fail(fmt.Errorf("cannot open the evidence pack: %w", err))
	}
	defer func() { _ = pack.Close() }()

	// Everything under the tape directory is named by the pack. A symbolic
	// link there points at bytes the pack does not hold, so LoadTape refuses
	// it instead of following it.
	recorded, err := tape.LoadTape(pack, "08_TAPES")
	if err != nil {
		return fail(err)
	}
	manifest, entries := recorded.Manifest, recorded.Entries

	replayed, issues := recorded.Replay()
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
				"each served value matches the value_hash recorded on its entry; every entry has a type the recorder writes; "+
				"tape_manifest.json lists every entry exactly once with seq, type, key, sha256 and size_bytes; "+
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

func init() {
	Register(Subcommand{Name: "replay", Aliases: []string{}, Usage: "Serve an EvidencePack's recorded tape back through the tape replayer and report misses and hash mismatches (--evidence); replays recorded inputs, does not re-execute the run", RunFn: runReplayCmd})
}
