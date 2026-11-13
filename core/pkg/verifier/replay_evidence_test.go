package verifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
)

const equalDeterminismManifest = `{"live_hash":"sha256:same","replay_hash":"sha256:same"}`

// writeTape records three entries and writes them as a pack holds a tape:
// 08_TAPES/tape_manifest.json and one entry_<n>.json per entry. editManifest
// may change the manifest rows before they are written.
func writeTape(t *testing.T, dir string, editManifest func(rows []map[string]any)) {
	t.Helper()
	recorder := tape.NewRecorder("run-1")
	recorder.RecordTime("kernel")
	recorder.RecordToolOutput("executor", "tool-search", []byte(`["a","b"]`))
	recorder.RecordNetwork("connector", "https://api.example.test/data", []byte(`{"ok":true}`))
	for i, entry := range recorder.Entries() {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		writeRaw(t, dir, fmt.Sprintf("08_TAPES/entry_%04d.json", i+1), data)
	}
	data, err := json.Marshal(recorder.BuildManifest())
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RunID   string           `json:"run_id"`
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if editManifest != nil {
		editManifest(manifest.Entries)
	}
	if data, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, dir, "08_TAPES/tape_manifest.json", data)
}

func replayResult(t *testing.T, dir string) CheckResult {
	t.Helper()
	return checkReplayDeterminism(dir).normalized()
}

// F4: under gate G2 the verifier parsed tape_manifest.json and counted its
// rows, so a sealed pack whose manifest says NETWORK where the entry says
// TOOL_OUTPUT was VERIFIED by `verify` and DIVERGED by `replay`. The tape is
// now replayed through the same code as `replay` whenever it carries entries.
func TestReplayDeterminism_ATapeThatDoesNotReplayFails(t *testing.T) {
	diverge := func(rows []map[string]any) { rows[1]["type"] = "NETWORK" }
	for gatesName, gates := range map[string]string{"under G2": `["G0","G2"]`, "without G2": `["G0"]`} {
		t.Run(gatesName, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexWithGates(t, dir, gates)
			writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
			writeTape(t, dir, diverge)
			result := replayResult(t, dir)
			if result.Status != CheckFailed {
				t.Fatalf("status = %s (%s%s), want FAILED for a tape that diverges from its manifest", result.Status, result.Detail, result.Reason)
			}
			if !strings.Contains(result.Reason, `seq=2 manifest field "type" is "NETWORK", tape entry has "TOOL_OUTPUT"`) {
				t.Fatalf("reason does not carry the replay issue: %q", result.Reason)
			}
		})
	}

	// Without a determinism manifest the pack states no replay result, but
	// the tape it carries is still replayed and a divergence still fails.
	dir := t.TempDir()
	writeIndexWithGates(t, dir, `["G0"]`)
	writeTape(t, dir, diverge)
	if result := replayResult(t, dir); result.Status != CheckFailed {
		t.Fatalf("tape without a determinism manifest: status = %s (%s%s), want FAILED", result.Status, result.Detail, result.Reason)
	}

	// The control: the same tape unedited replays, and the detail says so.
	dir = t.TempDir()
	writeIndexWithGates(t, dir, `["G0","G2"]`)
	writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
	writeTape(t, dir, nil)
	result := replayResult(t, dir)
	if result.Status != CheckVerified {
		t.Fatalf("intact tape: status = %s (%s%s), want VERIFIED", result.Status, result.Detail, result.Reason)
	}
	if !strings.Contains(result.Detail, "3 of 3 tape entries replayed") {
		t.Fatalf("detail does not say the tape was replayed: %q", result.Detail)
	}
}

// Entries without the manifest that would list them cannot be replayed: the
// replay command refuses such a tape, and the verifier fails it.
func TestReplayDeterminism_EntriesWithoutATapeManifestFail(t *testing.T) {
	dir := t.TempDir()
	writeIndexWithGates(t, dir, `["G0"]`)
	writeTape(t, dir, nil)
	if err := os.Remove(filepath.Join(dir, "08_TAPES", "tape_manifest.json")); err != nil {
		t.Fatal(err)
	}
	result := replayResult(t, dir)
	if result.Status != CheckFailed || !strings.Contains(result.Reason, "tape_manifest.json") {
		t.Fatalf("status = %s (%s%s), want FAILED naming the missing tape manifest", result.Status, result.Detail, result.Reason)
	}
}

// F8 G7, G8 and 05_DIFFS: each piece of replay evidence gate G2 requires is
// required on its own. Without these tests the mutants that drop one of the
// three requirements survived.
func TestReplayDeterminism_G2RequiresEachPieceOfReplayEvidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, dir string)
		want  string
	}{
		{
			name: "no tape manifest beside an existing 08_TAPES",
			build: func(t *testing.T, dir string) {
				writeRaw(t, dir, "08_TAPES/notes.json", []byte(`{}`))
				writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
			},
			want: "missing 08_TAPES/tape_manifest.json",
		},
		{
			name: "no determinism manifest",
			build: func(t *testing.T, dir string) {
				writeTape(t, dir, nil)
			},
			want: "missing 02_PROOFGRAPH/determinism_manifest.json",
		},
		{
			name: "a replay difference in 05_DIFFS",
			build: func(t *testing.T, dir string) {
				writeTape(t, dir, nil)
				writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
				writeRaw(t, dir, "05_DIFFS/replay.diff", []byte("- live\n+ replay\n"))
			},
			want: "05_DIFFS contains replay differences",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexWithGates(t, dir, `["G0","G2"]`)
			tc.build(t, dir)
			result := replayResult(t, dir)
			if result.Status != CheckFailed || !strings.Contains(result.Reason, tc.want) {
				t.Fatalf("status = %s (%s%s), want FAILED with %q", result.Status, result.Detail, result.Reason, tc.want)
			}
		})
	}
}

// N8: the launchpad writer creates 05_DIFFS/.keep, and gate G2 failed the pack
// for it ("05_DIFFS contains replay differences"). An empty file whose name
// starts with a dot is a placeholder, under G2 as without it.
func TestReplayDeterminism_PlaceholdersIn05DiffsAreNotDifferences(t *testing.T) {
	for _, placeholder := range []string{".keep", ".gitkeep"} {
		t.Run(placeholder, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexWithGates(t, dir, `["G0","G2"]`)
			writeTape(t, dir, nil)
			writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
			writeRaw(t, dir, "05_DIFFS/"+placeholder, nil)
			if result := replayResult(t, dir); result.Status != CheckVerified {
				t.Fatalf("status = %s (%s%s), want VERIFIED with only a placeholder in 05_DIFFS", result.Status, result.Detail, result.Reason)
			}
		})
	}

	// A dot file with content is not a placeholder.
	dir := t.TempDir()
	writeIndexWithGates(t, dir, `["G0","G2"]`)
	writeTape(t, dir, nil)
	writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
	writeRaw(t, dir, "05_DIFFS/.keep", []byte("- live\n+ replay\n"))
	if result := replayResult(t, dir); result.Status != CheckFailed {
		t.Fatalf("status = %s (%s%s), want FAILED for a dot file that holds a difference", result.Status, result.Detail, result.Reason)
	}
}

// NF5: verify loaded every tape entry whole with no bound over the tape. The
// entry files are sized before any is read, and a tape whose entry files
// hold more than 256 MiB fails by the name of the file that passes it. The
// files here are sparse, so they cost no disk.
func TestReplayDeterminism_ATapePastTheByteBudgetFailsByName(t *testing.T) {
	dir := t.TempDir()
	writeIndexWithGates(t, dir, `["G0"]`)
	writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
	writeRaw(t, dir, "08_TAPES/tape_manifest.json", []byte(`{"run_id":"r","entries":[]}`))
	for i := 1; i <= 5; i++ {
		file, err := os.Create(filepath.Join(dir, "08_TAPES", fmt.Sprintf("entry_%04d.json", i)))
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(60 << 20); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	result := replayResult(t, dir)
	if result.Status != CheckFailed {
		t.Fatalf("status = %s (%s%s), want FAILED", result.Status, result.Detail, result.Reason)
	}
	for _, want := range []string{"entry_0005.json", "256 MiB"} {
		if !strings.Contains(result.Reason, want) {
			t.Errorf("reason %q does not name %q", result.Reason, want)
		}
	}
}

// NF4 (N23): a tape that cannot be loaded, here an entry file that does not
// parse, fails the check; it is not a check that did not run.
func TestReplayDeterminism_ATapeThatCannotBeLoadedFails(t *testing.T) {
	for gatesName, gates := range map[string]string{"under G2": `["G0","G2"]`, "without G2": `["G0"]`} {
		t.Run(gatesName, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexWithGates(t, dir, gates)
			writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
			writeTape(t, dir, nil)
			writeRaw(t, dir, "08_TAPES/entry_0002.json", []byte(`{`))
			result := replayResult(t, dir)
			if result.Status != CheckFailed || !strings.Contains(result.Reason, "the tape cannot be replayed") || !strings.Contains(result.Reason, "entry_0002.json") {
				t.Fatalf("status = %s (%s%s), want FAILED naming entry_0002.json", result.Status, result.Detail, result.Reason)
			}
		})
	}
}

// NF4 (N19): a manifest that lists no entries beside entry files that hold
// some is a tape whose entries are not listed, not an empty tape.
func TestReplayDeterminism_EntryFilesAnEmptyManifestDoesNotListFail(t *testing.T) {
	for gatesName, gates := range map[string]string{"under G2": `["G0","G2"]`, "without G2": `["G0"]`} {
		t.Run(gatesName, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexWithGates(t, dir, gates)
			writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
			writeTape(t, dir, nil)
			writeRaw(t, dir, "08_TAPES/tape_manifest.json", []byte(`{"run_id":"run-1","entries":[]}`))
			result := replayResult(t, dir)
			if result.Status != CheckFailed || !strings.Contains(result.Reason, "seq=1 is on the tape but not listed in tape_manifest.json") {
				t.Fatalf("status = %s (%s%s), want FAILED: three entry files are not listed", result.Status, result.Detail, result.Reason)
			}
		})
	}
}

// NF4 (N21): under G2 only an empty file whose name starts with a dot is a
// placeholder in 05_DIFFS. An empty file with another name is a difference.
func TestReplayDeterminism_AnEmptyDiffWithoutALeadingDotIsADifference(t *testing.T) {
	dir := t.TempDir()
	writeIndexWithGates(t, dir, `["G0","G2"]`)
	writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
	writeTape(t, dir, nil)
	writeRaw(t, dir, "05_DIFFS/replay.diff", nil)
	result := replayResult(t, dir)
	if result.Status != CheckFailed || !strings.Contains(result.Reason, "05_DIFFS contains replay differences: 05_DIFFS/replay.diff") {
		t.Fatalf("status = %s (%s%s), want FAILED naming 05_DIFFS/replay.diff", result.Status, result.Detail, result.Reason)
	}
}

// NF10: under G2 a tape that holds no entries replays nothing. `replay`
// reports NOT_RUN and exits 1 for it, and `verify` passed the pack; G2
// requires replay evidence, so the check fails.
func TestReplayDeterminism_G2RequiresATapeWithEntries(t *testing.T) {
	dir := t.TempDir()
	writeIndexWithGates(t, dir, `["G0","G2"]`)
	writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
	writeRaw(t, dir, "08_TAPES/tape_manifest.json", []byte(`{"run_id":"r","entries":[]}`))
	result := replayResult(t, dir)
	if result.Status != CheckFailed || !strings.Contains(result.Reason, "lists 0 entries") || !strings.Contains(result.Reason, "nothing is replayed") {
		t.Fatalf("status = %s (%s%s), want FAILED: gate G2 with an empty tape", result.Status, result.Detail, result.Reason)
	}

	// Without G2 the pack claims no replay evidence, and an empty tape is
	// named as not replayed, as before.
	dir = t.TempDir()
	writeIndexWithGates(t, dir, `["G0"]`)
	writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(equalDeterminismManifest))
	writeRaw(t, dir, "08_TAPES/tape_manifest.json", []byte(`{"run_id":"r","entries":[]}`))
	if result := replayResult(t, dir); result.Status != CheckVerified || !strings.Contains(result.Detail, "lists 0 entries (not replayed)") {
		t.Fatalf("without G2: status = %s (%s%s), want VERIFIED naming the empty tape", result.Status, result.Detail, result.Reason)
	}
}
