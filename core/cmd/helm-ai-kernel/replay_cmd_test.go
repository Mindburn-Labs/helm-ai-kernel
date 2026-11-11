package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
)

// writeReplayTape records three entries and writes them the way the command
// reads them: 08_TAPES/tape_manifest.json plus one entry_*.json file per entry.
// mutate may change the entries and the manifest before they are written.
func writeReplayTape(t *testing.T, mutate func(entries []tape.Entry, manifest *tape.Manifest) []tape.Entry) string {
	t.Helper()
	recorder := tape.NewRecorder("run-replay-test")
	recorder.RecordTime("kernel")
	recorder.RecordToolOutput("executor", "tool-search", []byte(`["a","b"]`))
	recorder.RecordNetwork("connector", "https://api.example.test/data", []byte(`{"ok":true}`))
	entries := recorder.Entries()
	for i := range entries {
		entries[i].DataClass = "PUBLIC"
		entries[i].ResidencyRegion = "DE"
		entries[i].Encryption = "NONE"
		entries[i].RetentionBasis = "test"
	}
	manifest := recorder.BuildManifest()
	if mutate != nil {
		entries = mutate(entries, manifest)
	}

	evidenceDir := t.TempDir()
	tapesDir := filepath.Join(evidenceDir, "08_TAPES")
	if err := os.MkdirAll(tapesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := tape.WriteManifest(tapesDir, manifest); err != nil {
		t.Fatal(err)
	}
	for i, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		// Named by position, not by seq, so a test can write two files that
		// claim the same sequence number.
		if err := os.WriteFile(filepath.Join(tapesDir, fmt.Sprintf("entry_%04d.json", i)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return evidenceDir
}

func runReplayJSON(t *testing.T, evidenceDir string, extra ...string) (int, map[string]any, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runReplayCmd(append([]string{"--evidence", evidenceDir, "--json"}, extra...), &stdout, &stderr)
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("replay --json printed no result (exit=%d): %v\nstdout=%s\nstderr=%s", code, err, stdout.String(), stderr.String())
	}
	return code, result, stdout.String()
}

// M14: the command printed "Replay complete: N entries verified" after only
// listing files. It now serves every recorded entry back through
// tape.Replayer and reports what the replayer returned.
func TestReplayCmdServesEveryEntryThroughTheReplayer(t *testing.T) {
	evidenceDir := writeReplayTape(t, nil)

	code, result, raw := runReplayJSON(t, evidenceDir)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 for an intact tape\n%s", code, raw)
	}
	if result["replay_status"] != "COMPLETE" {
		t.Fatalf("replay_status = %v, want COMPLETE", result["replay_status"])
	}
	if result["entries_replayed"] != float64(3) || result["entry_count"] != float64(3) || result["manifest_refs"] != float64(3) {
		t.Fatalf("counts = replayed %v of %v entries, %v manifest refs; want 3/3/3", result["entries_replayed"], result["entry_count"], result["manifest_refs"])
	}
	if _, hasIssues := result["issues"]; hasIssues {
		t.Fatalf("intact tape reported issues: %v", result["issues"])
	}

	var stdout, stderr bytes.Buffer
	if code := runReplayCmd([]string{"--evidence", evidenceDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("text exit=%d: %s", code, stdout.String())
	}
	text := stdout.String()
	if !strings.Contains(text, "Replayed 3 of 3 tape entries through the tape replayer") {
		t.Fatalf("text output does not say what was replayed:\n%s", text)
	}
	if !strings.Contains(text, "does not re-execute the run") {
		t.Fatalf("text output does not state the limit of a tape replay:\n%s", text)
	}
	if strings.Contains(text, "entries verified") {
		t.Fatalf("text output still claims entries were verified:\n%s", text)
	}
}

// A tape with a hole, a tampered value or a manifest that disagrees with the
// entries used to exit 0 unless --verify was passed. The replayer finds each
// of them on the default path.
func TestReplayCmdReportsWhatTheReplayerFound(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutate    func(entries []tape.Entry, manifest *tape.Manifest) []tape.Entry
		wantIssue string
	}{
		{
			name: "missing entry",
			mutate: func(entries []tape.Entry, _ *tape.Manifest) []tape.Entry {
				return append(entries[:1:1], entries[2:]...)
			},
			wantIssue: "REPLAY_TAPE_MISS: seq=2",
		},
		{
			name: "tampered value",
			mutate: func(entries []tape.Entry, _ *tape.Manifest) []tape.Entry {
				entries[1].Value = []byte(`["tampered"]`)
				return entries
			},
			wantIssue: "seq=2",
		},
		{
			name: "manifest names an entry the tape does not hold",
			mutate: func(entries []tape.Entry, manifest *tape.Manifest) []tape.Entry {
				manifest.Entries = append(manifest.Entries, tape.ManifestItem{Seq: 4, Type: tape.EntryTypeTime, Key: "time", SHA256: "00"})
				return entries
			},
			wantIssue: "seq=4 referenced in manifest but not in entries",
		},
		{
			name: "two entries claim one sequence number",
			mutate: func(entries []tape.Entry, _ *tape.Manifest) []tape.Entry {
				return append(entries, entries[0])
			},
			wantIssue: "share a sequence number",
		},
		{
			name: "entry the manifest does not list",
			mutate: func(entries []tape.Entry, manifest *tape.Manifest) []tape.Entry {
				manifest.Entries = manifest.Entries[:2]
				return entries
			},
			wantIssue: "seq=3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidenceDir := writeReplayTape(t, tc.mutate)
			code, result, raw := runReplayJSON(t, evidenceDir)
			if code != 1 {
				t.Fatalf("exit=%d, want 1\n%s", code, raw)
			}
			if result["replay_status"] != "DIVERGED" {
				t.Fatalf("replay_status = %v, want DIVERGED", result["replay_status"])
			}
			issues := fmt.Sprint(result["issues"])
			if !strings.Contains(issues, tc.wantIssue) {
				t.Fatalf("issues %s do not contain %q", issues, tc.wantIssue)
			}
		})
	}
}

// R2: an empty suite is never a success. A tape with no entries replays
// nothing, so the command must not report a completed replay or exit 0.
func TestReplayCmdEmptyTapeIsNotASuccess(t *testing.T) {
	evidenceDir := writeReplayTape(t, func(_ []tape.Entry, manifest *tape.Manifest) []tape.Entry {
		manifest.Entries = nil
		return nil
	})
	code, result, raw := runReplayJSON(t, evidenceDir)
	if code != 1 {
		t.Fatalf("exit=%d, want 1 for a tape with nothing to replay\n%s", code, raw)
	}
	if result["replay_status"] != "NOT_RUN" || result["entries_replayed"] != float64(0) {
		t.Fatalf("replay_status=%v entries_replayed=%v, want NOT_RUN/0", result["replay_status"], result["entries_replayed"])
	}

	var stdout, stderr bytes.Buffer
	if code := runReplayCmd([]string{"--evidence", evidenceDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("text exit=%d, want 1: %s", code, stdout.String())
	}
	if text := stdout.String(); strings.Contains(text, "verified") || strings.Contains(text, "Replay complete") {
		t.Fatalf("empty tape reported as a completed replay:\n%s", text)
	}
}

// --verify keeps its residency check: an entry without data_class replays, and
// fails only when the caller asks for the metadata to be required.
func TestReplayCmdVerifyRequiresResidencyMetadata(t *testing.T) {
	evidenceDir := writeReplayTape(t, func(entries []tape.Entry, _ *tape.Manifest) []tape.Entry {
		entries[2].DataClass = ""
		return entries
	})
	if code, _, raw := runReplayJSON(t, evidenceDir); code != 0 {
		t.Fatalf("exit=%d, want 0 without --verify\n%s", code, raw)
	}
	code, result, raw := runReplayJSON(t, evidenceDir, "--verify")
	if code != 1 || result["replay_status"] != "DIVERGED" {
		t.Fatalf("exit=%d status=%v, want 1/DIVERGED with --verify\n%s", code, result["replay_status"], raw)
	}
	if issues := fmt.Sprint(result["issues"]); !strings.Contains(issues, "missing data_class") {
		t.Fatalf("issues %s do not name the missing data_class", issues)
	}
}
