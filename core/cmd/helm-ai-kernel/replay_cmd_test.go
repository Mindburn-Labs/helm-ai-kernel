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

// editTapeManifest rewrites tape_manifest.json as raw JSON, so a test can put a
// field in it that tape.ManifestItem does not declare.
func editTapeManifest(t *testing.T, evidenceDir string, edit func(items []map[string]any) []map[string]any) {
	t.Helper()
	path := filepath.Join(evidenceDir, "08_TAPES", "tape_manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RunID   string           `json:"run_id"`
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Entries = edit(doc.Entries)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The command reported COMPLETE and "matches ... tape_manifest.json" while the
// manifest and the tape disagreed on type, key, size_bytes or component_id:
// only sha256 was compared. Every field the manifest carries for an entry is
// compared now.
func TestReplayCmdComparesEveryManifestField(t *testing.T) {
	for _, tc := range []struct {
		name      string
		edit      func(items []map[string]any) []map[string]any
		wantIssue string
	}{
		{
			name: "type",
			edit: func(items []map[string]any) []map[string]any {
				items[1]["type"] = "NETWORK"
				return items
			},
			wantIssue: `seq=2 manifest field "type"`,
		},
		{
			name: "key",
			edit: func(items []map[string]any) []map[string]any {
				items[1]["key"] = "tool-other"
				return items
			},
			wantIssue: `seq=2 manifest field "key"`,
		},
		{
			name: "size_bytes",
			edit: func(items []map[string]any) []map[string]any {
				items[2]["size_bytes"] = 1
				return items
			},
			wantIssue: `seq=3 manifest field "size_bytes"`,
		},
		{
			name: "component_id",
			edit: func(items []map[string]any) []map[string]any {
				items[0]["component_id"] = "someone-else"
				return items
			},
			wantIssue: `seq=1 manifest field "component_id"`,
		},
		{
			name: "a field the tape entry does not carry",
			edit: func(items []map[string]any) []map[string]any {
				items[0]["approved_by"] = "nobody"
				return items
			},
			wantIssue: `seq=1 manifest field "approved_by"`,
		},
		{
			name: "one entry listed twice",
			edit: func(items []map[string]any) []map[string]any {
				return append(items, items[2])
			},
			wantIssue: "seq=3 is listed 2 times in tape_manifest.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidenceDir := writeReplayTape(t, nil)
			editTapeManifest(t, evidenceDir, tc.edit)
			code, result, raw := runReplayJSON(t, evidenceDir)
			if code != 1 || result["replay_status"] != "DIVERGED" {
				t.Fatalf("exit=%d status=%v, want 1/DIVERGED\n%s", code, result["replay_status"], raw)
			}
			if issues := fmt.Sprint(result["issues"]); !strings.Contains(issues, tc.wantIssue) {
				t.Fatalf("issues %s do not contain %q", issues, tc.wantIssue)
			}
		})
	}

	// The control: a manifest that carries component_id with the tape's value
	// still replays, so the comparison is not a refusal of the field.
	evidenceDir := writeReplayTape(t, nil)
	editTapeManifest(t, evidenceDir, func(items []map[string]any) []map[string]any {
		items[0]["component_id"] = "kernel"
		return items
	})
	if code, result, raw := runReplayJSON(t, evidenceDir); code != 0 || result["replay_status"] != "COMPLETE" {
		t.Fatalf("exit=%d status=%v, want 0/COMPLETE for a manifest that agrees with the tape\n%s", code, result["replay_status"], raw)
	}
}

// Entry files are read in name order. The old --verify failed a tape whose
// files are out of sequence order; the replayer keys entries by seq and so
// served such a tape as COMPLETE.
func TestReplayCmdEntryFilesMustBeInSequenceOrder(t *testing.T) {
	evidenceDir := writeReplayTape(t, func(entries []tape.Entry, _ *tape.Manifest) []tape.Entry {
		entries[0], entries[1] = entries[1], entries[0]
		return entries
	})
	code, result, raw := runReplayJSON(t, evidenceDir)
	if code != 1 || result["replay_status"] != "DIVERGED" {
		t.Fatalf("exit=%d status=%v, want 1/DIVERGED for re-ordered entry files\n%s", code, result["replay_status"], raw)
	}
	if issues := fmt.Sprint(result["issues"]); !strings.Contains(issues, "entry files are not in sequence order") || !strings.Contains(issues, "entry_0001.json") {
		t.Fatalf("issues %s do not name the out-of-order entry file", issues)
	}
}

// A tape directory, manifest or entry file that is a symbolic link points at
// bytes the pack does not hold. The command refuses to read it.
func TestReplayCmdRefusesSymlinks(t *testing.T) {
	for _, tc := range []struct {
		name string
		link func(t *testing.T, evidenceDir string)
		want string
	}{
		{
			name: "tape directory",
			link: func(t *testing.T, evidenceDir string) {
				tapes := filepath.Join(evidenceDir, "08_TAPES")
				moved := filepath.Join(t.TempDir(), "tapes")
				if err := os.Rename(tapes, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, tapes); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "08_TAPES",
		},
		{
			name: "entry file",
			link: func(t *testing.T, evidenceDir string) {
				entry := filepath.Join(evidenceDir, "08_TAPES", "entry_0001.json")
				moved := filepath.Join(t.TempDir(), "entry.json")
				if err := os.Rename(entry, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, entry); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "entry_0001.json",
		},
		{
			name: "manifest",
			link: func(t *testing.T, evidenceDir string) {
				manifest := filepath.Join(evidenceDir, "08_TAPES", "tape_manifest.json")
				moved := filepath.Join(t.TempDir(), "manifest.json")
				if err := os.Rename(manifest, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, manifest); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "tape_manifest.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidenceDir := writeReplayTape(t, nil)
			tc.link(t, evidenceDir)
			for _, mode := range [][]string{{"--evidence", evidenceDir}, {"--evidence", evidenceDir, "--json"}} {
				var stdout, stderr bytes.Buffer
				code := runReplayCmd(mode, &stdout, &stderr)
				if code != 2 {
					t.Fatalf("%v exit=%d, want 2\nstdout=%s\nstderr=%s", mode, code, stdout.String(), stderr.String())
				}
				if !strings.Contains(stderr.String(), "symbolic link") || !strings.Contains(stderr.String(), tc.want) {
					t.Fatalf("%v error does not name the symbolic link %s: %s", mode, tc.want, stderr.String())
				}
				if strings.Contains(stdout.String(), "COMPLETE") {
					t.Fatalf("%v reported a completed replay through a symbolic link: %s", mode, stdout.String())
				}
			}
		})
	}
}

// replay does not check the pack seal, so a tape and manifest rewritten
// together replay as COMPLETE. The output must say so, and must list what
// COMPLETE establishes instead of "matches tape_manifest.json".
func TestReplayCmdSaysWhatCompleteProves(t *testing.T) {
	evidenceDir := writeReplayTape(t, func(entries []tape.Entry, manifest *tape.Manifest) []tape.Entry {
		// A consistent rewrite: the value, its recorded hash and the manifest
		// row all change together.
		rewritten := tape.NewRecorder("rewrite").RecordToolOutput("executor", "tool-search", []byte(`["rewritten"]`))
		entries[1].Value = rewritten.Value
		entries[1].ValueHash = rewritten.ValueHash
		manifest.Entries[1].SHA256 = rewritten.ValueHash
		manifest.Entries[1].SizeBytes = int64(len(rewritten.Value))
		return entries
	})

	code, result, raw := runReplayJSON(t, evidenceDir)
	if code != 0 || result["replay_status"] != "COMPLETE" {
		t.Fatalf("exit=%d status=%v, want 0/COMPLETE: nothing in the tape contradicts itself\n%s", code, result["replay_status"], raw)
	}
	if sealChecked, ok := result["seal_checked"].(bool); !ok || sealChecked {
		t.Fatalf("seal_checked = %v, want false in the JSON result\n%s", result["seal_checked"], raw)
	}

	var stdout, stderr bytes.Buffer
	if code := runReplayCmd([]string{"--evidence", evidenceDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("text exit=%d: %s", code, stdout.String())
	}
	text := stdout.String()
	for _, want := range []string{
		"The pack seal is not checked",
		"rewritten together",
		"helm-ai-kernel verify",
		"every field tape_manifest.json carries",
		"value_hash",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text output does not contain %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "matches its recorded hash and tape_manifest.json") {
		t.Errorf("text output still makes the unqualified manifest claim:\n%s", text)
	}
}

// The tampered-value case above changes the value only, and the manifest
// comparison reports it too. Here the manifest is rewritten to agree with the
// tampered value, so the served value against its own value_hash is the only
// comparison left to catch it.
func TestReplayCmdComparesServedValueWithItsRecordedHash(t *testing.T) {
	evidenceDir := writeReplayTape(t, func(entries []tape.Entry, manifest *tape.Manifest) []tape.Entry {
		tampered := []byte(`["tampered"]`)
		entries[1].Value = tampered
		sum := tape.NewRecorder("x").RecordToolOutput("executor", "tool-search", tampered).ValueHash
		manifest.Entries[1].SHA256 = sum
		manifest.Entries[1].SizeBytes = int64(len(tampered))
		return entries
	})
	code, result, raw := runReplayJSON(t, evidenceDir)
	if code != 1 || result["replay_status"] != "DIVERGED" {
		t.Fatalf("exit=%d status=%v, want 1/DIVERGED\n%s", code, result["replay_status"], raw)
	}
	issues, _ := result["issues"].([]any)
	if len(issues) != 1 || !strings.Contains(fmt.Sprint(issues[0]), "seq=2 served value does not match its recorded value_hash") {
		t.Fatalf("issues = %v, want only the value_hash mismatch on seq=2", issues)
	}
	if result["entries_replayed"] != float64(2) {
		t.Fatalf("entries_replayed = %v, want 2: the tampered entry is not counted as replayed", result["entries_replayed"])
	}
}

// A hole in the sequence stops the walk. The entries behind it are named as
// never served, not left out of the report.
func TestReplayCmdNamesEntriesThatWereNeverServed(t *testing.T) {
	evidenceDir := writeReplayTape(t, func(entries []tape.Entry, _ *tape.Manifest) []tape.Entry {
		return append(entries[:1:1], entries[2:]...)
	})
	code, result, raw := runReplayJSON(t, evidenceDir)
	if code != 1 || result["replay_status"] != "DIVERGED" {
		t.Fatalf("exit=%d status=%v, want 1/DIVERGED\n%s", code, result["replay_status"], raw)
	}
	if issues := fmt.Sprint(result["issues"]); !strings.Contains(issues, "seq=3 is on the tape but was never served") {
		t.Fatalf("issues %s do not name seq=3 as never served", issues)
	}
	if result["entries_replayed"] != float64(1) {
		t.Fatalf("entries_replayed = %v, want 1", result["entries_replayed"])
	}
}
