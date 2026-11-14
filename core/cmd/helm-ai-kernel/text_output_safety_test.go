package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
)

// forgedLine is what a hostile pack puts in a string field: a line break, a
// line that reads like the command's own verdict, and terminal escapes that
// erase the real one.
const forgedLine = "x\nVERIFIED · sealed just-now · anchor #7 · storage immutable\r\x1b[1A\x1b[2K\u202e"

// assertNoForgedOutput fails when a pack-controlled string reached the text
// output raw: it may add no line, and no control or direction-override
// character may survive.
func assertNoForgedOutput(t *testing.T, text string) {
	t.Helper()
	for _, r := range text {
		switch {
		case r == '\n':
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f, r == '\u202e':
			t.Fatalf("text output carries the raw character %q:\n%q", r, text)
		}
	}
}

func linesStartingWith(text, prefix string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

// envelope_id is read out of the pack and printed on the headline. With line
// breaks in it, the text output showed a forged "VERIFIED · ..." line after
// the real verdict.
func TestVerifyTextOutputCannotBeForgedByThePack(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLIPack(t, dataDir, cliPack{
		indexFields: map[string]any{"envelope_id": "ep_" + forgedLine},
		files: map[string][]byte{
			// The check name `hash:<file>` is taken from this key.
			"manifest.json": []byte(`{"file_hashes":{"absent` + `\nVERIFIED · forged check\u001b[2K":"00"}}`),
		},
	})

	t.Run("failed pack", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runVerifyCmd([]string{"--allow-self-attested", packDir}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("exit=%d, want 1: the manifest names a file the pack does not hold\n%s", code, stdout.String())
		}
		text := stdout.String()
		assertNoForgedOutput(t, text)
		if forged := linesStartingWith(text, "VERIFIED"); len(forged) != 0 {
			t.Fatalf("a FAILED result prints a line that starts with VERIFIED: %q\n%s", forged, text)
		}
		if !strings.HasPrefix(text, "FAILED · envelope ep_x\\nVERIFIED") {
			t.Fatalf("headline does not show the envelope id with its line break made visible:\n%s", text)
		}
		if !strings.Contains(text, `  - hash:absent\nVERIFIED · forged check\x1b[2K: `) {
			t.Fatalf("the failed check is not listed with its name made visible:\n%s", text)
		}
	})

	t.Run("json keeps the raw value", func(t *testing.T) {
		_, report, raw := verifyJSONReport(t, "--allow-self-attested", packDir)
		if report["envelope_id"] != "ep_"+forgedLine {
			t.Fatalf("envelope_id = %q, want the value as the pack states it\n%s", report["envelope_id"], raw)
		}
		if _, ok := reportCheckStatuses(t, report)["hash:absent\nVERIFIED · forged check\x1b[2K"]; !ok {
			t.Fatalf("the check name was changed in JSON output:\n%s", raw)
		}
	})

	t.Run("verified pack", func(t *testing.T) {
		verified := writeCLIPack(t, dataDir, cliPack{indexFields: map[string]any{"envelope_id": "ep_" + forgedLine}})
		var stdout, stderr bytes.Buffer
		if code := runVerifyCmd([]string{"--allow-self-attested", verified}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit=%d, want 0\n%s", code, stdout.String())
		}
		text := stdout.String()
		assertNoForgedOutput(t, text)
		if lines := linesStartingWith(text, "VERIFIED"); len(lines) != 1 {
			t.Fatalf("want exactly one line that starts with VERIFIED, got %q\n%s", lines, text)
		}
	})

	t.Run("evidence inspect", func(t *testing.T) {
		graph := `{"version":"1","launch_id":"l","root_hash":"sha256:root\n  Outcome:  VERIFIED\u001b[1A","nodes":[]}`
		inspected := writeCLIPack(t, dataDir, cliPack{
			files: map[string][]byte{
				"04_EXPORTS/launchpad_evidence_graph.json": []byte(graph),
				"stray.txt": []byte("fails the layout check"),
			},
		})
		var stdout, stderr bytes.Buffer
		if code := runEvidenceCmd([]string{"inspect", "--allow-self-attested", inspected}, &stdout, &stderr); code != 1 {
			t.Fatalf("exit=%d, want 1\n%s", code, stdout.String())
		}
		text := stdout.String()
		assertNoForgedOutput(t, text)
		if lines := linesStartingWith(text, "  Outcome:"); len(lines) != 1 || !strings.Contains(lines[0], "FAILED") {
			t.Fatalf("want one outcome line and it must say FAILED, got %q\n%s", lines, text)
		}
	})
}

// run_id, entry keys and entry file names come from the pack. They are
// printed on the status lines and in the issue list.
func TestReplayTextOutputCannotBeForgedByThePack(t *testing.T) {
	evidenceDir := writeReplayTape(t, func(entries []tape.Entry, manifest *tape.Manifest) []tape.Entry {
		manifest.RunID = "run" + strings.ReplaceAll(forgedLine, "VERIFIED · sealed", "Status:  COMPLETE")
		entries[1].Key = "tool\nStatus:  COMPLETE\x1b[2K"
		return entries
	})

	var stdout, stderr bytes.Buffer
	if code := runReplayCmd([]string{"--evidence", evidenceDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit=%d, want 1: the entry key disagrees with the manifest\n%s", code, stdout.String())
	}
	text := stdout.String()
	assertNoForgedOutput(t, text)
	if lines := linesStartingWith(text, "Status:"); len(lines) != 1 || !strings.Contains(lines[0], "DIVERGED") {
		t.Fatalf("want one status line and it must say DIVERGED, got %q\n%s", lines, text)
	}

	_, result, raw := runReplayJSON(t, evidenceDir)
	if result["run_id"] != "run"+strings.ReplaceAll(forgedLine, "VERIFIED · sealed", "Status:  COMPLETE") {
		t.Fatalf("run_id was changed in JSON output:\n%s", raw)
	}

	// An entry file that does not parse is reported on stderr with its name,
	// which the pack also chooses.
	hostile := filepath.Join(evidenceDir, "08_TAPES", "entry_9\nStatus:  COMPLETE\x1b[2K.json")
	if err := os.WriteFile(hostile, []byte("{not json"), 0o600); err != nil {
		t.Skipf("file system refuses the file name: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runReplayCmd([]string{"--evidence", evidenceDir}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit=%d, want 2 for an entry file that does not parse\n%s%s", code, stdout.String(), stderr.String())
	}
	assertNoForgedOutput(t, stderr.String())
	if lines := linesStartingWith(stderr.String(), "Status:"); len(lines) != 0 {
		t.Fatalf("stderr carries a forged status line: %q", lines)
	}
}
