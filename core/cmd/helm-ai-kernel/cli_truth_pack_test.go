package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyDecisionLeadsWithTamperVerdict pins the S3 fix: a receipt whose
// contents were altered after signing must be announced as TAMPERED at the top,
// and its forged verdict must never be presented as a bare fact the reader can
// quote as the finding.
func TestVerifyDecisionLeadsWithTamperVerdict(t *testing.T) {
	dir := t.TempDir()

	// Produce a genuine signed DENY decision receipt.
	var out, errBuf bytes.Buffer
	code := runWorkstationDecisionCmd([]string{
		"--class", "shell",
		"--action", "rm-rf",
		"--target", "/",
		"--receipt-dir", dir,
		"--data-dir", dir,
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("decision command failed: code=%d stderr=%q", code, errBuf.String())
	}

	receiptPath := onlyJSONFile(t, dir)

	// Tamper: flip the signed verdict to ALLOW without re-signing.
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	// Flip to the opposite verdict so the signed bytes genuinely change,
	// whatever the default policy decided.
	if obj["verdict"] == "ALLOW" {
		obj["verdict"] = "DENY"
	} else {
		obj["verdict"] = "ALLOW"
	}
	forged := obj["verdict"].(string)
	tampered, _ := json.Marshal(obj)
	if err := os.WriteFile(receiptPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	var vout, verr bytes.Buffer
	vcode := runWorkstationVerifyDecisionCmd([]string{"--receipt", receiptPath, "--data-dir", dir}, &vout, &verr)
	if vcode != 1 {
		t.Fatalf("tampered receipt verify code=%d, want 1", vcode)
	}
	got := vout.String()
	firstLine := strings.SplitN(strings.TrimLeft(got, " \t"), "\n", 2)[0]
	if !strings.Contains(firstLine, "TAMPERED") {
		t.Fatalf("verify output must lead with TAMPERED; first line was %q", firstLine)
	}
	// The forged verdict, if it appears at all, must carry the unverified
	// qualifier — never a bare `verdict:   ALLOW` line.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "verdict:") && strings.Contains(line, forged) && !strings.Contains(line, "unverified") {
			t.Fatalf("forged verdict presented as a bare fact: %q", line)
		}
	}
}

func onlyJSONFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			if found != "" {
				t.Fatalf("expected exactly one receipt json in %s", dir)
			}
			found = filepath.Join(dir, e.Name())
		}
	}
	if found == "" {
		t.Fatalf("no receipt json written to %s", dir)
	}
	return found
}

// TestVersionFlagIsScriptable pins #21: the --version flag prints one plain
// line, --json is a valid object, and unknown args are rejected rather than
// silently succeeding.
func TestVersionFlagIsScriptable(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := runVersionFlag(nil, &out, &errBuf); code != 0 {
		t.Fatalf("--version code=%d", code)
	}
	line := strings.TrimSpace(out.String())
	if strings.Count(line, "\n") != 0 || !strings.HasPrefix(line, "v") {
		t.Fatalf("--version must be one line starting with v; got %q", out.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := runVersionFlag([]string{"--json"}, &out, &errBuf); code != 0 {
		t.Fatalf("--version --json code=%d", code)
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("--version --json is not valid JSON: %v (%q)", err, out.String())
	}

	for _, args := range [][]string{{"--bogus"}, {"extra", "args"}} {
		out.Reset()
		errBuf.Reset()
		if code := runVersionFlag(args, &out, &errBuf); code != 2 {
			t.Fatalf("--version %v code=%d, want 2", args, code)
		}
	}
}

// TestVersionSubcommandRejectsUnknownArgs pins #21's other half: `version
// --bogus` used to exit 0.
func TestVersionSubcommandRejectsUnknownArgs(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := runVersionCommand([]string{"--bogus"}, &out, &errBuf); code != 2 {
		t.Fatalf("version --bogus code=%d, want 2", code)
	}
	out.Reset()
	errBuf.Reset()
	if code := runVersionCommand(nil, &out, &errBuf); code != 0 {
		t.Fatalf("version (no args) code=%d, want 0", code)
	}
	if !strings.Contains(out.String(), "Report Schema") {
		t.Fatalf("version subcommand should print the full block; got %q", out.String())
	}
}
