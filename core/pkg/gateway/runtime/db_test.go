package runtime

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDBScramVerifierFromFileAndStdin(t *testing.T) {
	dir := t.TempDir()
	passwordFile := filepath.Join(dir, "runtime-password")
	password := "probe-" + strings.Repeat("ab", 8)
	if err := os.WriteFile(passwordFile, []byte(password+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "runtime.verifier")
	if err := runDB([]string{"scram-verifier", "--password-file=" + passwordFile, "--out=" + out}, nil, nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(written), "SCRAM-SHA-256$4096:") || strings.Contains(string(written), password) || info.Mode().Perm() != 0o600 {
		t.Fatalf("verifier file %q (mode %v)", written, info.Mode().Perm())
	}

	var stdout bytes.Buffer
	if err := runDB([]string{"scram-verifier"}, strings.NewReader(password), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "SCRAM-SHA-256$4096:") {
		t.Fatalf("stdout %q", stdout.String())
	}
}

func TestDBScramVerifierRefusesBadInput(t *testing.T) {
	for name, args := range map[string][]string{
		"no subcommand":    {},
		"other subcommand": {"migrate"},
		"extra argument":   {"scram-verifier", "extra"},
		"missing file":     {"scram-verifier", "--password-file=" + filepath.Join(t.TempDir(), "absent")},
	} {
		if err := runDB(args, strings.NewReader("pw"), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("%s: runDB accepted %v", name, args)
		}
	}
	for _, password := range []string{"", "\n", "café", "two\nlines"} {
		if err := runDB([]string{"scram-verifier"}, strings.NewReader(password), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("runDB accepted the password %q", password)
		}
	}
}
