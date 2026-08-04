package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyScanCommandVerifiesArchiveAndFailsClosedOnTampering(t *testing.T) {
	root := scanFixtureRoot(t)
	out := t.TempDir()
	pack := filepath.Join(out, "scan.tar")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{
		"helm-ai-kernel", "scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--evidence-pack", pack,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("scan code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "verify-scan", "--bundle", pack, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"verified": true`) {
		t.Fatalf("verify output=%s", stdout.String())
	}

	dir := t.TempDir()
	if err := extractEvidenceArchive(pack, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "risk-envelope.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "verify-scan", dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("tampered verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "FAILED") {
		t.Fatalf("tampered verify output=%s", stdout.String())
	}
}
