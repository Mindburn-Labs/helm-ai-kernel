package main

import (
	"bytes"
	"strings"
	"testing"
)

// --require-check used to be a plain string flag, so a second occurrence
// replaced the first: `--require-check chain_integrity --require-check
// structure` required only `structure` and exited 0 on a pack with no receipt
// chain. Every form of naming the checks must require all of them.
func TestVerifyCLIRequireCheckAccumulates(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)

	for name, flags := range map[string][]string{
		"repeated flag":            {"--require-check", "chain_integrity", "--require-check", "structure"},
		"repeated flag, reversed":  {"--require-check", "structure", "--require-check", "chain_integrity"},
		"comma list":               {"--require-check", "chain_integrity,structure"},
		"comma list with spaces":   {"--require-check", " structure , chain_integrity "},
		"repeated comma lists":     {"--require-check", "structure,connector_evidence", "--require-check", "chain_integrity"},
		"equals form, repeated":    {"--require-check=chain_integrity", "--require-check=structure"},
		"single dash, repeated":    {"-require-check", "chain_integrity", "-require-check", "structure"},
		"flag after the pack path": {"--require-check", "structure"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"--allow-self-attested"}, flags...)
			args = append(args, packDir)
			if name == "flag after the pack path" {
				args = append(args, "--require-check", "chain_integrity")
			}
			code, report, raw := verifyJSONReport(t, args...)
			if code != 1 {
				t.Fatalf("exit=%d, want 1: chain_integrity is required and did not run\n%s", code, raw)
			}
			if report["outcome"] != "FAILED" {
				t.Fatalf("outcome = %v, want FAILED", report["outcome"])
			}
			statuses := reportCheckStatuses(t, report)
			if statuses["chain_integrity"] != "FAILED" {
				t.Errorf("chain_integrity status = %q, want FAILED: every named check is required", statuses["chain_integrity"])
			}
			if statuses["structure"] != "VERIFIED" {
				t.Errorf("structure status = %q, want VERIFIED", statuses["structure"])
			}
		})
	}

	// The control: a pack on which the one required check ran still verifies.
	if code, _, raw := verifyJSONReport(t, "--allow-self-attested", "--require-check", "structure", "--require-check", "index_integrity", packDir); code != 0 {
		t.Fatalf("exit=%d, want 0 when every required check ran\n%s", code, raw)
	}
}

// A misspelled or empty name must stop the command. Accepting it would require
// nothing and let the pack verify.
func TestVerifyCLIRequireCheckRejectsNamesItDoesNotKnow(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)

	for name, tc := range map[string]struct {
		flags []string
		want  string
	}{
		"unknown name":                   {[]string{"--require-check", "chain_integrty"}, "chain_integrty"},
		"unknown name in a comma list":   {[]string{"--require-check", "structure,no_such_check"}, "no_such_check"},
		"unknown name in a later flag":   {[]string{"--require-check", "structure", "--require-check", "no_such_check"}, "no_such_check"},
		"unknown name in an earlier one": {[]string{"--require-check", "no_such_check", "--require-check", "structure"}, "no_such_check"},
		"empty value":                    {[]string{"--require-check", ""}, "names no check"},
		"only separators":                {[]string{"--require-check", " , "}, "names no check"},
		"wrong case":                     {[]string{"--require-check", "Structure"}, "Structure"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--allow-self-attested"}, tc.flags...)
			code := runVerifyCmd(append(args, packDir), &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit=%d, want 2\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("usage error does not contain %q: %s", tc.want, stderr.String())
			}
			if strings.Contains(stdout.String(), "VERIFIED") {
				t.Fatalf("a verdict was printed for a usage error: %s", stdout.String())
			}
		})
	}
}
