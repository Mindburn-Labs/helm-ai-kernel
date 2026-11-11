package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func verifyJSONReport(t *testing.T, args ...string) (int, map[string]any, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runVerifyCmd(append(args, "--json"), &stdout, &stderr)
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("verify --json did not print a report (exit=%d): %v\nstdout=%s\nstderr=%s", code, err, stdout.String(), stderr.String())
	}
	return code, report, stdout.String()
}

func reportCheckStatuses(t *testing.T, report map[string]any) map[string]string {
	t.Helper()
	checks, ok := report["checks"].([]any)
	if !ok {
		t.Fatalf("report has no checks: %v", report)
	}
	out := make(map[string]string, len(checks))
	for _, item := range checks {
		check := item.(map[string]any)
		out[fmt.Sprint(check["name"])] = fmt.Sprint(check["status"])
	}
	return out
}

// H12: `verify` printed "PASS: 12/12 checks passed" for a pack on which seven
// of those checks had nothing to read. The report must count them as not run,
// and both output forms must say the result covers only the checks that ran.
func TestVerifyCLIReportsNotRunChecksApartFromPasses(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)

	code, report, raw := verifyJSONReport(t, "--allow-self-attested", "--profile", "dev-local", packDir)
	if code != 0 {
		t.Fatalf("exit=%d, want 0: nothing the pack must carry is missing\n%s", code, raw)
	}
	statuses := reportCheckStatuses(t, report)
	passed, notRun := 0, 0
	for name, status := range statuses {
		switch status {
		case "VERIFIED":
			passed++
		case "NOT_RUN":
			notRun++
		default:
			t.Errorf("check %s status = %s", name, status)
		}
	}
	for _, name := range []string{"file_hashes", "eu_ai_act_profile", "connector_evidence", "chain_integrity", "lamport_monotonicity", "replay_determinism", "host_evidence", "embedded_signature_trust"} {
		if statuses[name] != "NOT_RUN" {
			t.Errorf("check %s status = %q, want NOT_RUN", name, statuses[name])
		}
	}
	if report["outcome"] != "VERIFIED" || report["verified"] != true {
		t.Fatalf("outcome=%v verified=%v, want VERIFIED/true", report["outcome"], report["verified"])
	}
	counts, _ := report["check_counts"].(map[string]any)
	if counts["passed"] != float64(passed) || counts["not_run"] != float64(notRun) || counts["failed"] != float64(0) {
		t.Fatalf("check_counts = %v, want passed=%d failed=0 not_run=%d", counts, passed, notRun)
	}
	summary := fmt.Sprint(report["summary"])
	if strings.Contains(summary, fmt.Sprintf("%d/%d", len(statuses), len(statuses))) {
		t.Fatalf("summary counts every check as passed: %q", summary)
	}

	var stdout, stderr bytes.Buffer
	if code := runVerifyCmd([]string{"--allow-self-attested", "--profile", "dev-local", packDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("text exit=%d: %s", code, stdout.String())
	}
	text := stdout.String()
	wantCounts := fmt.Sprintf("checks: %d passed, 0 failed, %d not run", passed, notRun)
	for _, want := range []string{"VERIFIED · ", wantCounts, "covers only the checks that ran", "not run: chain_integrity"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output does not contain %q:\n%s", want, text)
		}
	}
}

// A caller that needs a check to have run names it. A named check with no
// input is then a failure and the command exits 1, instead of exiting 0 on a
// result that silently left the check out.
func TestVerifyCLIRequireCheckFailsWhenTheCheckDidNotRun(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)

	code, report, raw := verifyJSONReport(t, "--allow-self-attested", "--require-check", "chain_integrity,connector_evidence", packDir)
	if code != 1 {
		t.Fatalf("exit=%d, want 1 when a required check did not run\n%s", code, raw)
	}
	if report["outcome"] != "FAILED" || report["verified"] != false {
		t.Fatalf("outcome=%v verified=%v, want FAILED/false", report["outcome"], report["verified"])
	}
	statuses := reportCheckStatuses(t, report)
	for _, name := range []string{"chain_integrity", "connector_evidence"} {
		if statuses[name] != "FAILED" {
			t.Errorf("required check %s status = %q, want FAILED", name, statuses[name])
		}
	}
	// A check the caller did not name keeps its own state.
	if statuses["eu_ai_act_profile"] != "NOT_RUN" {
		t.Errorf("eu_ai_act_profile status = %q, want NOT_RUN", statuses["eu_ai_act_profile"])
	}

	var stdout, stderr bytes.Buffer
	if code := runVerifyCmd([]string{"--allow-self-attested", "--require-check", "no_such_check", packDir}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown check name exit=%d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no_such_check") {
		t.Fatalf("usage error does not name the unknown check: %s", stderr.String())
	}
}

// The published schema for `verify --json` forbids unknown fields, so it must
// describe every field the command prints.
func TestVerifyCLIJSONMatchesPublishedSchema(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "..", "protocols", "json-schemas", "cli", "helm_cli_schema.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("helm_cli_schema.json", bytes.NewReader(schemaData)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("helm_cli_schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)
	for name, args := range map[string][]string{
		"verified":     {"--allow-self-attested", packDir},
		"failed":       {"--allow-self-attested", "--require-check", "chain_integrity", packDir},
		"unverifiable": {packDir},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "unverifiable" {
				clearVerifierTrustEnv(t)
			}
			_, report, raw := verifyJSONReport(t, args...)
			if err := schema.Validate(report); err != nil {
				t.Fatalf("verify --json does not match %s: %v\n%s", schemaPath, err, raw)
			}
			if name == "unverifiable" && report["outcome"] != "UNVERIFIABLE" {
				t.Fatalf("outcome = %v, want UNVERIFIABLE", report["outcome"])
			}
		})
	}
}

// A pack with many host receipts reports several not-run checks per receipt.
// The text output lists a bounded number and says how many it left out; the
// counts line always carries the full number.
func TestPrintVerifyCheckCountsBoundsTheNotRunListing(t *testing.T) {
	report := &verifier.VerifyReport{}
	for _, name := range []string{"structure", "evidence_pack_seal", "policy_decision_hashes"} {
		report.Checks = append(report.Checks, verifier.CheckResult{Name: name, Pass: true})
	}
	for i := range maxNotRunLines + 5 {
		report.Checks = append(report.Checks, verifier.CheckResult{
			Name:   fmt.Sprintf("host:%02d:external_host:hardware_root", i),
			Status: verifier.CheckNotRun,
			Reason: "makes no hardware root claim",
		})
	}
	report.Finalize()

	var out bytes.Buffer
	printVerifyCheckCounts(&out, report)
	text := out.String()
	if !strings.HasPrefix(text, fmt.Sprintf("checks: 3 passed, 0 failed, %d not run; this result covers only the checks that ran\n", maxNotRunLines+5)) {
		t.Fatalf("counts line is wrong:\n%s", text)
	}
	if got := strings.Count(text, "  not run: "); got != maxNotRunLines {
		t.Fatalf("listed %d not-run checks, want %d", got, maxNotRunLines)
	}
	if !strings.Contains(text, "... and 5 more not run (use --json for all of them)") {
		t.Fatalf("output does not say how many not-run checks it left out:\n%s", text)
	}
}
