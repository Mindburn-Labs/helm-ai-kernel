package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// quantum_posture: the host-evidence case signs with a classical Ed25519 test
// key; nothing here asserts post-quantum resistance.

// reportDocument is the report as a JSON consumer sees it, so these tests pin
// the wire shape and not only the Go fields.
func reportDocument(t *testing.T, report *VerifyReport) map[string]any {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	return doc
}

func checkDocuments(t *testing.T, doc map[string]any) map[string]map[string]any {
	t.Helper()
	raw, ok := doc["checks"].([]any)
	if !ok {
		t.Fatalf("report has no checks list: %v", doc)
	}
	out := make(map[string]map[string]any, len(raw))
	for _, item := range raw {
		check, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("check is not an object: %v", item)
		}
		out[fmt.Sprint(check["name"])] = check
	}
	return out
}

// H12: a pack that gives a check nothing to read used to count that check as
// passed. An empty directory and a missing path give no check any input, so no
// check may pass on either.
func TestVerifyBundle_EmptyPackPassesNoCheck(t *testing.T) {
	for name, dir := range map[string]string{
		"empty directory": t.TempDir(),
		"missing path":    filepath.Join(t.TempDir(), "absent"),
	} {
		t.Run(name, func(t *testing.T) {
			report, err := VerifyBundle(dir)
			if err != nil {
				t.Fatal(err)
			}
			if report.Verified {
				t.Fatalf("pack with no content verified: %s", report.Summary)
			}
			for _, check := range report.Checks {
				if check.Pass {
					t.Errorf("check %s passed without input: %q", check.Name, check.Detail)
				} else if strings.TrimSpace(check.Reason) == "" {
					t.Errorf("check %s did not pass and gives no reason", check.Name)
				}
			}
		})
	}
}

// H12: the canonical fixture carries no manifest hashes, no EU AI Act profile,
// no connector evidence, no receipt chain, no replay gate, no host evidence and
// no signed receipts. Those checks have nothing to read: they are NOT_RUN with
// a reason, never passed, and the summary counts them apart from the passes.
func TestVerifyBundle_ChecksWithoutInputAreNotRun(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	doc := reportDocument(t, report)
	checks := checkDocuments(t, doc)

	wantNotRun := []string{
		"file_hashes",
		"eu_ai_act_profile",
		"connector_evidence",
		"chain_integrity",
		"lamport_monotonicity",
		"replay_determinism",
		"host_evidence",
		"embedded_signature_trust",
	}
	for _, name := range wantNotRun {
		check, ok := checks[name]
		if !ok {
			t.Errorf("check %s is missing from the report", name)
			continue
		}
		if check["status"] != "NOT_RUN" {
			t.Errorf("check %s status = %v, want NOT_RUN", name, check["status"])
		}
		if check["pass"] != false {
			t.Errorf("check %s is counted as passed although it read no input", name)
		}
		if reason, _ := check["reason"].(string); strings.TrimSpace(reason) == "" {
			t.Errorf("check %s is not run and gives no reason", name)
		}
	}

	passed := 0
	for name, check := range checks {
		switch check["status"] {
		case "VERIFIED":
			passed++
			if check["pass"] != true {
				t.Errorf("check %s is VERIFIED but pass is %v", name, check["pass"])
			}
		case "NOT_RUN":
		default:
			t.Errorf("check %s status = %v on a valid fixture", name, check["status"])
		}
	}
	if passed == 0 {
		t.Fatal("no check ran on a valid fixture")
	}

	// Nothing the pack is required to carry is missing, so the verdict stays
	// VERIFIED, but it must say how much of the verifier actually ran.
	if doc["verified"] != true || doc["outcome"] != "VERIFIED" {
		t.Fatalf("verified=%v outcome=%v, want true / VERIFIED: %v", doc["verified"], doc["outcome"], doc["summary"])
	}
	counts, ok := doc["check_counts"].(map[string]any)
	if !ok {
		t.Fatalf("report has no check_counts: %v", doc)
	}
	if got := counts["passed"]; got != float64(passed) {
		t.Errorf("check_counts.passed = %v, want %d", got, passed)
	}
	if got := counts["not_run"]; got != float64(len(wantNotRun)) {
		t.Errorf("check_counts.not_run = %v, want %d", got, len(wantNotRun))
	}
	if counts["failed"] != float64(0) || counts["unverifiable"] != float64(0) {
		t.Errorf("check_counts = %v, want no failed or unverifiable checks", counts)
	}
	if doc["issue_count"] != float64(0) {
		t.Errorf("issue_count = %v, want 0: a check that did not run is not an issue", doc["issue_count"])
	}
	summary, _ := doc["summary"].(string)
	want := fmt.Sprintf("VERIFIED: %d passed, 0 failed, %d not run; this result covers only the %d checks that ran", passed, len(wantNotRun), passed)
	if !strings.HasPrefix(summary, want) {
		t.Errorf("summary = %q, want prefix %q", summary, want)
	}
	if strings.Contains(summary, fmt.Sprintf("%d/%d", len(checks), len(checks))) {
		t.Errorf("summary still counts every check as passed: %q", summary)
	}
}

// A manifest.json that does not parse is input the file-hash check could not
// read. It used to be reported as "no file hashes in manifest" and passed.
func TestVerifyBundle_UnparseableManifestFailsFileHashes(t *testing.T) {
	dir := createValidBundleFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	sealVerifierFixture(t, dir, "test-session-001")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatalf("pack with an unparseable manifest.json verified: %s", report.Summary)
	}
	assertCheck(t, report, "file_hashes", false)
}

// The replay check compares two hashes the pack states about itself and parses
// the tape manifest. Its passing detail must say that and must not claim a
// replay happened. The pack does not declare G2: under G2 a tape with no
// entries fails (TestReplayDeterminism_G2RequiresATapeWithEntries).
func TestVerifyBundle_ReplayDeterminismDetailSaysWhatWasCompared(t *testing.T) {
	dir := createValidBundleFixture(t)
	setBundleGates(t, dir, "G0", "G1")
	for _, sub := range []string{"08_TAPES", "02_PROOFGRAPH"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(t, filepath.Join(dir, "08_TAPES", "tape_manifest.json"), map[string]any{
		"run_id":  "test-session-001",
		"entries": []any{},
	})
	writeJSON(t, filepath.Join(dir, "02_PROOFGRAPH", "determinism_manifest.json"), map[string]any{
		"live_hash":   "sha256:same",
		"replay_hash": "sha256:same",
	})
	sealVerifierFixture(t, dir, "test-session-001")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range report.Checks {
		if check.Name != "replay_determinism" {
			continue
		}
		if !check.Pass {
			t.Fatalf("replay_determinism did not pass with the declared evidence: %+v", check)
		}
		if strings.Contains(check.Detail, "verified") {
			t.Errorf("detail claims verification of a replay that never ran: %q", check.Detail)
		}
		for _, want := range []string{"declared by the pack", "not replayed"} {
			if !strings.Contains(check.Detail, want) {
				t.Errorf("detail %q does not say %q", check.Detail, want)
			}
		}
		return
	}
	t.Fatal("missing replay_determinism check")
}

// Field-presence validators must not be reported as verification of what the
// fields point at.
func TestCheckDetailsStatePresenceNotVerification(t *testing.T) {
	t.Run("connector evidence", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, filepath.Join(dir, "connector_evidence.json"), map[string]any{
			"connector_contract_hash": "sha256:contract",
			"policy_hash":             "sha256:policy",
			"request_hash":            "sha256:request",
			"response_hash":           "sha256:response",
			"source_url_hashes":       []string{"sha256:source"},
			"receipt_ref":             "receipt:1",
			"evidence_pack_ref":       "pack:1",
		})
		check := checkConnectorEvidence(dir)
		if !check.Pass {
			t.Fatalf("connector evidence fixture did not pass: %+v", check)
		}
		if strings.Contains(check.Detail, "verified") || !strings.Contains(check.Detail, "not recomputed") {
			t.Errorf("detail overclaims: %q", check.Detail)
		}
	})
	t.Run("eu ai act profile", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, filepath.Join(dir, "profile.json"), map[string]any{
			"eu_ai_act_profile": map[string]any{
				"profile_id":                "eu-ai-act:minimal:1",
				"role_map":                  map[string]any{"deployer": "customer"},
				"risk_category":             "minimal",
				"relevant_articles":         []string{"Article 50"},
				"provider_or_deployer_role": "deployer",
				"redaction_profile":         "minimized",
				"timeline_status":           "FINAL",
			},
		})
		check := checkEUAIActEvidenceProfile(dir)
		if !check.Pass {
			t.Fatalf("EU AI Act fixture did not pass: %+v", check)
		}
		if strings.Contains(check.Detail, "verified") || !strings.Contains(check.Detail, "not resolved") {
			t.Errorf("detail overclaims: %q", check.Detail)
		}
	})
}

// The registry-wide guard: run every registered check on its own against packs
// that hold nothing, and fail if any of them reports VERIFIED. A check added
// later that passes when it has no input fails here.
func TestCheckRegistry_NoCheckPassesWithoutInput(t *testing.T) {
	seen := map[string]bool{}
	for _, check := range checkRegistry {
		if seen[check.name] {
			t.Fatalf("check %s is registered twice", check.name)
		}
		seen[check.name] = true
	}
	if !slices.Equal(CheckNames(), []string{
		"structure", "index_integrity", "roots", "evidence_pack_seal", "file_hashes",
		"eu_ai_act_profile", "connector_evidence", "chain_integrity", "lamport_monotonicity",
		"policy_decision_hashes", "replay_determinism", "host_evidence", "embedded_signature_trust",
	}) {
		t.Fatalf("registry changed: %v. Add the new check to this list once it reports NOT_RUN or FAILED without input", CheckNames())
	}

	packs := map[string]func(t *testing.T) string{
		"empty directory": func(t *testing.T) string { return t.TempDir() },
		"missing path":    func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") },
		// The layout with nothing in it: every directory a check looks into
		// exists and is empty.
		"empty canonical layout": func(t *testing.T) string {
			dir := t.TempDir()
			for _, sub := range []string{"receipts", "02_PROOFGRAPH/receipts", "05_DIFFS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "11_HOST_EVIDENCE", "host_evidence"} {
				if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			return dir
		},
	}
	for packName, makePack := range packs {
		for _, check := range checkRegistry {
			t.Run(packName+"/"+check.name, func(t *testing.T) {
				dir := makePack(t)
				run := &checkRun{bundlePath: dir, opts: VerifyOptions{AllowSelfAttested: true}, report: &VerifyReport{}}
				results := check.results(run)
				if len(results) == 0 {
					t.Fatal("check reported nothing; a check with no input must say NOT_RUN")
				}
				for _, result := range results {
					if result.Pass || result.Status == CheckVerified {
						t.Errorf("%s passed without input: %q", result.Name, result.Detail)
					}
					if result.Status != CheckFailed && result.Status != CheckNotRun {
						t.Errorf("%s status = %q, want FAILED or NOT_RUN", result.Name, result.Status)
					}
					if strings.TrimSpace(result.Reason) == "" {
						t.Errorf("%s (%s) gives no reason", result.Name, result.Status)
					}
				}
				// The checks a VERIFIED outcome cannot do without must fail
				// here, not merely stay out of the way.
				if slices.Contains(packChecksRequiredForVerified, check.name) && results[0].Status != CheckFailed {
					t.Errorf("required check %s is %s on a pack with nothing in it, want FAILED", check.name, results[0].Status)
				}
			})
		}
	}
}

// A check that cannot fail verifies nothing. Every registered check must have
// a pack here that makes it report FAILED; a new check without one fails this
// test until its failing case is written down.
func TestCheckRegistry_EveryCheckCanFail(t *testing.T) {
	write := func(t *testing.T, dir, rel string, v any) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, path, v)
	}
	nothing := func(*testing.T, string) {}
	failingPacks := map[string]func(t *testing.T, dir string){
		"structure": nothing,
		"index_integrity": func(t *testing.T, dir string) {
			write(t, dir, "01_SCORE.json", map[string]any{"pass": true})
			write(t, dir, "00_INDEX.json", map[string]any{"entries": []any{
				map[string]any{"path": "01_SCORE.json", "sha256": strings.Repeat("0", 64)},
			}})
		},
		"roots": func(t *testing.T, dir string) {
			write(t, dir, "00_INDEX.json", map[string]any{"entries": []any{
				map[string]any{"path": "01_SCORE.json", "sha256": "not-a-digest"},
			}})
		},
		"evidence_pack_seal": func(t *testing.T, dir string) {
			write(t, dir, "00_INDEX.json", map[string]any{"entries": []any{}})
		},
		"file_hashes": func(t *testing.T, dir string) {
			write(t, dir, "manifest.json", map[string]any{"file_hashes": map[string]string{"absent.json": strings.Repeat("0", 64)}})
		},
		"eu_ai_act_profile": func(t *testing.T, dir string) {
			write(t, dir, "profile.json", map[string]any{"eu_ai_act_profile": map[string]any{}})
		},
		"connector_evidence": func(t *testing.T, dir string) {
			write(t, dir, "connector_evidence.json", map[string]any{"receipt_ref": "receipt:1"})
		},
		"chain_integrity":        nothing,
		"lamport_monotonicity":   nothing,
		"policy_decision_hashes": nothing,
		"replay_determinism": func(t *testing.T, dir string) {
			write(t, dir, "00_INDEX.json", map[string]any{"gates": []string{"G2"}, "entries": []any{}})
		},
		"host_evidence": func(t *testing.T, dir string) {
			write(t, dir, "host_evidence/chain.json", map[string]any{"receipts": []any{}})
		},
		"embedded_signature_trust": func(t *testing.T, dir string) {
			write(t, dir, "receipts/receipt-001.json", map[string]any{"receipt_id": "rcpt-001", "signature": "attacker-controlled"})
		},
	}
	for _, check := range checkRegistry {
		t.Run(check.name, func(t *testing.T) {
			makePack, ok := failingPacks[check.name]
			if !ok {
				t.Fatalf("no failing pack is recorded for %s: a registered check must be able to fail", check.name)
			}
			dir := t.TempDir()
			makePack(t, dir)
			results := check.results(&checkRun{bundlePath: dir, report: &VerifyReport{}})
			for _, result := range results {
				if result.Status == CheckFailed {
					if strings.TrimSpace(result.Reason) == "" {
						t.Errorf("%s failed without a reason", result.Name)
					}
					return
				}
			}
			t.Fatalf("%s did not fail on a pack built to fail it: %+v", check.name, results)
		})
	}
}

// A pack with index entries but nothing else: the index and its roots have
// input, so those two may run. Everything else still has none.
func TestCheckRegistry_IndexOnlyPackRunsOnlyIndexChecks(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "01_SCORE.json"), map[string]any{"pass": true})
	writeSealFixtureIndex(t, dir)

	mayRun := []string{"structure", "index_integrity", "roots"}
	for _, check := range checkRegistry {
		run := &checkRun{bundlePath: dir, opts: VerifyOptions{AllowSelfAttested: true}, report: &VerifyReport{}}
		for _, result := range check.results(run) {
			if result.Status == CheckVerified && !slices.Contains(mayRun, check.name) {
				t.Errorf("%s passed on a pack that holds only an index: %q", result.Name, result.Detail)
			}
		}
	}
}

// Packs that hold an index or a manifest which lists nothing. The file is
// there, so structure holds; the checks that would read the listed hashes have
// none to read and must say NOT_RUN. A check that turned that into VERIFIED
// would pass on a pack that proves nothing.
func TestCheckRegistry_PacksThatListNothingRunOnlyStructure(t *testing.T) {
	const (
		emptyIndexReason    = "00_INDEX.json lists no entries"
		noFileHashesReason  = "manifest.json declares no file_hashes"
		noIndexReason       = "pack has no 00_INDEX.json"
		noManifestReason    = "pack has no manifest.json"
		indexName, rootName = "index_integrity", "roots"
	)
	for _, tc := range []struct {
		name  string
		files map[string]string
		// wantReason maps a check to a fragment its NOT_RUN reason must carry.
		wantReason map[string]string
	}{
		{
			name:       "index with no entries",
			files:      map[string]string{"00_INDEX.json": `{"version":"1.0.0","entries":[]}`},
			wantReason: map[string]string{indexName: emptyIndexReason, rootName: emptyIndexReason, "file_hashes": noManifestReason},
		},
		{
			name:       "index without an entries field",
			files:      map[string]string{"00_INDEX.json": `{"version":"1.0.0"}`},
			wantReason: map[string]string{indexName: emptyIndexReason, rootName: emptyIndexReason, "file_hashes": noManifestReason},
		},
		{
			name:       "manifest with an empty file_hashes",
			files:      map[string]string{"manifest.json": `{"session_id":"s","file_hashes":{}}`},
			wantReason: map[string]string{indexName: noIndexReason, rootName: noIndexReason, "file_hashes": noFileHashesReason},
		},
		{
			name:       "manifest without file_hashes",
			files:      map[string]string{"manifest.json": `{"session_id":"s"}`},
			wantReason: map[string]string{indexName: noIndexReason, rootName: noIndexReason, "file_hashes": noFileHashesReason},
		},
		{
			name: "empty index and empty manifest",
			files: map[string]string{
				"00_INDEX.json": `{"entries":[]}`,
				"manifest.json": `{"file_hashes":{}}`,
			},
			wantReason: map[string]string{indexName: emptyIndexReason, rootName: emptyIndexReason, "file_hashes": noFileHashesReason},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			seen := map[string]bool{}
			for _, check := range checkRegistry {
				run := &checkRun{bundlePath: dir, opts: VerifyOptions{AllowSelfAttested: true}, report: &VerifyReport{}}
				for _, result := range check.results(run) {
					if result.Status == CheckVerified && check.name != "structure" {
						t.Errorf("%s passed on a pack that lists nothing: %q", result.Name, result.Detail)
					}
					want, pinned := tc.wantReason[result.Name]
					if !pinned {
						continue
					}
					seen[result.Name] = true
					if result.Status != CheckNotRun || result.Pass {
						t.Errorf("%s = %s (pass=%v), want NOT_RUN", result.Name, result.Status, result.Pass)
					}
					if !strings.Contains(result.Reason, want) {
						t.Errorf("%s reason = %q, want it to contain %q", result.Name, result.Reason, want)
					}
				}
			}
			for name := range tc.wantReason {
				if !seen[name] {
					t.Errorf("check %s reported no result under its own name", name)
				}
			}
		})
	}
}

// An index that cannot be read or parsed declares nothing either way. That is
// a failure of replay_determinism, not a pack that claims no replay evidence.
func TestReplayDeterminism_UnreadableIndexFails(t *testing.T) {
	t.Run("does not parse", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), []byte(`{"gates":["G2"`), 0o600); err != nil {
			t.Fatal(err)
		}
		result := checkReplayDeterminism(dir).normalized()
		if result.Status != CheckFailed || !strings.Contains(result.Reason, "cannot parse the gates 00_INDEX.json declares") {
			t.Fatalf("result = %s %q, want FAILED naming the unparseable index", result.Status, result.Reason)
		}
	})
	t.Run("cannot be read", func(t *testing.T) {
		if os.Geteuid() == 0 || runtime.GOOS == "windows" {
			t.Skip("file modes do not stop this user from reading")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "00_INDEX.json")
		if err := os.WriteFile(path, []byte(`{"gates":["G0"]}`), 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		result := checkReplayDeterminism(dir).normalized()
		if result.Status != CheckFailed || !strings.Contains(result.Reason, "cannot read the gates 00_INDEX.json declares") {
			t.Fatalf("result = %s %q, want FAILED naming the unreadable index", result.Status, result.Reason)
		}
	})
}

func TestConclude(t *testing.T) {
	required := []string{"seal", "receipts"}
	for _, tc := range []struct {
		name        string
		outcomes    []CheckOutcome
		want        receiptverify.Verdict
		wantCounts  CheckCounts
		wantMissing []string
	}{
		{name: "no checks", want: receiptverify.VerdictFailed, wantMissing: required},
		{
			name:        "nothing ran",
			outcomes:    []CheckOutcome{{"seal", CheckNotRun}, {"receipts", CheckNotRun}},
			want:        receiptverify.VerdictFailed,
			wantCounts:  CheckCounts{NotRun: 2},
			wantMissing: required,
		},
		{
			name:       "all required verified",
			outcomes:   []CheckOutcome{{"seal", CheckVerified}, {"receipts", CheckVerified}},
			want:       receiptverify.VerdictVerified,
			wantCounts: CheckCounts{Passed: 2},
		},
		{
			name:       "optional check not run is counted apart and does not block",
			outcomes:   []CheckOutcome{{"seal", CheckVerified}, {"receipts", CheckVerified}, {"tapes", CheckNotRun}},
			want:       receiptverify.VerdictVerified,
			wantCounts: CheckCounts{Passed: 2, NotRun: 1},
		},
		{
			name:        "required check not run",
			outcomes:    []CheckOutcome{{"seal", CheckVerified}, {"receipts", CheckNotRun}},
			want:        receiptverify.VerdictUnverifiable,
			wantCounts:  CheckCounts{Passed: 1, NotRun: 1},
			wantMissing: []string{"receipts"},
		},
		{
			name:        "required check absent",
			outcomes:    []CheckOutcome{{"seal", CheckVerified}},
			want:        receiptverify.VerdictUnverifiable,
			wantCounts:  CheckCounts{Passed: 1},
			wantMissing: []string{"receipts"},
		},
		{
			name:       "one unverifiable",
			outcomes:   []CheckOutcome{{"seal", CheckUnverifiable}, {"receipts", CheckVerified}},
			want:       receiptverify.VerdictUnverifiable,
			wantCounts: CheckCounts{Passed: 1, Unverifiable: 1},
		},
		{
			name:       "failed beats unverifiable",
			outcomes:   []CheckOutcome{{"seal", CheckUnverifiable}, {"receipts", CheckFailed}},
			want:       receiptverify.VerdictFailed,
			wantCounts: CheckCounts{Failed: 1, Unverifiable: 1},
		},
		{
			name:       "unknown status fails",
			outcomes:   []CheckOutcome{{"seal", CheckVerified}, {"receipts", "PASS"}},
			want:       receiptverify.VerdictFailed,
			wantCounts: CheckCounts{Passed: 1, Failed: 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Conclude(tc.outcomes, required)
			if got.Outcome != tc.want {
				t.Errorf("outcome = %s, want %s", got.Outcome, tc.want)
			}
			if got.Counts != tc.wantCounts {
				t.Errorf("counts = %+v, want %+v", got.Counts, tc.wantCounts)
			}
			if !slices.Equal(got.RequiredNotRun, tc.wantMissing) {
				t.Errorf("required not run = %v, want %v", got.RequiredNotRun, tc.wantMissing)
			}
		})
	}
}

func TestCheckResultNormalizedNeverInventsAPass(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   CheckResult
		want CheckStatus
	}{
		{"pass alone", CheckResult{Pass: true}, CheckVerified},
		{"neither", CheckResult{}, CheckFailed},
		{"verified without pass", CheckResult{Status: CheckVerified}, CheckFailed},
		{"not run with pass set", CheckResult{Status: CheckNotRun, Pass: true}, CheckNotRun},
		{"failed with pass set", CheckResult{Status: CheckFailed, Pass: true}, CheckFailed},
		{"unverifiable with pass set", CheckResult{Status: CheckUnverifiable, Pass: true}, CheckUnverifiable},
		{"unknown status with pass set", CheckResult{Status: "PASS", Pass: true}, CheckFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.normalized()
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q", got.Status, tc.want)
			}
			if got.Pass != (tc.want == CheckVerified) {
				t.Errorf("pass = %v for status %q", got.Pass, got.Status)
			}
		})
	}
}

func TestSummarizeStatesEachCountApart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outcomes []CheckOutcome
		want     string
	}{
		{
			name:     "every check ran",
			outcomes: []CheckOutcome{{"structure", CheckVerified}, {"evidence_pack_seal", CheckVerified}, {"policy_decision_hashes", CheckVerified}},
			want:     "VERIFIED: 3 passed, 0 failed, 0 not run",
		},
		{
			name:     "some checks had no input",
			outcomes: []CheckOutcome{{"structure", CheckVerified}, {"evidence_pack_seal", CheckVerified}, {"policy_decision_hashes", CheckVerified}, {"file_hashes", CheckNotRun}},
			want:     "VERIFIED: 3 passed, 0 failed, 1 not run; this result covers only the 3 checks that ran",
		},
		{
			name:     "a failure",
			outcomes: []CheckOutcome{{"structure", CheckVerified}, {"evidence_pack_seal", CheckFailed}, {"policy_decision_hashes", CheckVerified}, {"file_hashes", CheckNotRun}},
			want:     "FAILED: 2 passed, 1 failed, 1 not run",
		},
		{
			name:     "no trust root",
			outcomes: []CheckOutcome{{"structure", CheckVerified}, {"evidence_pack_seal", CheckUnverifiable}, {"policy_decision_hashes", CheckVerified}, {"file_hashes", CheckNotRun}},
			want:     "UNVERIFIABLE: no trust root for the seal signer; 2 passed, 0 failed, 1 unverifiable, 1 not run (pass --config, set HELM_EVIDENCE_TRUST_CONFIG or HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX)",
		},
		{
			name:     "a required check is missing from the report",
			outcomes: []CheckOutcome{{"structure", CheckVerified}, {"policy_decision_hashes", CheckVerified}},
			want:     "UNVERIFIABLE: required checks did not run (evidence_pack_seal); 2 passed, 0 failed, 0 not run",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarize(Conclude(tc.outcomes, packChecksRequiredForVerified)); got != tc.want {
				t.Errorf("summary = %q, want %q", got, tc.want)
			}
		})
	}
}

// A caller that needs a check to have run names it in RequireChecks. The named
// check then fails instead of reporting NOT_RUN; unnamed checks are untouched.
func TestVerifyBundle_RequireChecksFailsACheckThatDidNotRun(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{RequireChecks: []string{"chain_integrity"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified || report.Outcome != receiptverify.VerdictFailed {
		t.Fatalf("pack verified although a required check did not run: %s", report.Summary)
	}
	for _, check := range report.Checks {
		switch check.Name {
		case "chain_integrity":
			if check.Status != CheckFailed || !strings.Contains(check.Reason, "required by the caller, but it did not run") {
				t.Errorf("required check = %+v, want FAILED naming the requirement", check)
			}
		case "lamport_monotonicity":
			if check.Status != CheckNotRun {
				t.Errorf("unnamed check = %+v, want NOT_RUN", check)
			}
		}
	}

	if _, err := VerifyBundleWithOptions(dir, VerifyOptions{RequireChecks: []string{"chain_integrty"}}); err == nil || !strings.Contains(err.Error(), "chain_integrty") {
		t.Fatalf("misspelled check name was accepted: %v", err)
	}
}

// The seal's missing trust root still reads UNVERIFIABLE, now as a check
// status and an outcome a consumer can read without parsing the summary.
func TestVerifyBundle_UnverifiableIsACheckStatusAndAnOutcome(t *testing.T) {
	dir := createValidBundleFixture(t)
	for _, key := range []string{"HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "HELM_EVIDENCE_TRUST_CONFIG", "HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX"} {
		t.Setenv(key, "")
	}
	t.Setenv("HELM_DATA_DIR", t.TempDir())

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != receiptverify.VerdictUnverifiable || report.Verified {
		t.Fatalf("outcome=%s verified=%v, want UNVERIFIABLE/false: %s", report.Outcome, report.Verified, report.Summary)
	}
	if report.CheckCounts.Unverifiable != 1 || report.CheckCounts.Failed != 0 || report.IssueCount != 1 {
		t.Fatalf("counts=%+v issue_count=%d, want one unverifiable check and no failure", report.CheckCounts, report.IssueCount)
	}
	for _, check := range report.Checks {
		if check.Name == "evidence_pack_seal" && (check.Status != CheckUnverifiable || check.Pass) {
			t.Fatalf("seal check = %+v, want UNVERIFIABLE", check)
		}
	}
	if report.SealState != evidencepkg.EvidencePackSealStateUnverifiable {
		t.Fatalf("seal_state = %q", report.SealState)
	}
}

// Host receipt checks that have nothing to read (no hardware root claim, no
// declared chain hash, no foreign payload to bind) reach the pack report as
// NOT_RUN, not as passes.
func TestVerifyBundle_HostEvidenceChecksWithoutInputAreNotRun(t *testing.T) {
	for name, status := range map[string]CheckStatus{
		externalhost.StatusVerified: CheckVerified,
		externalhost.StatusFailed:   CheckFailed,
		externalhost.StatusNotRun:   CheckNotRun,
	} {
		if CheckStatus(name) != status {
			t.Fatalf("externalhost status %q does not match the verifier's %q", name, status)
		}
	}

	dir := createValidCanonicalBundleFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(verifierTestChain(t, priv, hex.EncodeToString(pub)))
	if err != nil {
		t.Fatal(err)
	}
	hostDir := filepath.Join(dir, "11_HOST_EVIDENCE", "test")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "chain.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sealVerifierFixture(t, dir, "canonical-test")

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{ExternalHostKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("pack with signed host evidence should verify: %s", report.Summary)
	}
	const prefix = "11_HOST_EVIDENCE/test/chain.json:external_host:"
	want := map[string]CheckStatus{
		prefix + "receipts":       CheckVerified,
		prefix + "receipt_schema": CheckVerified,
		prefix + "receipt_hash":   CheckVerified,
		prefix + "signature":      CheckVerified,
		prefix + "binding":        CheckNotRun,
		prefix + "hardware_root":  CheckNotRun,
		prefix + "chain_hash":     CheckNotRun,
	}
	for _, check := range report.Checks {
		if status, ok := want[check.Name]; ok {
			if check.Status != status {
				t.Errorf("%s status = %s, want %s (%s%s)", check.Name, check.Status, status, check.Detail, check.Reason)
			}
			delete(want, check.Name)
		}
		if check.Name == "host_evidence" {
			t.Errorf("host_evidence placeholder reported although chains were found: %+v", check)
		}
	}
	for name := range want {
		t.Errorf("host evidence check %s missing from the report", name)
	}

	// Requiring host evidence asks for a chain. The chain is there, so the
	// per-receipt checks it has nothing to read for stay NOT_RUN.
	required, err := VerifyBundleWithOptions(dir, VerifyOptions{
		ExternalHostKeyHex: hex.EncodeToString(pub),
		RequireChecks:      []string{"host_evidence"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !required.Verified {
		t.Fatalf("pack with a verified host chain failed --require-check host_evidence: %s", required.Summary)
	}
	for _, check := range required.Checks {
		if check.Name == prefix+"hardware_root" && check.Status != CheckNotRun {
			t.Errorf("%s = %s under RequireChecks, want NOT_RUN", check.Name, check.Status)
		}
	}
}

// An embedded signature nothing vouches for fails a pack whose seal is
// trusted. When the seal has no trust root either, the same signature is
// unproven rather than tampered, so the pack stays UNVERIFIABLE and does not
// read as FAILED.
func TestVerifyBundle_UntrustedEmbeddedSignatureFollowsSealTrust(t *testing.T) {
	dir := createValidBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
		"signature":     "attacker-controlled",
	})
	sealVerifierFixture(t, dir, "test-session-001")

	embedded := func(report *VerifyReport) CheckResult {
		t.Helper()
		for _, check := range report.Checks {
			if check.Name == "embedded_signature_trust" {
				return check
			}
		}
		t.Fatal("missing embedded_signature_trust check")
		return CheckResult{}
	}

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != receiptverify.VerdictFailed || embedded(report).Status != CheckFailed {
		t.Fatalf("trusted seal: outcome=%s embedded=%s, want FAILED/FAILED", report.Outcome, embedded(report).Status)
	}

	for _, key := range []string{"HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "HELM_EVIDENCE_TRUST_CONFIG", "HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX"} {
		t.Setenv(key, "")
	}
	t.Setenv("HELM_DATA_DIR", t.TempDir())
	report, err = VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != receiptverify.VerdictUnverifiable || embedded(report).Status != CheckUnverifiable {
		t.Fatalf("no seal trust root: outcome=%s embedded=%s, want UNVERIFIABLE/UNVERIFIABLE: %s", report.Outcome, embedded(report).Status, report.Summary)
	}
	if report.CheckCounts.Unverifiable != 2 || report.CheckCounts.Failed != 0 {
		t.Fatalf("counts = %+v, want the seal and the embedded signatures unverifiable and nothing failed", report.CheckCounts)
	}
}
