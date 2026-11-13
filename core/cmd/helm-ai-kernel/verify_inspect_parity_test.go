package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

// cliPack describes a canonical pack to build and seal. Every file is listed
// in 00_INDEX.json, so the seal covers it.
type cliPack struct {
	// files are added to the canonical layout, keyed by pack-relative path.
	files map[string][]byte
	// indexFields are extra top-level fields of 00_INDEX.json.
	indexFields map[string]any
	// omitDirs names canonical directories to leave out.
	omitDirs []string
}

func writeCLIPack(t *testing.T, dataDir string, pack cliPack) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{
		"01_SCORE.json":                         []byte(`{"pass":true}`),
		"02_PROOFGRAPH/receipts/receipt-1.json": []byte(`{"receipt_id":"rcpt-1","decision_id":"dec-1","decision_hash":"sha256:test","lamport_clock":1}`),
	}
	for rel, data := range pack.files {
		files[rel] = data
	}
	omitted := map[string]bool{}
	for _, sub := range pack.omitDirs {
		omitted[sub] = true
	}
	for _, sub := range []string{"02_PROOFGRAPH", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "12_REPORTS"} {
		if omitted[sub] {
			continue
		}
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths := make([]string, 0, len(files))
	for rel := range files {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	entries := make([]map[string]string, 0, len(paths))
	for _, rel := range paths {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, files[rel], 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(files[rel])
		entries = append(entries, map[string]string{"path": rel, "sha256": hex.EncodeToString(sum[:])})
	}
	index := map[string]any{"version": "1.0.0", "entries": entries}
	for key, value := range pack.indexFields {
		index[key] = value
	}
	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(indexData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{
		PackID:  "cli-pack",
		DataDir: dataDir,
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// manifestWithHashes is a manifest.json whose file_hashes cover the given
// pack files.
func manifestWithHashes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	hashes := map[string]string{}
	for rel, data := range files {
		sum := sha256.Sum256(data)
		hashes[rel] = hex.EncodeToString(sum[:])
	}
	data, err := json.Marshal(map[string]any{"session_id": "cli-pack", "file_hashes": hashes})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func inspectJSONReport(t *testing.T, args ...string) (int, map[string]any, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runEvidenceCmd(append([]string{"inspect", "--json"}, args...), &stdout, &stderr)
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("evidence inspect --json did not print a report (exit=%d): %v\nstdout=%s\nstderr=%s", code, err, stdout.String(), stderr.String())
	}
	return code, report, stdout.String()
}

// A sealed pack with a valid manifest.json was FAILED by `verify`
// ("conform:unexpected top-level entry: manifest.json") and VERIFIED by
// `evidence inspect`, so `verify --require-check file_hashes` could never be
// satisfied. file_hashes reads manifest.json, so it is a legal top-level entry.
func TestVerifyCLIAcceptsAManifestTheFileHashesCheckReads(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	score := []byte(`{"pass":true}`)
	packDir := writeCLIPack(t, dataDir, cliPack{files: map[string][]byte{
		"manifest.json": manifestWithHashes(t, map[string][]byte{"01_SCORE.json": score}),
	}})

	code, report, raw := verifyJSONReport(t, "--allow-self-attested", "--require-check", "file_hashes", packDir)
	if code != 0 || report["outcome"] != "VERIFIED" {
		t.Fatalf("exit=%d outcome=%v, want 0/VERIFIED for a sealed pack with a valid manifest.json\n%s", code, report["outcome"], raw)
	}
	statuses := reportCheckStatuses(t, report)
	if statuses["hash:01_SCORE.json"] != "VERIFIED" {
		t.Fatalf("hash:01_SCORE.json = %q, want VERIFIED\n%s", statuses["hash:01_SCORE.json"], raw)
	}
	for name := range statuses {
		if strings.HasPrefix(name, "conform:") {
			t.Errorf("layout check rejected the pack: %s", name)
		}
	}
}

// `verify` and `evidence inspect` judge one pack with one piece of code: the
// same checks, the same statuses, the same outcome and the same exit code.
// inspect ran only the verifier library, so a pack `verify` failed on its
// layout was VERIFIED there.
func TestVerifyAndEvidenceInspectReachTheSameVerdict(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	score := []byte(`{"pass":true}`)

	for _, tc := range []struct {
		name        string
		pack        cliPack
		args        []string
		clearTrust  bool
		wantOutcome string
		wantExit    int
	}{
		{name: "sealed pack", args: []string{"--allow-self-attested"}, wantOutcome: "VERIFIED", wantExit: 0},
		{
			name: "sealed pack with a valid manifest",
			pack: cliPack{files: map[string][]byte{
				"manifest.json": manifestWithHashes(t, map[string][]byte{"01_SCORE.json": score}),
			}},
			args:        []string{"--allow-self-attested"},
			wantOutcome: "VERIFIED", wantExit: 0,
		},
		{
			name: "manifest hash does not match",
			pack: cliPack{files: map[string][]byte{
				"manifest.json": manifestWithHashes(t, map[string][]byte{"01_SCORE.json": []byte("something else")}),
			}},
			args:        []string{"--allow-self-attested"},
			wantOutcome: "FAILED", wantExit: 1,
		},
		{
			name:        "unexpected top-level entry",
			pack:        cliPack{files: map[string][]byte{"stray.txt": []byte("not part of the layout")}},
			args:        []string{"--allow-self-attested"},
			wantOutcome: "FAILED", wantExit: 1,
		},
		{
			name:        "mandatory directory missing",
			pack:        cliPack{omitDirs: []string{"12_REPORTS"}},
			args:        []string{"--allow-self-attested"},
			wantOutcome: "FAILED", wantExit: 1,
		},
		{name: "no trust root", clearTrust: true, wantOutcome: "UNVERIFIABLE", wantExit: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packDir := writeCLIPack(t, dataDir, tc.pack)
			if tc.clearTrust {
				clearVerifierTrustEnv(t)
			}
			verifyCode, verifyReport, verifyRaw := verifyJSONReport(t, append(tc.args, packDir)...)
			inspectCode, inspectReport, inspectRaw := inspectJSONReport(t, append(tc.args, packDir)...)

			if verifyReport["outcome"] != tc.wantOutcome || verifyCode != tc.wantExit {
				t.Errorf("verify: outcome=%v exit=%d, want %s/%d\n%s", verifyReport["outcome"], verifyCode, tc.wantOutcome, tc.wantExit, verifyRaw)
			}
			if inspectReport["outcome"] != tc.wantOutcome || inspectCode != tc.wantExit {
				t.Errorf("evidence inspect: outcome=%v exit=%d, want %s/%d\n%s", inspectReport["outcome"], inspectCode, tc.wantOutcome, tc.wantExit, inspectRaw)
			}
			if got, want := fmt.Sprint(reportCheckStatuses(t, inspectReport)), fmt.Sprint(reportCheckStatuses(t, verifyReport)); got != want {
				t.Errorf("the two commands report different checks:\ninspect: %s\nverify:  %s", got, want)
			}
			if fmt.Sprint(inspectReport["check_counts"]) != fmt.Sprint(verifyReport["check_counts"]) {
				t.Errorf("check_counts differ: inspect %v, verify %v", inspectReport["check_counts"], verifyReport["check_counts"])
			}
			if inspectReport["verified"] != verifyReport["verified"] {
				t.Errorf("verified differs: inspect %v, verify %v", inspectReport["verified"], verifyReport["verified"])
			}

			// Text mode exits the same way as JSON mode.
			var stdout, stderr bytes.Buffer
			textCode := runEvidenceCmd(append(append([]string{"inspect"}, tc.args...), packDir), &stdout, &stderr)
			if textCode != tc.wantExit {
				t.Errorf("evidence inspect text exit=%d, want %d\n%s", textCode, tc.wantExit, stdout.String())
			}
			if !strings.Contains(stdout.String(), "Outcome:  "+tc.wantOutcome) {
				t.Errorf("evidence inspect text does not state the outcome %s:\n%s", tc.wantOutcome, stdout.String())
			}
		})
	}
}

// The published schema calls outcome, check_counts and checks[].status always
// present, so it must reject a report that leaves one out.
func TestVerifyCLISchemaRequiresTheFieldsItCallsAlwaysPresent(t *testing.T) {
	schema := compileVerifyCLISchema(t)

	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)
	_, report, raw := verifyJSONReport(t, "--allow-self-attested", packDir)
	if err := schema.Validate(report); err != nil {
		t.Fatalf("the emitted report does not match the schema: %v\n%s", err, raw)
	}

	clone := func() map[string]any {
		var out map[string]any
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for name, drop := range map[string]func(doc map[string]any){
		"outcome":         func(doc map[string]any) { delete(doc, "outcome") },
		"check_counts":    func(doc map[string]any) { delete(doc, "check_counts") },
		"checks[].status": func(doc map[string]any) { delete(doc["checks"].([]any)[0].(map[string]any), "status") },
	} {
		t.Run(name, func(t *testing.T) {
			doc := clone()
			drop(doc)
			if err := schema.Validate(doc); err == nil {
				t.Fatalf("the schema accepts a report without %s although it describes the field as always present", name)
			}
		})
	}
}
