package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// quantum_posture: the host-evidence cases sign with a classical Ed25519 test
// key; nothing here asserts post-quantum resistance.

// These tests hold the rule docs/VERIFICATION.md states as "evidence that is
// present must validate": a check may report NOT_RUN only when the pack holds
// nothing for it, and the reason it gives must be true of the pack.

func writeRaw(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeIndexWithGates(t *testing.T, dir string, gates string) {
	t.Helper()
	doc := `{"version":"1.0.0","entries":[]`
	if gates != "" {
		doc += `,"gates":` + gates
	}
	writeRaw(t, dir, "00_INDEX.json", []byte(doc+"}"))
}

// A `gates` value that is not a list of gate names is malformed input. It used
// to read as "declares no gates" and leave replay_determinism NOT_RUN.
func TestReplayDeterminism_MalformedGatesFail(t *testing.T) {
	for name, gates := range map[string]string{
		"a string":              `"G2"`,
		"an object":             `{"G2":true}`,
		"a number":              `2`,
		"a boolean":             `true`,
		"a list with a number":  `["G0",2]`,
		"a list with an object": `[{"G2":true}]`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexWithGates(t, dir, gates)
			result := checkReplayDeterminism(dir).normalized()
			if result.Status != CheckFailed {
				t.Fatalf("status = %s (%s%s), want FAILED for gates=%s", result.Status, result.Detail, result.Reason, gates)
			}
			if !strings.Contains(result.Reason, "gates") {
				t.Fatalf("reason does not name the malformed gates value: %q", result.Reason)
			}
		})
	}

	// Absent and null both mean the pack declares no gates.
	for name, gates := range map[string]string{"absent": "", "null": "null", "empty list": "[]"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexWithGates(t, dir, gates)
			if result := checkReplayDeterminism(dir).normalized(); result.Status != CheckNotRun {
				t.Fatalf("status = %s (%s), want NOT_RUN: nothing is declared and nothing is carried", result.Status, result.Reason)
			}
		})
	}
}

// A pack that carries replay material is checked on it whether or not it lists
// gate G2. A determinism manifest with diverging hashes used to be NOT_RUN
// ("the pack claims no replay evidence") when G2 was left out or misspelled.
func TestReplayDeterminism_PresentMaterialIsValidatedWithoutG2(t *testing.T) {
	const detManifest = "02_PROOFGRAPH/determinism_manifest.json"
	const tapeManifest = "08_TAPES/tape_manifest.json"
	equalHashes := []byte(`{"live_hash":"sha256:same","replay_hash":"sha256:same"}`)

	for _, tc := range []struct {
		name       string
		files      map[string]string
		want       CheckStatus
		wantInText string
	}{
		{
			name:       "diverging hashes",
			files:      map[string]string{detManifest: `{"live_hash":"sha256:live","replay_hash":"sha256:replay"}`},
			want:       CheckFailed,
			wantInText: "replay hash divergence",
		},
		{
			name:       "determinism manifest that does not parse",
			files:      map[string]string{detManifest: `{not json`},
			want:       CheckFailed,
			wantInText: "invalid determinism manifest JSON",
		},
		{
			name:       "determinism manifest without hashes",
			files:      map[string]string{detManifest: `{"live_hash":"sha256:only"}`},
			want:       CheckFailed,
			wantInText: "must declare live_hash and replay_hash",
		},
		{
			name:       "tape manifest that does not parse",
			files:      map[string]string{tapeManifest: `garbage`},
			want:       CheckFailed,
			wantInText: "invalid tape manifest JSON",
		},
		{
			name:       "valid determinism manifest beside a broken tape manifest",
			files:      map[string]string{detManifest: string(equalHashes), tapeManifest: `[`},
			want:       CheckFailed,
			wantInText: "invalid tape manifest JSON",
		},
		{
			name:       "consistent determinism manifest",
			files:      map[string]string{detManifest: string(equalHashes)},
			want:       CheckVerified,
			wantInText: "gate G2 is not declared",
		},
		{
			name:       "consistent determinism manifest beside an empty tape manifest",
			files:      map[string]string{detManifest: string(equalHashes), tapeManifest: `{"run_id":"r","entries":[]}`},
			want:       CheckVerified,
			wantInText: "tape_manifest.json parses and lists 0 entries (not replayed); determinism_manifest.json states equal",
		},
		{
			// Manifest rows are entries the tape claims to hold. The tape is
			// replayed, as `replay` replays it, and rows without an entry fail
			// it. They used to be counted and reported as "not replayed".
			name:       "tape manifest whose rows name entries the tape does not hold",
			files:      map[string]string{detManifest: string(equalHashes), tapeManifest: `{"run_id":"r","entries":[{"seq":1},{"seq":2}]}`},
			want:       CheckFailed,
			wantInText: "seq=1 referenced in manifest but not in entries",
		},
		{
			// A tape manifest states no replay result. It is parsed, and the
			// reason says it is there, but it does not make the check run:
			// VERIFIED on it would satisfy --require-check with nothing compared.
			name:       "tape manifest only",
			files:      map[string]string{tapeManifest: `{"run_id":"r","entries":[]}`},
			want:       CheckNotRun,
			wantInText: "no 02_PROOFGRAPH/determinism_manifest.json, so it states no replay result to compare; 08_TAPES/tape_manifest.json parses and lists 0 entries (not replayed)",
		},
		{
			name:       "tape manifest only, with rows the tape does not hold",
			files:      map[string]string{tapeManifest: `{"run_id":"r","entries":[{"seq":1}]}`},
			want:       CheckFailed,
			wantInText: "seq=1 referenced in manifest but not in entries",
		},
	} {
		for gatesName, gates := range map[string]string{"gates without G2": `["G0","G1"]`, "gates misspell G2": `["g2"]`, "no gates": ""} {
			t.Run(tc.name+"/"+gatesName, func(t *testing.T) {
				dir := t.TempDir()
				writeIndexWithGates(t, dir, gates)
				for rel, content := range tc.files {
					writeRaw(t, dir, rel, []byte(content))
				}
				result := checkReplayDeterminism(dir).normalized()
				if result.Status != tc.want {
					t.Fatalf("status = %s (%s%s), want %s", result.Status, result.Detail, result.Reason, tc.want)
				}
				if text := result.Detail + result.Reason; !strings.Contains(text, tc.wantInText) {
					t.Fatalf("result text %q does not contain %q", text, tc.wantInText)
				}
			})
		}
	}

	t.Run("no replay material", func(t *testing.T) {
		dir := t.TempDir()
		writeIndexWithGates(t, dir, `["G0"]`)
		// Files that are not replay material: producers keep placeholders and
		// other artifacts in these directories.
		writeRaw(t, dir, "05_DIFFS/.gitkeep", nil)
		writeRaw(t, dir, "08_TAPES/scenarios.json", []byte(`{}`))
		result := checkReplayDeterminism(dir).normalized()
		if result.Status != CheckNotRun {
			t.Fatalf("status = %s (%s%s), want NOT_RUN", result.Status, result.Detail, result.Reason)
		}
		for _, want := range []string{"G2", "tape_manifest.json", "determinism_manifest.json"} {
			if !strings.Contains(result.Reason, want) {
				t.Errorf("reason %q does not name %s", result.Reason, want)
			}
		}
	})
}

// The reviewer's pack: a sealed pack whose determinism manifest states
// diverging hashes, with a recorded difference, and gates that leave G2 out.
// It verified with replay_determinism NOT_RUN.
func TestVerifyBundle_DivergingReplayMaterialFailsWithoutG2(t *testing.T) {
	dir := createValidBundleFixture(t)
	writeRaw(t, dir, "02_PROOFGRAPH/determinism_manifest.json", []byte(`{"live_hash":"sha256:live","replay_hash":"sha256:replay"}`))
	writeRaw(t, dir, "05_DIFFS/replay.diff", []byte("- live\n+ replay\n"))
	sealVerifierFixture(t, dir, "test-session-001")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatalf("pack with diverging replay hashes verified: %s", report.Summary)
	}
	assertCheck(t, report, "replay_determinism", false)
	for _, check := range report.Checks {
		if check.Name == "replay_determinism" && check.Status != CheckFailed {
			t.Fatalf("replay_determinism = %s (%s), want FAILED", check.Status, check.Reason)
		}
	}
}

func bigJSONWithProfile(profile string) []byte {
	// Larger than the 2 MiB bound the scan used to stop reading at.
	padding := strings.Repeat("x", 2*1024*1024+512)
	return []byte(`{"padding":"` + padding + `","nested":[{"eu_ai_act_profile":` + profile + `}]}`)
}

const validEUAIActProfile = `{"profile_id":"eu-ai-act:minimal:1","role_map":{"deployer":"customer"},"risk_category":"minimal","relevant_articles":["Article 50"],"provider_or_deployer_role":"deployer","redaction_profile":"minimized","timeline_status":"FINAL"}`

// An invalid profile in a JSON file over 2 MiB was skipped by size, and the
// check said "no JSON file in the pack carries an eu_ai_act_profile object".
func TestEUAIActProfile_LargeFilesAreRead(t *testing.T) {
	t.Run("invalid profile in a large file fails", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, "04_EXPORTS/large.json", bigJSONWithProfile(`{}`))
		result := checkEUAIActEvidenceProfile(dir).normalized()
		if result.Status != CheckFailed {
			t.Fatalf("status = %s (%s%s), want FAILED", result.Status, result.Detail, result.Reason)
		}
	})
	t.Run("valid profile in a large file is validated", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, "04_EXPORTS/large.json", bigJSONWithProfile(validEUAIActProfile))
		result := checkEUAIActEvidenceProfile(dir).normalized()
		if result.Status != CheckVerified {
			t.Fatalf("status = %s (%s%s), want VERIFIED", result.Status, result.Detail, result.Reason)
		}
	})
}

// The profile key is found the way a JSON reader finds it: under an escaped
// spelling, in every repeated occurrence, and in each document of a
// line-delimited file.
func TestEUAIActProfile_FindsEveryProfileAJSONReaderWouldSee(t *testing.T) {
	for name, content := range map[string]string{
		"escaped key":                     `{"eu_ai_act_pro\u0066ile":{}}`,
		"repeated key, invalid one first": `{"eu_ai_act_profile":{},"eu_ai_act_profile":` + validEUAIActProfile + `}`,
		"second document of a JSONL file": "{\"a\":1}\n{\"eu_ai_act_profile\":{}}\n",
		"profile followed by garbage":     `{"eu_ai_act_profile":` + validEUAIActProfile + `} trailing garbage`,
		"profile in a truncated document": `{"eu_ai_act_profile":` + validEUAIActProfile + `,"rest":[1,2`,
		"profile that is not an object":   `{"eu_ai_act_profile":"yes"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRaw(t, dir, "profile.json", []byte(content))
			result := checkEUAIActEvidenceProfile(dir).normalized()
			if result.Status != CheckFailed {
				t.Fatalf("status = %s (%s%s), want FAILED", result.Status, result.Detail, result.Reason)
			}
		})
	}
}

// A file that does not parse as JSON and shows no profile is skipped, and the
// reason says so instead of claiming every JSON file was read.
func TestEUAIActProfile_NotRunReasonCountsFilesThatDoNotParse(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "ok.json", []byte(`{"a":1}`))
	writeRaw(t, dir, "broken.json", []byte(`not json at all`))
	result := checkEUAIActEvidenceProfile(dir).normalized()
	if result.Status != CheckNotRun {
		t.Fatalf("status = %s (%s%s), want NOT_RUN", result.Status, result.Detail, result.Reason)
	}
	for _, want := range []string{"1 of 2", "broken.json", "do not parse"} {
		if !strings.Contains(result.Reason, want) {
			t.Errorf("reason %q does not contain %q", result.Reason, want)
		}
	}

	clean := t.TempDir()
	writeRaw(t, clean, "ok.json", []byte(`{"a":1}`))
	if result := checkEUAIActEvidenceProfile(clean).normalized(); result.Status != CheckNotRun || strings.Contains(result.Reason, "do not parse") {
		t.Fatalf("clean pack: status = %s reason = %q", result.Status, result.Reason)
	}
}

func hostEvidenceStatuses(t *testing.T, dir string, opts VerifyOptions) map[string]CheckResult {
	t.Helper()
	out := map[string]CheckResult{}
	for _, result := range checkHostEvidence(dir, opts) {
		out[result.Name] = result.normalized()
	}
	return out
}

// Files named like a correlation or verification report are not read as
// receipt chains. One that holds garbage was skipped by name and the check
// said "pack has no receipt chain files".
func TestHostEvidence_GarbageInAReportFileFails(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "host_evidence/chain-verification.json", []byte("\x00\x01 not json"))

	results := hostEvidenceStatuses(t, dir, VerifyOptions{})
	if _, placeholder := results["host_evidence"]; placeholder {
		t.Fatalf("host evidence reported as absent although a file is there: %+v", results["host_evidence"])
	}
	failed := false
	for name, result := range results {
		if result.Status == CheckFailed && strings.Contains(result.Reason, "host_evidence/chain-verification.json") {
			failed = true
		}
		if result.Status == CheckVerified {
			t.Errorf("%s verified on a garbage file", name)
		}
	}
	if !failed {
		t.Fatalf("no FAILED check names the garbage file: %+v", results)
	}
}

// A receipt chain is a chain whatever its file is called: naming it like a
// report must not take it out of verification.
func TestHostEvidence_ChainNamedLikeAReportIsVerified(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := verifierTestChain(t, priv, hex.EncodeToString(pub))
	// Break the chain: the receipt no longer matches its signature.
	chain.Receipts[0].HostID = "tampered-host"
	data, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeRaw(t, dir, "11_HOST_EVIDENCE/test/chain-verification.json", data)

	results := hostEvidenceStatuses(t, dir, VerifyOptions{ExternalHostKeyHex: hex.EncodeToString(pub)})
	const prefix = "11_HOST_EVIDENCE/test/chain-verification.json:external_host:"
	if results[prefix+"receipts"].Status != CheckVerified {
		t.Fatalf("the chain was not read: %+v", results)
	}
	if results[prefix+"receipt_hash"].Status != CheckFailed {
		t.Fatalf("receipt_hash = %+v, want FAILED for the tampered receipt", results[prefix+"receipt_hash"])
	}
}

// A report that parses is not a chain. The check stays NOT_RUN and its reason
// names the file it did not read as one.
func TestHostEvidence_NotRunReasonNamesReportFiles(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "host_evidence/correlation.json", []byte(`{"bundle":"x","host_receipts":0,"results":[]}`))

	results := hostEvidenceStatuses(t, dir, VerifyOptions{})
	result, ok := results["host_evidence"]
	if !ok || result.Status != CheckNotRun {
		t.Fatalf("results = %+v, want one NOT_RUN host_evidence result", results)
	}
	if !strings.Contains(result.Reason, "host_evidence/correlation.json") {
		t.Fatalf("reason does not name the report file that was not read as a chain: %q", result.Reason)
	}
}

// file_hashes read whatever path manifest.json named, so "../../outside.txt"
// was VERIFIED "SHA-256 matches manifest.json" for a file that is not in the
// pack. A manifest path must stay inside the pack directory.
func TestFileHashes_RefusePathsOutsideThePack(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sub", "pack")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := []byte("not part of the pack")
	writeRaw(t, root, "outside.txt", outside)
	writeRaw(t, dir, "inside/data.json", []byte(`{"ok":true}`))
	outsideHash := sha256Hex(outside)
	insideHash := sha256Hex([]byte(`{"ok":true}`))

	cases := map[string]string{
		"parent directory":          "../../outside.txt",
		"parent after a directory":  "inside/../../../outside.txt",
		"dot-dot that stays inside": "inside/../inside/data.json",
		"absolute path":             filepath.Join(root, "outside.txt"),
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(root, "outside.txt"), filepath.Join(dir, "link.txt")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(root, filepath.Join(dir, "linkdir")); err != nil {
			t.Fatal(err)
		}
		cases["symlink to a file outside"] = "link.txt"
		cases["through a symlinked directory"] = "linkdir/outside.txt"
	}
	for name, manifestPath := range cases {
		t.Run(name, func(t *testing.T) {
			hash := outsideHash
			if name == "dot-dot that stays inside" {
				hash = insideHash
			}
			writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{"file_hashes": map[string]string{manifestPath: hash}})
			results := checkFileHashes(dir)
			if len(results) != 1 {
				t.Fatalf("results = %+v, want one", results)
			}
			result := results[0].normalized()
			if result.Status != CheckFailed {
				t.Fatalf("%s = %s (%s%s), want FAILED", result.Name, result.Status, result.Detail, result.Reason)
			}
			if !strings.Contains(result.Reason, "outside the pack") && !strings.Contains(result.Reason, "..") {
				t.Fatalf("reason does not say the path leaves the pack: %q", result.Reason)
			}
		})
	}

	// The control: a nested path inside the pack still verifies.
	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{"file_hashes": map[string]string{"inside/data.json": insideHash}})
	if results := checkFileHashes(dir); len(results) != 1 || results[0].normalized().Status != CheckVerified {
		t.Fatalf("nested path inside the pack = %+v, want VERIFIED", results)
	}
}

// index_integrity and file_hashes share one containment rule, so an indexed
// path that resolves outside the pack through a symbolic link fails too.
func TestIndexIntegrity_RefusesPathsOutsideThePack(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pack")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := []byte("not part of the pack")
	writeRaw(t, root, "outside.txt", outside)

	cases := map[string]string{
		"parent directory":          "../outside.txt",
		"dot-dot that stays inside": "a/../01_SCORE.json",
		"absolute path":             filepath.Join(root, "outside.txt"),
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(root, "outside.txt"), filepath.Join(dir, "link.txt")); err != nil {
			t.Fatal(err)
		}
		cases["symlink to a file outside"] = "link.txt"
	}
	writeRaw(t, dir, "01_SCORE.json", outside)
	for name, indexedPath := range cases {
		t.Run(name, func(t *testing.T) {
			writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{"entries": []any{
				map[string]any{"path": indexedPath, "sha256": sha256Hex(outside)},
			}})
			result := checkIndex(dir).normalized()
			if result.Status != CheckFailed {
				t.Fatalf("status = %s (%s%s), want FAILED", result.Status, result.Detail, result.Reason)
			}
		})
	}
}
