package verifier

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests hold the rule that the verifier reads a pack only from inside
// the pack directory, only from regular files, and within a bounded amount of
// work, whatever the pack holds.

// A file nested deeper than encoding/json accepts used to send the EU AI Act
// scan into one recursive call per level. Four million "[" overflowed the
// goroutine stack, a fatal error no caller of VerifyBundleWithOptions can
// recover from. The scan now stops where encoding/json does, at depth 10000,
// and treats the file like any other that does not parse.
func TestEUAIActProfile_DeeplyNestedFileIsAJSONErrorNotACrash(t *testing.T) {
	const fiveMB = 5 << 20
	for _, tc := range []struct {
		name    string
		content []byte
		want    CheckStatus
		inText  string
	}{
		{name: "nested arrays", content: bytes.Repeat([]byte("["), fiveMB), want: CheckNotRun, inText: "do not parse"},
		{name: "nested objects", content: bytes.Repeat([]byte(`{"a":`), fiveMB/5), want: CheckNotRun, inText: "do not parse"},
		{
			// A profile before the damage still makes the file a profile
			// carrier that a reader cannot use.
			name:    "nested arrays after a profile",
			content: append([]byte(`[{"eu_ai_act_profile":`+validEUAIActProfile+`},`), bytes.Repeat([]byte("["), fiveMB)...),
			want:    CheckFailed,
			inText:  "does not parse",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRaw(t, dir, "12_REPORTS/deep.json", tc.content)
			result := checkEUAIActEvidenceProfile(dir).normalized()
			if result.Status != tc.want {
				t.Fatalf("status = %s (%s%s), want %s", result.Status, result.Detail, result.Reason, tc.want)
			}
			if text := result.Detail + result.Reason; !strings.Contains(text, tc.inText) || !strings.Contains(text, "12_REPORTS/deep.json") {
				t.Fatalf("result %q does not name the file and say %q", text, tc.inText)
			}
		})
	}
}

// The in-process callers (launch, mcp proof, conform) reach the scan through
// VerifyBundleWithOptions. A deeply nested file that the pack does not index
// must leave them a report, not a dead process.
func TestVerifyBundle_DeeplyNestedJSONLeavesTheCallerAReport(t *testing.T) {
	dir := createValidBundleFixture(t)
	writeRaw(t, dir, "12_REPORTS/deep.json", bytes.Repeat([]byte("["), 5<<20))

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{AllowSelfAttested: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatalf("pack with an unindexed file verified: %s", report.Summary)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "eu_ai_act_profile" {
			found = true
		}
	}
	if !found {
		t.Fatal("eu_ai_act_profile reported nothing")
	}
}

// A .json file larger than the scan reads is named in a FAILED result: an
// eu_ai_act_profile in it would otherwise go unvalidated while the check said
// the pack carries none. The file here is sparse, so it costs no disk.
func TestEUAIActProfile_AFileOverTheReadLimitIsNamed(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "ok.json", []byte(`{"a":1}`))
	path := filepath.Join(dir, "04_EXPORTS", "huge.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(64<<20 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	result := checkEUAIActEvidenceProfile(dir).normalized()
	if result.Status != CheckFailed {
		t.Fatalf("status = %s (%s%s), want FAILED for a file the scan did not read", result.Status, result.Detail, result.Reason)
	}
	for _, want := range []string{"04_EXPORTS/huge.json", "not read", "limit"} {
		if !strings.Contains(result.Reason, want) {
			t.Errorf("reason %q does not contain %q", result.Reason, want)
		}
	}
}

// S2: every profile in a file is validated, not only the first. A valid
// profile before an invalid one must not hide it.
func TestEUAIActProfile_AnInvalidProfileAfterAValidOneFails(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "profiles.json", []byte(`{"eu_ai_act_profile":`+validEUAIActProfile+`,"eu_ai_act_profile":{}}`))
	result := checkEUAIActEvidenceProfile(dir).normalized()
	if result.Status != CheckFailed {
		t.Fatalf("status = %s (%s%s), want FAILED", result.Status, result.Detail, result.Reason)
	}
	if !strings.Contains(result.Reason, "profile[1]") || strings.Contains(result.Reason, "profile[0]") {
		t.Fatalf("reason %q should fault the second profile only", result.Reason)
	}
}

// N6: a UTF-8 byte order mark is read past, the way JSON readers that accept
// one (Python's utf-8-sig) read the file. An invalid profile behind it used to
// leave the check NOT_RUN ("do not parse").
func TestEUAIActProfile_AByteOrderMarkDoesNotHideAProfile(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "bom.json", append([]byte("\xef\xbb\xbf"), []byte(`{"eu_ai_act_profile":{}}`)...))
	result := checkEUAIActEvidenceProfile(dir).normalized()
	if result.Status != CheckFailed || !strings.Contains(result.Reason, "profile[0]") {
		t.Fatalf("status = %s (%s%s), want FAILED on the profile behind the byte order mark", result.Status, result.Detail, result.Reason)
	}
}

// N6: a file that does not parse but names the profile member is a profile
// carrier a reader cannot use, whether the damage comes before the profile or
// after it.
func TestEUAIActProfile_AFileThatNamesTheProfileAndDoesNotParseFails(t *testing.T) {
	for name, content := range map[string]string{
		"damaged before the profile": `{"a": tru, "eu_ai_act_profile":` + validEUAIActProfile + `}`,
		"damaged after the profile":  `{"eu_ai_act_profile":` + validEUAIActProfile + `, "a": tru}`,
		"damaged inside the profile": `{"eu_ai_act_profile":{"profile_id": }}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRaw(t, dir, "damaged.json", []byte(content))
			result := checkEUAIActEvidenceProfile(dir).normalized()
			if result.Status != CheckFailed || !strings.Contains(result.Reason, "damaged.json") {
				t.Fatalf("status = %s (%s%s), want FAILED naming damaged.json", result.Status, result.Detail, result.Reason)
			}
		})
	}
}

// outsideFixture builds a pack directory beside a directory that is not part
// of it, and returns both.
func outsideFixture(t *testing.T) (pack, outside string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	root := t.TempDir()
	pack = filepath.Join(root, "pack")
	outside = filepath.Join(root, "outside")
	for _, dir := range []string{pack, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return pack, outside
}

// linkOut writes content outside the pack and links rel inside the pack to it.
func linkOut(t *testing.T, pack, outside, rel string, content []byte) {
	t.Helper()
	target := filepath.Join(outside, strings.ReplaceAll(rel, "/", "_"))
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(pack, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// F6: fixed-name reads, walk-based scans and receipts followed a symbolic link
// out of the pack and judged the file there. A determinism manifest linked to
// an outside file with equal hashes made replay_determinism VERIFIED. Every
// pack file is now read through one os.Root, so a link that leaves the pack is
// refused and the check that wanted the file fails.
func TestChecksRefuseFilesLinkedFromOutsideThePack(t *testing.T) {
	validConnector := []byte(`{"connector_contract_hash":"sha256:contract","policy_hash":"sha256:policy","request_hash":"sha256:request",` +
		`"response_hash":"sha256:response","source_url_hashes":["sha256:source"],"receipt_ref":"receipt:1","evidence_pack_ref":"pack:1"}`)
	for _, tc := range []struct {
		name    string
		rel     string
		content []byte
		setup   func(t *testing.T, pack string)
		check   func(dir string) []CheckResult
	}{
		{
			name:    "determinism manifest",
			rel:     "02_PROOFGRAPH/determinism_manifest.json",
			content: []byte(`{"live_hash":"a","replay_hash":"a"}`),
			check:   func(dir string) []CheckResult { return []CheckResult{checkReplayDeterminism(dir)} },
		},
		{
			name:    "tape manifest",
			rel:     "08_TAPES/tape_manifest.json",
			content: []byte(`{"run_id":"r","entries":[]}`),
			setup: func(t *testing.T, pack string) {
				writeRaw(t, pack, "02_PROOFGRAPH/determinism_manifest.json", []byte(`{"live_hash":"a","replay_hash":"a"}`))
			},
			check: func(dir string) []CheckResult { return []CheckResult{checkReplayDeterminism(dir)} },
		},
		{
			name:    "connector evidence",
			rel:     "connector_evidence.json",
			content: validConnector,
			check:   func(dir string) []CheckResult { return []CheckResult{checkConnectorEvidence(dir)} },
		},
		{
			name:    "eu ai act profile in a walked directory",
			rel:     "12_REPORTS/eu.json",
			content: []byte(`{"eu_ai_act_profile":` + validEUAIActProfile + `}`),
			check:   func(dir string) []CheckResult { return []CheckResult{checkEUAIActEvidenceProfile(dir)} },
		},
		{
			name:    "manifest",
			rel:     "manifest.json",
			content: []byte(`{"file_hashes":{"inside.txt":"` + sha256Hex([]byte("inside")) + `"}}`),
			setup:   func(t *testing.T, pack string) { writeRaw(t, pack, "inside.txt", []byte("inside")) },
			check:   checkFileHashes,
		},
		{
			name:    "index",
			rel:     "00_INDEX.json",
			content: []byte(`{"entries":[{"path":"inside.txt","sha256":"` + sha256Hex([]byte("inside")) + `"}]}`),
			setup:   func(t *testing.T, pack string) { writeRaw(t, pack, "inside.txt", []byte("inside")) },
			check:   func(dir string) []CheckResult { return []CheckResult{checkIndex(dir)} },
		},
		{
			name:    "receipt",
			rel:     "receipts/receipt-001.json",
			content: []byte(`{"receipt_id":"rcpt-001","decision_id":"dec-001","decision_hash":"sha256:abc","lamport_clock":1}`),
			check:   func(dir string) []CheckResult { return []CheckResult{checkPolicyDecisionHashes(dir)} },
		},
		{
			name:    "proof graph",
			rel:     "proofgraph.json",
			content: []byte(`{"nodes":[],"edges":[]}`),
			setup: func(t *testing.T, pack string) {
				writeRaw(t, pack, "receipts/receipt-001.json", []byte(`{"receipt_id":"rcpt-001","decision_hash":"sha256:abc","lamport_clock":1}`))
			},
			check: func(dir string) []CheckResult { return []CheckResult{checkChainIntegrity(dir)} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pack, outside := outsideFixture(t)
			if tc.setup != nil {
				tc.setup(t, pack)
			}
			linkOut(t, pack, outside, tc.rel, tc.content)
			for _, result := range tc.check(pack) {
				result = result.normalized()
				if result.Status == CheckVerified {
					t.Fatalf("%s VERIFIED on a file outside the pack: %s", result.Name, result.Detail)
				}
				if result.Status != CheckFailed {
					t.Fatalf("%s = %s (%s), want FAILED: the pack names a file it does not hold", result.Name, result.Status, result.Reason)
				}
				if !strings.Contains(result.Reason, "outside the pack") {
					t.Fatalf("%s reason does not say the file is outside the pack: %q", result.Name, result.Reason)
				}
			}
		})
	}
}

// NF4 (N09): a receipts directory linked out of the pack is refused, not
// taken for a missing one. Read as missing, the checks fell back to
// 02_PROOFGRAPH/receipts and judged the pack on the receipts there.
func TestReceiptsDirectoryLinkedOutOfThePackFails(t *testing.T) {
	pack, outside := outsideFixture(t)
	receipt := []byte(`{"receipt_id":"rcpt-001","decision_id":"dec-001","decision_hash":"sha256:abc","lamport_clock":1}`)
	writeRaw(t, pack, "02_PROOFGRAPH/receipts/receipt-001.json", receipt)
	writeRaw(t, outside, "receipts/receipt-001.json", receipt)
	if err := os.Symlink(filepath.Join(outside, "receipts"), filepath.Join(pack, "receipts")); err != nil {
		t.Fatal(err)
	}
	for _, result := range []CheckResult{checkPolicyDecisionHashes(pack), checkChainIntegrity(pack), checkLamportMonotonicity(pack)} {
		result = result.normalized()
		if result.Status != CheckFailed || !strings.Contains(result.Reason, "receipts is not read") || !strings.Contains(result.Reason, "outside the pack") {
			t.Errorf("%s = %s (%s%s), want FAILED: receipts is a link out of the pack", result.Name, result.Status, result.Detail, result.Reason)
		}
	}
}

// N3: whether a pack is named by a relative or an absolute path must not
// change what is read. A symbolic link with an absolute target that points
// back into the pack was refused for one spelling of the pack path and read
// for the other. Absolute links are refused for both.
func TestPackContainmentDoesNotDependOnHowThePackPathIsWritten(t *testing.T) {
	pack, _ := outsideFixture(t)
	writeRaw(t, pack, "inside.txt", []byte("inside"))
	if err := os.Symlink(filepath.Join(pack, "inside.txt"), filepath.Join(pack, "out-and-back.txt")); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(pack, "manifest.json"), map[string]any{"file_hashes": map[string]string{"out-and-back.txt": sha256Hex([]byte("inside"))}})

	statusFor := func(bundlePath string) CheckStatus {
		results := checkFileHashes(bundlePath)
		if len(results) != 1 {
			t.Fatalf("results = %+v, want one", results)
		}
		return results[0].normalized().Status
	}
	absolute := statusFor(pack)
	t.Chdir(filepath.Dir(pack))
	relative := statusFor(filepath.Base(pack))
	if absolute != relative {
		t.Fatalf("absolute pack path gives %s, relative gives %s", absolute, relative)
	}
	if absolute != CheckFailed {
		t.Fatalf("an absolute symbolic link was followed: %s", absolute)
	}
}

// N4: on a case-insensitive file system a manifest key spelled in another
// letter case named a file anyway, so the same pack verified on macOS and
// failed on Linux. A name a pack states must match the file it names exactly.
func TestFileHashes_NamesMustMatchTheFileExactly(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "01_SCORE.json", []byte(`{"pass":true}`))
	// Both filesystem kinds must produce the same result. On a case-sensitive
	// filesystem the wrong spelling is absent; on a case-insensitive one the
	// verifier must reject the alias even though the OS can resolve it.
	for _, tc := range []struct {
		name string
		want CheckStatus
	}{
		{"01_SCORE.json", CheckVerified},
		{"01_score.JSON", CheckFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{"file_hashes": map[string]string{tc.name: sha256Hex([]byte(`{"pass":true}`))}})
			results := checkFileHashes(dir)
			if len(results) != 1 || results[0].normalized().Status != tc.want {
				t.Fatalf("results = %+v, want one %s: manifest names %s and pack holds 01_SCORE.json", results, tc.want, tc.name)
			}
		})
	}
}
