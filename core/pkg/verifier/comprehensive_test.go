package verifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBundle_NotADirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(f, []byte("hi"), 0o644)
	r, err := VerifyBundle(f)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verified {
		t.Fatal("non-directory bundle should fail")
	}
}

func TestVerifyBundle_NonexistentPath(t *testing.T) {
	r, _ := VerifyBundle("/tmp/nonexistent-bundle-xyz-99999")
	if r.Verified {
		t.Fatal("nonexistent path should fail")
	}
}

func TestVerifyBundle_EmptyReceiptsDir(t *testing.T) {
	dir := createValidBundleFixture(t)
	receiptsDir := filepath.Join(dir, "receipts")
	entries, _ := os.ReadDir(receiptsDir)
	for _, e := range entries {
		os.Remove(filepath.Join(receiptsDir, e.Name()))
	}
	r, _ := VerifyBundle(dir)
	if r.Verified {
		t.Fatal("empty receipts dir should cause failure")
	}
}

func TestVerifyBundle_NoDecisionHash(t *testing.T) {
	dir := createValidBundleFixture(t)
	receiptsDir := filepath.Join(dir, "receipts")
	// Overwrite receipt without decision_hash
	writeJSON(t, filepath.Join(receiptsDir, "receipt-001.json"), map[string]any{"receipt_id": "r1", "status": "ok"})
	r, _ := VerifyBundle(dir)
	if r.Verified {
		t.Fatal("receipts without decision_hash should fail policy_decision_hashes check")
	}
}

func TestVerifyBundle_WithTapesDirectory(t *testing.T) {
	dir := createValidBundleFixture(t)
	tapesDir := filepath.Join(dir, "08_TAPES")
	os.MkdirAll(tapesDir, 0o755)
	os.WriteFile(filepath.Join(tapesDir, "tape1.json"), []byte(`{}`), 0o644)
	r, _ := VerifyBundle(dir)
	found := false
	for _, c := range r.Checks {
		if c.Name == "replay_determinism" && c.Pass {
			found = true
		}
	}
	if !found {
		t.Fatal("replay_determinism check should pass with tapes dir")
	}
}

func TestVerifyBundle_ReportIssueCount(t *testing.T) {
	dir := t.TempDir()
	r, _ := VerifyBundle(dir)
	if r.IssueCount == 0 {
		t.Fatal("empty dir should have issues")
	}
	if r.IssueCount != len(filterFailed(r.Checks)) {
		t.Fatalf("IssueCount %d does not match failed checks %d", r.IssueCount, len(filterFailed(r.Checks)))
	}
}

func TestSha256Hex_Deterministic(t *testing.T) {
	h1 := sha256Hex([]byte("test"))
	h2 := sha256Hex([]byte("test"))
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("sha256Hex should be deterministic 64-char hex: %s", h1)
	}
}

func TestCheckResult_JSONRoundtrip(t *testing.T) {
	cr := CheckResult{Name: "test-check", Pass: true, Detail: "all good"}
	data, _ := json.Marshal(cr)
	var decoded CheckResult
	json.Unmarshal(data, &decoded)
	if decoded.Name != "test-check" || !decoded.Pass {
		t.Fatalf("roundtrip failed: %+v", decoded)
	}
}

func TestFileExists_False(t *testing.T) {
	if fileExists("/tmp/does-not-exist-xyz-99999") {
		t.Fatal("should return false for nonexistent file")
	}
}

func TestDirExists_False(t *testing.T) {
	if dirExists("/tmp/does-not-exist-dir-xyz-99999") {
		t.Fatal("should return false for nonexistent dir")
	}
}

func filterFailed(checks []CheckResult) []CheckResult {
	var out []CheckResult
	for _, c := range checks {
		if !c.Pass {
			out = append(out, c)
		}
	}
	return out
}
