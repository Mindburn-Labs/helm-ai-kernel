package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

type registryFile struct {
	Version string            `json:"version"`
	Codes   []reasonCodeEntry `json:"codes"`
}

type reasonCodeEntry struct {
	Code      string   `json:"code"`
	AppliesTo []string `json:"applies_to"`
}

func TestCanonicalVerdicts_AreStable(t *testing.T) {
	got := CanonicalVerdicts()
	want := []Verdict{VerdictAllow, VerdictDeny, VerdictEscalate}
	if !slices.Equal(got, want) {
		t.Fatalf("canonical verdicts mismatch: got %v want %v", got, want)
	}
}

func TestReasonCodeRegistry_MatchesContracts(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	registryPath := filepath.Join(
		filepath.Dir(thisFile),
		"..", "..", "..",
		"protocols", "json-schemas", "reason-codes", "reason-codes-v1.json",
	)

	var registry registryFile
	loadJSONFile(t, registryPath, &registry)
	if registry.Version != "1.0.0" {
		t.Fatalf("unexpected registry version %q", registry.Version)
	}

	seen := map[string]struct{}{}
	for _, entry := range registry.Codes {
		if entry.Code == "" {
			t.Fatal("registry contains empty reason code")
		}
		if _, exists := seen[entry.Code]; exists {
			t.Fatalf("duplicate reason code %q in registry", entry.Code)
		}
		seen[entry.Code] = struct{}{}
		for _, verdict := range entry.AppliesTo {
			if verdict == string(VerdictAllow) {
				t.Fatalf("reason code %q incorrectly applies to ALLOW", entry.Code)
			}
			if !IsCanonicalVerdict(verdict) {
				t.Fatalf("reason code %q has non-canonical verdict %q", entry.Code, verdict)
			}
		}
	}

	var got []string
	for _, reason := range CoreReasonCodes() {
		got = append(got, string(reason))
	}
	slices.Sort(got)

	var want []string
	for _, entry := range registry.Codes {
		want = append(want, entry.Code)
	}
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Fatalf("core reason-code registry mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func loadJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
