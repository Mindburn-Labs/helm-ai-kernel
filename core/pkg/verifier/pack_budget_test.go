package verifier

import (
	"strings"
	"testing"
)

// The scan reads at most a fixed number of bytes per pack. The files past that
// budget are named, in walk order, instead of being skipped.
func TestEUAIActProfile_FilesPastThePackBudgetAreNamed(t *testing.T) {
	restore := euAIActScanPackLimit
	t.Cleanup(func() { euAIActScanPackLimit = restore })
	euAIActScanPackLimit = 64

	dir := t.TempDir()
	writeRaw(t, dir, "a.json", []byte(`{"padding":"`+strings.Repeat("x", 40)+`"}`))
	writeRaw(t, dir, "b.json", []byte(`{"padding":"`+strings.Repeat("y", 40)+`"}`))
	writeRaw(t, dir, "c.json", []byte(`{"eu_ai_act_profile":{}}`))

	result := checkEUAIActEvidenceProfile(dir).normalized()
	if result.Status != CheckFailed {
		t.Fatalf("status = %s (%s%s), want FAILED: two files were not read", result.Status, result.Detail, result.Reason)
	}
	for _, want := range []string{"b.json", "c.json", "per pack"} {
		if !strings.Contains(result.Reason, want) {
			t.Errorf("reason %q does not contain %q", result.Reason, want)
		}
	}
	if strings.Contains(result.Reason, "a.json") {
		t.Errorf("reason names a.json, which was read: %q", result.Reason)
	}
}
