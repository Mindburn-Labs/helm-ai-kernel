package verifier

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// NF1: every repeat of the member was captured, unmarshalled, validated and
// joined into one reason. A 60 MiB file of `"eu_ai_act_profile":{},` took
// 12.7 GB and printed a 1.3 GB result. The scan validates at most 1024
// profiles per pack and fails by name at the file that holds more; the reason
// lists at most 10 issues and counts the rest.
func TestEUAIActProfile_ProfilesPastTheCapFailByName(t *testing.T) {
	const maxProfiles = 1024
	profiles := func(n int, profile string) []byte {
		return []byte(`{` + strings.Repeat(`"eu_ai_act_profile":`+profile+`,`, n) + `"x":0}`)
	}

	t.Run("a valid profile past the cap", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, "12_REPORTS/a.json", profiles(maxProfiles-1, validEUAIActProfile))
		writeRaw(t, dir, "12_REPORTS/b.json", profiles(2, validEUAIActProfile))
		result := checkEUAIActEvidenceProfile(dir).normalized()
		if result.Status != CheckFailed {
			t.Fatalf("status = %s (%.300s%.300s), want FAILED past %d profiles", result.Status, result.Detail, result.Reason, maxProfiles)
		}
		for _, want := range []string{"12_REPORTS/b.json", fmt.Sprint(maxProfiles)} {
			if !strings.Contains(result.Reason, want) {
				t.Errorf("reason %q does not contain %q", result.Reason, want)
			}
		}
	})

	t.Run("the cap itself is validated", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, "12_REPORTS/a.json", profiles(maxProfiles, validEUAIActProfile))
		if result := checkEUAIActEvidenceProfile(dir).normalized(); result.Status != CheckVerified {
			t.Fatalf("status = %s (%.300s%.300s), want VERIFIED with %d valid profiles", result.Status, result.Detail, result.Reason, maxProfiles)
		}
	})

	t.Run("issues are summarized", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, "12_REPORTS/a.json", profiles(50, `{}`))
		result := checkEUAIActEvidenceProfile(dir).normalized()
		if result.Status != CheckFailed || !strings.Contains(result.Reason, "profile[0]: ") || !strings.Contains(result.Reason, " more") {
			t.Fatalf("status = %s (%.500s), want FAILED listing the first issues and counting the rest", result.Status, result.Reason)
		}
		if len(result.Reason) > 4096 {
			t.Fatalf("reason holds %d bytes for 50 profiles, want at most 4096", len(result.Reason))
		}
	})

	t.Run("the reviewer's 60 MiB file", func(t *testing.T) {
		dir := t.TempDir()
		member := []byte(`"eu_ai_act_profile":{},`)
		content := append([]byte(`{`), bytes.Repeat(member, (60<<20)/len(member))...)
		writeRaw(t, dir, "12_REPORTS/p.json", append(content, `"x":0}`...))
		content = nil

		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		result := checkEUAIActEvidenceProfile(dir).normalized()
		runtime.ReadMemStats(&after)
		t.Logf("reason: %d bytes, scan allocated %d MiB: %.200s", len(result.Reason), (after.TotalAlloc-before.TotalAlloc)>>20, result.Reason)

		if result.Status != CheckFailed || !strings.Contains(result.Reason, "12_REPORTS/p.json") {
			t.Errorf("status = %s (%.300s), want FAILED naming 12_REPORTS/p.json", result.Status, result.Reason)
		}
		if len(result.Reason) > 4096 {
			t.Errorf("reason holds %d bytes, want at most 4096", len(result.Reason))
		}
		// The file is read whole once (64 MiB at most, and io.ReadAll grows
		// its buffer by doubling); nothing proportional to the number of
		// members is allocated.
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 512<<20 {
			t.Errorf("the scan allocated %d MiB for a 60 MiB file, want at most 512 MiB", allocated>>20)
		}
	})
}

// NF9: encoding/json matches a member to a struct field in any letter case,
// so the Go readers of a pack (contracts.EvidencePack, the export manifest)
// take `EU_AI_ACT_PROFILE` as the profile. The scan matched the name only as
// written and left such a pack NOT_RUN.
func TestEUAIActProfile_TheMemberNameMatchesInAnyLetterCase(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		want    CheckStatus
	}{
		"upper case, invalid":          {`{"EU_AI_ACT_PROFILE":{}}`, CheckFailed},
		"mixed case, valid":            {`{"Eu_Ai_Act_Profile":` + validEUAIActProfile + `}`, CheckVerified},
		"escaped upper case":           {`{"EU_AI_ACT_PROFILE":{}}`, CheckFailed},
		"upper case in a damaged file": {`{"a": tru, "EU_AI_ACT_PROFILE":` + validEUAIActProfile + `}`, CheckFailed},
		"upper case as plain text":     {`{EU_AI_ACT_PROFILE: {}}`, CheckFailed},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRaw(t, dir, "12_REPORTS/upper.json", []byte(tc.content))
			if result := checkEUAIActEvidenceProfile(dir).normalized(); result.Status != tc.want {
				t.Fatalf("status = %s (%s%s), want %s", result.Status, result.Detail, result.Reason, tc.want)
			}
		})
	}
}

// NF4 (N11): a damaged file that holds the member name only as plain text,
// where the scan cannot read it as a member, still fails: a reader that
// repairs the file would find the profile there.
func TestEUAIActProfile_ADamagedFileThatNamesTheProfileAsPlainTextFails(t *testing.T) {
	for name, content := range map[string]string{
		"an unquoted member name":      `{eu_ai_act_profile: {"profile_id": "x"}}`,
		"the name as a string value":   `["eu_ai_act_profile", tru]`,
		"the name in a later document": `{"a":1}` + "\n" + `{"note": eu_ai_act_profile}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRaw(t, dir, "12_REPORTS/damaged.json", []byte(content))
			result := checkEUAIActEvidenceProfile(dir).normalized()
			if result.Status != CheckFailed || !strings.Contains(result.Reason, "12_REPORTS/damaged.json") {
				t.Fatalf("status = %s (%s%s), want FAILED naming 12_REPORTS/damaged.json", result.Status, result.Detail, result.Reason)
			}
		})
	}
}
