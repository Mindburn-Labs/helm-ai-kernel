package conform

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEngineNewHasNoGates(t *testing.T) {
	e := NewEngine()
	if e == nil || len(e.gates) != 0 || len(e.ordered) != 0 {
		t.Fatal("new engine should have empty gates")
	}
}

func TestEngineRegisterGatePreservesOrder(t *testing.T) {
	e := NewEngine()
	e.RegisterGate(&stubGate{id: "GA", name: "Alpha"})
	e.RegisterGate(&stubGate{id: "GB", name: "Beta"})
	if len(e.ordered) != 2 || e.ordered[0] != "GA" || e.ordered[1] != "GB" {
		t.Fatal("gates should be ordered by registration")
	}
}

func TestEngineRegisterDuplicateDoesNotDuplicateOrder(t *testing.T) {
	e := NewEngine()
	e.RegisterGate(&stubGate{id: "GA", name: "v1"})
	e.RegisterGate(&stubGate{id: "GA", name: "v2"})
	if len(e.ordered) != 1 || e.gates["GA"].Name() != "v2" {
		t.Fatal("duplicate gate should overwrite but not duplicate order")
	}
}

func TestEngineClockOverride(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := NewEngine().WithClock(func() time.Time { return fixed })
	if e.clock().Year() != 2026 {
		t.Fatal("clock override should take effect")
	}
}

func TestProfilesContainsRequiredIDs(t *testing.T) {
	profiles := Profiles()
	required := []ProfileID{ProfileSMB, ProfileCore, ProfileEnterprise, ProfileL3}
	for _, id := range required {
		if _, ok := profiles[id]; !ok {
			t.Fatalf("missing profile %s", id)
		}
	}
}

func TestGatesForUnknownProfileReturnsNil(t *testing.T) {
	gates := GatesForProfile("NONEXISTENT")
	if gates != nil {
		t.Fatal("unknown profile should return nil")
	}
}

func TestGatesForSMBIncludesG0(t *testing.T) {
	gates := GatesForProfile(ProfileSMB)
	if len(gates) == 0 {
		t.Fatal("SMB profile should have gates")
	}
	found := false
	for _, g := range gates {
		if g == "G0" {
			found = true
		}
	}
	if !found {
		t.Fatal("SMB should include G0")
	}
}

func TestProfileEnterpriseInheritsCore(t *testing.T) {
	profiles := Profiles()
	if profiles[ProfileEnterprise].Inherits != ProfileCore {
		t.Fatal("Enterprise should inherit from Core")
	}
}

func TestCreateEvidencePackSubdirs(t *testing.T) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("eptest-%d", time.Now().UnixNano()))
	defer os.RemoveAll(dir)
	if err := CreateEvidencePackDirs(dir); err != nil {
		t.Fatalf("create dirs: %v", err)
	}
	for _, sub := range EvidencePackSubdirs {
		if _, err := os.Stat(filepath.Join(dir, sub)); err != nil {
			t.Fatalf("missing subdir %s", sub)
		}
	}
}

func TestValidateEvidencePackMissingFiles(t *testing.T) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("epval-%d", time.Now().UnixNano()))
	defer os.RemoveAll(dir)
	CreateEvidencePackDirs(dir)
	issues := ValidateEvidencePackStructure(dir)
	if len(issues) < 2 {
		t.Fatal("should report missing 00_INDEX.json and 01_SCORE.json")
	}
}

func TestValidateEvidencePackComplete(t *testing.T) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("epfull-%d", time.Now().UnixNano()))
	defer os.RemoveAll(dir)
	CreateEvidencePackDirs(dir)
	os.WriteFile(filepath.Join(dir, "00_INDEX.json"), []byte("{}"), 0600)
	os.WriteFile(filepath.Join(dir, "01_SCORE.json"), []byte("{}"), 0600)
	issues := ValidateEvidencePackStructure(dir)
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

func TestWriteAndCheckPanicRecord(t *testing.T) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("panic-%d", time.Now().UnixNano()))
	defer os.RemoveAll(dir)
	rec := &PanicRecord{Timestamp: time.Now(), RunID: "r1", Reason: "disk full", LastGoodSeq: 42}
	if err := WritePanicRecord(dir, rec); err != nil {
		t.Fatalf("write panic: %v", err)
	}
	got, err := CheckPanicRecord(dir)
	if err != nil || got == nil || got.LastGoodSeq != 42 {
		t.Fatalf("check panic failed: %v, got=%+v", err, got)
	}
}

func TestCheckPanicRecordNoneExists(t *testing.T) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("nopanic-%d", time.Now().UnixNano()))
	defer os.RemoveAll(dir)
	os.MkdirAll(dir, 0750)
	got, err := CheckPanicRecord(dir)
	if err != nil || got != nil {
		t.Fatalf("expected nil panic record, got %+v, err=%v", got, err)
	}
}

func TestAllReasonCodesCountAbove20(t *testing.T) {
	codes := AllReasonCodes()
	if len(codes) < 20 {
		t.Fatalf("expected at least 20 reason codes, got %d", len(codes))
	}
}

func TestInferContentTypeMapping(t *testing.T) {
	cases := map[string]string{".json": "application/json", ".sig": "application/pgp-signature", ".bin": "application/octet-stream"}
	for ext, want := range cases {
		got := inferContentType("file" + ext)
		if got != want {
			t.Fatalf("inferContentType(%s): expected %s, got %s", ext, want, got)
		}
	}
}
