package conform

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReportSigningAndVerification_IsReachable(t *testing.T) {
	evidenceDir := t.TempDir()
	requireEvidence := func(name string, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(evidenceDir, name), []byte(data), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	requireEvidence("00_INDEX.json", `{"ok":true}`)
	requireEvidence("01_SCORE.json", `{"score":100}`)
	if err := os.MkdirAll(filepath.Join(evidenceDir, "07_ATTESTATIONS"), 0750); err != nil {
		t.Fatalf("mkdir attestations: %v", err)
	}

	signer := func(data []byte) (string, error) {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	}

	_, err := SignReport(evidenceDir, "policyhash", "schemabundlehash", "tester", signer)
	if err != nil {
		t.Fatalf("SignReport: %v", err)
	}

	verifier := func(data []byte, sig string) error {
		want, err := signer(data)
		if err != nil {
			return err
		}
		if sig != want {
			return fmt.Errorf("signature mismatch: want %q got %q", want, sig)
		}
		return nil
	}

	if err := VerifyReport(evidenceDir, verifier); err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
}

func TestAllReasonCodes_IsReachable(t *testing.T) {
	codes := AllReasonCodes()
	if len(codes) == 0 {
		t.Fatal("expected non-empty reason code list")
	}
}
