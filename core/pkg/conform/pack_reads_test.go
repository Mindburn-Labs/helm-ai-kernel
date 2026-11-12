package conform

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// signedReportPack writes 00_INDEX.json and 01_SCORE.json under a fresh pack
// directory, signs the conformance report, and returns the pack directory, a
// directory beside it that is not part of it, and the verifier that accepts
// the signature.
func signedReportPack(t *testing.T, index string) (pack, outside string, verify func([]byte, string) error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	root := t.TempDir()
	pack = filepath.Join(root, "pack")
	outside = filepath.Join(root, "outside")
	for _, dir := range []string{filepath.Join(pack, "07_ATTESTATIONS"), outside} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{"00_INDEX.json": index, "01_SCORE.json": `{"score":100}`} {
		if err := os.WriteFile(filepath.Join(pack, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sign := func(data []byte) (string, error) {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	}
	if _, err := SignReport(pack, "policyhash", "schemabundlehash", "tester", sign); err != nil {
		t.Fatal(err)
	}
	verify = func(data []byte, sig string) error {
		want, _ := sign(data)
		if sig != want {
			return fmt.Errorf("signature mismatch")
		}
		return nil
	}
	return pack, outside, verify
}

// moveOut moves the pack file rel to the outside directory and links rel to
// it, so the pack names the same bytes from a file it does not hold.
func moveOut(t *testing.T, pack, outside, rel string) {
	t.Helper()
	inside := filepath.Join(pack, filepath.FromSlash(rel))
	target := filepath.Join(outside, strings.ReplaceAll(rel, "/", "_"))
	if err := os.Rename(inside, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, inside); err != nil {
		t.Fatal(err)
	}
}

// F6: the conformance signature check `verify` adds read the signature, the
// index and the score by path and followed a symbolic link out of the pack,
// so a signature over files the pack does not hold verified. It reads through
// an os.Root on the pack directory now and refuses the link.
func TestVerifyReportReadsOnlyFromInsideThePack(t *testing.T) {
	for _, rel := range []string{"00_INDEX.json", "01_SCORE.json", "07_ATTESTATIONS/conformance_report.sig"} {
		t.Run(rel, func(t *testing.T) {
			pack, outside, verify := signedReportPack(t, `{"ok":true}`)
			if err := VerifyReport(pack, verify); err != nil {
				t.Fatalf("VerifyReport on the signed pack: %v", err)
			}
			moveOut(t, pack, outside, rel)
			err := VerifyReport(pack, verify)
			if err == nil {
				t.Fatalf("VerifyReport verified with %s linked from outside the pack", rel)
			}
			if !strings.Contains(err.Error(), "outside the pack") {
				t.Fatalf("error %q does not say %s is outside the pack", err, rel)
			}
		})
	}
}

// The layout check takes the extensions 00_INDEX.json declares. An index
// linked from outside the pack declared extensions the pack does not.
func TestDeclaredExtensionsAreReadOnlyFromInsideThePack(t *testing.T) {
	pack, outside, _ := signedReportPack(t, `{"extensions":["ext-a"]}`)
	if got := declaredEvidencePackExtensions(pack); len(got) != 1 || got[0] != "ext-a" {
		t.Fatalf("extensions of the pack's own index = %v, want [ext-a]", got)
	}
	moveOut(t, pack, outside, "00_INDEX.json")
	if got := declaredEvidencePackExtensions(pack); got != nil {
		t.Fatalf("extensions read through a link out of the pack: %v", got)
	}
}
