package skillpacks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

func TestLoadDirBoundsBothInputsBeforeScanning(t *testing.T) {
	for _, name := range []string{"SKILL.md", "skillpack.json"} {
		t.Run(name, func(t *testing.T) {
			dir := writeTestSkill(t, testManifest("test/bounded"), "safe skill")
			var input string
			if name == "SKILL.md" {
				// An absent content_hash is computed by the loader. Both sizes
				// remain valid instructions independently of the read limit.
				manifest := testManifest("test/bounded")
				manifest.ContentHash = ""
				data, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(dir, "skillpack.json"), string(data))
				input = strings.Repeat("a", maxPackFileBytes)
			} else {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				// JSON permits trailing whitespace; the oversized input is
				// otherwise the same valid manifest as the accepted input.
				input = string(data) + strings.Repeat(" ", maxPackFileBytes-len(data))
			}
			writeTestFile(t, filepath.Join(dir, name), input)
			if _, err := LoadDir(dir); err != nil {
				t.Fatalf("valid input exactly at limit: %v", err)
			}
			writeTestFile(t, filepath.Join(dir, name), input+" ")
			if _, err := LoadDir(dir); !errors.Is(err, packfs.ErrTooLarge) {
				t.Fatalf("oversized %s: got %v, want read-limit error", name, err)
			}
		})
	}
}

func TestLoadDirNeverReadsInputsOutsideThePack(t *testing.T) {
	for _, name := range []string{"SKILL.md", "skillpack.json"} {
		t.Run(name, func(t *testing.T) {
			dir := writeTestSkill(t, testManifest("test/contained"), "safe skill")
			input := filepath.Join(dir, name)
			outside := filepath.Join(t.TempDir(), name)
			if err := os.Rename(input, outside); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, input); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			if _, err := LoadDir(dir); !errors.Is(err, packfs.ErrOutside) {
				t.Fatalf("external %s: got %v, want containment error", name, err)
			}
		})
	}
}

func TestLoadDirReportsAnUnreadableManifest(t *testing.T) {
	dir := writeTestSkill(t, testManifest("test/unreadable"), "safe skill")
	path := filepath.Join(dir, "skillpack.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); !errors.Is(err, packfs.ErrNotRegular) {
		t.Fatalf("manifest directory: got %v, want non-regular-file error", err)
	}
}
