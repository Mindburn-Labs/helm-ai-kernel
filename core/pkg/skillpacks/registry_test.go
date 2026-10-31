package skillpacks

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFirstPartyRegistryPacksAreDiscoverableAndAllowed keeps every shipped
// first-party pack loadable, scan-clean, and discoverable by agents that read
// SKILL.md frontmatter (name matching the directory, a one-line description).
func TestFirstPartyRegistryPacksAreDiscoverableAndAllowed(t *testing.T) {
	root := firstPartyRepoRoot(t)
	var dirs []string
	err := filepath.WalkDir(filepath.Join(root, "registry", "skills"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "skillpack.json" {
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("no first-party skill packs found under registry/skills")
	}
	for _, dir := range dirs {
		dir := dir
		t.Run(filepath.Base(dir), func(t *testing.T) {
			pack, err := LoadDir(dir)
			if err != nil {
				t.Fatalf("LoadDir: %v", err)
			}
			front := skillFrontmatter(pack.SkillMD)
			if front["name"] != filepath.Base(dir) {
				t.Fatalf("frontmatter name = %q, want %q", front["name"], filepath.Base(dir))
			}
			if desc := front["description"]; desc == "" || len(desc) > 200 {
				t.Fatalf("frontmatter description must be one short sentence, got %q", desc)
			}
			result, err := Scan(pack)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if result.Verdict != VerdictAllow {
				t.Fatalf("Scan verdict = %s (%s), findings=%+v", result.Verdict, result.ReasonCode, result.Findings)
			}
		})
	}
}

// firstPartyRepoRoot walks up from the test directory to the repository root.
// findRepoRoot is not used because it also matches the Go package directory
// core/pkg/registry/skills.
func firstPartyRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, errMod := os.Stat(filepath.Join(dir, "core", "go.mod"))
		_, errReg := os.Stat(filepath.Join(dir, "registry", "skills", "helm"))
		if errMod == nil && errReg == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("repository root with registry/skills/helm not found")
		}
		dir = next
	}
}

// skillFrontmatter returns the single-line key/value pairs of a leading
// "---" delimited YAML block, or an empty map when there is none.
func skillFrontmatter(skillMD string) map[string]string {
	out := map[string]string{}
	rest, ok := strings.CutPrefix(skillMD, "---\n")
	if !ok {
		return out
	}
	block, _, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return out
	}
	for _, line := range strings.Split(block, "\n") {
		if key, value, found := strings.Cut(line, ":"); found {
			out[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}
