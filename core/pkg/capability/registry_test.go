package capability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDir_Valid(t *testing.T) {
	reg, err := LoadDir(filepath.Join("testdata", "valid"))
	if err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}
	if reg.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", reg.Len())
	}
	entry := reg.Resolve("helm.cap.gui.gelab.tap")
	if entry == nil {
		t.Fatal("expected tap manifest to resolve")
	}
	if entry.Manifest.EffectClass != EffectWriteExternal {
		t.Fatalf("unexpected effect class: %s", entry.Manifest.EffectClass)
	}
	if entry.Hash == "" || len(entry.Hash) != len("sha256:")+64 {
		t.Fatalf("manifest hash malformed: %q", entry.Hash)
	}
	if reg.Resolve("helm.cap.does.not.exist") != nil {
		t.Fatal("unknown capability must not resolve")
	}
	ids := reg.IDs()
	if len(ids) != 2 || ids[0] != "helm.cap.fs.read" || ids[1] != "helm.cap.gui.gelab.tap" {
		t.Fatalf("IDs not sorted as expected: %v", ids)
	}
}

func TestLoadDir_HashDeterministic(t *testing.T) {
	reg, err := LoadDir(filepath.Join("testdata", "valid"))
	if err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}
	entry := reg.Resolve("helm.cap.gui.gelab.tap")
	again, err := HashManifest(&entry.Manifest)
	if err != nil {
		t.Fatalf("HashManifest failed: %v", err)
	}
	if again != entry.Hash {
		t.Fatalf("hash not deterministic: %s vs %s", again, entry.Hash)
	}
}

func TestLoadDir_RejectsInvalidManifest(t *testing.T) {
	if _, err := LoadDir(filepath.Join("testdata", "invalid")); err == nil {
		t.Fatal("expected load failure for manifest missing rollback plan ref")
	}
}

func TestLoadDir_RejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join("testdata", "valid", "tap.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), src, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected duplicate capability_id load failure")
	}
}

func TestLoadDir_Errors(t *testing.T) {
	if _, err := LoadDir(filepath.Join("testdata", "does-not-exist")); err == nil {
		t.Fatal("expected error for missing directory")
	}
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Fatal("expected error for empty directory")
	}
}

func TestResolve_NilRegistry(t *testing.T) {
	var reg *Registry
	if reg.Resolve("helm.cap.gui.gelab.tap") != nil {
		t.Fatal("nil registry must resolve nothing")
	}
	if reg.Len() != 0 {
		t.Fatal("nil registry length must be 0")
	}
}
