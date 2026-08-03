package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDir_Valid(t *testing.T) {
	reg, err := LoadDir(filepath.Join("testdata", "valid"))
	if err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}
	if reg.Len() != 6 {
		t.Fatalf("expected 6 entries, got %d", reg.Len())
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
	want := []string{
		"helm.cap.fs.read",
		"helm.cap.gui.gelab.delete",
		"helm.cap.gui.gelab.tap",
		"helm.cap.gui.gelab.upload-photo",
		"helm.cap.msg.send-external",
		"helm.cap.net.fetch",
	}
	if len(ids) != len(want) {
		t.Fatalf("IDs length %d, want %d: %v", len(ids), len(want), ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("IDs[%d] = %s, want %s (all: %v)", i, ids[i], want[i], ids)
		}
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

func TestLoadDir_RejectsUnknownAndTrailingJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "valid", "tap.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: strings.Replace(string(raw), `"name": "gelab-tap",`, `"name": "gelab-tap",\n  "unexpected": true,`, 1),
		},
		{
			name: "trailing JSON value",
			body: string(raw) + "\n{}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDir(dir); err == nil {
				t.Fatal("expected strict parse rejection")
			}
		})
	}
}
