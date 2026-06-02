package pack

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverageFSRegistryEdges(t *testing.T) {
	ctx := context.Background()

	t.Run("GetPack reports missing and ListVersions errors", func(t *testing.T) {
		root := t.TempDir()
		registry := NewFSRegistry(root)
		if _, err := registry.GetPack(ctx, "missing"); err == nil {
			t.Fatal("expected missing pack to fail")
		}

		fileRoot := filepath.Join(root, "file-root")
		if err := os.WriteFile(fileRoot, []byte("not a directory"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := NewFSRegistry(fileRoot).GetPack(ctx, "pack"); err == nil {
			t.Fatal("expected non-directory registry root to fail")
		}
	})

	t.Run("FindByCapability handles missing root errors skips and matches", func(t *testing.T) {
		missing := NewFSRegistry(filepath.Join(t.TempDir(), "missing"))
		packs, err := missing.FindByCapability(ctx, "capture")
		if err != nil {
			t.Fatalf("FindByCapability missing root: %v", err)
		}
		if len(packs) != 0 {
			t.Fatalf("missing root packs = %#v", packs)
		}

		root := t.TempDir()
		fileRoot := filepath.Join(root, "file-root")
		if err := os.WriteFile(fileRoot, []byte("not a directory"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := NewFSRegistry(fileRoot).FindByCapability(ctx, "capture"); err == nil {
			t.Fatal("expected non-directory root to fail")
		}

		if err := os.WriteFile(filepath.Join(root, "README"), []byte("skip me"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(root, "invalid-pack", "1.0.0"), 0700); err != nil {
			t.Fatalf("MkdirAll invalid: %v", err)
		}
		writePackManifest(t, root, "version-mismatch", "1.0.0", PackManifest{
			PackID:       "version-mismatch",
			Name:         "version-mismatch",
			Version:      "missing-version",
			Capabilities: []string{"attest"},
		})
		writePackManifest(t, root, "good-pack", "1.0.0", PackManifest{
			PackID:       "good-pack",
			Name:         "good-pack",
			Version:      "1.0.0",
			Capabilities: []string{"capture", "attest"},
		})
		writePackManifest(t, root, "other-pack", "1.0.0", PackManifest{
			PackID:       "other-pack",
			Name:         "other-pack",
			Version:      "1.0.0",
			Capabilities: []string{"observe"},
		})

		found, err := NewFSRegistry(root).FindByCapability(ctx, "attest")
		if err != nil {
			t.Fatalf("FindByCapability: %v", err)
		}
		if len(found) != 1 || found[0].PackID != "good-pack" {
			t.Fatalf("found = %#v", found)
		}
	})

	t.Run("ListVersions skips invalid entries and sorts fallback versions", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "pack"), []byte("not a directory"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := NewFSRegistry(root).ListVersions(ctx, "pack"); err == nil {
			t.Fatal("expected pack path file to fail")
		}

		writePackManifest(t, root, "versions", "2.0.0", PackManifest{
			PackID: "versions", Name: "versions", Version: "2.0.0",
		})
		writePackManifest(t, root, "versions", "1.0.0", PackManifest{
			PackID: "versions", Name: "versions", Version: "1.0.0",
		})
		writePackManifest(t, root, "versions", "bad-version", PackManifest{
			PackID: "versions", Name: "versions", Version: "bad-version",
		})
		if err := os.WriteFile(filepath.Join(root, "versions", "README"), []byte("skip"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(root, "versions", "invalid", "nested"), 0700); err != nil {
			t.Fatalf("MkdirAll invalid: %v", err)
		}

		versions, err := NewFSRegistry(root).ListVersions(ctx, "versions")
		if err != nil {
			t.Fatalf("ListVersions: %v", err)
		}
		if len(versions) != 3 {
			t.Fatalf("versions = %#v", versions)
		}
		if versions[0].Version != "1.0.0" || versions[1].Version != "2.0.0" || versions[2].Version != "bad-version" {
			t.Fatalf("unexpected version order: %#v", versions)
		}
	})

	t.Run("loadPack and content hashing report malformed inputs", func(t *testing.T) {
		root := t.TempDir()
		registry := NewFSRegistry(root)
		if _, err := registry.loadPack("missing", "1.0.0"); err == nil {
			t.Fatal("expected missing manifest to fail")
		}

		badDir := filepath.Join(root, "bad", "1.0.0")
		if err := os.MkdirAll(badDir, 0700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(badDir, "manifest.json"), []byte("{"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := registry.loadPack("bad", "1.0.0"); err == nil {
			t.Fatal("expected malformed manifest to fail")
		}

		brokenDir := filepath.Join(root, "broken", "1.0.0")
		if err := os.MkdirAll(brokenDir, 0700); err != nil {
			t.Fatalf("MkdirAll broken: %v", err)
		}
		writePackManifest(t, root, "broken", "1.0.0", PackManifest{
			PackID: "broken", Name: "broken", Version: "1.0.0",
		})
		if err := os.Symlink(filepath.Join(root, "does-not-exist"), filepath.Join(brokenDir, "broken-link")); err != nil {
			t.Fatalf("Symlink broken pack: %v", err)
		}
		if _, err := registry.loadPack("broken", "1.0.0"); err == nil {
			t.Fatal("expected content hash error from broken symlink")
		}

		if _, err := registry.computeContentHash(filepath.Join(root, "missing-dir")); err == nil {
			t.Fatal("expected missing directory hash to fail")
		}

		hashDir := filepath.Join(root, "hash")
		if err := os.MkdirAll(hashDir, 0700); err != nil {
			t.Fatalf("MkdirAll hash: %v", err)
		}
		if err := os.WriteFile(filepath.Join(hashDir, ".DS_Store"), []byte("ignored"), 0600); err != nil {
			t.Fatalf("WriteFile ds store: %v", err)
		}
		if err := os.Symlink(filepath.Join(root, "does-not-exist"), filepath.Join(hashDir, "broken-link")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if _, err := registry.computeContentHash(hashDir); err == nil {
			t.Fatal("expected broken symlink open to fail")
		}
	})
}

func writePackManifest(t *testing.T, root, name, version string, manifest PackManifest) {
	t.Helper()

	dir := filepath.Join(root, name, version)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll %s: %v", dir, err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
}
