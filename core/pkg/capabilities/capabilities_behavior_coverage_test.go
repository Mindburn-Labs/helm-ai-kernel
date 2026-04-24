package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestToolCatalog_AddAndGet(t *testing.T) {
	cat := NewToolCatalog()
	cat.Add(Capability{ID: "t1", Name: "tool-one"})
	cap, ok := cat.Get("t1")
	if !ok || cap.Name != "tool-one" {
		t.Fatal("expected to find capability t1")
	}
}

func TestToolCatalog_GetMissing(t *testing.T) {
	cat := NewToolCatalog()
	_, ok := cat.Get("nonexistent")
	if ok {
		t.Fatal("should not find nonexistent capability")
	}
}

func TestToolCatalog_OverwriteCapability(t *testing.T) {
	cat := NewToolCatalog()
	cat.Add(Capability{ID: "t1", Name: "v1"})
	cat.Add(Capability{ID: "t1", Name: "v2"})
	cap, _ := cat.Get("t1")
	if cap.Name != "v2" {
		t.Fatalf("expected v2, got %s", cap.Name)
	}
}

func TestFileBlobStore_StoreAndGet(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := store.Store(context.Background(), []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", data)
	}
}

func TestFileBlobStore_Idempotent(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileBlobStore(dir)
	h1, _ := store.Store(context.Background(), []byte("dup"))
	h2, _ := store.Store(context.Background(), []byte("dup"))
	if h1 != h2 {
		t.Fatalf("idempotent store should return same hash: %s vs %s", h1, h2)
	}
}

func TestFileBlobStore_GetNotFound(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileBlobStore(dir)
	_, err := store.Get(context.Background(), "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error for missing blob")
	}
}

func TestFileBlobStore_GetInvalidHashFormat(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileBlobStore(dir)
	_, err := store.Get(context.Background(), "md5:abc")
	if err == nil {
		t.Fatal("expected error for invalid hash format")
	}
}

func TestFileBlobStore_CreatesDirIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deep")
	_, err := NewFileBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatal("expected directory to be created")
	}
}

func TestComputeDeltaHash_Deterministic(t *testing.T) {
	d := GenomeDelta{DeltaID: "d1", Operation: "add", TargetPath: "cap.x", Payload: map[string]interface{}{"k": "v"}}
	h1 := computeDeltaHash(d)
	h2 := computeDeltaHash(d)
	if h1 != h2 || h1 == "" {
		t.Fatalf("hash should be deterministic and non-empty: %s vs %s", h1, h2)
	}
}
