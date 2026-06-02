package fs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/objstore"
)

func TestStoreRoundTripAndList(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	hash := "sha256:abcdef012345"
	if got := store.objectPath("abc"); got != filepath.Join(root, "abc") {
		t.Fatalf("short object path = %q", got)
	}
	if got := store.objectPath(hash); got != filepath.Join(root, "ab", "cd", "abcdef012345") {
		t.Fatalf("sharded object path = %q", got)
	}

	if err := store.Put(ctx, hash, strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Put(ctx, hash, strings.NewReader("ignored")); err != nil {
		t.Fatalf("idempotent Put: %v", err)
	}

	reader, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(reader)
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("unexpected payload %q", got)
	}

	exists, err := store.Exists(ctx, hash)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected object to exist")
	}

	otherHash := "beef00000000"
	if err := store.Put(ctx, otherHash, strings.NewReader("other")); err != nil {
		t.Fatalf("Put other: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".tmp-ignore"), []byte("tmp"), 0600); err != nil {
		t.Fatalf("WriteFile tmp: %v", err)
	}

	hashes, err := store.List(ctx, "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	sort.Strings(hashes)
	if strings.Join(hashes, ",") != "abcdef012345,beef00000000" {
		t.Fatalf("unexpected hashes %v", hashes)
	}

	hashes, err = store.List(ctx, "ab")
	if err != nil {
		t.Fatalf("List prefix: %v", err)
	}
	if len(hashes) != 1 || hashes[0] != "abcdef012345" {
		t.Fatalf("unexpected prefixed hashes %v", hashes)
	}

	if err := store.Delete(ctx, hash); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ctx, hash); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}
	exists, err = store.Exists(ctx, hash)
	if err != nil {
		t.Fatalf("Exists after delete: %v", err)
	}
	if exists {
		t.Fatal("expected object to be deleted")
	}

	_, err = store.Get(ctx, hash)
	var missing *objstore.ErrNotFound
	if !errors.As(err, &missing) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestNewError(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	fsMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir failed") }
	if _, err := New(t.TempDir()); err == nil || !strings.Contains(err.Error(), "create object store root") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
}

func TestPutErrors(t *testing.T) {
	ctx := context.Background()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash := "abcdef012345"

	restore := replaceHooks()
	defer restore()

	fsMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir failed") }
	if err := store.Put(ctx, hash, strings.NewReader("payload")); err == nil || !strings.Contains(err.Error(), "create directory") {
		t.Fatalf("expected directory error, got %v", err)
	}
	restore()

	fsCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("temp failed") }
	if err := store.Put(ctx, hash, strings.NewReader("payload")); err == nil || !strings.Contains(err.Error(), "create temp file") {
		t.Fatalf("expected temp error, got %v", err)
	}
	restore()

	if err := store.Put(ctx, hash, iotest.ErrReader(errors.New("copy failed"))); err == nil || !strings.Contains(err.Error(), "write object") {
		t.Fatalf("expected write error, got %v", err)
	}

	fsCloseFile = func(f *os.File) error {
		_ = f.Close()
		return errors.New("close failed")
	}
	if err := store.Put(ctx, hash, strings.NewReader("payload")); err == nil || !strings.Contains(err.Error(), "close temp file") {
		t.Fatalf("expected close error, got %v", err)
	}
	restore()

	fsRename = func(string, string) error { return errors.New("rename failed") }
	if err := store.Put(ctx, hash, strings.NewReader("payload")); err == nil || !strings.Contains(err.Error(), "rename to final path") {
		t.Fatalf("expected rename error, got %v", err)
	}
}

func TestGetExistsDeleteErrors(t *testing.T) {
	ctx := context.Background()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash := "abcdef012345"

	restore := replaceHooks()
	defer restore()

	fsOpen = func(string) (*os.File, error) { return nil, errors.New("open failed") }
	if _, err := store.Get(ctx, hash); err == nil || !strings.Contains(err.Error(), "open object") {
		t.Fatalf("expected open error, got %v", err)
	}
	restore()

	fsStat = func(string) (os.FileInfo, error) { return nil, errors.New("stat failed") }
	if _, err := store.Exists(ctx, hash); err == nil || !strings.Contains(err.Error(), "stat object") {
		t.Fatalf("expected stat error, got %v", err)
	}
	restore()

	fsRemove = func(string) error { return errors.New("remove failed") }
	if err := store.Delete(ctx, hash); err == nil || !strings.Contains(err.Error(), "delete object") {
		t.Fatalf("expected delete error, got %v", err)
	}
}

func TestListErrors(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sentinel := errors.New("walk failed")

	restore := replaceHooks()
	defer restore()

	fsWalk = func(root string, fn filepath.WalkFunc) error {
		return fn(root, nil, sentinel)
	}
	if _, err := store.List(context.Background(), ""); !errors.Is(err, sentinel) {
		t.Fatalf("expected callback walk error, got %v", err)
	}
	restore()

	fsWalk = func(string, filepath.WalkFunc) error {
		return sentinel
	}
	if _, err := store.List(context.Background(), ""); !errors.Is(err, sentinel) {
		t.Fatalf("expected walk error, got %v", err)
	}
}

func replaceHooks() func() {
	originalMkdirAll := fsMkdirAll
	originalStat := fsStat
	originalCreateTemp := fsCreateTemp
	originalCloseFile := fsCloseFile
	originalRemove := fsRemove
	originalRename := fsRename
	originalOpen := fsOpen
	originalWalk := fsWalk

	return func() {
		fsMkdirAll = originalMkdirAll
		fsStat = originalStat
		fsCreateTemp = originalCreateTemp
		fsCloseFile = originalCloseFile
		fsRemove = originalRemove
		fsRename = originalRename
		fsOpen = originalOpen
		fsWalk = originalWalk
	}
}
