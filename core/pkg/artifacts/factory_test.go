package artifacts

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNewStoreFromEnv_Default(t *testing.T) {
	// Clear any existing env vars
	_ = os.Unsetenv("ARTIFACT_STORAGE_TYPE")
	_ = os.Unsetenv("DATA_DIR")

	// Create temp directory
	tmpDir := t.TempDir()
	_ = os.Setenv("DATA_DIR", tmpDir)
	defer func() { _ = os.Unsetenv("DATA_DIR") }()

	store, err := NewStoreFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewStoreFromEnv failed: %v", err)
	}

	// Should be a FileStore
	fs, ok := store.(*FileStore)
	if !ok {
		t.Fatalf("Expected *FileStore, got %T", store)
	}

	expectedBase := filepath.Join(tmpDir, "artifacts")
	if fs.baseDir != expectedBase {
		t.Errorf("Expected baseDir %s, got %s", expectedBase, fs.baseDir)
	}
}

func TestNewStoreFromEnv_ExplicitFS(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Setenv("ARTIFACT_STORAGE_TYPE", "fs")
	_ = os.Setenv("DATA_DIR", tmpDir)
	defer func() {
		_ = os.Unsetenv("ARTIFACT_STORAGE_TYPE")
		_ = os.Unsetenv("DATA_DIR")
	}()

	store, err := NewStoreFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewStoreFromEnv failed: %v", err)
	}

	_, ok := store.(*FileStore)
	if !ok {
		t.Fatalf("Expected *FileStore, got %T", store)
	}
}

func TestNewStoreFromEnv_S3MissingBucket(t *testing.T) {
	_ = os.Setenv("ARTIFACT_STORAGE_TYPE", "s3")
	_ = os.Unsetenv("ARTIFACT_S3_BUCKET")
	defer func() { _ = os.Unsetenv("ARTIFACT_STORAGE_TYPE") }()

	_, err := NewStoreFromEnv(context.Background())
	if err == nil {
		t.Fatal("Expected error for missing S3 bucket")
	}

	expectedMsg := "ARTIFACT_S3_BUCKET is required"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got: %v", expectedMsg, err)
	}
}

func TestNewStoreFromEnv_GCSMissingBucket(t *testing.T) {
	_ = os.Setenv("ARTIFACT_STORAGE_TYPE", "gcs")
	_ = os.Unsetenv("ARTIFACT_GCS_BUCKET")
	defer func() { _ = os.Unsetenv("ARTIFACT_STORAGE_TYPE") }()

	_, err := NewStoreFromEnv(context.Background())
	if err == nil {
		t.Fatal("Expected error for missing GCS bucket")
	}

	expectedMsg := "ARTIFACT_GCS_BUCKET is required"
	// If GCS is not enabled in this build, we get a different error, which is also valid behavior
	if contains(err.Error(), "GCS storage is not enabled") {
		return
	}
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got: %v", expectedMsg, err)
	}
}

func TestNewStoreFromEnv_UnsupportedType(t *testing.T) {
	_ = os.Setenv("ARTIFACT_STORAGE_TYPE", "azure")
	defer func() { _ = os.Unsetenv("ARTIFACT_STORAGE_TYPE") }()

	_, err := NewStoreFromEnv(context.Background())
	if err == nil {
		t.Fatal("Expected error for unsupported storage type")
	}

	expectedMsg := "unsupported artifact storage type"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got: %v", expectedMsg, err)
	}
}

func TestFileStore_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileStore(filepath.Join(tmpDir, "artifacts"))
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	ctx := context.Background()
	data := []byte("Hello, HELM!")

	// Store
	hash, err := store.Store(ctx, data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if hash[:7] != "sha256:" {
		t.Errorf("Expected hash to start with sha256:, got: %s", hash)
	}

	// Get
	retrieved, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved) != string(data) {
		t.Errorf("Expected %q, got %q", data, retrieved)
	}
}

func TestFileStore_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileStore(filepath.Join(tmpDir, "artifacts"))
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	ctx := context.Background()
	data := []byte("Idempotent data")

	// Store twice
	hash1, err := store.Store(ctx, data)
	if err != nil {
		t.Fatalf("First store failed: %v", err)
	}

	hash2, err := store.Store(ctx, data)
	if err != nil {
		t.Fatalf("Second store failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Expected same hash, got %s and %s", hash1, hash2)
	}
}

func TestFileStore_GetNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileStore(filepath.Join(tmpDir, "artifacts"))
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	ctx := context.Background()
	_, err = store.Get(ctx, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("Expected error for non-existent artifact")
	}

	expectedMsg := "artifact not found"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got: %v", expectedMsg, err)
	}
}

func TestFileStore_InvalidHashFormat(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileStore(filepath.Join(tmpDir, "artifacts"))
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	ctx := context.Background()
	_, err = store.Get(ctx, "invalid-hash")
	if err == nil {
		t.Fatal("Expected error for invalid hash format")
	}

	expectedMsg := "invalid hash format"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got: %v", expectedMsg, err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
