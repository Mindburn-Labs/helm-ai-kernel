package kernel

import (
	"context"
	"testing"
)

//nolint:gocognit // test complexity is acceptable
func TestInMemoryBlobStore(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBlobStore()

	t.Run("Store and Get", func(t *testing.T) {
		data := []byte(`{"test": "data"}`)
		addr, err := store.Store(ctx, data, "application/json")
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}
		if addr == "" {
			t.Fatal("Expected non-empty address")
		}

		record, err := store.Get(ctx, addr)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if string(record.Content) != string(data) {
			t.Errorf("Data mismatch: got %s, want %s", record.Content, data)
		}
		if record.MimeType != "application/json" {
			t.Errorf("MimeType mismatch: got %s, want application/json", record.MimeType)
		}
	})

	t.Run("Store and Has", func(t *testing.T) {
		data := []byte(`{"another": "blob"}`)
		addr, err := store.Store(ctx, data, "application/json")
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		if !store.Has(ctx, addr) {
			t.Error("Has returned false for stored blob")
		}

		if store.Has(ctx, "nonexistent-address") {
			t.Error("Has returned true for nonexistent blob")
		}
	})

	t.Run("StoreRedacted", func(t *testing.T) {
		contentHash := "abc123def456"

		addr, err := store.StoreRedacted(ctx, contentHash, "application/octet-stream")
		if err != nil {
			t.Fatalf("StoreRedacted failed: %v", err)
		}
		if addr == "" {
			t.Fatal("Expected non-empty address")
		}

		if !store.Has(ctx, addr) {
			t.Error("Redacted blob not stored")
		}

		// Verify it's marked as redacted
		record, err := store.Get(ctx, addr)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if !record.Redacted {
			t.Error("Record should be marked as redacted")
		}
		if record.Content != nil {
			t.Error("Redacted record should have nil content")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		data := []byte(`{"delete": "me"}`)
		addr, err := store.Store(ctx, data, "application/json")
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		err = store.Delete(ctx, addr)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		if store.Has(ctx, addr) {
			t.Error("Blob still exists after delete")
		}
	})

	t.Run("List", func(t *testing.T) {
		store2 := NewInMemoryBlobStore()

		// Store multiple blobs
		for i := 0; i < 3; i++ {
			data := []byte{byte(i), byte(i + 1)}
			_, err := store2.Store(ctx, data, "application/octet-stream")
			if err != nil {
				t.Fatalf("Store %d failed: %v", i, err)
			}
		}

		list, err := store2.List(ctx)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(list) != 3 {
			t.Errorf("Expected 3 blobs, got %d", len(list))
		}
	})

	t.Run("Get nonexistent", func(t *testing.T) {
		_, err := store.Get(ctx, "nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent blob")
		}
	})

	t.Run("Content addressing - same data same address", func(t *testing.T) {
		data := []byte(`{"deterministic": true}`)

		addr1, _ := store.Store(ctx, data, "application/json")
		addr2, _ := store.Store(ctx, data, "application/json")

		if addr1 != addr2 {
			t.Errorf("Same data should produce same address: %s != %s", addr1, addr2)
		}
	})

	t.Run("Content addressing - different data different address", func(t *testing.T) {
		data1 := []byte(`{"version": 1}`)
		data2 := []byte(`{"version": 2}`)

		addr1, _ := store.Store(ctx, data1, "application/json")
		addr2, _ := store.Store(ctx, data2, "application/json")

		if addr1 == addr2 {
			t.Errorf("Different data should produce different address: %s == %s", addr1, addr2)
		}
	})
}

func TestComputeBlobAddress(t *testing.T) {
	// Test that computeBlobAddress is deterministic
	data := []byte("test content")
	addr1 := computeBlobAddress(data)
	addr2 := computeBlobAddress(data)

	if addr1 != addr2 {
		t.Errorf("computeBlobAddress is not deterministic: %s != %s", addr1, addr2)
	}

	// Verify it starts with sha256: prefix
	if len(addr1) < 7 || string(addr1[:7]) != "sha256:" {
		t.Errorf("Address should start with 'sha256:', got %s", addr1)
	}
}
