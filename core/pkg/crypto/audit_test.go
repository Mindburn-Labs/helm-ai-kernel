package crypto

import (
	"os"
	"testing"
)

func TestFileAuditLog(t *testing.T) {
	tmpParams := "test_audit_*.log"
	f, err := os.CreateTemp("", tmpParams)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	log, err := NewFileAuditLog(f.Name())
	if err != nil {
		t.Fatalf("Failed to create audit log: %v", err)
	}

	// append
	err = log.Append("alice", "login", map[string]interface{}{"ip": "127.0.0.1"})
	if err != nil {
		t.Fatalf("Failed to append event: %v", err)
	}

	// read back
	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	if entries[0].Actor != "alice" {
		t.Errorf("Expected actor 'alice', got '%s'", entries[0].Actor)
	}
}

func TestMemoryAuditLog(t *testing.T) {
	log := NewMemoryAuditLog()

	err := log.Append("bob", "dataset_access", nil)
	if err != nil {
		t.Fatalf("Failed to append: %v", err)
	}

	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	if entries[0].Action != "dataset_access" {
		t.Errorf("Expected action 'dataset_access', got '%s'", entries[0].Action)
	}
}
