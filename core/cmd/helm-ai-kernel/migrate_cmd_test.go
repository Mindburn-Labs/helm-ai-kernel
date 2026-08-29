package main

import (
	"strings"
	"testing"
)

func TestMigrationDatabaseURLRequiresOwnerCredential(t *testing.T) {
	if _, err := migrationDatabaseURL(func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "HELM_MIGRATION_DATABASE_URL") {
		t.Fatalf("missing migration URL error = %v", err)
	}
}

func TestMigrationDatabaseURLTrimsOwnerCredential(t *testing.T) {
	got, err := migrationDatabaseURL(func(string) string { return " postgres://migration/db " })
	if err != nil {
		t.Fatalf("migrationDatabaseURL: %v", err)
	}
	if got != "postgres://migration/db" {
		t.Fatalf("migration URL = %q, want trimmed DSN", got)
	}
}
