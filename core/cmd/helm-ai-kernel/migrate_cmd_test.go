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

func TestValidatedMigrationDatabaseURLAppliesTLSPolicy(t *testing.T) {
	secure := func(string) string { return " postgres://migration/db?sslmode=verify-full " }
	got, err := validatedMigrationDatabaseURL(secure)
	if err != nil {
		t.Fatalf("validatedMigrationDatabaseURL secure DSN: %v", err)
	}
	if got != "postgres://migration/db?sslmode=verify-full" {
		t.Fatalf("migration URL = %q, want trimmed secure DSN", got)
	}

	for name, values := range map[string]string{
		"missing sslmode":  "postgres://migration/db",
		"insecure sslmode": "postgres://migration/db?sslmode=disable",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validatedMigrationDatabaseURL(func(key string) string {
				if key == "HELM_MIGRATION_DATABASE_URL" {
					return values
				}
				return ""
			}); err == nil {
				t.Fatal("validatedMigrationDatabaseURL accepted an insecure DSN")
			}
		})
	}
}

func TestValidatedMigrationDatabaseURLAllowsInsecureOnlyWithLocalOptOut(t *testing.T) {
	local := map[string]string{
		"HELM_MIGRATION_DATABASE_URL": "postgres://migration/db?sslmode=disable",
		"HELM_KERNEL_PG_INSECURE":     "1",
		"HELM_ENV":                    "local",
	}
	if _, err := validatedMigrationDatabaseURL(func(key string) string { return local[key] }); err != nil {
		t.Fatalf("local insecure migration DSN rejected: %v", err)
	}

	for name, values := range map[string]map[string]string{
		"unset labels": {
			"HELM_MIGRATION_DATABASE_URL": "postgres://migration/db?sslmode=disable",
			"HELM_KERNEL_PG_INSECURE":     "1",
		},
		"unknown label": {
			"HELM_MIGRATION_DATABASE_URL": "postgres://migration/db?sslmode=disable",
			"HELM_KERNEL_PG_INSECURE":     "1",
			"HELM_ENV":                    "qa",
		},
		"production flag": {
			"HELM_MIGRATION_DATABASE_URL": "postgres://migration/db?sslmode=disable",
			"HELM_KERNEL_PG_INSECURE":     "1",
			"HELM_ENV":                    "local",
			"HELM_PRODUCTION":             "1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validatedMigrationDatabaseURL(func(key string) string { return values[key] }); err == nil {
				t.Fatal("validatedMigrationDatabaseURL accepted insecure DSN outside local development")
			}
		})
	}
}
