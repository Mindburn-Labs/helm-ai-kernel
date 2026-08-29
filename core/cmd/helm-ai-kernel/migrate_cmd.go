package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/postgresmigration"
)

func init() {
	Register(Subcommand{
		Name:  "migrate",
		Usage: "Apply the Kernel Postgres schema once using HELM_MIGRATION_DATABASE_URL.",
		RunFn: runMigrateCommand,
		HelpFn: func(stdout io.Writer) {
			fmt.Fprintln(stdout, "Usage: helm-ai-kernel migrate")
			fmt.Fprintln(stdout, "Applies all Kernel-owned Postgres schemas with HELM_MIGRATION_DATABASE_URL.")
		},
	})
}

func runMigrateCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel migrate")
		return 2
	}
	dsn, err := validatedMigrationDatabaseURL(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintf(stderr, "open migration database: %v\n", err)
		return 1
	}
	defer db.Close()
	// The one-shot command intentionally reads no serving configuration: the
	// owner credential is its only database input.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(stderr, "ping migration database: %v\n", err)
		return 1
	}
	if err := postgresmigration.Migrate(ctx, db); err != nil {
		fmt.Fprintf(stderr, "Kernel Postgres migration failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "Kernel Postgres migrations applied")
	return 0
}

func migrationDatabaseURL(getenv func(string) string) (string, error) {
	dsn := strings.TrimSpace(getenv("HELM_MIGRATION_DATABASE_URL"))
	if dsn == "" {
		return "", fmt.Errorf("HELM_MIGRATION_DATABASE_URL is required")
	}
	return dsn, nil
}

func validatedMigrationDatabaseURL(getenv func(string) string) (string, error) {
	dsn, err := migrationDatabaseURL(getenv)
	if err != nil {
		return "", err
	}
	if err := validateRuntimePostgresURLWithEnv(dsn, getenv); err != nil {
		return "", fmt.Errorf("invalid migration database TLS: %w", err)
	}
	return dsn, nil
}
