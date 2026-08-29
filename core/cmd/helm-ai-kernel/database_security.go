package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

const kernelPostgresInsecureEnv = "HELM_KERNEL_PG_INSECURE"

func validateProductionDatabaseURL(dbURL string) error {
	return validatePostgresDatabaseURL(dbURL, false)
}

func validateRuntimePostgresURL(dbURL string) error {
	return validateRuntimePostgresURLWithEnv(dbURL, os.Getenv)
}

func validateRuntimePostgresURLWithEnv(dbURL string, getenv func(string) string) error {
	return validatePostgresDatabaseURL(dbURL, kernelPostgresInsecureOptOutActive(getenv))
}

func validatePostgresDatabaseURL(dbURL string, allowInsecure bool) error {
	mode, ok, err := postgresSSLMode(dbURL)
	if err != nil {
		return err
	}
	if !ok || mode == "" {
		return fmt.Errorf("postgres DATABASE_URL requires explicit sslmode=require, verify-ca, or verify-full")
	}
	switch mode {
	case "require", "verify-ca", "verify-full":
		return nil
	case "disable", "allow", "prefer":
		if allowInsecure {
			return nil
		}
		return fmt.Errorf("postgres DATABASE_URL uses insecure sslmode=%s; use require, verify-ca, or verify-full (set %s=1 only for local development)", mode, kernelPostgresInsecureEnv)
	default:
		return fmt.Errorf("postgres DATABASE_URL uses unsupported sslmode=%s; use require, verify-ca, or verify-full", mode)
	}
}

func kernelPostgresInsecureOptOutActive(getenv func(string) string) bool {
	if getenv(kernelPostgresInsecureEnv) != "1" || envBoolValue(getenv("HELM_PRODUCTION")) {
		return false
	}
	sawLocalLabel := false
	for _, key := range []string{"HELM_ENV", "HELM_PROFILE"} {
		switch value := strings.ToLower(strings.TrimSpace(getenv(key))); value {
		case "":
			continue
		case "development", "dev", "test", "testing", "local":
			sawLocalLabel = true
		default:
			return false
		}
	}
	return sawLocalLabel
}

func envBoolValue(value string) bool {
	switch strings.TrimSpace(value) {
	case "1", "true", "TRUE", "yes", "YES":
		return true
	default:
		return false
	}
}

func postgresSSLMode(dbURL string) (string, bool, error) {
	dsn := strings.TrimSpace(dbURL)
	if dsn == "" {
		return "", false, nil
	}
	lower := strings.ToLower(dsn)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			return "", false, fmt.Errorf("parse postgres DATABASE_URL: %w", err)
		}
		mode := strings.ToLower(strings.TrimSpace(parsed.Query().Get("sslmode")))
		return mode, mode != "", nil
	}
	for _, field := range strings.Fields(dsn) {
		key, value, ok := strings.Cut(field, "=")
		if !ok || strings.ToLower(strings.TrimSpace(key)) != "sslmode" {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		return strings.ToLower(value), value != "", nil
	}
	return "", false, nil
}
