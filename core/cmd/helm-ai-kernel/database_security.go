package main

import (
	"fmt"
	"net/url"
	"strings"
)

func validateProductionDatabaseURL(dbURL string) error {
	mode, ok, err := postgresSSLMode(dbURL)
	if err != nil {
		return err
	}
	if !ok || mode == "" {
		return fmt.Errorf("production postgres DATABASE_URL requires sslmode=require, verify-ca, or verify-full")
	}
	switch mode {
	case "require", "verify-ca", "verify-full":
		return nil
	default:
		return fmt.Errorf("production postgres DATABASE_URL uses insecure sslmode=%s; use require, verify-ca, or verify-full", mode)
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
