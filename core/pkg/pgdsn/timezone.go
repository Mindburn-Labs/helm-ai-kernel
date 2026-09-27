package pgdsn

import (
	"fmt"
	"net/url"
	"strings"
)

// WithUTCTimeZone returns dsn with the session time zone pinned to UTC.
//
// Stores validate that the timestamps they read back are in UTC, and lib/pq
// returns timestamptz values in the session's time zone, which defaults to the
// server's. A server whose timezone is not UTC therefore made those stores
// reject their own rows and fail closed (HELM-776). lib/pq sends unrecognised
// connection parameters to the server as run-time parameters, so setting
// timezone here pins every connection the DSN opens. An existing timezone
// setting is replaced: these stores require UTC.
//
// Both DSN forms lib/pq accepts are handled: postgres:// or postgresql:// URLs
// and key=value strings.
func WithUTCTimeZone(dsn string) (string, error) {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return "", fmt.Errorf("pgdsn: empty Postgres DSN")
	}
	if strings.HasPrefix(trimmed, "postgres://") || strings.HasPrefix(trimmed, "postgresql://") {
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("pgdsn: parse Postgres URL: %w", err)
		}
		query := parsed.Query()
		for key := range query {
			if strings.EqualFold(key, "timezone") {
				query.Del(key)
			}
		}
		query.Set("timezone", "UTC")
		parsed.RawQuery = query.Encode()
		return parsed.String(), nil
	}
	// key=value form: lib/pq keeps the last value of a repeated key.
	return trimmed + " timezone=UTC", nil
}
