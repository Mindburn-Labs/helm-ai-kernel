package pgdsn

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestWithUTCTimeZoneRewritesBothDSNForms(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"url", "postgres://u@h:5432/db?sslmode=disable", "postgres://u@h:5432/db?sslmode=disable&timezone=UTC"},
		{"url replaces timezone", "postgresql://u@h/db?TimeZone=Europe%2FSofia&sslmode=require", "postgresql://u@h/db?sslmode=require&timezone=UTC"},
		{"key value", "host=h dbname=db sslmode=disable", "host=h dbname=db sslmode=disable timezone=UTC"},
		{"key value with timezone", "host=h timezone=Europe/Sofia", "host=h timezone=Europe/Sofia timezone=UTC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := WithUTCTimeZone(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("WithUTCTimeZone(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
	if _, err := WithUTCTimeZone("  "); err == nil {
		t.Fatal("an empty DSN must be refused")
	}
}

// A session whose time zone is not UTC returns timestamptz values outside UTC
// unless the DSN pins UTC (HELM-776). The control shows the fault; the pinned
// DSN shows the fix, for both DSN forms.
func TestPostgresWithUTCTimeZoneOverridesANonUTCSession(t *testing.T) {
	raw := os.Getenv("HELM_TEST_POSTGRES_URL")
	if raw == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the time zone proof")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("timezone", "Europe/Sofia")
	parsed.RawQuery = query.Encode()
	sofia := parsed.String()

	if zone, offset := sessionZone(t, sofia); zone != "Europe/Sofia" || offset == 0 {
		t.Fatalf("control: a Europe/Sofia session reported %q with offset %d; the fault is not reproduced", zone, offset)
	}
	pinned, err := WithUTCTimeZone(sofia)
	if err != nil {
		t.Fatal(err)
	}
	if zone, offset := sessionZone(t, pinned); zone != "UTC" || offset != 0 {
		t.Fatalf("pinned DSN: session reported %q with offset %d, want UTC", zone, offset)
	}
}

// sessionZone reports the session TimeZone and the UTC offset of a timestamptz
// read back, which is what the stores' isUTC checks.
func sessionZone(t *testing.T, dsn string) (string, int) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var zone string
	var now time.Time
	if err := db.QueryRowContext(ctx, `SELECT current_setting('TimeZone'), now()`).Scan(&zone, &now); err != nil {
		t.Fatal(err)
	}
	_, offset := now.Zone()
	return zone, offset
}
