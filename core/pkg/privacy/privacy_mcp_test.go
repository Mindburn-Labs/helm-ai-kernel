// quantum_posture: these tests exercise classical SHA-256 stable references
// and privacy filtering only; no post-quantum assurance is added or claimed.
package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestProtectDeepValuesRedactsOnlyOrdinaryPII(t *testing.T) {
	manager := NewPrivacyManager()
	input := map[string]any{
		"email": "person@example.com",
		"nested": map[string]string{
			"phone": "+1 (415) 555-2671",
			"id":    "2026082712345",
			"date":  "2026-08-27",
		},
		"values": []string{"person@example.com", "+44 20 7946 0958", "2026-08-27"},
	}

	protected, findings, err := manager.Protect(context.Background(), input)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if !reflect.DeepEqual(input["email"], "person@example.com") {
		t.Fatal("Protect mutated the source map")
	}
	wantFindings := []string{"email", "phone"}
	if !reflect.DeepEqual(findings, wantFindings) {
		t.Fatalf("findings = %v, want %v", findings, wantFindings)
	}
	encoded, err := json.Marshal(protected)
	if err != nil {
		t.Fatalf("marshal protected value: %v", err)
	}
	output := string(encoded)
	for _, raw := range []string{"person@example.com", "+1 (415) 555-2671", "+44 20 7946 0958"} {
		if strings.Contains(output, raw) {
			t.Fatalf("protected value contains raw PII %q: %s", raw, output)
		}
	}
	for _, preserved := range []string{"2026082712345", "2026-08-27"} {
		if !strings.Contains(output, preserved) {
			t.Fatalf("protected value changed clean control %q: %s", preserved, output)
		}
	}
	bareID, _, err := manager.Protect(context.Background(), "2026082712345")
	if err != nil || bareID.(string) != "2026082712345" {
		t.Fatalf("bare numeric ID changed or failed: value=%v err=%v", bareID, err)
	}
	cleanDate, _, err := manager.Protect(context.Background(), "2026-08-27")
	if err != nil || cleanDate.(string) != "2026-08-27" {
		t.Fatalf("ISO date changed or failed: value=%v err=%v", cleanDate, err)
	}
}

func TestProtectRestrictedValuesFailClosedWithoutValueInError(t *testing.T) {
	manager := NewPrivacyManager()
	cases := []struct {
		name  string
		value any
		raw   string
	}{
		{name: "secret key", value: map[string]any{"api_key": "sk_live_1234567890"}, raw: "sk_live_1234567890"},
		{name: "ssn", value: "SSN: 123-45-6789", raw: "123-45-6789"},
		{name: "card", value: "4111 1111 1111 1111", raw: "4111 1111 1111 1111"},
		{name: "iban", value: "GB82 WEST 1234 5698 7654 32", raw: "GB82 WEST 1234 5698 7654 32"},
		{name: "jwt", value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature1234", raw: "eyJhbGciOiJIUzI1NiJ9"},
		{name: "private key", value: "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----", raw: "-----BEGIN RSA PRIVATE KEY-----"},
		{name: "short password assignment", value: "password=abc123", raw: "abc123"},
		{name: "short token assignment", value: "token: x", raw: "x"},
		{name: "standalone live secret", value: "sk_live_1234", raw: "sk_live_1234"},
		{name: "standalone test secret", value: "sk_test_1234", raw: "sk_test_1234"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := manager.Protect(context.Background(), tc.value)
			if !errors.Is(err, ErrDataEgressBlocked) {
				t.Fatalf("Protect() error = %v, want ErrDataEgressBlocked", err)
			}
			if strings.Contains(err.Error(), tc.raw) {
				t.Fatalf("error contains raw restricted value: %v", err)
			}
		})
	}
}

func TestProtectDoubleEscapedJSONValue(t *testing.T) {
	manager := NewPrivacyManager()
	doubleEscapedEmail := `\\u0070\\u0065\\u0072\\u0073\\u006f\\u006e\\u0040\\u0065\\u0078\\u0061\\u006d\\u0070\\u006c\\u0065\\u002e\\u0063\\u006f\\u006d`
	doubleEscapedPhone := `\\u002b\\u0031\\u0020\\u0034\\u0031\\u0035\\u0020\\u0035\\u0035\\u0035\\u002d\\u0032\\u0036\\u0037\\u0031`
	doubleEscaped := map[string]any{
		"email": json.RawMessage(mustJSON(t, doubleEscapedEmail)),
		"phone": json.RawMessage(mustJSON(t, doubleEscapedPhone)),
	}
	protected, _, err := manager.Protect(context.Background(), doubleEscaped)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	output, err := json.Marshal(protected)
	if err != nil {
		t.Fatalf("marshal protected value: %v", err)
	}
	if strings.Contains(string(output), "person@example.com") || strings.Contains(string(output), "+1 415 555-2671") {
		t.Fatalf("double-escaped PII survived: %s", output)
	}
	if !strings.Contains(string(output), "REDACTED_EMAIL") || !strings.Contains(string(output), "REDACTED_PHONE") {
		t.Fatalf("double-escaped PII was not normalized and redacted: %s", output)
	}
}

func TestProtectPreservesCleanLiteralUnicodeEscapes(t *testing.T) {
	manager := NewPrivacyManager()
	clean := `source literal: \u007b\u007d and \\u0061`
	protected, findings, err := manager.Protect(context.Background(), clean)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean escaped value findings = %v, want none", findings)
	}
	if got := protected.(string); got != clean {
		t.Fatalf("clean escaped value changed from %q to %q", clean, got)
	}
}

func TestProtectDoubleEscapedRestrictedJSONValueFailsClosed(t *testing.T) {
	manager := NewPrivacyManager()
	for _, tc := range []struct {
		name  string
		value string
		raw   string
	}{
		{name: "ssn", value: `\\u0031\\u0032\\u0033\\u002d\\u0034\\u0035\\u002d\\u0036\\u0037\\u0038\\u0039`, raw: "123-45-6789"},
		{name: "card", value: `\\u0034\\u0031\\u0031\\u0031\\u0020\\u0031\\u0031\\u0031\\u0031\\u0020\\u0031\\u0031\\u0031\\u0031\\u0020\\u0031\\u0031\\u0031\\u0031`, raw: "4111 1111 1111 1111"},
		{name: "iban", value: `\\u0047\\u0042\\u0038\\u0032\\u0020\\u0057\\u0045\\u0053\\u0054\\u0020\\u0031\\u0032\\u0033\\u0034\\u0020\\u0035\\u0036\\u0039\\u0038\\u0020\\u0037\\u0036\\u0035\\u0034\\u0020\\u0033\\u0032`, raw: "GB82 WEST 1234 5698 7654 32"},
		{name: "secret", value: `\\u0061\\u0070\\u0069\\u005f\\u006b\\u0065\\u0079\\u003d\\u0073\\u006b\\u005f\\u006c\\u0069\\u0076\\u0065\\u005f\\u0031\\u0032\\u0033\\u0034\\u0035\\u0036\\u0037\\u0038\\u0039\\u0030`, raw: "sk_live_1234567890"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(mustJSON(t, tc.value))
			_, _, err := manager.Protect(context.Background(), raw)
			if !errors.Is(err, ErrDataEgressBlocked) {
				t.Fatalf("Protect() error = %v, want ErrDataEgressBlocked", err)
			}
			if strings.Contains(err.Error(), tc.raw) {
				t.Fatal("error exposed the restricted value")
			}
		})
	}
	for _, value := range []any{
		json.Number("4111111111111111"),
		json.RawMessage("4111111111111111"),
		int64(4111111111111111),
		float64(4111111111111111),
	} {
		if _, _, err := manager.Protect(context.Background(), value); !errors.Is(err, ErrDataEgressBlocked) {
			t.Fatalf("numeric card value %v error = %v, want ErrDataEgressBlocked", value, err)
		}
	}
}

func TestProtectEscapedRestrictedKeyFailsClosed(t *testing.T) {
	manager := NewPrivacyManager()
	_, _, err := manager.Protect(context.Background(), map[string]any{
		`\\u0061pi\\u005fkey`: "sk_live_1234567890",
	})
	if !errors.Is(err, ErrDataEgressBlocked) {
		t.Fatalf("Protect() error = %v, want ErrDataEgressBlocked", err)
	}
	_, _, err = manager.Protect(context.Background(), map[string]any{"clientSecret": "not-safe"})
	if !errors.Is(err, ErrDataEgressBlocked) {
		t.Fatalf("camel-case restricted key error = %v, want ErrDataEgressBlocked", err)
	}
}

func TestProtectRejectsUnsupportedAndCyclicValues(t *testing.T) {
	manager := NewPrivacyManager()
	if _, _, err := manager.Protect(context.Background(), make(chan int)); !errors.Is(err, ErrDataEgressInvalid) {
		t.Fatalf("unsupported value error = %v, want ErrDataEgressInvalid", err)
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, _, err := manager.Protect(context.Background(), cycle); !errors.Is(err, ErrDataEgressInvalid) {
		t.Fatalf("cyclic value error = %v, want ErrDataEgressInvalid", err)
	}
}

func TestProtectRejectsPostRedactionExpansion(t *testing.T) {
	manager := NewPrivacyManager()
	value := strings.Repeat("a@b.co ", 140000)
	_, _, err := manager.Protect(context.Background(), value)
	if !errors.Is(err, ErrDataEgressInvalid) {
		t.Fatalf("expanded redaction error = %v, want ErrDataEgressInvalid", err)
	}
}

func TestProtectRejectsAggregateStringBudget(t *testing.T) {
	manager := NewPrivacyManager()
	large := strings.Repeat("x", maxProtectTotalBytes/4)
	if _, _, err := manager.Protect(context.Background(), []string{large, large, large, large, large}); !errors.Is(err, ErrDataEgressInvalid) {
		t.Fatalf("large string slice error = %v, want ErrDataEgressInvalid", err)
	}
	if _, _, err := manager.Protect(context.Background(), map[string]string{
		"a": large,
		"b": large,
		"c": large,
		"d": large,
		"e": large,
	}); !errors.Is(err, ErrDataEgressInvalid) {
		t.Fatalf("large string map error = %v, want ErrDataEgressInvalid", err)
	}
}

func TestProtectConcurrent(t *testing.T) {
	manager := NewPrivacyManager()
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, findings, err := manager.Protect(context.Background(), map[string]any{
				"email": "person@example.com",
				"phone": "+1 415 555 2671",
			})
			if err != nil || len(findings) != 2 || value == nil {
				t.Errorf("concurrent Protect() = value=%v findings=%v err=%v", value, findings, err)
			}
		}()
	}
	wait.Wait()
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON fixture: %v", err)
	}
	return fmt.Sprintf("%s", data)
}
