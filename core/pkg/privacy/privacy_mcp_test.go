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
			"phone":               "+1 (415) 555-2671",
			"compact_phone":       "4155552671",
			"international_phone": "442079460958",
			"id":                  "2026082712345",
			"date":                "2026-08-27",
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
	for _, raw := range []string{"person@example.com", "+1 (415) 555-2671", "4155552671", "442079460958", "+44 20 7946 0958"} {
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
	barePhone, findings, err := manager.Protect(context.Background(), "442079460958")
	if err != nil || barePhone != "[REDACTED_PHONE]" || !reflect.DeepEqual(findings, []string{"phone"}) {
		t.Fatalf("international phone protection = value=%v findings=%v err=%v", barePhone, findings, err)
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
		{name: "AWS secret access key", value: map[string]any{"aws_secret_access_key": "ordinary40charactercredentialmaterial000"}, raw: "ordinary40charactercredentialmaterial000"},
		{name: "ssn", value: "SSN: 123-45-6789", raw: "123-45-6789"},
		{name: "space separated ssn", value: "SSN: 123 45 6789", raw: "123 45 6789"},
		{name: "compact ssn", value: "SSN: 123456789", raw: "123456789"},
		{name: "card", value: "4111 1111 1111 1111", raw: "4111 1111 1111 1111"},
		{name: "dot separated card", value: "card: 4111.1111.1111.1111", raw: "4111.1111.1111.1111"},
		{name: "iban", value: "GB82 WEST 1234 5698 7654 32", raw: "GB82 WEST 1234 5698 7654 32"},
		{name: "Irish iban", value: "IE29 AIBK 9311 5212 3456 78", raw: "IE29 AIBK 9311 5212 3456 78"},
		{name: "jwt", value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature1234", raw: "eyJhbGciOiJIUzI1NiJ9"},
		{name: "jwt with short claims segment", value: "eyJhbGciOiJIUzI1NiJ9.e30.signature1234", raw: "signature1234"},
		{name: "private key", value: "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----", raw: "-----BEGIN RSA PRIVATE KEY-----"},
		{name: "PGP private key", value: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret\n-----END PGP PRIVATE KEY BLOCK-----", raw: "-----BEGIN PGP PRIVATE KEY BLOCK-----"},
		{name: "connection URI credential", value: "postgres://alice:pA55word!@db:5432/app", raw: "pA55word!"},
		{name: "Google API key", value: "AIza" + strings.Repeat("A", 35), raw: "AIza"},
		{name: "short password assignment", value: "password=abc123", raw: "abc123"},
		{name: "quoted JSON password", value: `{"password":"abc123"}`, raw: "abc123"},
		{name: "escaped quoted JSON password", value: `{\"password\":\"abc123\"}`, raw: "abc123"},
		{name: "camel-case JSON token", value: `{"refreshToken":"abc123"}`, raw: "abc123"},
		{name: "escaped camel-case JSON token", value: `{\"refreshToken\":\"abc123\"}`, raw: "abc123"},
		{name: "basic authorization header", value: "Authorization: Basic dXNlcjpwYXNzd29yZA==", raw: "dXNlcjpwYXNzd29yZA=="},
		{name: "short token assignment", value: "token: x", raw: "x"},
		{name: "labeled jwt", value: "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234", raw: "signature1234"},
		{name: "URL jwt", value: "https://example.test/callback?jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234&next=1", raw: "signature1234"},
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

func TestProtectRejectsMixedEncodedRestrictedKey(t *testing.T) {
	manager := NewPrivacyManager()
	_, _, err := manager.Protect(context.Background(), map[string]any{
		"%5Cu0061pi_key": "opaque",
	})
	if !errors.Is(err, ErrDataEgressBlocked) {
		t.Fatalf("Protect() error = %v, want ErrDataEgressBlocked", err)
	}
}

func TestProtectEncodedPIIAndInternationalPhones(t *testing.T) {
	manager := NewPrivacyManager()
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "percent encoded email",
			value: "https://example.test/?email=alice%40example.com&next=1",
			want:  "https://example.test/?email=[REDACTED_EMAIL]&next=1",
		},
		{
			name:  "double percent encoded email fails closed",
			value: "https://example.test/?email=alice%2540example.com",
		},
		{
			name:  "HTML entity encoded email fails closed",
			value: "alice&#64;example.com",
		},
		{
			name:  "Unicode and HTML entity encoded email fails closed",
			value: `alice\u0026#64;example.com`,
		},
		{
			name:  "00 prefixed phone",
			value: "call 0044 20 7946 0958 now",
			want:  "call [REDACTED_PHONE] now",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protected, _, err := manager.Protect(context.Background(), tc.value)
			if tc.want == "" {
				if !errors.Is(err, ErrDataEgressBlocked) {
					t.Fatalf("Protect() error = %v, want ErrDataEgressBlocked", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Protect() error = %v", err)
			}
			if protected != tc.want {
				t.Fatalf("Protect() = %q, want %q", protected, tc.want)
			}
		})
	}
}

func TestProtectRedactsInternationalizedEmailAddresses(t *testing.T) {
	manager := NewPrivacyManager()
	for _, address := range []string{
		"用户@例子.公司",
		"alice@例子。公司",
	} {
		protected, findings, err := manager.Protect(context.Background(), address)
		if err != nil {
			t.Fatalf("Protect(%q) error = %v", address, err)
		}
		if protected != "[REDACTED_EMAIL]" || !reflect.DeepEqual(findings, []string{"email"}) {
			t.Fatalf("Protect(%q) = value=%v findings=%v", address, protected, findings)
		}
		if scrubbed := manager.Scrub(context.Background(), address, PIISensitive); scrubbed != "[REDACTED_EMAIL]" {
			t.Fatalf("Scrub(%q) = %q", address, scrubbed)
		}
	}
}

func TestProtectDistinguishesNumericIDsPhonesAndIPv4(t *testing.T) {
	manager := NewPrivacyManager()
	input := map[string]any{
		"comment_id": int64(12345678901),
		"phone":      json.Number("442079460958"),
		"endpoint":   "http://192.168.100.200/api",
		"document":   `{"comment_id":12345678901}`,
	}
	protected, findings, err := manager.Protect(context.Background(), input)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	got := protected.(map[string]any)
	if got["comment_id"] != input["comment_id"] {
		t.Fatalf("comment id changed: %#v", got["comment_id"])
	}
	if got["phone"] != "[REDACTED_PHONE]" {
		t.Fatalf("numeric phone = %#v, want redaction", got["phone"])
	}
	if got["endpoint"] != input["endpoint"] || got["document"] != input["document"] {
		t.Fatalf("clean network/id values changed: %#v", got)
	}
	if !reflect.DeepEqual(findings, []string{"phone"}) {
		t.Fatalf("findings = %v, want phone", findings)
	}
	for _, value := range []any{int64(12345678901), json.Number("12345678901")} {
		if protected, findings, err := manager.Protect(context.Background(), value); err != nil || protected != value || len(findings) != 0 {
			t.Fatalf("bare numeric id = %#v findings=%v err=%v", protected, findings, err)
		}
	}
}

func TestProtectAcceptsJSONSafeNamedPrimitives(t *testing.T) {
	type status string
	type count int64
	type ratio float64
	type enabled bool

	input := map[string]any{
		"status":  status("ready"),
		"count":   count(42),
		"ratio":   ratio(1.5),
		"enabled": enabled(true),
	}
	protected, findings, err := NewPrivacyManager().Protect(context.Background(), input)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if len(findings) != 0 || !reflect.DeepEqual(protected, input) {
		t.Fatalf("Protect() = %#v findings=%v, want named primitives preserved", protected, findings)
	}
}

func TestProtectRejectsMaestroPANs(t *testing.T) {
	for _, value := range []any{
		"6759649826438453",
		json.Number("6759649826438453"),
		int64(6759649826438453),
	} {
		if _, _, err := NewPrivacyManager().Protect(context.Background(), value); !errors.Is(err, ErrDataEgressBlocked) {
			t.Fatalf("Maestro PAN %#v error = %v, want ErrDataEgressBlocked", value, err)
		}
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

func TestProtectRedactsPIIWithoutDecodingUnrelatedEscapes(t *testing.T) {
	manager := NewPrivacyManager()
	input := `literal=\u007b owner=person@example.com phone=4155552671`
	protected, findings, err := manager.Protect(context.Background(), input)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if !reflect.DeepEqual(findings, []string{"email", "phone"}) {
		t.Fatalf("findings = %v, want email and phone", findings)
	}
	want := `literal=\u007b owner=[REDACTED_EMAIL] phone=[REDACTED_PHONE]`
	if got := protected.(string); got != want {
		t.Fatalf("protected escaped value = %q, want %q", got, want)
	}
}

func TestProtectAllowsTokenMetadataAndLuhnDeviceIdentifiers(t *testing.T) {
	manager := NewPrivacyManager()
	input := map[string]any{
		"max_tokens":           2048,
		"token_count":          42,
		"tokenizer":            "cl100k_base",
		"device_id":            "490154203237518",
		"product_code":         "5600000000069",
		"authorization_status": "approved",
		"authorizationStatus":  "approved",
	}
	protected, findings, err := manager.Protect(context.Background(), input)
	if err != nil {
		t.Fatalf("Protect() metadata error = %v", err)
	}
	if len(findings) != 0 || !reflect.DeepEqual(protected, input) {
		t.Fatalf("Protect() metadata = value=%#v findings=%v", protected, findings)
	}
	for _, value := range []string{`{"token_count":42}`, `tokenizer=cl100k_base`} {
		if protected, findings, err := manager.Protect(context.Background(), value); err != nil || protected != value || len(findings) != 0 {
			t.Fatalf("Protect() text metadata = value=%#v findings=%v err=%v", protected, findings, err)
		}
	}
	if _, _, err := manager.Protect(context.Background(), map[string]any{"auth_token": "abc123"}); !errors.Is(err, ErrDataEgressBlocked) {
		t.Fatalf("auth_token error = %v, want ErrDataEgressBlocked", err)
	}
	for _, key := range []string{"refreshToken", "oauthToken", "tokenValue"} {
		if _, _, err := manager.Protect(context.Background(), map[string]any{key: "abc123"}); !errors.Is(err, ErrDataEgressBlocked) {
			t.Fatalf("%s error = %v, want ErrDataEgressBlocked", key, err)
		}
	}
	for _, value := range []any{
		"490154203237518",
		json.Number("490154203237518"),
		"5600000000069",
		json.Number("5600000000069"),
	} {
		if _, _, err := manager.Protect(context.Background(), value); err != nil {
			t.Fatalf("non-payment Luhn identifier %v was blocked: %v", value, err)
		}
	}
}

func TestProtectDoesNotMisclassifyNonRegisteredIBANShapes(t *testing.T) {
	manager := NewPrivacyManager()
	for _, value := range []string{
		"ZZ8112345678901",
		"GB3312345678901",
	} {
		protected, findings, err := manager.Protect(context.Background(), value)
		if err != nil || protected != value || len(findings) != 0 {
			t.Fatalf("Protect(%q) = value=%#v findings=%v err=%v", value, protected, findings, err)
		}
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
		json.Number("4.111111111111111e15"),
		json.Number("4000000000000000006"),
		json.RawMessage("4111111111111111"),
		int64(4111111111111111),
		float64(4111111111111111),
	} {
		if _, _, err := manager.Protect(context.Background(), value); !errors.Is(err, ErrDataEgressBlocked) {
			t.Fatalf("numeric card value %v error = %v, want ErrDataEgressBlocked", value, err)
		}
	}
	if _, _, err := manager.Protect(context.Background(), float64(4000000000000000006)); !errors.Is(err, ErrDataEgressInvalid) {
		t.Fatalf("imprecise float PAN error = %v, want ErrDataEgressInvalid", err)
	}
}

func TestExactIntegerDigitsBoundsExponentExpansion(t *testing.T) {
	if got := exactIntegerDigits("4.111111111111111e15"); got != "4111111111111111" {
		t.Fatalf("scientific integer = %q, want exact PAN digits", got)
	}
	if got := exactIntegerDigits("41111111111111110e-1"); got != "4111111111111111" {
		t.Fatalf("negative exponent integer = %q, want exact PAN digits", got)
	}
	var got string
	allocs := testing.AllocsPerRun(10, func() {
		got = exactIntegerDigits("1e1000000")
	})
	if got != "" {
		t.Fatalf("huge exponent expanded to %d digits", len(got))
	}
	if allocs > 8 {
		t.Fatalf("huge exponent allocations = %.0f, want <= 8", allocs)
	}
}

func BenchmarkProtectManyDistinctEmails(b *testing.B) {
	manager := NewPrivacyManager()
	var input strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&input, "person%d@example%d.test ", i, i)
	}
	value := input.String()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := manager.Protect(context.Background(), value); err != nil {
			b.Fatal(err)
		}
	}
}

func TestProtectManyDistinctEmailsAllocationBound(t *testing.T) {
	manager := NewPrivacyManager()
	var input strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&input, "person%d@example%d.test ", i, i)
	}
	value := input.String()
	allocs := testing.AllocsPerRun(1, func() {
		if _, _, err := manager.Protect(context.Background(), value); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 50_000 {
		t.Fatalf("Protect() allocations = %.0f, want <= 50000", allocs)
	}
}

func TestProtectEscapedRestrictedKeyFailsClosed(t *testing.T) {
	manager := NewPrivacyManager()
	for _, key := range []string{`\\u0061pi\\u005fkey`, "api%5Fkey"} {
		_, _, err := manager.Protect(context.Background(), map[string]any{key: "not-safe"})
		if !errors.Is(err, ErrDataEgressBlocked) {
			t.Fatalf("restricted key %q error = %v, want ErrDataEgressBlocked", key, err)
		}
	}
	_, _, err := manager.Protect(context.Background(), map[string]any{"clientSecret": "not-safe"})
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
