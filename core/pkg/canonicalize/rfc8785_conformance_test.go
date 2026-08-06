package canonicalize

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests pin HELM canonical JSON to the bytes described in
// protocols/specs/rfc/canonical-json-v1.md. Every assertion here is a byte
// a third party will hold us to once a vector pack ships, so any change that
// alters canonical output must fail here first.

// TestRFC8785Section323SortingVector runs the object-property sorting example
// published in RFC 8785 Section 3.2.3. It is the load-bearing conformance
// check: the emoji key U+1F600 is a supplementary-plane character whose UTF-16
// surrogate pair (D83D DE00) sorts BEFORE the BMP key U+FB33, while UTF-8 byte
// order (equivalently, code point order) puts it after. An implementation that
// sorts by code point fails this test; the HELM canonicalizer did, before
// 2026-08-06.
func TestRFC8785Section323SortingVector(t *testing.T) {
	input := `{
	  "€": "Euro Sign",
	  "\r": "Carriage Return",
	  "דּ": "Hebrew Letter Dalet With Dagesh",
	  "1": "One",
	  "😀": "Emoji: Grinning Face",
	  "": "Control",
	  "ö": "Latin Small Letter O With Diaeresis"
	}`

	var generic interface{}
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		t.Fatalf("decode RFC 8785 sample: %v", err)
	}

	got, err := JCS(generic)
	if err != nil {
		t.Fatalf("JCS: %v", err)
	}

	// RFC 8785 Section 3.2.3 publishes this exact property order.
	wantOrder := []string{
		"Carriage Return",
		"One",
		"Control",
		"Latin Small Letter O With Diaeresis",
		"Euro Sign",
		"Emoji: Grinning Face",
		"Hebrew Letter Dalet With Dagesh",
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v", err)
	}
	prev := -1
	for _, value := range wantOrder {
		idx := strings.Index(string(got), `:"`+value+`"`)
		if idx < 0 {
			t.Fatalf("value %q missing from canonical output %s", value, got)
		}
		if idx <= prev {
			t.Fatalf("property %q is out of RFC 8785 order in %s", value, got)
		}
		prev = idx
	}

	// Byte-exact expectation. U+0080 is outside the RFC 8785 Section 3.2.2.2
	// escape set (U+0000..U+001F only), so it is emitted as literal UTF-8.
	want := "{" +
		`"\r":"Carriage Return",` +
		`"1":"One",` +
		"\"\":\"Control\"," +
		"\"ö\":\"Latin Small Letter O With Diaeresis\"," +
		"\"€\":\"Euro Sign\"," +
		"\"\U0001F600\":\"Emoji: Grinning Face\"," +
		"\"דּ\":\"Hebrew Letter Dalet With Dagesh\"" +
		"}"
	if string(got) != want {
		t.Fatalf("canonical bytes mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestKeyOrderingIsUTF16NotCodePoint isolates the single input class where the
// two orderings disagree, with no other variable in play.
func TestKeyOrderingIsUTF16NotCodePoint(t *testing.T) {
	// U+FFFD  -> UTF-16 [FFFD],       UTF-8 EF BF BD
	// U+10000 -> UTF-16 [D800 DC00],  UTF-8 F0 90 80 80
	// UTF-16:      D800 < FFFD, so U+10000 sorts first.
	// Code point:  FFFD < 10000, so U+FFFD would sort first.
	got, err := JCS(map[string]int{"�": 1, "\U00010000": 2})
	if err != nil {
		t.Fatalf("JCS: %v", err)
	}
	want := "{\"\U00010000\":2,\"�\":1}"
	if string(got) != want {
		t.Fatalf("supplementary-plane key must sort first\n got: %q\nwant: %q", got, want)
	}
}

func TestLessUTF16(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"a", "b", true},
		{"b", "a", false},
		{"a", "a", false},
		{"a", "ab", true},
		{"ab", "a", false},
		// The divergence class.
		{"\U00010000", "�", true},
		{"�", "\U00010000", false},
		{"\U0001F600", "דּ", true},
		{"דּ", "\U0001F600", false},
		// U+E000 is the first BMP code point that outranks a surrogate lead.
		{"\U00010000", "", true},
		// Below U+E000 the two orderings agree.
		{"퟿", "\U00010000", true},
		{"€", "\U0001F600", true},
	}
	for _, tc := range cases {
		if got := lessUTF16(tc.a, tc.b); got != tc.want {
			t.Errorf("lessUTF16(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestStringEscapeSetMatchesRFC8785 pins RFC 8785 Section 3.2.2.2: only
// U+0000..U+001F, '"' and '\' are escaped; everything else is literal UTF-8.
func TestStringEscapeSetMatchesRFC8785(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"quote", `"`, `{"v":"\""}`},
		{"backslash", `\`, `{"v":"\\"}`},
		{"backspace", "\b", `{"v":"\b"}`},
		{"formfeed", "\f", `{"v":"\f"}`},
		{"newline", "\n", `{"v":"\n"}`},
		{"carriage_return", "\r", `{"v":"\r"}`},
		{"tab", "\t", `{"v":"\t"}`},
		{"other_control", "\u0001", `{"v":"\u0001"}`},
		{"unit_separator", "\u001f", `{"v":"\u001f"}`},
		// Not escaped by RFC 8785, though encoding/json and many ad-hoc
		// canonicalizers escape them.
		{"html_chars", "<&>", `{"v":"<&>"}`},
		{"delete_u007f", "", "{\"v\":\"\"}"},
		{"line_separator_u2028", " ", "{\"v\":\" \"}"},
		{"paragraph_separator_u2029", " ", "{\"v\":\" \"}"},
		{"c1_control_u0080", "", "{\"v\":\"\"}"},
		{"astral", "\U0001F600", "{\"v\":\"\U0001F600\"}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := JCS(map[string]string{"v": tc.value})
			if err != nil {
				t.Fatalf("JCS: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestNumberLiteralsArePreservedNotES6 pins the one documented deviation from
// RFC 8785. Each `wantRFC8785` value is what ECMAScript Number-to-String
// (RFC 8785 Section 3.2.2.3) produces; `want` is what HELM emits. Where they
// differ, CheckInteroperableNumbers MUST reject the input — that pairing is
// the property the specification promises.
func TestNumberLiteralsArePreservedNotES6(t *testing.T) {
	cases := []struct {
		literal       string
		want          string
		wantRFC8785   string
		interoperable bool
	}{
		{"0", "0", "0", true},
		{"-1", "-1", "-1", true},
		{"9007199254740991", "9007199254740991", "9007199254740991", true},
		{"-9007199254740991", "-9007199254740991", "-9007199254740991", true},

		// Deviations. HELM preserves the literal; RFC 8785 re-renders.
		{"1e2", "1e2", "100", false},
		{"1E2", "1E2", "100", false},
		{"1.0", "1.0", "1", false},
		{"1.50", "1.50", "1.5", false},
		{"-0", "-0", "0", false},
		{"1e21", "1e21", "1e+21", false},
		{"9007199254740993", "9007199254740993", "9007199254740992", false},
		{"10000000000000000000", "10000000000000000000", "10000000000000000000", false},
		{"0.1", "0.1", "0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.literal, func(t *testing.T) {
			var generic interface{}
			decoder := json.NewDecoder(strings.NewReader(`{"a":` + tc.literal + `}`))
			decoder.UseNumber()
			if err := decoder.Decode(&generic); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got, err := JCS(generic)
			if err != nil {
				t.Fatalf("JCS: %v", err)
			}
			if string(got) != `{"a":`+tc.want+`}` {
				t.Fatalf("JCS(%s) = %s, want {\"a\":%s}", tc.literal, got, tc.want)
			}
			err = CheckInteroperableNumbers(generic)
			if tc.interoperable {
				if err != nil {
					t.Fatalf("literal %s must be inside the interoperable subset: %v", tc.literal, err)
				}
				if tc.want != tc.wantRFC8785 {
					t.Fatalf("literal %s is admitted but HELM (%s) and RFC 8785 (%s) disagree", tc.literal, tc.want, tc.wantRFC8785)
				}
				return
			}
			if err == nil {
				t.Fatalf("literal %s deviates from RFC 8785 (%s vs %s) and MUST be rejected", tc.literal, tc.want, tc.wantRFC8785)
			}
		})
	}
}

// TestGoValueNumberFormatting pins what Go-typed fields produce, because the
// JCS entry point pre-marshals through encoding/json.
func TestGoValueNumberFormatting(t *testing.T) {
	type sample struct {
		Int64   int64   `json:"i"`
		Uint64  uint64  `json:"u"`
		Float   float64 `json:"f"`
		NegZero float64 `json:"z"`
	}
	negZero := func() float64 { z := 0.0; return -z }()
	got, err := JCS(sample{Int64: 9007199254740993, Uint64: 18446744073709551615, Float: 1e21, NegZero: negZero})
	if err != nil {
		t.Fatalf("JCS: %v", err)
	}
	want := `{"f":1e+21,"i":9007199254740993,"u":18446744073709551615,"z":-0}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
	// Every one of those four is outside the interoperable subset, so the
	// fence catches a struct like this before its bytes can be published.
	if err := CheckInteroperableNumbers(sample{Int64: 9007199254740993}); err == nil {
		t.Fatal("int64 beyond 2^53-1 must be rejected")
	}
	if err := CheckInteroperableNumbers(sample{NegZero: negZero}); err == nil {
		t.Fatal("negative zero must be rejected")
	}
	if err := CheckInteroperableNumbers(sample{Float: 1e21}); err == nil {
		t.Fatal("float in exponential form must be rejected")
	}
}

func TestCheckInteroperableNumbers(t *testing.T) {
	t.Run("accepts safe integers everywhere", func(t *testing.T) {
		v := map[string]interface{}{
			"a": 0,
			"b": []interface{}{1, -1, MaxSafeInteger, -MaxSafeInteger},
			"c": map[string]interface{}{"d": 42},
			"e": "1e2 in a string is fine",
			"f": nil,
			"g": true,
		}
		if err := CheckInteroperableNumbers(v); err != nil {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})

	t.Run("names the path of the first offender", func(t *testing.T) {
		var nested interface{}
		decoder := json.NewDecoder(strings.NewReader(`{"outer":{"inner":[0,1,2.5]}}`))
		decoder.UseNumber()
		if err := decoder.Decode(&nested); err != nil {
			t.Fatalf("decode: %v", err)
		}
		err := CheckInteroperableNumbers(nested)
		if err == nil {
			t.Fatal("2.5 must be rejected")
		}
		if !strings.Contains(err.Error(), "$.outer.inner[2]") {
			t.Fatalf("error must name the JSON path, got %v", err)
		}
	})

	t.Run("MaxSafeInteger boundary", func(t *testing.T) {
		for _, lit := range []string{"9007199254740991", "-9007199254740991"} {
			if !isInteroperableNumberLiteral(lit) {
				t.Errorf("%s must be accepted", lit)
			}
		}
		for _, lit := range []string{"9007199254740992", "-9007199254740992", "-0", "00", "01", "1e2", "1.0", ""} {
			if isInteroperableNumberLiteral(lit) {
				t.Errorf("%s must be rejected", lit)
			}
		}
	})

	t.Run("InteroperableJCS gates the bytes", func(t *testing.T) {
		if _, err := InteroperableJCS(map[string]float64{"v": 2.5}); err == nil {
			t.Fatal("InteroperableJCS must refuse a non-integer")
		}
		got, err := InteroperableJCS(map[string]int{"v": 2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != `{"v":2}` {
			t.Fatalf("got %s", got)
		}
	})
}

// TestJCSIsLossyOnInvalidUTF8 pins a behaviour a verifier author must know:
// ill-formed UTF-8 is silently repaired to U+FFFD by the encoding/json
// pre-marshal, so JCS never sees it and never errors.
func TestJCSIsLossyOnInvalidUTF8(t *testing.T) {
	got, err := JCS(map[string]string{"v": string([]byte{0xff, 0xfe})})
	if err != nil {
		t.Fatalf("JCS unexpectedly failed: %v", err)
	}
	want := "{\"v\":\"��\"}"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// The guard inside marshalJCSString is still the backstop for callers that
	// reach it with a raw string value.
	if _, err := marshalJCSString(string([]byte{0xff})); err == nil {
		t.Fatal("marshalJCSString must reject ill-formed UTF-8")
	}
}

// TestASCIIKeysAreOrderingNeutral is the regression guard for the claim that
// switching to UTF-16 ordering changed no published bytes: every canonical
// artifact in this repository uses ASCII object keys, and for those the two
// orderings are identical.
func TestASCIIKeysAreOrderingNeutral(t *testing.T) {
	keys := []string{
		"signature_version", "receipt_id", "decision_id", "effect_id", "status",
		"output_hash", "prev_hash", "lamport_clock", "args_hash", "verdict",
		"reason_code", "policy_hash", "session_id", "log_id", "root_hash",
		"timestamp", "tree_size", "Z", "a", "0", "_", "~",
	}
	for _, a := range keys {
		for _, b := range keys {
			if lessUTF16(a, b) != (a < b) {
				t.Fatalf("ASCII keys %q/%q order differently under UTF-16 and byte comparison", a, b)
			}
		}
	}
}
