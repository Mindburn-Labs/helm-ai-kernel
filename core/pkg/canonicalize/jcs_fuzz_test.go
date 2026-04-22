package canonicalize

import (
	"encoding/json"
	"testing"
)

// TEST-001: Fuzz tests for JCS canonicalization (RFC 8785)

func FuzzJCS(f *testing.F) {
	// Seed corpus with interesting payloads
	f.Add([]byte(`{"a":1,"b":2}`))
	f.Add([]byte(`{"z":{"y":"foo","x":"bar"},"a":1}`))
	f.Add([]byte(`{"html":"<script>alert('xss')</script> &"}`))
	f.Add([]byte(`{"num":123.456,"bool":true,"null":null}`))
	f.Add([]byte(`{"arr":[3,1,2],"nested":{"deep":{"key":"val"}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"":"empty_key","a":""}`))
	f.Add([]byte(`{"unicode":"こんにちは","emoji":"🚀"}`))
	f.Add([]byte(`{"escape":"line1\nline2\ttab"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse as generic JSON — skip invalid JSON
		var v interface{}
		if err := json.Unmarshal(data, &v); err != nil {
			t.Skip("invalid JSON input")
			return
		}

		// JCS must not panic on any valid JSON
		b1, err := JCS(v)
		if err != nil {
			// Some valid JSON may not be representable; that's OK
			return
		}

		// Determinism: same input must produce identical output
		b2, err := JCS(v)
		if err != nil {
			t.Fatal("JCS returned error on second call but not first")
		}

		if string(b1) != string(b2) {
			t.Errorf("JCS non-deterministic:\n  first:  %s\n  second: %s", b1, b2)
		}

		// Output must be valid JSON
		var check interface{}
		if err := json.Unmarshal(b1, &check); err != nil {
			t.Errorf("JCS output is not valid JSON: %s", string(b1))
		}

		// Hash determinism
		h1, err := CanonicalHash(v)
		if err != nil {
			return
		}
		h2, err := CanonicalHash(v)
		if err != nil {
			t.Fatal("CanonicalHash returned error on second call but not first")
		}
		if h1 != h2 {
			t.Errorf("CanonicalHash non-deterministic: %s != %s", h1, h2)
		}
	})
}

func FuzzJCSString(f *testing.F) {
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(`{"a":1,"c":3,"b":2}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var v interface{}
		if err := json.Unmarshal(data, &v); err != nil {
			t.Skip("invalid JSON")
			return
		}

		s, err := JCSString(v)
		if err != nil {
			return
		}

		// String output must match byte output
		b, err := JCS(v)
		if err != nil {
			t.Fatal("JCS failed but JCSString succeeded")
		}

		if s != string(b) {
			t.Errorf("JCSString != JCS: %q vs %q", s, string(b))
		}
	})
}
