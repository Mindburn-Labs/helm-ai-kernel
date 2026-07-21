package tracing

import (
	"net/http"
	"testing"
)

func TestIsValidCorrelationID(t *testing.T) {
	valid := "d2f1c3a4-5b6e-4f70-8a91-b2c3d4e5f601"
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"canonical lowercase", valid, true},
		{"empty", "", false},
		{"garbage", "not-a-uuid", false},
		{"uppercase alias rejected", "D2F1C3A4-5B6E-4F70-8A91-B2C3D4E5F601", false},
		{"urn alias rejected", "urn:uuid:" + valid, false},
		{"braced alias rejected", "{" + valid + "}", false},
		{"no hyphens rejected", "d2f1c3a45b6e4f708a91b2c3d4e5f601", false},
		{"injection payload rejected", `x" onload="alert(1)`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidCorrelationID(tc.in); got != tc.want {
				t.Errorf("IsValidCorrelationID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestAdoptOrMintFromHeaders_AdoptsValidInbound(t *testing.T) {
	inbound := "d2f1c3a4-5b6e-4f70-8a91-b2c3d4e5f601"
	h := http.Header{}
	h.Set("X-Helm-Correlation-ID", inbound)

	got, adopted := AdoptOrMintFromHeaders(h)
	if !adopted {
		t.Fatal("expected inbound ID to be adopted")
	}
	if string(got) != inbound {
		t.Errorf("adopted ID = %q, want %q", got, inbound)
	}
}

func TestAdoptOrMintFromHeaders_MintsOnInvalid(t *testing.T) {
	for _, bad := range []string{"", "garbage", "D2F1C3A4-5B6E-4F70-8A91-B2C3D4E5F601"} {
		h := http.Header{}
		if bad != "" {
			h.Set("X-Helm-Correlation-ID", bad)
		}
		got, adopted := AdoptOrMintFromHeaders(h)
		if adopted {
			t.Errorf("inbound %q must not be adopted", bad)
		}
		if !IsValidCorrelationID(string(got)) {
			t.Errorf("minted ID %q is not canonically valid", got)
		}
		if string(got) == bad {
			t.Errorf("minted ID must differ from rejected inbound %q", bad)
		}
	}
}

func TestExtractHTTPHeaders_RejectsMalformed(t *testing.T) {
	h := http.Header{}
	h.Set("X-Helm-Correlation-ID", "not-a-uuid")
	if _, ok := ExtractHTTPHeaders(h); ok {
		t.Error("malformed header value must be rejected")
	}

	valid := "d2f1c3a4-5b6e-4f70-8a91-b2c3d4e5f601"
	h.Set("X-Helm-Correlation-ID", valid)
	id, ok := ExtractHTTPHeaders(h)
	if !ok || string(id) != valid {
		t.Errorf("ExtractHTTPHeaders = (%q, %v), want (%q, true)", id, ok, valid)
	}
}
