package tee

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestQuoteValidateBasic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		quote   *Quote
		wantErr string
	}{
		{
			name:    "nil",
			quote:   nil,
			wantErr: "quote is nil",
		},
		{
			name:    "empty platform",
			quote:   &Quote{Raw: []byte{1}, Nonce: make([]byte, NonceSize)},
			wantErr: "empty platform",
		},
		{
			name:    "empty raw",
			quote:   &Quote{Platform: PlatformSEVSNP, Nonce: make([]byte, NonceSize)},
			wantErr: "raw is empty",
		},
		{
			name:    "wrong nonce size",
			quote:   &Quote{Platform: PlatformSEVSNP, Raw: []byte{1}, Nonce: make([]byte, 16)},
			wantErr: "nonce length",
		},
		{
			name:    "ok",
			quote:   &Quote{Platform: PlatformSEVSNP, Raw: []byte{1}, Nonce: make([]byte, NonceSize)},
			wantErr: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.quote.ValidateBasic()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestQuoteString(t *testing.T) {
	t.Parallel()
	q := &Quote{Platform: PlatformMock, Raw: []byte{1, 2, 3}, Nonce: make([]byte, NonceSize), Measurement: make([]byte, 32)}
	got := q.String()
	if !strings.Contains(got, "platform=mock") {
		t.Fatalf("Quote.String() missing platform: %q", got)
	}
	if got2 := (*Quote)(nil).String(); got2 != "<nil quote>" {
		t.Fatalf("nil Quote.String() = %q, want <nil quote>", got2)
	}
}

func TestPlatformConstants(t *testing.T) {
	t.Parallel()
	for _, p := range []Platform{PlatformSEVSNP, PlatformTDX, PlatformNitro, PlatformMock} {
		if string(p) == "" {
			t.Fatalf("platform constant is empty")
		}
	}
}

func TestNewAttestationResultEnvelopeRequiresSignedVerifierResult(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	result := &VerifyResult{
		Platform:    PlatformNitro,
		Measurement: []byte{1, 2, 3},
		Nonce:       []byte{4, 5, 6},
	}
	profile := contracts.VerifierProfile{ProfileID: "nitro-prod", AppraisalPolicyHash: "sha256:policy"}
	if _, err := NewAttestationResultEnvelope(AppraisalInput{
		Result:     result,
		Profile:    profile,
		EnvelopeID: "attestation-1",
		Subject:    "verifier",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Minute),
	}); err == nil {
		t.Fatal("expected unsigned appraisal result rejection")
	}
	env, err := NewAttestationResultEnvelope(AppraisalInput{
		Result:     result,
		Profile:    profile,
		EnvelopeID: "attestation-1",
		Subject:    "verifier",
		Signature:  "sig",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.ProfileID != "nitro-prod" || env.Platform != string(PlatformNitro) || env.TrustTier != "verified" || env.Synthetic {
		t.Fatalf("unexpected attestation result envelope: %+v", env)
	}
}

// Compile-time assertion that every adapter implements the interface.
var (
	_ RemoteAttester = (*MockAttester)(nil)
	_ RemoteAttester = (*SEVSNPAttester)(nil)
	_ RemoteAttester = (*TDXAttester)(nil)
	_ RemoteAttester = (*NitroAttester)(nil)
)
