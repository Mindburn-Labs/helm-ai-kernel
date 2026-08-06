package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

func testPermitSigner(t *testing.T) *Ed25519Signer {
	t.Helper()
	signer, err := NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x17}, ed25519.SeedSize), "permit-test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func testPermit() *effects.EffectPermit {
	issued := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	return &effects.EffectPermit{
		PermitID:    "permit-0123456789abcdef",
		IntentHash:  "sha256:intent",
		VerdictHash: "sha256:verdict",
		PolicyHash:  "sha256:policy",
		EffectType:  effects.EffectTypeWrite,
		ConnectorID: "connector-under-test",
		Scope: effects.EffectScope{
			AllowedAction: "files.write",
			AllowedParams: []string{"path", "contents"},
			DenyPatterns:  []string{"/etc/*"},
		},
		ResourceRef:      "file:///workspace/report.md",
		ExpiresAt:        issued.Add(5 * time.Minute),
		SingleUse:        true,
		Nonce:            "nonce-abc",
		IssuedAt:         issued,
		IssuerID:         "kernel-issuer",
		EvidenceBindings: map[string]string{"decision_id": "decision-1"},
	}
}

type stubNonceStore struct {
	consumed map[string]bool
}

func (s stubNonceStore) HasNonce(nonce string) bool { return s.consumed[nonce] }

func (s stubNonceStore) RecordNonce(nonce string) error {
	s.consumed[nonce] = true
	return nil
}

func TestSignPermitProducesVerifiableSignature(t *testing.T) {
	signer := testPermitSigner(t)
	permit := testPermit()
	if err := SignPermit(signer, permit); err != nil {
		t.Fatalf("SignPermit: %v", err)
	}
	if permit.Signature == "" {
		t.Fatal("permit carries no signature after signing")
	}
	if permit.SignatureVersion != PermitSignatureV1 {
		t.Fatalf("signature version = %q, want %q", permit.SignatureVersion, PermitSignatureV1)
	}
	if err := VerifyPermitSignature(signer.PublicKey(), permit); err != nil {
		t.Fatalf("freshly signed permit does not verify: %v", err)
	}
}

// Every field the envelope binds must break the signature when altered. This is
// the F-05 lesson: receipt v4 bound 8 of ~80 fields, leaving verdict, policy
// hash and key id rewritable under a valid signature.
func TestPermitSignatureBindsEveryAuthorizingField(t *testing.T) {
	signer := testPermitSigner(t)
	tamper := map[string]func(p *effects.EffectPermit){
		"permit id":         func(p *effects.EffectPermit) { p.PermitID = "permit-other" },
		"intent hash":       func(p *effects.EffectPermit) { p.IntentHash = "sha256:other" },
		"verdict hash":      func(p *effects.EffectPermit) { p.VerdictHash = "sha256:other" },
		"policy hash":       func(p *effects.EffectPermit) { p.PolicyHash = "sha256:other" },
		"effect type":       func(p *effects.EffectPermit) { p.EffectType = effects.EffectTypeRead },
		"connector id":      func(p *effects.EffectPermit) { p.ConnectorID = "other-connector" },
		"allowed action":    func(p *effects.EffectPermit) { p.Scope.AllowedAction = "files.delete" },
		"allowed params":    func(p *effects.EffectPermit) { p.Scope.AllowedParams = append(p.Scope.AllowedParams, "mode") },
		"deny patterns":     func(p *effects.EffectPermit) { p.Scope.DenyPatterns = nil },
		"resource ref":      func(p *effects.EffectPermit) { p.ResourceRef = "file:///etc/passwd" },
		"expiry":            func(p *effects.EffectPermit) { p.ExpiresAt = p.ExpiresAt.Add(time.Hour) },
		"single use":        func(p *effects.EffectPermit) { p.SingleUse = false },
		"nonce":             func(p *effects.EffectPermit) { p.Nonce = "nonce-other" },
		"issued at":         func(p *effects.EffectPermit) { p.IssuedAt = p.IssuedAt.Add(time.Minute) },
		"issuer id":         func(p *effects.EffectPermit) { p.IssuerID = "other-issuer" },
		"evidence bindings": func(p *effects.EffectPermit) { p.EvidenceBindings["decision_id"] = "decision-2" },
		"signature version": func(p *effects.EffectPermit) { p.SignatureVersion = "permit.v99" },
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			permit := testPermit()
			if err := SignPermit(signer, permit); err != nil {
				t.Fatalf("SignPermit: %v", err)
			}
			mutate(permit)
			err := VerifyPermitSignature(signer.PublicKey(), permit)
			if err == nil {
				t.Fatalf("tampering with %s left the signature valid", name)
			}
			if !errors.Is(err, ErrPermitSignatureInvalid) {
				t.Fatalf("tampering with %s: err = %v, want ErrPermitSignatureInvalid", name, err)
			}
		})
	}
}

// F-06: the v4 receipt preimage joined fields with a bare ":" and escaped
// nothing, so a colon inside a value shifted the boundaries and two distinct
// records shared one preimage. A JCS object cannot do that; prove it.
func TestPermitPreimageResistsFieldBoundaryConfusion(t *testing.T) {
	first := testPermit()
	first.Scope.AllowedAction = "files.write:extra"
	first.ResourceRef = "file:///a"

	second := testPermit()
	second.Scope.AllowedAction = "files.write"
	second.ResourceRef = "extra:file:///a"

	firstPayload, err := CanonicalizePermitV1(first)
	if err != nil {
		t.Fatalf("canonicalize first: %v", err)
	}
	secondPayload, err := CanonicalizePermitV1(second)
	if err != nil {
		t.Fatalf("canonicalize second: %v", err)
	}
	if bytes.Equal(firstPayload, secondPayload) {
		t.Fatal("two distinct permits produced the same preimage")
	}
}

func TestCanonicalPermitPayloadIsTimezoneStable(t *testing.T) {
	utc := testPermit()
	shifted := testPermit()
	zone := time.FixedZone("UTC+3", 3*60*60)
	shifted.IssuedAt = shifted.IssuedAt.In(zone)
	shifted.ExpiresAt = shifted.ExpiresAt.In(zone)

	utcPayload, err := CanonicalizePermitV1(utc)
	if err != nil {
		t.Fatalf("canonicalize utc: %v", err)
	}
	shiftedPayload, err := CanonicalizePermitV1(shifted)
	if err != nil {
		t.Fatalf("canonicalize shifted: %v", err)
	}
	if !bytes.Equal(utcPayload, shiftedPayload) {
		t.Fatal("the same instant in another location produced a different preimage")
	}
}

func TestPermitVerifyPayloadRejectsUnknownAndMissingVersions(t *testing.T) {
	permit := testPermit()
	permit.SignatureVersion = ""
	if _, err := PermitVerifyPayload(permit); err == nil {
		t.Fatal("an unversioned permit must not resolve to a preimage")
	}
	permit.SignatureVersion = "permit.v2"
	if _, err := PermitVerifyPayload(permit); err == nil {
		t.Fatal("an unknown version must be rejected rather than guessed")
	}
}

// The consumption gate: every one of these must deny.
func TestVerifyPermitForUseFailsClosed(t *testing.T) {
	signer := testPermitSigner(t)
	now := time.Date(2026, 8, 6, 12, 1, 0, 0, time.UTC)

	cases := []struct {
		name    string
		prepare func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions)
		wantErr error
	}{
		{
			name: "unsigned permit",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				return testPermit(), PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: now}
			},
			wantErr: ErrPermitUnsigned,
		},
		{
			name: "signature present but version missing",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				p := testPermit()
				if err := SignPermit(signer, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				p.SignatureVersion = ""
				return p, PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: now}
			},
			wantErr: ErrPermitUnsigned,
		},
		{
			name: "tampered scope",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				p := testPermit()
				if err := SignPermit(signer, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				p.Scope.AllowedAction = "files.delete"
				return p, PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: now}
			},
			wantErr: ErrPermitSignatureInvalid,
		},
		{
			name: "signed by an unrelated key",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				foreign, err := NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize), "foreign")
				if err != nil {
					t.Fatalf("foreign signer: %v", err)
				}
				p := testPermit()
				if err := SignPermit(foreign, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				return p, PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: now}
			},
			wantErr: ErrPermitSignatureInvalid,
		},
		{
			name: "expired permit",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				p := testPermit()
				if err := SignPermit(signer, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				return p, PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: p.ExpiresAt.Add(time.Second)}
			},
			wantErr: ErrPermitExpired,
		},
		{
			name: "replayed single-use nonce",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				p := testPermit()
				if err := SignPermit(signer, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				store := stubNonceStore{consumed: map[string]bool{p.Nonce: true}}
				return p, PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: now, NonceStore: store}
			},
			wantErr: ErrPermitReplayed,
		},
		{
			name: "action outside scope",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				p := testPermit()
				if err := SignPermit(signer, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				return p, PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: now, Action: "files.delete"}
			},
			wantErr: ErrPermitOutOfScope,
		},
		{
			name: "parameter outside scope",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				p := testPermit()
				if err := SignPermit(signer, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				return p, PermitVerificationOptions{
					PublicKeyHex: signer.PublicKey(),
					Now:          now,
					Action:       "files.write",
					Params:       map[string]any{"path": "/tmp/x", "mode": "0777"},
				}
			},
			wantErr: ErrPermitOutOfScope,
		},
		{
			name: "connector rebinding",
			prepare: func(t *testing.T) (*effects.EffectPermit, PermitVerificationOptions) {
				p := testPermit()
				if err := SignPermit(signer, p); err != nil {
					t.Fatalf("SignPermit: %v", err)
				}
				return p, PermitVerificationOptions{PublicKeyHex: signer.PublicKey(), Now: now, ConnectorID: "another-connector"}
			},
			wantErr: ErrPermitOutOfScope,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			permit, opts := tc.prepare(t)
			err := VerifyPermitForUse(permit, opts)
			if err == nil {
				t.Fatalf("%s was allowed; the gate must deny", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyPermitForUseAllowsAnIntactPermit(t *testing.T) {
	signer := testPermitSigner(t)
	permit := testPermit()
	if err := SignPermit(signer, permit); err != nil {
		t.Fatalf("SignPermit: %v", err)
	}
	err := VerifyPermitForUse(permit, PermitVerificationOptions{
		PublicKeyHex: signer.PublicKey(),
		Now:          permit.IssuedAt.Add(time.Minute),
		NonceStore:   stubNonceStore{consumed: map[string]bool{}},
		ConnectorID:  permit.ConnectorID,
		Action:       permit.Scope.AllowedAction,
		Params:       map[string]any{"path": "/workspace/report.md"},
	})
	if err != nil {
		t.Fatalf("an intact permit was denied: %v", err)
	}
}

func TestSignPermitRefusesNilSigner(t *testing.T) {
	err := SignPermit(nil, testPermit())
	if err == nil || !strings.Contains(err.Error(), "signer is nil") {
		t.Fatalf("err = %v, want a nil-signer refusal", err)
	}
}
