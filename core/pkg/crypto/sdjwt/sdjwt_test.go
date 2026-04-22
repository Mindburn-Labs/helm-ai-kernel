package sdjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func newTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	return pub, priv
}

func TestIssueAndVerify_AllDisclosed(t *testing.T) {
	pub, priv := newTestKeys(t)
	issuer := NewIssuer(priv, "helm-kernel")
	verifier := NewVerifier(pub)

	claims := map[string]any{
		"compliance_level": "L3",
		"org_id":           "org-123",
		"audit_score":      95.5,
	}

	sdJWT, disclosures, err := issuer.Issue(claims, []string{"compliance_level", "org_id", "audit_score"})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// Present all disclosures.
	presentation := Presentation(sdJWT, disclosures)
	result, err := verifier.Verify(presentation)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.IssuerID != "helm-kernel" {
		t.Fatalf("expected issuer helm-kernel, got %s", result.IssuerID)
	}
	if len(result.Disclosed) != 3 {
		t.Fatalf("expected 3 disclosed claims, got %d", len(result.Disclosed))
	}
	if result.Claims["compliance_level"] != "L3" {
		t.Fatalf("expected compliance_level=L3, got %v", result.Claims["compliance_level"])
	}
}

func TestIssueAndVerify_SelectiveDisclosure(t *testing.T) {
	pub, priv := newTestKeys(t)
	issuer := NewIssuer(priv, "helm-kernel")
	verifier := NewVerifier(pub)

	claims := map[string]any{
		"compliance_level": "L3",
		"org_id":           "org-123",
		"internal_score":   42,
		"visible":          true,
	}

	sdJWT, disclosures, err := issuer.Issue(claims, []string{"org_id", "internal_score"})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// Present only org_id, withhold internal_score.
	var selected []*Disclosure
	for _, d := range disclosures {
		if d.ClaimName == "org_id" {
			selected = append(selected, d)
		}
	}
	presentation := Presentation(sdJWT, selected)
	result, err := verifier.Verify(presentation)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// org_id should be present (disclosed).
	if result.Claims["org_id"] != "org-123" {
		t.Fatalf("expected org_id=org-123, got %v", result.Claims["org_id"])
	}
	// internal_score should NOT be present (withheld).
	if _, exists := result.Claims["internal_score"]; exists {
		t.Fatal("internal_score should not be visible when not disclosed")
	}
	// visible should be present (non-disclosable, always in payload).
	if result.Claims["visible"] != true {
		t.Fatalf("expected visible=true, got %v", result.Claims["visible"])
	}
	// compliance_level should also be present (non-disclosable).
	if result.Claims["compliance_level"] != "L3" {
		t.Fatalf("expected compliance_level=L3, got %v", result.Claims["compliance_level"])
	}

	if len(result.Disclosed) != 1 {
		t.Fatalf("expected 1 disclosed claim, got %d: %v", len(result.Disclosed), result.Disclosed)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	pub, priv := newTestKeys(t)
	issuer := NewIssuer(priv, "helm-kernel")
	verifier := NewVerifier(pub)

	claims := map[string]any{"test": "value"}
	sdJWT, _, err := issuer.Issue(claims, nil)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// Tamper with the signature by flipping a character.
	tampered := strings.Replace(sdJWT, "~", "", 1) // remove trailing ~
	parts := strings.SplitN(tampered, ".", 3)
	if len(parts) == 3 {
		// Flip first char of signature.
		sig := parts[2]
		if sig[0] == 'A' {
			sig = "B" + sig[1:]
		} else {
			sig = "A" + sig[1:]
		}
		tampered = parts[0] + "." + parts[1] + "." + sig + "~"
	}

	_, err = verifier.Verify(tampered)
	if err == nil {
		t.Fatal("expected verification failure for tampered signature")
	}
}

func TestVerify_WrongPublicKey(t *testing.T) {
	_, priv1 := newTestKeys(t)
	pub2, _ := newTestKeys(t) // Different key pair
	issuer := NewIssuer(priv1, "helm-kernel")
	verifier := NewVerifier(pub2) // Wrong public key

	claims := map[string]any{"test": "value"}
	sdJWT, disclosures, err := issuer.Issue(claims, nil)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	presentation := Presentation(sdJWT, disclosures)
	_, err = verifier.Verify(presentation)
	if err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}
}

func TestVerify_FakeDisclosure(t *testing.T) {
	pub, priv := newTestKeys(t)
	issuer := NewIssuer(priv, "helm-kernel")
	verifier := NewVerifier(pub)

	claims := map[string]any{
		"level": "L3",
	}
	sdJWT, _, err := issuer.Issue(claims, []string{"level"})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// Create a fake disclosure that wasn't issued.
	fake := NewDisclosureWithSalt("fake-salt", "level", "L5") // Trying to claim L5 instead of L3

	presentation := Presentation(sdJWT, []*Disclosure{fake})
	_, err = verifier.Verify(presentation)
	if err == nil {
		t.Fatal("expected verification failure for fake disclosure")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func TestDisclosure_DeterministicHash(t *testing.T) {
	d1 := NewDisclosureWithSalt("test-salt", "claim", "value")
	d2 := NewDisclosureWithSalt("test-salt", "claim", "value")

	if d1.Hash() != d2.Hash() {
		t.Fatal("same disclosure inputs should produce same hash")
	}
	if d1.Encoded != d2.Encoded {
		t.Fatal("same disclosure inputs should produce same encoding")
	}

	d3 := NewDisclosureWithSalt("different-salt", "claim", "value")
	if d1.Hash() == d3.Hash() {
		t.Fatal("different salts should produce different hashes")
	}
}

func TestNoDisclosableClaims(t *testing.T) {
	pub, priv := newTestKeys(t)
	issuer := NewIssuer(priv, "helm-kernel")
	verifier := NewVerifier(pub)

	claims := map[string]any{
		"public_fact": "always visible",
	}

	sdJWT, disclosures, err := issuer.Issue(claims, nil)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if len(disclosures) != 0 {
		t.Fatalf("expected 0 disclosures, got %d", len(disclosures))
	}

	presentation := Presentation(sdJWT, nil)
	result, err := verifier.Verify(presentation)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if result.Claims["public_fact"] != "always visible" {
		t.Fatalf("expected public_fact='always visible', got %v", result.Claims["public_fact"])
	}
}
