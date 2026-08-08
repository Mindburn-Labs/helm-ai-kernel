// quantum_posture: test-only. Ed25519 appears here solely to obtain a signer
// for the round trip; the tests assert wire/preimage parity, not cryptographic
// strength, and add no production cryptographic control or post-quantum
// assurance. The permit preimage itself stays algorithm-neutral (see
// effect_permit.go), so a future ML-DSA signer satisfies these tests unchanged.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

// The signed permit envelope and the published wire contract must agree.
//
// They did not: effect_permit.v1 signs evidence_bindings and
// protocols/proto/helm/effects/v1/effects.proto had no such field, so any
// proto hop dropped a signed field and verification failed on the far side —
// v1 signatures were in-process only. Nothing caught it because the two
// artifacts live in different modules and no test compared them.
//
// This test compares them as data. core cannot import the generated SDK
// package (separate module, and the dependency would point the wrong way), so
// it reads the .proto text: enough to prove a signed field has a wire home,
// which is the property that was violated.
func TestSignedPermitFieldsExistInTheWireContract(t *testing.T) {
	source, err := os.ReadFile("../../../protocols/proto/helm/effects/v1/effects.proto")
	if err != nil {
		t.Fatalf("read permit wire contract: %v", err)
	}
	block := regexp.MustCompile(`(?s)message EffectPermit \{(.*?)\n\}`).FindSubmatch(source)
	if block == nil {
		t.Fatal("message EffectPermit not found in the wire contract")
	}
	wire := map[string]struct{}{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:map<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*\d+;`).FindAllSubmatch(block[1], -1) {
		wire[string(m[1])] = struct{}{}
	}
	if len(wire) == 0 {
		t.Fatal("parsed no fields from message EffectPermit")
	}

	payload, err := EffectPermitSigningPayload(fullyPopulatedPermit())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	var signed map[string]json.RawMessage
	if err := json.Unmarshal(payload, &signed); err != nil {
		t.Fatalf("decode canonical permit: %v", err)
	}

	for field := range signed {
		// signature_version is the preimage's own domain separator, not a
		// permit field; it is reconstructed by the verifier, never transported.
		if field == "signature_version" {
			continue
		}
		if _, ok := wire[field]; !ok {
			t.Fatalf("effect_permit.v1 signs %q but message EffectPermit has no such field: "+
				"a transport that drops it produces a permit that cannot verify", field)
		}
	}
}

// The parity above is only meaningful if losing a signed field actually breaks
// verification. Prove it on the field that was missing.
func TestDroppingASignedFieldInTransitBreaksVerification(t *testing.T) {
	signer, err := NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize), "wire-parity")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	permit := fullyPopulatedPermit()
	if err := SignPermit(signer, permit); err != nil {
		t.Fatalf("sign: %v", err)
	}

	transported := *permit
	transported.EvidenceBindings = nil // a transport predating the wire field

	ok, err := VerifyPermit(signer.PublicKey(), &transported)
	if err == nil && ok {
		t.Fatal("verification passed with a signed field stripped in transit")
	}
}

func fullyPopulatedPermit() *effects.EffectPermit {
	issued := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	return &effects.EffectPermit{
		PermitID:    "permit-parity",
		IntentHash:  "sha256:intent",
		VerdictHash: "sha256:verdict",
		PlanHash:    "sha256:plan",
		PolicyHash:  "sha256:policy",
		EffectType:  effects.EffectTypeWrite,
		ConnectorID: "linear",
		Scope: effects.EffectScope{
			AllowedAction: "linear.create_issue",
			AllowedParams: []string{"team_id=s:team-1"},
			DenyPatterns:  []string{"linear:team:forbidden"},
		},
		ResourceRef:      "linear:team:team-1",
		ExpiresAt:        issued.Add(5 * time.Minute),
		SingleUse:        true,
		Nonce:            "nonce-parity",
		IssuedAt:         issued,
		IssuerID:         "kernel",
		EvidenceBindings: map[string]string{"decision_id": "decision-parity"},
	}
}
