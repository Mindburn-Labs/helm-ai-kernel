// quantum_posture: these tests exercise classical Ed25519 permit verification
// only.
package receiptverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

type frozenPermitFixture struct {
	PublicKeyHex string          `json:"public_key_hex"`
	KeyID        string          `json:"key_id"`
	Permits      []*PermitRecord `json:"permits"`
}

func loadFrozenPermit(t *testing.T) frozenPermitFixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "frozen-permit-2026.json"))
	if err != nil {
		t.Fatalf("read frozen permit fixture: %v", err)
	}
	var fx frozenPermitFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatalf("parse frozen permit fixture: %v", err)
	}
	if len(fx.Permits) != 1 {
		t.Fatalf("fixture should hold 1 permit, got %d", len(fx.Permits))
	}
	return fx
}

// bundleWithPermit joins the frozen receipt chain and the frozen permit under
// a trust root holding both signing keys, which is the shape a counterparty
// actually receives: receipts signed by the kernel's receipt key, permits by
// the issuer key.
func bundleWithPermit(t *testing.T) (Bundle, TrustRoot) {
	t.Helper()
	rfx := loadFrozen(t)
	pfx := loadFrozenPermit(t)
	trust := TrustRoot{Keys: map[string]string{
		rfx.KeyID: rfx.PublicKeyHex,
		pfx.KeyID: pfx.PublicKeyHex,
	}}
	return Bundle{Receipts: rfx.Receipts, Permits: pfx.Permits}, trust
}

// TestFrozenPermitStillVerifies extends the 2036 property to permits.
//
// The permit in the fixture EXPIRED at 2026-08-09T13:00:00Z. It still has to
// verify: "was this authorization genuine" does not stop being answerable when
// the authorization stops being usable. The signing key was discarded when the
// fixture was written, so a pass here can only come from the committed
// signature bytes still verifying under the retained effect_permit.v1
// envelope.
func TestFrozenPermitStillVerifies(t *testing.T) {
	b, trust := bundleWithPermit(t)

	res := VerifyBundle(b, trust)
	if !res.Valid {
		t.Fatalf("a bundle with a frozen permit no longer verifies: %+v", res)
	}
	var permit Check
	for _, c := range res.Checks {
		if c.Name == CheckPermit {
			permit = c
		}
	}
	if permit.Status != StatusPass {
		t.Fatalf("permit check did not pass: %s %s", permit.Status, permit.Detail)
	}
	if !strings.Contains(permit.Detail, "evidence_bindings") {
		t.Errorf("a passing permit check must state the evidence-obligation coverage; got %q", permit.Detail)
	}
	if !strings.Contains(permit.Detail, "1 bind evidence obligations") {
		t.Errorf("the fixture permit carries evidence bindings and the verdict must count it; got %q", permit.Detail)
	}
}

// TestFrozenPermitFailsWhenTampered proves the permit check can fail, field by
// field. The evidence_bindings cases are the point of the exercise: #798 put
// the obligations inside the signed envelope and #803 gave them a wire home,
// and this is the offline counterparty end of that story — rewriting, adding
// or dropping an obligation must break the signature with no HELM service
// consulted.
func TestFrozenPermitFailsWhenTampered(t *testing.T) {
	for _, tc := range []struct {
		field  string
		mutate func(*PermitRecord)
	}{
		{"permit_id", func(p *PermitRecord) { p.PermitID = "permit-other" }},
		{"intent_hash", func(p *PermitRecord) { p.IntentHash = "sha256:other-intent" }},
		{"verdict_hash", func(p *PermitRecord) { p.VerdictHash = "sha256:other-verdict" }},
		{"plan_hash", func(p *PermitRecord) { p.PlanHash = "sha256:other-plan" }},
		{"policy_hash", func(p *PermitRecord) { p.PolicyHash = "sha256:other-policy" }},
		{"effect_type", func(p *PermitRecord) { p.EffectType = "DELETE" }},
		{"connector_id", func(p *PermitRecord) { p.ConnectorID = "connector.other" }},
		{"scope.allowed_action", func(p *PermitRecord) { p.Scope.AllowedAction = "fs.delete" }},
		{"scope.allowed_params", func(p *PermitRecord) { p.Scope.AllowedParams = append(p.Scope.AllowedParams, "mode") }},
		{"scope.deny_patterns", func(p *PermitRecord) { p.Scope.DenyPatterns = nil }},
		{"resource_ref", func(p *PermitRecord) { p.ResourceRef = "helm://workspace/other" }},
		{"expires_at", func(p *PermitRecord) { p.ExpiresAt = p.ExpiresAt.AddDate(10, 0, 0) }},
		{"single_use", func(p *PermitRecord) { p.SingleUse = false }},
		{"nonce", func(p *PermitRecord) { p.Nonce = "nonce-replayed" }},
		{"issuer_id", func(p *PermitRecord) { p.IssuerID = "someone-else" }},
		{"evidence_bindings value rewritten", func(p *PermitRecord) {
			p.EvidenceBindings["sandbox_grant_hash"] = "sha256:forged-grant"
		}},
		{"evidence_bindings obligation added", func(p *PermitRecord) {
			p.EvidenceBindings["extra_obligation"] = "sha256:invented"
		}},
		{"evidence_bindings obligation dropped", func(p *PermitRecord) {
			delete(p.EvidenceBindings, "reviewed_spec_hash")
		}},
		{"evidence_bindings emptied", func(p *PermitRecord) { p.EvidenceBindings = nil }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			b, trust := bundleWithPermit(t)
			tc.mutate(b.Permits[0])

			res := VerifyBundle(b, trust)
			if res.Valid {
				t.Fatalf("rewriting %s left the bundle valid; that field is not bound by the permit signature", tc.field)
			}
			for _, c := range res.Checks {
				if c.Name == CheckPermit && c.Status != StatusFail {
					t.Errorf("permit check should fail for %s, got %s: %s", tc.field, c.Status, c.Detail)
				}
			}
		})
	}
}

// TestPermitCanonicalizationAgreesWithCrypto pins the duplicated permit
// envelope to crypto.EffectPermitSigningPayload, byte for byte, through the
// same JSON hop a real bundle crosses. If either side drifts — a field added,
// omitempty introduced, UTC normalization dropped — this fails naming the
// bytes, instead of a counterparty discovering that a genuine permit does not
// verify.
func TestPermitCanonicalizationAgreesWithCrypto(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "frozen-permit-2026.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mine frozenPermitFixture
	if err := json.Unmarshal(raw, &mine); err != nil {
		t.Fatal(err)
	}
	var theirs struct {
		Permits []*effects.EffectPermit `json:"permits"`
	}
	if err := json.Unmarshal(raw, &theirs); err != nil {
		t.Fatal(err)
	}

	myBytes, err := canonicalizePermitV1(mine.Permits[0])
	if err != nil {
		t.Fatal(err)
	}
	theirBytes, err := crypto.EffectPermitSigningPayload(theirs.Permits[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(myBytes) != string(theirBytes) {
		t.Fatalf("permit preimage drifted from crypto.EffectPermitSigningPayload:\n mine:   %s\n theirs: %s", myBytes, theirBytes)
	}
	if effectPermitSignatureV1 != crypto.EffectPermitSignatureV1 {
		t.Fatalf("version constant drifted: %q vs %q", effectPermitSignatureV1, crypto.EffectPermitSignatureV1)
	}
}

func TestUnsignedPermitIsRefused(t *testing.T) {
	b, trust := bundleWithPermit(t)
	b.Permits[0].Signature = ""

	res := VerifyBundle(b, trust)
	if res.Valid {
		t.Fatal("an unsigned permit was accepted; an unsigned permit authorizes nothing")
	}
	for _, c := range res.Checks {
		if c.Name == CheckPermit {
			if c.Status != StatusFail || !strings.Contains(c.Detail, "unsigned") {
				t.Errorf("an unsigned permit must fail by name, got %s: %s", c.Status, c.Detail)
			}
		}
	}
}

// TestBundleEmbeddedKeyIsSelfAttestedOptIn is the regression test for the
// bundle-level key material. A bundle that carries public_key_hex about itself
// must be refused with an empty trust root, must verify once the caller opts
// in, and the pass must be labelled self-attestation — for receipts and
// permits alike.
func TestBundleEmbeddedKeyIsSelfAttestedOptIn(t *testing.T) {
	t.Run("receipts", func(t *testing.T) {
		rfx := loadFrozen(t)
		b := Bundle{Receipts: rfx.Receipts, PublicKeyHex: rfx.PublicKeyHex, KeyID: rfx.KeyID}

		if res := VerifyBundle(b, TrustRoot{}); res.Valid {
			t.Fatal("a bundle supplying its own key verified with an empty trust root")
		}
		res := VerifyBundle(b, TrustRoot{AllowSelfAttested: true})
		if !res.Valid {
			t.Fatalf("the same bundle did not verify under AllowSelfAttested: %+v", res)
		}
		for _, c := range res.Checks {
			if c.Name == CheckIdentity && !strings.Contains(c.Detail, "self-attestation") {
				t.Errorf("a self-attested receipt pass must say so; got %q", c.Detail)
			}
		}
	})

	t.Run("permits", func(t *testing.T) {
		rfx := loadFrozen(t)
		pfx := loadFrozenPermit(t)
		// Receipts carry their own PublicKeySet; the permit relies on the
		// bundle-level key. Both routes are self-attestation and both must be
		// gated by the same opt-in.
		r := rfx.Receipts[0]
		r.PublicKeySet = map[string]string{rfx.KeyID: rfx.PublicKeyHex}
		b := Bundle{
			Receipts:     []*contracts.Receipt{r},
			Permits:      pfx.Permits,
			PublicKeyHex: pfx.PublicKeyHex,
			KeyID:        pfx.KeyID,
		}

		if res := VerifyBundle(b, TrustRoot{}); res.Valid {
			t.Fatal("a self-keyed bundle verified with an empty trust root")
		}
		res := VerifyBundle(b, TrustRoot{AllowSelfAttested: true})
		if !res.Valid {
			t.Fatalf("the same bundle did not verify under AllowSelfAttested: %+v", res)
		}
		for _, c := range res.Checks {
			if c.Name == CheckPermit && !strings.Contains(c.Detail, "self-attestation") {
				t.Errorf("a self-attested permit pass must say so; got %q", c.Detail)
			}
		}
	})
}

// TestPermitOnlyBundleIsAnError: permits authorize; receipts attest. A bundle
// with no receipts records no conduct, and "your authorization checks out" is
// not a verdict this tool should hand out on its own.
func TestPermitOnlyBundleIsAnError(t *testing.T) {
	pfx := loadFrozenPermit(t)
	res := VerifyBundle(
		Bundle{Permits: pfx.Permits},
		TrustRoot{Keys: map[string]string{pfx.KeyID: pfx.PublicKeyHex}},
	)
	if res.Valid {
		t.Fatal("a permit-only bundle verified; there is no conduct to attest to")
	}
	if len(res.Errors) == 0 {
		t.Error("a permit-only bundle must say why it was refused")
	}
}
