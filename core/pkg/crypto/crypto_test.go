package crypto

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

func TestCanonicalHasher_Hash(t *testing.T) {
	h := NewCanonicalHasher()

	// Test map sorting determinism
	m1 := map[string]int{"a": 1, "b": 2}
	m2 := map[string]int{"b": 2, "a": 1}

	h1, err := h.Hash(m1)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	h2, err := h.Hash(m2)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if h1 != h2 {
		t.Errorf("Maps with different key order should produce same hash")
	}
}

func TestEd25519Signer_SignVerify(t *testing.T) {
	signer, err := NewEd25519Signer("key-1")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	data := []byte("hello world")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey := signer.PublicKey()

	valid, err := Verify(pubKey, sig, data)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}

	// Test tampering
	valid, _ = Verify(pubKey, sig, []byte("hello world modified"))
	if valid {
		t.Error("Tampered data should not verify")
	}
}

func TestEd25519Signer_SignReceiptSetsProfileMetadata(t *testing.T) {
	signer, err := NewEd25519Signer("key-1")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-ed-001",
		DecisionID:   "dec-ed-001",
		EffectID:     "eff-ed-001",
		Status:       "EXECUTED",
		OutputHash:   "sha256:out",
		PrevHash:     "sha256:prev",
		LamportClock: 1,
		ArgsHash:     "sha256:args",
		Timestamp:    time.Now(),
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatalf("SignReceipt failed: %v", err)
	}
	if receipt.SignatureProfile != ReceiptProfileClassical {
		t.Fatalf("signature_profile = %q", receipt.SignatureProfile)
	}
	if receipt.SignatureAlgorithm != SigPrefixEd25519 {
		t.Fatalf("signature_algorithm = %q", receipt.SignatureAlgorithm)
	}
	if receipt.KeyID != "key-1" {
		t.Fatalf("key_id = %q", receipt.KeyID)
	}
	if receipt.PublicKeySet[SigPrefixEd25519] != signer.PublicKey() {
		t.Fatalf("public_key_set = %#v", receipt.PublicKeySet)
	}
}

func TestAuditLog_Append(t *testing.T) {
	log := NewMemoryAuditLog()

	err := log.Append("user-1", "login", map[string]string{"ip": "127.0.0.1"})
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	entries := log.Entries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}
	if entries[0].Hash == "" {
		t.Error("Expected hash to be populated")
	}
}

// --- EffectPermit signing (effect_permit.v1) ------------------------------

func testEffectPermit() *effects.EffectPermit {
	issued := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	return &effects.EffectPermit{
		PermitID:    "permit-abc",
		IntentHash:  "sha256:intent",
		VerdictHash: "sha256:verdict",
		PlanHash:    "sha256:plan",
		PolicyHash:  "sha256:policy",
		EffectType:  effects.EffectTypeWrite,
		ConnectorID: "linear",
		Scope: effects.EffectScope{
			AllowedAction: "linear.create_issue",
			AllowedParams: []string{"team_id=s:team-1", "title=s:Bug"},
			DenyPatterns:  []string{"^secret"},
		},
		ResourceRef:      "linear:team:team-1",
		ExpiresAt:        issued.Add(5 * time.Minute),
		SingleUse:        true,
		Nonce:            "nonce-1",
		IssuedAt:         issued,
		IssuerID:         "mcp-governed-bridge-v1",
		EvidenceBindings: map[string]string{"decision_id": "dec-1"},
	}
}

func TestSignPermit_RoundTrip(t *testing.T) {
	signer, err := NewEd25519Signer("permit-key")
	if err != nil {
		t.Fatal(err)
	}
	permit := testEffectPermit()
	if permit.Signature != "" {
		t.Fatal("fixture must start unsigned")
	}
	if err := SignPermit(signer, permit); err != nil {
		t.Fatalf("SignPermit: %v", err)
	}
	if permit.Signature == "" {
		t.Fatal("SignPermit did not populate Signature")
	}
	ok, err := VerifyPermit(signer.PublicKey(), permit)
	if err != nil || !ok {
		t.Fatalf("freshly signed permit must verify: ok=%v err=%v", ok, err)
	}
}

// permitTampers mutates exactly one covered field each. The keys are the
// effects.EffectPermit field names (dotted for Scope members) so
// TestVerifyPermit_CoversEveryFieldButSignature can prove the set is complete.
var permitTampers = map[string]func(p *effects.EffectPermit){
	"PermitID":            func(p *effects.EffectPermit) { p.PermitID = "permit-evil" },
	"IntentHash":          func(p *effects.EffectPermit) { p.IntentHash = "sha256:evil" },
	"VerdictHash":         func(p *effects.EffectPermit) { p.VerdictHash = "sha256:evil" },
	"PlanHash":            func(p *effects.EffectPermit) { p.PlanHash = "sha256:evil" },
	"PolicyHash":          func(p *effects.EffectPermit) { p.PolicyHash = "sha256:evil" },
	"EffectType":          func(p *effects.EffectPermit) { p.EffectType = effects.EffectTypeDelete },
	"ConnectorID":         func(p *effects.EffectPermit) { p.ConnectorID = "github" },
	"Scope.AllowedAction": func(p *effects.EffectPermit) { p.Scope.AllowedAction = "linear.delete_issue" },
	"Scope.AllowedParams": func(p *effects.EffectPermit) { p.Scope.AllowedParams = []string{"team_id=s:team-evil"} },
	"Scope.DenyPatterns":  func(p *effects.EffectPermit) { p.Scope.DenyPatterns = nil },
	"ResourceRef":         func(p *effects.EffectPermit) { p.ResourceRef = "linear:team:team-evil" },
	"ExpiresAt":           func(p *effects.EffectPermit) { p.ExpiresAt = p.ExpiresAt.Add(time.Hour) },
	"SingleUse":           func(p *effects.EffectPermit) { p.SingleUse = false },
	"Nonce":               func(p *effects.EffectPermit) { p.Nonce = "nonce-evil" },
	"IssuedAt":            func(p *effects.EffectPermit) { p.IssuedAt = p.IssuedAt.Add(-time.Hour) },
	"IssuerID":            func(p *effects.EffectPermit) { p.IssuerID = "issuer-evil" },
	"EvidenceBindings":    func(p *effects.EffectPermit) { p.EvidenceBindings = map[string]string{"decision_id": "dec-evil"} },
}

func TestVerifyPermit_TamperedFieldFailsVerification(t *testing.T) {
	signer, err := NewEd25519Signer("permit-tamper-key")
	if err != nil {
		t.Fatal(err)
	}
	for name, tamper := range permitTampers {
		t.Run(name, func(t *testing.T) {
			permit := testEffectPermit()
			if err := SignPermit(signer, permit); err != nil {
				t.Fatal(err)
			}
			tamper(permit)
			ok, err := VerifyPermit(signer.PublicKey(), permit)
			if err != nil {
				t.Fatalf("tampered permit must fail verification, not error: %v", err)
			}
			if ok {
				t.Fatalf("tampered %s verified — the field is not covered by the signature", name)
			}
		})
	}
}

// TestVerifyPermit_CoversEveryFieldButSignature is the guard that keeps the
// documented covered-field list honest: a field added to EffectPermit without a
// matching tamper vector fails here rather than silently riding unsigned.
func TestVerifyPermit_CoversEveryFieldButSignature(t *testing.T) {
	covered := make(map[string]struct{}, len(permitTampers))
	for name := range permitTampers {
		root, _, _ := strings.Cut(name, ".")
		covered[root] = struct{}{}
	}
	typ := reflect.TypeOf(effects.EffectPermit{})
	for i := range typ.NumField() {
		field := typ.Field(i).Name
		if field == "Signature" {
			if _, present := covered[field]; present {
				t.Fatal("Signature must not be an input to the signature that authenticates it")
			}
			continue
		}
		if _, present := covered[field]; !present {
			t.Fatalf("EffectPermit.%s has no tamper vector: either it is uncovered by "+
				"effect_permit.v1 or the vector set is stale", field)
		}
	}

	// Scope is a nested struct. A root-level "Scope" vector proves the field is
	// reachable, not that every member of EffectScope is signed — so walk it too
	// and require a per-member vector keyed "Scope.<Field>".
	scopeCovered := make(map[string]struct{}, len(permitTampers))
	for name := range permitTampers {
		root, rest, found := strings.Cut(name, ".")
		if found && root == "Scope" {
			scopeCovered[rest] = struct{}{}
		}
	}
	scopeTyp := reflect.TypeOf(effects.EffectScope{})
	for i := range scopeTyp.NumField() {
		field := scopeTyp.Field(i).Name
		if _, present := scopeCovered[field]; !present {
			t.Fatalf("EffectScope.%s has no tamper vector: a field added to the scope "+
				"rides unsigned unless a Scope.%s vector proves otherwise", field, field)
		}
	}
}

func TestVerifyPermit_UnsignedIsRefused(t *testing.T) {
	signer, err := NewEd25519Signer("permit-unsigned-key")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPermit(signer.PublicKey(), testEffectPermit())
	if ok {
		t.Fatal("an unsigned permit must never verify")
	}
	if err == nil {
		t.Fatal("an unsigned permit must be distinguishable from a forged one")
	}
}

func TestVerifyPermit_ForeignSignerRejected(t *testing.T) {
	issuer, err := NewEd25519Signer("permit-issuer")
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := NewEd25519Signer("permit-impostor")
	if err != nil {
		t.Fatal(err)
	}
	permit := testEffectPermit()
	if err := SignPermit(impostor, permit); err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPermit(issuer.PublicKey(), permit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("a permit signed by an untrusted key must not verify")
	}
}

// The preimage normalizes timestamps to UTC, so a permit that crossed a
// transport carrying a numeric zone offset still verifies against the instant
// it was signed over.
func TestVerifyPermit_TimestampZoneIsNormalized(t *testing.T) {
	signer, err := NewEd25519Signer("permit-zone-key")
	if err != nil {
		t.Fatal(err)
	}
	permit := testEffectPermit()
	if err := SignPermit(signer, permit); err != nil {
		t.Fatal(err)
	}
	permit.IssuedAt = permit.IssuedAt.In(time.FixedZone("UTC+3", 3*60*60))
	permit.ExpiresAt = permit.ExpiresAt.In(time.FixedZone("UTC-7", -7*60*60))

	ok, err := VerifyPermit(signer.PublicKey(), permit)
	if err != nil || !ok {
		t.Fatalf("same instant in another zone must verify: ok=%v err=%v", ok, err)
	}
}

func TestSignPermit_NilArgumentsAreErrors(t *testing.T) {
	signer, err := NewEd25519Signer("permit-nil-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := SignPermit(nil, testEffectPermit()); err == nil {
		t.Fatal("nil signer must error")
	}
	if err := SignPermit(signer, nil); err == nil {
		t.Fatal("nil permit must error")
	}
	if _, err := VerifyPermit(signer.PublicKey(), nil); err == nil {
		t.Fatal("nil permit must error")
	}
}
