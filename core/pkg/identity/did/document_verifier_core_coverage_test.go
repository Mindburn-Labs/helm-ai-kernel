package did

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/vcredentials"
)

func TestResolvedDocumentPrimaryAssertionKeyBranches(t *testing.T) {
	multibase, err := EncodeEd25519Multibase(testPubKey)
	if err != nil {
		t.Fatal(err)
	}
	vmID := "did:key:ztest#key-1"
	vm := VerificationMethod{
		ID:                 vmID,
		Type:               ed25519VerificationKey2020,
		Controller:         "did:key:ztest",
		PublicKeyMultibase: multibase,
	}

	for _, doc := range []*ResolvedDocument{
		{ID: "did:key:ztest", VerificationMethod: []VerificationMethod{vm}, AssertionMethod: []string{vmID}},
		{ID: "did:key:ztest", VerificationMethod: []VerificationMethod{vm}, Authentication: []string{vmID}},
		{ID: "did:key:ztest", VerificationMethod: []VerificationMethod{vm}},
		{ID: "did:key:ztest", VerificationMethod: []VerificationMethod{{ID: vmID, Type: "Ed25519VerificationKey2018", PublicKeyMultibase: multibase}}, AssertionMethod: []string{vmID}},
	} {
		pub, err := doc.PrimaryAssertionKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, testPubKey) {
			t.Fatalf("unexpected assertion key: %x", pub)
		}
	}

	errorCases := []struct {
		name string
		doc  *ResolvedDocument
		want string
	}{
		{name: "nil", doc: nil, want: "nil document"},
		{name: "no methods", doc: &ResolvedDocument{ID: "did:key:ztest"}, want: "no verification method"},
		{name: "missing ref", doc: &ResolvedDocument{ID: "did:key:ztest", AssertionMethod: []string{"missing"}, VerificationMethod: []VerificationMethod{vm}}, want: "not found"},
		{name: "unsupported type", doc: &ResolvedDocument{ID: "did:key:ztest", VerificationMethod: []VerificationMethod{{ID: vmID, Type: "JsonWebKey2020"}}, AssertionMethod: []string{vmID}}, want: "not yet supported"},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.doc.PrimaryAssertionKey()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestDIDDocumentMultibaseAndJSONBranches(t *testing.T) {
	if _, err := EncodeEd25519Multibase([]byte("short")); err == nil {
		t.Fatal("expected short Ed25519 key to fail")
	}
	if _, err := decodeEd25519Multibase(""); err == nil {
		t.Fatal("expected empty multibase to fail")
	}
	if _, err := decodeEd25519Multibase("fabc"); err == nil {
		t.Fatal("expected unsupported multibase prefix to fail")
	}
	if _, err := decodeEd25519Multibase("z0"); err == nil {
		t.Fatal("expected invalid base58 to fail")
	}
	if _, err := decodeEd25519Multibase("z" + encodeBase58([]byte{multicodecEd25519Byte0, multicodecEd25519Byte1})); err == nil {
		t.Fatal("expected decoded key length mismatch to fail")
	}
	wrongPrefix := append([]byte{0x00, 0x01}, testPubKey...)
	if _, err := decodeEd25519Multibase("z" + encodeBase58(wrongPrefix)); err == nil {
		t.Fatal("expected wrong multicodec prefix to fail")
	}

	doc := &ResolvedDocument{ID: "did:key:ztest"}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), w3cDIDContext) {
		t.Fatalf("default DID context was not marshaled: %s", data)
	}
}

func TestDIDAdditionalValidationBranches(t *testing.T) {
	if DID("did:").Method() != "" {
		t.Fatal("malformed DID method should be empty")
	}
	if _, err := DID("did:key:z1").PublicKeyBytes(); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected decoded-too-short error, got %v", err)
	}
	wrongPrefix := append([]byte{0x00, 0x01}, testPubKey...)
	if _, err := DID("did:key:z" + encodeBase58(wrongPrefix)).PublicKeyBytes(); err == nil || !strings.Contains(err.Error(), "unsupported multicodec") {
		t.Fatalf("expected unsupported multicodec error, got %v", err)
	}
	shortKey := append([]byte{multicodecEd25519Byte0, multicodecEd25519Byte1}, testPubKey[:31]...)
	if _, err := DID("did:key:z" + encodeBase58(shortKey)).PublicKeyBytes(); err == nil || !strings.Contains(err.Error(), "expected 32") {
		t.Fatalf("expected extracted key length error, got %v", err)
	}
	if _, err := DID("not-a-did").Document(); err == nil {
		t.Fatal("expected invalid DID document generation to fail")
	}
}

func TestResolverMethodsNilRegisterAndErrorBranches(t *testing.T) {
	resolver := NewResolver()
	resolver.Register(nil)
	if methods := resolver.Methods(); len(methods) != 0 {
		t.Fatalf("nil register should not add methods: %v", methods)
	}
	resolver.Register(&stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:ztest"}})
	if methods := resolver.Methods(); len(methods) != 1 || methods[0] != "key" {
		t.Fatalf("unexpected registered methods: %v", methods)
	}

	if _, err := resolver.Resolve(context.Background(), ""); err == nil {
		t.Fatal("expected empty DID resolution to fail")
	}
	if _, err := resolver.Resolve(context.Background(), "not-a-did"); err == nil {
		t.Fatal("expected malformed DID resolution to fail")
	}

	nilDoc := NewResolver()
	nilDoc.Register(&stubMethod{name: "key"})
	if _, err := nilDoc.Resolve(context.Background(), "did:key:ztest"); err == nil || !strings.Contains(err.Error(), "nil document") {
		t.Fatalf("expected nil document error, got %v", err)
	}

	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	ks := NewMemoryKeystore()
	if err := ks.PutDIDDocument("did:key:zexpired", &ResolvedDocument{ID: "did:key:zexpired"}, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	stub := &stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:zexpired"}}
	withExpiredStore := NewResolver(WithClock(func() time.Time { return now }), WithKeystore(ks))
	withExpiredStore.Register(stub)
	if _, err := withExpiredStore.Resolve(context.Background(), "did:key:zexpired"); err != nil {
		t.Fatal(err)
	}
	if stub.calls != 1 {
		t.Fatalf("expired keystore entry should fall through to driver, calls=%d", stub.calls)
	}
}

func TestDIDVerifierBranches(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := NewVerifier(NewResolver()).VerifyVC(context.Background(), nil); err == nil {
		t.Fatal("expected nil credential to fail")
	}
	if err := NewVerifier(nil).VerifyVC(context.Background(), &vcredentials.VerifiableCredential{}); err == nil {
		t.Fatal("expected nil resolver to fail")
	}
	if err := NewVerifier(NewResolver()).VerifyVC(context.Background(), &vcredentials.VerifiableCredential{}); err == nil {
		t.Fatal("expected empty issuer to fail")
	}
	if err := NewVerifier(NewResolver(), WithTrustedIssuers([]string{"did:key:trusted"})).VerifyVC(context.Background(), &vcredentials.VerifiableCredential{Issuer: vcredentials.CredentialIssuer{ID: "did:key:other"}}); err == nil {
		t.Fatal("expected untrusted issuer to fail")
	}

	resolverErr := NewResolver()
	if err := NewVerifier(resolverErr).VerifyVC(context.Background(), &vcredentials.VerifiableCredential{Issuer: vcredentials.CredentialIssuer{ID: "did:key:zmissing"}}); err == nil || !strings.Contains(err.Error(), "resolving issuer") {
		t.Fatalf("expected resolver error, got %v", err)
	}

	noKeyResolver := NewResolver()
	noKeyResolver.Register(&stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:znokey"}})
	if err := NewVerifier(noKeyResolver).VerifyVC(context.Background(), &vcredentials.VerifiableCredential{Issuer: vcredentials.CredentialIssuer{ID: "did:key:znokey"}}); err == nil || !strings.Contains(err.Error(), "extracting assertion key") {
		t.Fatalf("expected assertion key extraction error, got %v", err)
	}

	signer, err := crypto.NewEd25519Signer("did-verifier")
	if err != nil {
		t.Fatal(err)
	}
	issuerDID := "did:key:zissuer"
	multibase, err := EncodeEd25519Multibase(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	doc := &ResolvedDocument{
		ID: issuerDID,
		VerificationMethod: []VerificationMethod{{
			ID:                 issuerDID + "#key-1",
			Type:               ed25519VerificationKey2020,
			Controller:         issuerDID,
			PublicKeyMultibase: multibase,
		}},
		AssertionMethod: []string{issuerDID + "#key-1"},
	}
	resolver := NewResolver()
	resolver.Register(&stubMethod{name: "key", doc: doc})

	unsigned := &vcredentials.VerifiableCredential{Issuer: vcredentials.CredentialIssuer{ID: issuerDID}}
	if err := NewVerifier(resolver).VerifyVC(context.Background(), unsigned); err == nil || !strings.Contains(err.Error(), "credential has no proof") {
		t.Fatalf("expected inner verifier proof error, got %v", err)
	}

	issuer := vcredentials.NewIssuerWithClock(issuerDID, "Issuer", signer, func() time.Time { return now })
	vc, err := issuer.Issue("urn:vc:did-success", didVerifierSubject(now), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifier(
		resolver,
		WithTrustedIssuers([]string{issuerDID, issuerDID}),
		WithVerifierClock(func() time.Time { return now.Add(time.Minute) }),
	)
	if err := verifier.VerifyVC(context.Background(), vc); err != nil {
		t.Fatalf("expected DID VC verification to pass: %v", err)
	}
}

func didVerifierSubject(now time.Time) vcredentials.AgentCapabilitySubject {
	return vcredentials.AgentCapabilitySubject{
		ID:        "did:key:zagent",
		AgentName: "DID Agent",
		Capabilities: []vcredentials.CapabilityClaim{{
			Action:     "EXECUTE_TOOL",
			Resource:   "local",
			Verified:   true,
			VerifiedAt: now,
		}},
	}
}

type failingPutKeystore struct {
	*MemoryKeystore
}

func (f *failingPutKeystore) PutDIDDocument(did string, doc *ResolvedDocument, expiresAt time.Time) error {
	_ = did
	_ = doc
	_ = expiresAt
	return errors.New("ignored")
}
