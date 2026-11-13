package admission

// The owner passkey verifier (helm-tracker#334) as a pure function: what makes
// a WebAuthn assertion the approver's own act over exactly this challenge. The
// Postgres proofs of the same checks inside the approval transaction are in
// owner_assertion_postgres_test.go.
//
// quantum_posture: verifies classical ES256 and Ed25519 test assertions; no
// post-quantum claim.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/passkey"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

const testRPID = "app.helm.example"

func credentialOf(k *passkey.Authenticator) effectargs.Credential {
	return effectargs.Credential{ID: k.ID, Alg: k.Alg, PublicKeySPKI: k.SPKI, RPID: k.RPID}
}

func assertionOf(a passkey.Assertion) OwnerAssertion {
	return OwnerAssertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}
}

// The challenges are SHA-256 over length-prefixed fields, and every field
// moves them.
func TestOwnerChallengesAreBoundToEveryInput(t *testing.T) {
	digest := bytes.Repeat([]byte{7}, 32)
	base := OwnerChallengeV1("tenant-a", "usr_owner", "attempt-1", digest)
	if len(base) != 32 {
		t.Fatalf("challenge is %d bytes", len(base))
	}
	for name, other := range map[string][]byte{
		"tenant":   OwnerChallengeV1("tenant-b", "usr_owner", "attempt-1", digest),
		"approver": OwnerChallengeV1("tenant-a", "usr_other", "attempt-1", digest),
		"attempt":  OwnerChallengeV1("tenant-a", "usr_owner", "attempt-2", digest),
		"digest":   OwnerChallengeV1("tenant-a", "usr_owner", "attempt-1", bytes.Repeat([]byte{8}, 32)),
		// The length prefix keeps a shifted boundary from colliding.
		"boundary": OwnerChallengeV1("tenant-au", "sr_owner", "attempt-1", digest),
		"genesis":  GenesisChallengeV1("tenant-a", "usr_owner", []byte("attempt-1")),
	} {
		if bytes.Equal(base, other) {
			t.Errorf("the challenge does not move with the %s", name)
		}
	}
	// The vector the design note publishes, recomputed from its definition.
	var m bytes.Buffer
	field(&m, []byte("helm.gateway.v1.owner-assertion.v1"))
	field(&m, []byte("tenant-a"))
	field(&m, []byte("usr_owner"))
	field(&m, []byte("attempt-1"))
	field(&m, digest)
	want := sha256.Sum256(m.Bytes())
	if !bytes.Equal(base, want[:]) {
		t.Fatal("OwnerChallengeV1 is not its definition")
	}
	if got := hex.EncodeToString(GenesisChallengeV1("tenant-a", "usr_owner", []byte{1, 2, 3})); got != genesisVector {
		t.Fatalf("genesis challenge vector = %s", got)
	}
	if got := hex.EncodeToString(base); got != ownerVector {
		t.Fatalf("owner challenge vector = %s", got)
	}
}

// Test vectors of docs/architecture/gateway-provisioning-api.md.
const (
	ownerVector   = "d2e4e465b01baf195c7c40b8a6e204934a4ab7c4ebda7b231503dbc300714859"
	genesisVector = "830fd3d75a171a0829096b3fb2e10b844df3146b35efecbceb3c1945993dbb23"
)

// Known good: an ES256 and an EdDSA passkey each sign an assertion the
// verifier accepts, and the counter it returns is the one signed.
func TestVerifyAssertionAcceptsTheApproversOwnPasskey(t *testing.T) {
	challenge := OwnerChallengeV1("tenant-a", "usr_owner", "attempt-1", bytes.Repeat([]byte{1}, 32))
	for _, alg := range []int{passkey.ES256, passkey.EdDSA} {
		k := passkey.New(t, alg, testRPID)
		counter, err := VerifyAssertion(credentialOf(k), 0, assertionOf(k.Assert(t, challenge)), challenge)
		if err != nil || counter != 1 {
			t.Fatalf("alg %d: counter %d, %v", alg, counter, err)
		}
		// An authenticator without a counter signs zero, which a zero stored
		// counter accepts.
		k.Counting, k.Counter = false, 0
		if _, err := VerifyAssertion(credentialOf(k), 0, assertionOf(k.Assert(t, challenge)), challenge); err != nil {
			t.Fatalf("alg %d without a counter: %v", alg, err)
		}
	}
}

// Known bad: each way an assertion is not the approver's act over this
// challenge is refused, with the reason in the error.
func TestVerifyAssertionRefusesForgedReplayedAndMisboundAssertions(t *testing.T) {
	challenge := OwnerChallengeV1("tenant-a", "usr_owner", "attempt-1", bytes.Repeat([]byte{1}, 32))
	k := passkey.New(t, passkey.ES256, testRPID)
	other := passkey.New(t, passkey.ES256, testRPID)
	cred := credentialOf(k)
	valid := assertionOf(k.Assert(t, challenge))
	cases := map[string]struct {
		cred      effectargs.Credential
		count     uint32
		assertion OwnerAssertion
		want      string
	}{
		"another credential id": {cred, 0, func() OwnerAssertion { a := valid; a.CredentialID = other.ID; return a }(), "another credential"},
		"another key": {cred, 0, func() OwnerAssertion {
			a := assertionOf(other.Assert(t, challenge))
			a.CredentialID = k.ID
			return a
		}(), "does not verify"},
		"a forged signature": {cred, 0, func() OwnerAssertion {
			a := valid
			a.Signature = append([]byte(nil), a.Signature...)
			a.Signature[len(a.Signature)-1] ^= 1
			return a
		}(), "does not verify"},
		"changed authenticator data": {cred, 0, func() OwnerAssertion {
			a := valid
			a.AuthenticatorData = append([]byte(nil), a.AuthenticatorData...)
			a.AuthenticatorData[36]++
			return a
		}(), "does not verify"},
		"another challenge":     {cred, 0, assertionOf(k.Assert(t, OwnerChallengeV1("tenant-a", "usr_owner", "attempt-2", bytes.Repeat([]byte{1}, 32)))), "challenge"},
		"another relying party": {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) { p.RPID = "evil.example" })), "relying party"},
		"no user verification":  {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) { p.Flags = 0x01 })), "UV"},
		"no user presence":      {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) { p.Flags = 0x04 })), "UP"},
		"a registration ceremony": {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) {
			p.ClientData["type"] = "webauthn.create"
		})), "webauthn.get"},
		"a case-folded type": {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) {
			p.ClientDataJSON = []byte(`{"Type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `"}`)
		})), "webauthn.get"},
		"a duplicate challenge key": {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) {
			c := base64.RawURLEncoding.EncodeToString(challenge)
			p.ClientDataJSON = []byte(`{"type":"webauthn.get","challenge":"AAAA","challenge":"` + c + `"}`)
		})), "duplicate"},
		"a padded challenge": {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) {
			p.ClientData["challenge"] = base64.URLEncoding.EncodeToString(challenge)
		})), "challenge"},
		"a cross-origin frame": {cred, 0, assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) {
			p.ClientData["crossOrigin"] = true
		})), "cross-origin"},
		"a counter that went backwards": {cred, 1000, assertionOf(k.Assert(t, challenge)), "counter"},
		"a replayed counter":            {cred, valid.signCountOf(), valid, "counter"},
		"a zero counter over a stored one": {cred, 3, func() OwnerAssertion {
			k.Counting, k.Counter = false, 0
			defer func() { k.Counting = true }()
			return assertionOf(k.Assert(t, challenge))
		}(), "counter"},
		"an Ed25519 credential's key under ES256": {effectargs.Credential{ID: k.ID, Alg: passkey.EdDSA, PublicKeySPKI: k.SPKI, RPID: testRPID}, 0, valid, "Ed25519"},
		"short authenticator data": {cred, 0, func() OwnerAssertion {
			a := valid
			a.AuthenticatorData = a.AuthenticatorData[:36]
			return a
		}(), "authenticator data"},
		"no signature": {cred, 0, func() OwnerAssertion { a := valid; a.Signature = nil; return a }(), "signature"},
	}
	for name, c := range cases {
		if _, err := VerifyAssertion(c.cred, c.count, c.assertion, challenge); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, c.want)
		}
	}
}

// signCountOf is the counter an assertion's authenticator data carries.
func (a OwnerAssertion) signCountOf() uint32 {
	d := a.AuthenticatorData
	return uint32(d[33])<<24 | uint32(d[34])<<16 | uint32(d[35])<<8 | uint32(d[36])
}

// A replay is named by what the credential signed, not by the signature's
// bytes: an ECDSA signature can be re-encoded without the key.
func TestSignedPayloadDigestIgnoresTheSignature(t *testing.T) {
	k := passkey.New(t, passkey.ES256, testRPID)
	a := assertionOf(k.Assert(t, []byte("challenge")))
	b := a
	b.Signature = []byte("another encoding")
	if !bytes.Equal(signedPayloadDigest(a), signedPayloadDigest(b)) {
		t.Fatal("the replay key moves with the signature bytes")
	}
	c := a
	c.ClientDataJSON = append(append([]byte(nil), a.ClientDataJSON...), ' ')
	if bytes.Equal(signedPayloadDigest(a), signedPayloadDigest(c)) {
		t.Fatal("the replay key does not move with the signed client data")
	}
}

// Only the owner's assertion satisfies the step-up of an authority widening
// once the gateway requires it; anything else keeps the step-up proof.
func TestOwnerAssertionOnlyCoversAuthorityWideningsWhenRequired(t *testing.T) {
	for _, effect := range []string{effectargs.AuthorityProvision, effectargs.AuthorityLift, effectargs.AuthorityWorkReassignmentGrant} {
		if !ownerAssertionOnly(true, effect) {
			t.Errorf("%s accepts a step-up proof with owner assertions required", effect)
		}
		if ownerAssertionOnly(false, effect) {
			t.Errorf("%s refuses a step-up proof with owner assertions not required", effect)
		}
	}
	for _, effect := range []string{effectargs.AuthorityNarrow, effectargs.GitHubPullRequestMerge, "ops.release.publish"} {
		if ownerAssertionOnly(true, effect) {
			t.Errorf("%s needs an owner assertion: only widenings do", effect)
		}
	}
}
