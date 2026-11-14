// Package passkey is a software WebAuthn authenticator for the gateway's owner
// passkey proofs (helm-tracker#334): it holds an ES256 or EdDSA key, and signs
// assertions over a challenge exactly as an authenticator and a browser do
// (authenticatorData || SHA-256(clientDataJSON)). Tests only; it has no I/O.
//
// quantum_posture: generates classical ECDSA P-256 and Ed25519 test keys; no
// post-quantum claim.
package passkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// The COSE algorithms an authenticator holds.
const (
	ES256 = -7
	EdDSA = -8
)

// Authenticator is one passkey.
type Authenticator struct {
	Alg  int
	ID   []byte
	RPID string
	// Counter is the signature counter the next assertion carries; Assert
	// adds one first unless it is zero and Counting is false.
	Counter  uint32
	Counting bool
	SPKI     []byte
	signer   crypto.Signer
}

// New returns a fresh passkey of alg for rpID with a random credential id and
// a counting signature counter.
func New(t testing.TB, alg int, rpID string) *Authenticator {
	t.Helper()
	a := &Authenticator{Alg: alg, RPID: rpID, Counting: true, ID: make([]byte, 16)}
	if _, err := rand.Read(a.ID); err != nil {
		t.Fatal(err)
	}
	switch alg {
	case ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		a.signer = k
	case EdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		a.signer = k
	default:
		t.Fatalf("passkey: alg %d", alg)
	}
	spki, err := x509.MarshalPKIXPublicKey(a.signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	a.SPKI = spki
	return a
}

// Assertion is a WebAuthn assertion as navigator.credentials.get returns it.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// Parts is what an assertion is made of before it is signed; a test changes
// them to forge one.
type Parts struct {
	RPID       string
	Flags      byte
	Counter    uint32
	ClientData map[string]any
	// ClientDataJSON, when set, is signed as it is instead of ClientData.
	ClientDataJSON []byte
}

// Assert signs an assertion over challenge, user present and verified.
func (a *Authenticator) Assert(t testing.TB, challenge []byte) Assertion {
	t.Helper()
	return a.AssertWith(t, challenge, nil)
}

// AssertWith signs an assertion over challenge after edit has changed its
// parts (nil keeps them).
func (a *Authenticator) AssertWith(t testing.TB, challenge []byte, edit func(*Parts)) Assertion {
	t.Helper()
	if a.Counting {
		a.Counter++
	}
	p := Parts{RPID: a.RPID, Flags: 0x01 | 0x04, Counter: a.Counter, ClientData: map[string]any{
		"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin": "https://" + a.RPID, "crossOrigin": false,
	}}
	if edit != nil {
		edit(&p)
	}
	rpIDHash := sha256.Sum256([]byte(p.RPID))
	auth := append(append([]byte(nil), rpIDHash[:]...), p.Flags)
	auth = binary.BigEndian.AppendUint32(auth, p.Counter)
	clientData := p.ClientDataJSON
	if clientData == nil {
		var err error
		if clientData, err = json.Marshal(p.ClientData); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), auth...), digest[:]...)
	var sig []byte
	var err error
	switch k := a.signer.(type) {
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(signed)
		sig, err = ecdsa.SignASN1(rand.Reader, k, h[:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, signed)
	}
	if err != nil {
		t.Fatal(err)
	}
	return Assertion{CredentialID: append([]byte(nil), a.ID...), AuthenticatorData: auth, ClientDataJSON: clientData, Signature: sig}
}
