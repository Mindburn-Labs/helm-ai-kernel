// quantum_posture: these tests exercise the RFC 9421 wire format against the
// RFC's own classical Ed25519 test vector. They assert interoperability with a
// published signature, not cryptographic strength, and make no hybrid or
// post-quantum claim.

package httpsig

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
)

// The Ed25519 test key from RFC 9421 Appendix B.1.4.
const (
	rfc9421PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`
	rfc9421PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`

	// The Date header of the B.2 example request.
	rfc9421Date = "Tue, 20 Apr 2021 02:07:55 GMT"

	// The signature RFC 9421 Appendix B.2.6 expects for this request and key. The
	// RFC prints it wrapped per RFC 8792; it is one line here.
	rfc9421ExpectedSignature = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
)

func rfc9421Keys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	privBlock, _ := pem.Decode([]byte(rfc9421PrivateKeyPEM))
	if privBlock == nil {
		t.Fatal("private key PEM did not decode")
	}
	parsedPriv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	priv, ok := parsedPriv.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want ed25519.PrivateKey", parsedPriv)
	}
	pubBlock, _ := pem.Decode([]byte(rfc9421PublicKeyPEM))
	if pubBlock == nil {
		t.Fatal("public key PEM did not decode")
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	pub, ok := parsedPub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", parsedPub)
	}
	return priv, pub
}

// rfc9421Request rebuilds the example request from RFC 9421 Appendix B.2.
func rfc9421Request(t *testing.T) *http.Request {
	t.Helper()
	body := `{"hello": "world"}`
	r, err := http.NewRequest(http.MethodPost, "https://example.com/foo?param=Value&Pet=dog", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "example.com"
	r.Header.Set("Date", rfc9421Date)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", "18")
	return r
}

func rfc9421Params() Params {
	return Params{
		// Exactly the components B.2.6 covers, in the order it covers them. Order
		// is part of the signature base, so it is not ours to tidy.
		Components: []string{
			"date", ComponentMethod, ComponentPath, ComponentAuthority,
			"content-type", "content-length",
		},
		Created: 1618884473,
		KeyID:   "test-key-ed25519",
	}
}

// TestRFC9421KeyPairIsAPair guards the vector itself. A corrupt public key would
// still pass every round-trip test in this file, because signing and verifying
// would both use the private half. This is what caught a transcription error
// while these tests were being written.
func TestRFC9421KeyPairIsAPair(t *testing.T) {
	priv, pub := rfc9421Keys(t)
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("private key produced a %T public key", priv.Public())
	}
	if !derived.Equal(pub) {
		t.Fatalf("the RFC test key halves are not a pair\n derived: %x\n  stated: %x", derived, pub)
	}
}

// TestSignatureBaseMatchesRFC9421 is the test that makes this package worth
// having. The signature base is the exact byte string both parties must derive
// independently; if ours differs from the RFC's by one character, every signature
// we produce is unverifiable by every conforming implementation, and no amount of
// internal round-tripping would reveal it.
func TestSignatureBaseMatchesRFC9421(t *testing.T) {
	want := `"date": ` + rfc9421Date + "\n" +
		`"@method": POST` + "\n" +
		`"@path": /foo` + "\n" +
		`"@authority": example.com` + "\n" +
		`"content-type": application/json` + "\n" +
		`"content-length": 18` + "\n" +
		`"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`

	got, err := SignatureBase(rfc9421Request(t), rfc9421Params())
	if err != nil {
		t.Fatalf("SignatureBase: %v", err)
	}
	if got != want {
		t.Fatalf("signature base does not match RFC 9421 B.2.6\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestSignProducesTheRFC9421Signature proves the whole path end to end against a
// published expected value: same key, same request, same bytes out. Ed25519 is
// deterministic, so this is an equality check and not a "verifies" check.
func TestSignProducesTheRFC9421Signature(t *testing.T) {
	priv, _ := rfc9421Keys(t)
	r := rfc9421Request(t)

	if err := Sign(r, "sig-b26", priv, rfc9421Params()); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	gotSignature := r.Header.Get("Signature")
	want := "sig-b26=:" + rfc9421ExpectedSignature + ":"
	if gotSignature != want {
		t.Errorf("Signature header\n got: %s\nwant: %s", gotSignature, want)
	}
	wantInput := `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	if got := r.Header.Get("Signature-Input"); got != wantInput {
		t.Errorf("Signature-Input\n got: %s\nwant: %s", got, wantInput)
	}
}

// TestVerifyAcceptsTheRFC9421Signature checks the other direction against the
// same published value, so verification is proven against a signature this
// package did not produce.
func TestVerifyAcceptsTheRFC9421Signature(t *testing.T) {
	_, pub := rfc9421Keys(t)
	r := rfc9421Request(t)
	r.Header.Set("Signature", "sig-b26=:"+rfc9421ExpectedSignature+":")

	if err := Verify(r, "sig-b26", pub, rfc9421Params()); err != nil {
		t.Fatalf("Verify rejected the RFC's own signature: %v", err)
	}
}

// TestVerifyRejectsATamperedRequest is the property that matters in use: the
// verifier rebuilds the base from what arrived, so changing any covered part of
// the request must break verification even though the signature itself is intact.
func TestVerifyRejectsATamperedRequest(t *testing.T) {
	priv, pub := rfc9421Keys(t)

	tamper := map[string]func(*http.Request){
		"method changed":    func(r *http.Request) { r.Method = http.MethodGet },
		"authority changed": func(r *http.Request) { r.Host = "evil.example" },
		"path changed":      func(r *http.Request) { r.URL.Path = "/bar" },
		"date changed":      func(r *http.Request) { r.Header.Set("Date", "Wed, 21 Apr 2021 02:07:55 GMT") },
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			r := rfc9421Request(t)
			if err := Sign(r, "sig-b26", priv, rfc9421Params()); err != nil {
				t.Fatal(err)
			}
			mutate(r)
			if err := Verify(r, "sig-b26", pub, rfc9421Params()); err == nil {
				t.Fatal("a tampered request verified; the signature is not binding the request")
			}
		})
	}
}

// TestAuthorityOmitsTheDefaultPort covers the canonicalisation that silently
// breaks interop: a request signed with an explicit :443 and verified without it
// derives two different bases. The RFC settles it by dropping the default port.
func TestAuthorityOmitsTheDefaultPort(t *testing.T) {
	cases := map[string]struct{ host, url, want string }{
		"https default":     {"example.com:443", "https://example.com:443/foo", "example.com"},
		"https non-default": {"example.com:8443", "https://example.com:8443/foo", "example.com:8443"},
		"http default":      {"example.com:80", "http://example.com:80/foo", "example.com"},
		"uppercase host":    {"EXAMPLE.com", "https://EXAMPLE.com/foo", "example.com"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = tc.host
			base, err := SignatureBase(r, Params{Components: []string{ComponentAuthority}, KeyID: "k"})
			if err != nil {
				t.Fatal(err)
			}
			want := `"@authority": ` + tc.want + "\n"
			if !strings.HasPrefix(base, want) {
				t.Errorf("authority line\n got: %q\nwant prefix: %q", base, want)
			}
		})
	}
}

// TestEmptyPathSignsAsRoot pins the other canonicalisation with an interop edge:
// https://example.com and https://example.com/ are the same request and must sign
// the same.
func TestEmptyPathSignsAsRoot(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	base, err := SignatureBase(r, Params{Components: []string{ComponentPath}, KeyID: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(base, `"@path": /`+"\n") {
		t.Errorf("empty path did not canonicalise to /: %q", base)
	}
}

// TestSignatureBaseRefusesAMissingHeader fails closed. Signing over a component
// that is not present would produce a signature whose base the verifier cannot
// rebuild, so it is refused at signing time rather than discovered at the origin.
func TestSignatureBaseRefusesAMissingHeader(t *testing.T) {
	r := rfc9421Request(t)
	r.Header.Del("Date")
	if _, err := SignatureBase(r, rfc9421Params()); err == nil {
		t.Fatal("signing covered a header the request does not carry")
	}
}

// TestDirectoryIsStableAndValidated covers the document a Web Bot Auth verifier
// fetches to resolve a keyid.
func TestDirectoryIsStableAndValidated(t *testing.T) {
	_, pub := rfc9421Keys(t)
	directory, err := NewDirectory(map[string]ed25519.PublicKey{"b-key": pub, "a-key": pub})
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Keys) != 2 {
		t.Fatalf("directory has %d keys, want 2", len(directory.Keys))
	}
	// Sorted, so the document is byte-stable across requests and cacheable.
	if directory.Keys[0].KeyID != "a-key" || directory.Keys[1].KeyID != "b-key" {
		t.Errorf("directory is not in sorted key order: %v", directory.Keys)
	}
	if directory.Keys[0].KeyType != "OKP" || directory.Keys[0].Curve != "Ed25519" {
		t.Errorf("unexpected key type/curve: %+v", directory.Keys[0])
	}
	if _, err := NewDirectory(map[string]ed25519.PublicKey{"short": {1, 2, 3}}); err == nil {
		t.Error("a key that is not ed25519-sized was accepted into the directory")
	}
	if _, err := NewDirectory(map[string]ed25519.PublicKey{" ": pub}); err == nil {
		t.Error("a blank key id was accepted into the directory")
	}
}

// TestSignatureAgentMustBeHTTPS keeps the verifier from being pointed at a key
// over a channel the network can rewrite.
func TestSignatureAgentMustBeHTTPS(t *testing.T) {
	if _, err := SignatureAgentURL("https://agent.example/.well-known/http-message-signatures-directory"); err != nil {
		t.Errorf("a valid https signature-agent was rejected: %v", err)
	}
	for _, bad := range []string{"http://agent.example/dir", "/relative/dir", "agent.example"} {
		if _, err := SignatureAgentURL(bad); err == nil {
			t.Errorf("signature-agent %q should have been refused", bad)
		}
	}
}
