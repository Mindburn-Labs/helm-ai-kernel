package effectargs

// quantum_posture: a credential carries a classical ECDSA P-256 or Ed25519
// public key, which the gateway verifies WebAuthn assertions with; no hybrid or
// post-quantum protection is provided or claimed.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"regexp"
)

// The COSE algorithms a passkey of a human principal may use (helm-tracker#334).
const (
	// AlgES256 is ECDSA on P-256 with SHA-256.
	AlgES256 = -7
	// AlgEdDSA is Ed25519.
	AlgEdDSA = -8
)

// Bounds of one credential.
const (
	MaxCredentialIDBytes = 1023
	maxSPKIBytes         = 512
	maxRPIDBytes         = 253
	// MaxPrincipalCredentials bounds the passkeys one plan entry or one
	// registration carries.
	MaxPrincipalCredentials = 16
)

var rpIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Credential is a human principal's passkey: the public half of a WebAuthn
// credential, in the form the gateway stores and verifies with. The Control
// Plane converts the COSE key to SubjectPublicKeyInfo at registration.
type Credential struct {
	ID            []byte
	Alg           int
	PublicKeySPKI []byte
	RPID          string
}

// CheckCredential refuses a credential the gateway could not verify an
// assertion with: an id of 1 to 1023 bytes, ES256 with a DER
// SubjectPublicKeyInfo of a P-256 key or EdDSA with one of an Ed25519 key, and
// a relying party id that is a lower-case DNS name of at most 253 bytes.
func CheckCredential(c Credential) error {
	if len(c.ID) == 0 || len(c.ID) > MaxCredentialIDBytes {
		return invalid("a credential id is 1 to %d bytes", MaxCredentialIDBytes)
	}
	if len(c.RPID) == 0 || len(c.RPID) > maxRPIDBytes || !rpIDPattern.MatchString(c.RPID) {
		return invalid("rp_id %q is not a lower-case DNS name of at most %d bytes", c.RPID, maxRPIDBytes)
	}
	if len(c.PublicKeySPKI) == 0 || len(c.PublicKeySPKI) > maxSPKIBytes {
		return invalid("public_key_spki is 1 to %d bytes", maxSPKIBytes)
	}
	key, err := x509.ParsePKIXPublicKey(c.PublicKeySPKI)
	if err != nil {
		return invalid("public_key_spki is not a DER SubjectPublicKeyInfo")
	}
	switch c.Alg {
	case AlgES256:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return invalid("alg -7 (ES256) needs a P-256 public key")
		}
	case AlgEdDSA:
		if _, ok := key.(ed25519.PublicKey); !ok {
			return invalid("alg -8 (EdDSA) needs an Ed25519 public key")
		}
	default:
		return invalid("alg %d is not -7 (ES256) or -8 (EdDSA)", c.Alg)
	}
	return nil
}
