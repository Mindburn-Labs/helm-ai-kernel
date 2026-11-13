package admission

// quantum_posture: verifies classical ECDSA P-256 (ES256) and Ed25519 WebAuthn
// assertions with the standard library and binds them with SHA-256
// challenges; no hybrid or post-quantum protection is provided or claimed.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// OwnerAssertion is a WebAuthn authentication assertion
// (navigator.credentials.get), exactly as the authenticator and the browser
// produced it (helm-tracker#334). The gateway verifies it itself against the
// passkey the approver registered: the Control Plane's issuer is not in the
// path.
type OwnerAssertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// Bounds of an assertion the gateway reads and keeps.
const (
	minAuthenticatorDataBytes = 37
	maxAuthenticatorDataBytes = 4096
	MaxClientDataJSONBytes    = 4096
	maxSignatureBytes         = 256
)

// WebAuthn authenticator data flags (W3C WebAuthn Level 2 §6.1).
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// The domain tags of the two challenges an owner's passkey signs.
const (
	ownerAssertionTag = "helm.gateway.v1.owner-assertion.v1"
	genesisTag        = "helm.gateway.v1.genesis.v1"
)

// OwnerChallengeV1 is the challenge an approver's passkey signs to approve an
// attempt: SHA-256 over the domain tag "helm.gateway.v1.owner-assertion.v1",
// the tenant, the approver's principal id, the attempt id and the approval
// digest, each prefixed with its length as a big-endian uint64. It binds the
// assertion to one approver, one attempt and the exact digest shown.
func OwnerChallengeV1(tenantID, approverID, attemptID string, approvalDigest []byte) []byte {
	var m bytes.Buffer
	field(&m, []byte(ownerAssertionTag))
	field(&m, []byte(tenantID))
	field(&m, []byte(approverID))
	field(&m, []byte(attemptID))
	field(&m, approvalDigest)
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}

// GenesisChallengeV1 is the challenge the owner's passkey signs to enrol itself
// at the tenant's genesis: SHA-256 over the domain tag
// "helm.gateway.v1.genesis.v1", the tenant, the owner's principal id and the
// credential id, framed as OwnerChallengeV1 frames its inputs.
func GenesisChallengeV1(tenantID, principalID string, credentialID []byte) []byte {
	var m bytes.Buffer
	field(&m, []byte(genesisTag))
	field(&m, []byte(tenantID))
	field(&m, []byte(principalID))
	field(&m, credentialID)
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}

// CheckAssertionShape refuses an assertion that cannot be one before anything
// is read: an id, authenticator data and client data within their bounds, and
// a signature.
func CheckAssertionShape(a OwnerAssertion) error {
	switch {
	case len(a.CredentialID) == 0 || len(a.CredentialID) > effectargs.MaxCredentialIDBytes:
		return fmt.Errorf("the credential id is 1 to %d bytes", effectargs.MaxCredentialIDBytes)
	case len(a.AuthenticatorData) < minAuthenticatorDataBytes || len(a.AuthenticatorData) > maxAuthenticatorDataBytes:
		return fmt.Errorf("authenticator data is %d to %d bytes", minAuthenticatorDataBytes, maxAuthenticatorDataBytes)
	case len(a.ClientDataJSON) == 0 || len(a.ClientDataJSON) > MaxClientDataJSONBytes:
		return fmt.Errorf("clientDataJSON is 1 to %d bytes", MaxClientDataJSONBytes)
	case len(a.Signature) == 0 || len(a.Signature) > maxSignatureBytes:
		return fmt.Errorf("the signature is 1 to %d bytes", maxSignatureBytes)
	}
	return nil
}

// VerifyAssertion verifies a WebAuthn assertion by cred, whose stored
// signature counter is signCount, over challenge, and returns the counter the
// assertion carries. It is pure: the caller reads the credential and records
// the counter in its own transaction. It checks, in order:
//
//   - the assertion is by this credential, and of a shape the gateway keeps;
//   - authenticator data: rpIdHash is SHA-256 of the credential's rp_id, and
//     the user-present and user-verified flags are set;
//   - clientDataJSON: one JSON object with no duplicate key, whose "type" is
//     "webauthn.get", whose "challenge" is the unpadded base64url of challenge,
//     and whose "crossOrigin" is absent or false;
//   - the signed origin exactly matches the operator allowlist, or
//     https://<credential rp_id> when no origins are configured;
//   - the signature over authenticatorData || SHA-256(clientDataJSON) by the
//     credential's key: ASN.1 DER ECDSA P-256 with SHA-256 for ES256, Ed25519
//     for EdDSA;
//   - the counter never goes backwards: when either it or the stored one is
//     not zero, it is greater than the stored one (WebAuthn §6.1.1).
func VerifyAssertion(cred effectargs.Credential, signCount uint32, a OwnerAssertion, challenge []byte, origins ...string) (uint32, error) {
	if err := CheckAssertionShape(a); err != nil {
		return 0, err
	}
	if len(origins) == 0 {
		origins = []string{"https://" + cred.RPID}
	}
	if err := CheckOwnerOrigins(origins); err != nil {
		return 0, err
	}
	if !bytes.Equal(a.CredentialID, cred.ID) {
		return 0, errors.New("the assertion is by another credential")
	}
	auth := a.AuthenticatorData
	rpIDHash := sha256.Sum256([]byte(cred.RPID))
	if !bytes.Equal(auth[:32], rpIDHash[:]) {
		return 0, errors.New("the authenticator data is for another relying party than the credential's rp_id")
	}
	if auth[32]&flagUserPresent == 0 || auth[32]&flagUserVerified == 0 {
		return 0, errors.New("the authenticator did not verify a present user (UP and UV must both be set)")
	}
	counter := binary.BigEndian.Uint32(auth[33:37])
	if err := checkClientData(a.ClientDataJSON, challenge, origins); err != nil {
		return 0, err
	}
	digest := sha256.Sum256(a.ClientDataJSON)
	signed := make([]byte, 0, len(auth)+len(digest))
	signed = append(append(signed, auth...), digest[:]...)
	key, err := x509.ParsePKIXPublicKey(cred.PublicKeySPKI)
	if err != nil {
		return 0, errors.New("the credential's public key does not parse")
	}
	switch cred.Alg {
	case effectargs.AlgES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return 0, errors.New("the credential's key is not an ECDSA key")
		}
		hash := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(pub, hash[:], a.Signature) {
			return 0, errors.New("the signature does not verify with the credential's key")
		}
	case effectargs.AlgEdDSA:
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return 0, errors.New("the credential's key is not an Ed25519 key")
		}
		if !ed25519.Verify(pub, signed, a.Signature) {
			return 0, errors.New("the signature does not verify with the credential's key")
		}
	default:
		return 0, fmt.Errorf("the credential's algorithm %d is not ES256 or EdDSA", cred.Alg)
	}
	if (counter != 0 || signCount != 0) && counter <= signCount {
		return 0, fmt.Errorf("the signature counter %d is not above the stored %d: a replayed assertion or a cloned authenticator", counter, signCount)
	}
	return counter, nil
}

// checkClientData reads clientDataJSON by exact key: encoding/json folds case,
// so a "Type" or "CHALLENGE" member must not stand in for the real one.
func checkClientData(raw, challenge []byte, origins []string) error {
	if err := effectargs.CheckNoDuplicateKeys(raw); err != nil {
		return errors.New("clientDataJSON is not one JSON object without duplicate keys")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return errors.New("clientDataJSON is not a JSON object")
	}
	text := func(key string) (string, bool) {
		v, ok := members[key]
		var s string
		if !ok || len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &s) != nil {
			return "", false
		}
		return s, true
	}
	if typ, ok := text("type"); !ok || typ != "webauthn.get" {
		return errors.New(`clientDataJSON's type is not "webauthn.get"`)
	}
	if origin, ok := text("origin"); !ok || !slices.Contains(origins, origin) {
		return errors.New("clientDataJSON's origin is not an expected owner origin")
	}
	encoded, ok := text("challenge")
	if !ok {
		return errors.New("clientDataJSON carries no challenge")
	}
	got, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || !bytes.Equal(got, challenge) {
		return errors.New("clientDataJSON's challenge is not the gateway's challenge for this act")
	}
	if v, ok := members["crossOrigin"]; ok && string(bytes.TrimSpace(v)) != "false" {
		return errors.New("the assertion was made in a cross-origin frame")
	}
	return nil
}

// signedPayloadDigest names an assertion for replay: SHA-256 of what the
// credential signed. A second presentation of the same signed bytes is the
// same assertion, however its signature is encoded.
func signedPayloadDigest(a OwnerAssertion) []byte {
	digest := sha256.Sum256(a.ClientDataJSON)
	sum := sha256.Sum256(append(append([]byte(nil), a.AuthenticatorData...), digest[:]...))
	return sum[:]
}
