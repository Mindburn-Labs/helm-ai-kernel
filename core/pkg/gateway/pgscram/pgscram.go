// Package pgscram computes a PostgreSQL SCRAM-SHA-256 password verifier on
// the client. `ALTER ROLE ... PASSWORD '<verifier>'` stores it as is, so a
// role's password is set without the plaintext reaching the server, its
// statement log or the wire. The chart's database bootstrap uses it through
// `helm-gateway db scram-verifier` (HELM-789).
package pgscram

// quantum_posture: SCRAM-SHA-256 (RFC 7677, PBKDF2-HMAC-SHA-256) as
// PostgreSQL stores it; a classical password verifier with no post-quantum
// claim.

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// Iterations is PostgreSQL's default scram_iterations.
	Iterations = 4096
	// SaltLen is the salt length PostgreSQL itself generates.
	SaltLen = 16
	// MaxPasswordLen bounds the input; PostgreSQL has no smaller limit.
	MaxPasswordLen = 1024
)

// New returns a verifier for password with a fresh random salt.
func New(password string) (string, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return Verifier(password, salt, Iterations)
}

// Verifier returns SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
// in PostgreSQL's encoding.
//
// PostgreSQL normalizes a password with SASLprep before deriving the keys.
// SASLprep leaves printable ASCII unchanged, so Verifier accepts printable
// ASCII only and refuses anything else rather than derive keys the server
// would not.
func Verifier(password string, salt []byte, iterations int) (string, error) {
	if password == "" || len(password) > MaxPasswordLen {
		return "", fmt.Errorf("password must be 1 to %d bytes", MaxPasswordLen)
	}
	for i := 0; i < len(password); i++ {
		if password[i] < 0x20 || password[i] > 0x7e {
			return "", errors.New("password must be printable ASCII: SASLprep would change anything else")
		}
	}
	if len(salt) == 0 || iterations < 1 {
		return "", errors.New("a salt and a positive iteration count are required")
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	clientKey := mac(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := mac(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func mac(key []byte, message string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}
