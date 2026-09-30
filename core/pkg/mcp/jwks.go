package mcp

// quantum_posture: classical RSA (RS256) JWT signature verification via JWKS;
// no hybrid or post-quantum path. The verifier lives in pkg/auth/jwks.

import (
	"crypto/x509"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
)

// The bearer-token verifier moved to pkg/auth/jwks so the effect gateway can
// use it without importing this package. These names keep existing callers
// unchanged.
type (
	JWKSValidationErrorKind = jwks.JWKSValidationErrorKind
	JWKSValidationError     = jwks.JWKSValidationError
	JWKSConfig              = jwks.JWKSConfig
	OAuthTokenClaims        = jwks.OAuthTokenClaims
	JWKSValidator           = jwks.JWKSValidator
)

const (
	JWKSErrExpiredToken     = jwks.JWKSErrExpiredToken
	JWKSErrNotYetValid      = jwks.JWKSErrNotYetValid
	JWKSErrInvalidIssuer    = jwks.JWKSErrInvalidIssuer
	JWKSErrInvalidAudience  = jwks.JWKSErrInvalidAudience
	JWKSErrInvalidSignature = jwks.JWKSErrInvalidSignature
	JWKSErrMissingScope     = jwks.JWKSErrMissingScope
	JWKSErrInvalidResource  = jwks.JWKSErrInvalidResource
	JWKSErrKeyNotFound      = jwks.JWKSErrKeyNotFound
	JWKSErrMalformedToken   = jwks.JWKSErrMalformedToken
	JWKSErrFetchFailed      = jwks.JWKSErrFetchFailed
	JWKSErrInvalidActor     = jwks.JWKSErrInvalidActor
	JWKSErrInvalidLifetime  = jwks.JWKSErrInvalidLifetime
)

// NewJWKSValidator creates a validator with the given config.
func NewJWKSValidator(config JWKSConfig) *JWKSValidator { return jwks.NewJWKSValidator(config) }

// CertificateMatchesThumbprint reports whether cert is the certificate a
// token's "cnf.x5t#S256" names (RFC 8705 §3.1).
func CertificateMatchesThumbprint(cert *x509.Certificate, thumbprint string) bool {
	return jwks.CertificateMatchesThumbprint(cert, thumbprint)
}
