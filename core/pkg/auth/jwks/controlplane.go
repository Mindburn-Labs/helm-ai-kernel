package jwks

// quantum_posture: Control Plane identity tokens are classical RS256 JWTs
// verified against the Control Plane's JWKS (ADR-0005 §4); no post-quantum
// claim is made.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// The ADR-0005 Control Plane identity configuration. The kernel and the
// effect gateway read the same variables; each deployment sets its own
// audience (helm-kernel:<env> or helm-gateway:<env>).
const (
	EnvCPIdentityJWKSURL    = "HELM_CP_IDENTITY_JWKS_URL"
	EnvCPIdentityIssuer     = "HELM_CP_IDENTITY_ISSUER"
	EnvCPIdentityAudience   = "HELM_CP_IDENTITY_AUDIENCE"
	EnvCPIdentityActor      = "HELM_CP_IDENTITY_ACTOR"
	EnvCPIdentityMaxTTL     = "HELM_CP_IDENTITY_MAX_TTL"
	EnvCPIdentityRequireCNF = "HELM_CP_IDENTITY_REQUIRE_CNF"
	EnvCPIdentityCAFile     = "HELM_CP_IDENTITY_OUTBOUND_CA_BUNDLE_FILE"

	// CPIdentityMaxTTLCeiling bounds exp - iat (ADR-0005 §2).
	CPIdentityMaxTTLCeiling = 300 * time.Second
	// CPIdentityClockSkew is the allowance on exp, nbf and iat.
	CPIdentityClockSkew = 30 * time.Second
)

// ControlPlaneIdentity is a verified-at-startup ADR-0005 configuration.
type ControlPlaneIdentity struct {
	// Issuer is the pinned iss.
	Issuer string
	// Actor is the Control Plane workload identity, the act.sub it presents.
	Actor string
	// RequireCNF requires cnf.x5t#S256 to match the TLS client certificate.
	RequireCNF bool

	config JWKSConfig
}

// ControlPlaneIdentityFromEnv reads the HELM_CP_IDENTITY_* variables through
// getenv. It returns nil when none of the four required values is set, and an
// error for a partial or unusable configuration, never a silently disabled
// check.
func ControlPlaneIdentityFromEnv(getenv func(string) string) (*ControlPlaneIdentity, error) {
	values := map[string]string{}
	for _, name := range []string{EnvCPIdentityJWKSURL, EnvCPIdentityIssuer, EnvCPIdentityAudience, EnvCPIdentityActor} {
		if value := strings.TrimSpace(getenv(name)); value != "" {
			values[name] = value
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 4 {
		return nil, fmt.Errorf("%s, %s, %s and %s must be set together", EnvCPIdentityJWKSURL, EnvCPIdentityIssuer, EnvCPIdentityAudience, EnvCPIdentityActor)
	}
	maxTTL := CPIdentityMaxTTLCeiling
	if raw := strings.TrimSpace(getenv(EnvCPIdentityMaxTTL)); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > CPIdentityMaxTTLCeiling {
			return nil, fmt.Errorf("%s must be a duration in (0, %s]", EnvCPIdentityMaxTTL, CPIdentityMaxTTLCeiling)
		}
		maxTTL = parsed
	}
	client, err := pinnedCAClient(strings.TrimSpace(getenv(EnvCPIdentityCAFile)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvCPIdentityCAFile, err)
	}
	// The key set is fetched from exactly the configured URL: a redirect would
	// let whoever controls it choose the keys.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ControlPlaneIdentity{
		Issuer:     values[EnvCPIdentityIssuer],
		Actor:      values[EnvCPIdentityActor],
		RequireCNF: envTrue(getenv(EnvCPIdentityRequireCNF)),
		config: JWKSConfig{
			JWKSURL:     values[EnvCPIdentityJWKSURL],
			Issuer:      values[EnvCPIdentityIssuer],
			Audience:    values[EnvCPIdentityAudience],
			Algorithms:  []string{"RS256"},
			MaxTokenTTL: maxTTL,
			Leeway:      CPIdentityClockSkew,
			HTTPClient:  client,
		},
	}, nil
}

// Validator returns a validator for the configuration. With requireActor, a
// token's act.sub must equal Actor (the kernel's rule, ADR-0005 §3). Without
// it the claim is optional and the caller checks it: the effect gateway
// accepts a principal's own token as well as one the Control Plane carries.
func (c *ControlPlaneIdentity) Validator(requireActor bool) *JWKSValidator {
	config := c.config
	if requireActor {
		config.RequiredActor = c.Actor
	}
	return NewJWKSValidator(config)
}

// pinnedCAClient trusts only the CA bundle in caFile, or the system roots when
// caFile is empty.
func pinnedCAClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{Timeout: 10 * time.Second}, nil
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured CA bundle path
	if err != nil {
		return nil, fmt.Errorf("read outbound CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("outbound CA is invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil
}

func envTrue(value string) bool {
	switch strings.TrimSpace(value) {
	case "1", "true", "TRUE", "yes", "YES":
		return true
	}
	return false
}
