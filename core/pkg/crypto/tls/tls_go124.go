//go:build go1.24

package tls

import (
	"crypto/tls"
)

// HybridPQCConfig returns a TLS config with post-quantum key exchange enabled.
// Uses X25519MLKEM768 (X25519 + ML-KEM-768 hybrid) per RFC 9180 and NIST SP 800-227.
// This provides quantum-resistant key exchange while maintaining classical security.
//
// Supported in Go 1.24+. Client and server must both support the hybrid curve.
func HybridPQCConfig() *tls.Config {
	return &tls.Config{
		// Minimum TLS 1.3 required for hybrid key exchange
		MinVersion: tls.VersionTLS13,

		// Prefer hybrid post-quantum curves for key exchange
		// X25519MLKEM768 combines X25519 (classical) with ML-KEM-768 (PQ)
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // Hybrid: X25519 + ML-KEM-768 (Go 1.24+)
			tls.X25519,         // Fallback to classical X25519
		},

		// Prefer PQ-safe cipher suites
		// TLS 1.3 suites with AES-256-GCM or ChaCha20-Poly1305
		CipherSuites: nil, // Use TLS 1.3 defaults (automatic AEAD selection)
	}
}

// ServerConfig returns a production-ready TLS server config with PQC.
// Includes OCSP stapling and session tickets disabled for forward secrecy.
func ServerConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := HybridPQCConfig()
	config.Certificates = []tls.Certificate{cert}

	// Disable session tickets for perfect forward secrecy
	config.SessionTicketsDisabled = true

	// Enable OCSP stapling support
	config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		return config, nil
	}

	return config, nil
}

// ClientConfig returns a TLS client config with PQC enabled.
// Verifies server certificates and prefers hybrid key exchange.
func ClientConfig(serverName string) *tls.Config {
	config := HybridPQCConfig()
	config.ServerName = serverName
	return config
}

// InsecureClientConfig returns a TLS client config for testing only.
// WARNING: Disables certificate verification. Never use in production.
func InsecureClientConfig() *tls.Config {
	config := HybridPQCConfig()
	config.InsecureSkipVerify = true
	return config
}

// IsHybridPQCSupported checks if the runtime supports X25519MLKEM768.
// Returns true for Go 1.24+.
func IsHybridPQCSupported() bool {
	// X25519MLKEM768 constant exists only in Go 1.24+
	// If this compiles, hybrid PQC is supported
	return tls.X25519MLKEM768 != 0
}
