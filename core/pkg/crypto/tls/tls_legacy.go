//go:build !go1.24

package tls

import (
	"crypto/tls"
)

// Legacy Fallback for Go < 1.24 (No Hybrid ML-KEM Support)

func HybridPQCConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519, // Use classical X25519 only
		},
	}
}

func IsHybridPQCSupported() bool {
	return false
}
